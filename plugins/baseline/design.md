# Baseline 插件 — 弱口令扫描 & 应用安全基线 设计文档

## 一、功能概述

本次 baseline 插件新增以下能力：

1. **弱口令扫描**：检查 Redis、MySQL、PostgreSQL、Nacos 四个应用的认证配置，识别无密码、默认口令、弱口令风险。
2. **应用安全基线**：检查 Nacos、Archery、XXL-Job 三个应用的安全配置项。
3. **弱口令字典管理**：Server 端支持在线管理弱口令字典，通过任务下发同步至 Agent 端。

## 二、整体架构

```
Server 端                                Agent 端 (baseline 插件)
┌─────────────────────┐                 ┌──────────────────────────────┐
│ UpdateWeakPassDict  │ ──── Task ────► │ TaskData.WeakPasswords       │
│ GetWeakPassDict     │                 │   └─► UpdateWeakPassDict()   │
│ (MongoDB 存储)       │                 │       (内存中维护弱口令字典)    │
└─────────────────────┘                 │                              │
                                        │ BaselineId + CheckIdList     │
┌─────────────────────┐                 │   └─► AnalysisBaseline()     │
│ Baseline 任务下发    │ ──── Task ────► │       └─► FuncCheck()        │
│                     │                 │           ├─ check_redis_*   │
│                     │ ◄── 结果上报 ─── │           ├─ check_mysql_*   │
└─────────────────────┘                 │           ├─ check_postgres_*│
                                        │           ├─ check_nacos_*   │
                                        │           ├─ check_archery_* │
                                        │           └─ check_xxl_job_* │
                                        └──────────────────────────────┘
```

## 三、实现方式 — 基于 func_check 扩展

### 3.1 为什么用 func_check 而非 file_line_check

现有的 `file_line_check` 适合已知固定路径的配置文件。应用级弱口令/安全检查面临以下挑战：

- 应用可能不存在于主机上（需先发现进程）
- 配置文件路径不固定（可能在 cmdline 参数中指定）
- 需要多个配置项的组合判断
- 不同应用的配置格式不同（Redis 空格分隔 / Java properties / Python settings.py）

因此使用 `func_check` 类型，在 Go 中实现检查逻辑。

### 3.2 YAML 配置

每个检查项在 YAML 中注册为 `func_check` 类型：

```yaml
- check_id: 5001
  type: "WeakPassword"
  title: "Redis Weak Password Check"
  security: "high"
  check:
    rules:
      - type: "func_check"
        param:
          - "check_redis_weak_password"
```

check_id 分配：

| check_id | 检查项 |
|----------|--------|
| 5001 | Redis 弱口令 |
| 5002 | MySQL 弱口令 |
| 5003 | PostgreSQL 弱口令 |
| 5004 | Nacos 弱口令 |
| 5005 | Nacos 安全配置 |
| 5006 | Archery 安全配置 |
| 5007 | XXL-Job 安全配置 |

## 四、检查函数设计 (app_check.go)

### 4.1 公共基础设施

```
findProcesses(pattern)     扫描 /proc 查找匹配的进程
findConfigFile(proc, ...)  从 cmdline 或默认路径查找配置文件
readProperties(path)       解析 key=value 格式的配置文件
isWeakPassword(pass)       线程安全地检查密码是否在弱口令字典中
collectRisks(risks)        收集多个风险后合并返回
```

### 4.2 风险收集模式

所有 Check 函数采用统一的风险收集模式，支持报告同一应用的多个风险：

```go
var risks []string
for _, proc := range procs {
    // ... 检查逻辑 ...
    if 发现风险 {
        risks = append(risks, "High Risk: [pid=xxx] 风险描述")
    }
}
return collectRisks(risks)  // 无风险返回 (true, nil)，有风险返回 (false, error)
```

### 4.3 各检查函数详细设计

#### CheckRedisWeakPassword

| 项目 | 说明 |
|------|------|
| 进程匹配 | `redis-server` |
| 配置查找 | cmdline 中的 positional arg (.conf) → `/etc/redis/redis.conf` → `/etc/redis.conf` |
| 检查项 | `requirepass`、`masterauth` |
| 解析方式 | 逐行读取，跳过 `#` 注释行，正则 `^requirepass\s+(\S+)` |
| 判断逻辑 | 无密码→高危，默认密码(redis/admin)→高危，弱口令→中危 |

#### CheckMysqlWeakPassword

| 项目 | 说明 |
|------|------|
| 进程匹配 | `mysqld` |
| 配置查找 | `--defaults-file` → `/etc/my.cnf` `/etc/mysql/my.cnf` `/var/lib/my.cnf` `/var/lib/mysql/my.cnf` |
| 检查项 | `password` (明文出现在配置文件中的场景) |
| 已知限制 | MySQL 密码通常存储为 hash，配置文件中明文密码仅在特定部署场景下存在 |

#### CheckPostgresWeakPassword

| 项目 | 说明 |
|------|------|
| 进程匹配 | `postgres` |
| 配置查找 | cmdline `-D` 参数 → 常见路径 + `/etc/postgresql/{version}/main/pg_hba.conf` + `/var/lib/postgresql/{version}/main/pg_hba.conf` |
| 检查项 | pg_hba.conf 中的认证方式 |
| 判断逻辑 | 存在 `trust` 认证方式 → 高危 |

#### CheckNacosWeakPassword

| 项目 | 说明 |
|------|------|
| 进程匹配 | `nacos` |
| 配置查找 | `-Dnacos.home` → cwd 下的 `conf/application.properties` |
| 检查项 | `nacos.core.auth.enabled`、`token.secret.key`、`default.token.secret.key`、schema.sql 默认密码 |
| 共享逻辑 | 通过 `findNacosHomeAndProps()` 与 CheckNacosConfig 共享配置解析 |

#### CheckNacosConfig

| 项目 | 说明 |
|------|------|
| 配置项 | 检查内容 |
| `nacos.core.auth.enabled` | 是否为 true |
| `nacos.core.auth.admin.enabled` | 是否为 true |
| `nacos.core.auth.console.enabled` | 是否为 true |
| `nacos.core.auth.enable.userAgentAuthWhite` | 是否为 false |
| `nacos.core.auth.plugin.nacos.token.secret.key` | 是否为默认密钥，长度是否 >= 32 |
| `nacos.core.auth.default.token.secret.key` | 是否为默认密钥 (1.2.0~2.0.4) |
| `nacos.core.auth.server.identity.key` | 是否为默认值 serverIdentity |
| `nacos.core.auth.server.identity.value` | 是否为默认值 security |
| `management.endpoints.web.exposure.include` | 是否为 * (暴露所有端点) |
| `management.endpoints.web.exposure.exclude` | 是否配置为 * (关闭所有端点暴露) |
| mysql-schema.sql / derby-schema.sql | 是否包含 nacos/nacos 默认密码 |

#### CheckArcheryConfig

| 项目 | 说明 |
|------|------|
| 进程匹配 | `archery` |
| 配置查找 | `{cwd}/archery/settings.py` |
| 检查项 | `DEBUG` 是否为 True (正则匹配)，`SECRET_KEY` 是否为默认值 |

#### CheckXxlJobConfig

| 项目 | 说明 |
|------|------|
| 进程匹配 | `xxl-job-admin` |
| 配置查找 | `-Dspring.config.location` → `/xxl-job/xxl-job-admin/src/main/resources/application.properties` |
| 检查项 | `xxl.job.accessToken` 非空且非弱密码，`spring.datasource.password` 非空且非弱密码 |

## 五、弱口令字典管理

### 5.1 Agent 端

- 内置基础弱口令列表：`123456, password, admin, root, 12345678`
- `UpdateWeakPassDict(passwords)` 全量替换字典（内置 + 下发）
- 线程安全：使用 `sync.RWMutex` 保护

### 5.2 Server 端

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/v6/baseline/UpdateWeakPassDict` | POST | 更新弱口令字典（MongoDB 存储） |
| `/api/v6/baseline/GetWeakPassDict` | GET | 获取当前字典 |

更新后异步触发 `SyncWeakPassTask`，批量（每批 1000）下发至所有在线 Agent 的 baseline 插件。

### 5.3 TaskData 协议扩展

```json
{
    "baseline_id": 0,
    "weak_passwords": ["pass1", "pass2", "..."]
}
```

`baseline_id=0` 表示仅同步字典不执行检查。

## 六、analysis.go 改动

- `TaskData` 新增 `WeakPasswords []string` 字段
- `AnalysisBaseline` 入口新增弱口令字典更新逻辑
- 错误处理增强：通过 `strings.Contains(err.Error(), "Risk")` 区分风险报告和系统错误
