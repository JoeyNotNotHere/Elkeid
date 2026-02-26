# Code Review: feat:baseline and collector

> 分支: `feature_baseline_and_collector`  
> Commit: `c0eb79e feat:baseline and collector`  
> Review 日期: 2026-02-27

---

## 一、代码缺陷（Bug）

### 【严重】BUG-1: `matchFunc` 从未被 `GenerateApp` 调用，Apache APISIX 和 Kibana 无法识别

**文件**: `plugins/collector/app.go`

`AppRule` 结构体新增了 `matchFunc` 字段，并在 `nginxRule`/`tegineRule`/`openrestyRule`（用于识别 Apache APISIX）和 `nodeRule`（用于识别 Kibana）中赋值。但 `GenerateApp` 方法中**从未调用 `matchFunc`**，导致这两个应用永远无法被识别。

**影响**: 需求文档中要求识别的 Apache APISIX 和 Kibana 完全失效。

**修复方案**: 在 `GenerateApp` 方法中，在 sub 链处理之前或版本检测之前，调用 `matchFunc`：

```go
func (r *AppRule) GenerateApp(rc RuleContext) ([]byte, *App) {
    // 优先检查 matchFunc
    if r.matchFunc != nil {
        if output, app := r.matchFunc(rc); app != nil {
            if r.confFunc != nil {
                app.Conf = r.confFunc(rc)
            }
            return output, app
        }
    }
    // ... 后续原有逻辑
}
```

---

### 【严重】BUG-2: Java 应用版本提取逻辑失效

**文件**: `plugins/collector/app.go`

新增的 Java 应用规则（`kafkaRule`、`nacosRule`、`elasticsearchRule` 等）设置了 `versionRegex`，但 **没有设置 `versionArgs`**。`GenerateApp` 中的版本提取逻辑是：

```go
output, err = ExecAs(..., rc.exe, r.versionArgs...)
```

对于 Java 进程，`rc.exe` = `/usr/bin/java`，`versionArgs` 为 nil，因此会执行 `java`（无参数），输出 Java 的帮助信息，而非 Kafka/Nacos 等的版本信息。`versionRegex` 对 Java 帮助信息匹配不到任何内容，版本永远为空。

此外，`versionRegex` 使用了捕获组（如 `nacos-server-(\d+\.\d+\.\d+)`），但代码使用 `Find`（返回整个匹配）而非 `FindSubmatch`（返回捕获组），且 `versionTrimPrefix` 为空，即使匹配成功，版本值也会是 `nacos-server-2.0.3` 而非 `2.0.3`。

**影响**: kafka、nacos、elasticsearch 等所有新增 Java 应用均无法获取正确版本号。

**修复方案**: Java 应用不应通过执行二进制获取版本。应从 cmdline 中提取版本信息：

```go
// 在 GenerateApp 的 java_app dispatch 段中
if strings.Contains(cmdline, "nacos") {
    rc.appVersion = extractVersionFromCmdline(cmdline, nacosRule.versionRegex)
    return nacosRule.GenerateApp(rc)
}

func extractVersionFromCmdline(cmdline string, re *regexp.Regexp) string {
    matches := re.FindStringSubmatch(cmdline)
    if len(matches) > 1 {
        return matches[1]
    }
    return ""
}
```

同时，对使用捕获组的 regex 改用 `FindSubmatch`，或者修改 regex 去掉捕获组并设置正确的 `versionTrimPrefix`。

---

### 【严重】BUG-3: `findJar` 中 `r.Close()` 在循环内部导致资源提前释放

**文件**: `plugins/collector/software.go`

新增的 pom.properties 版本提取代码复制了已有 MANIFEST.MF 解析的错误模式：

```go
if version == "" && strings.HasSuffix(f.Name, "pom.properties") {
    if r, err := f.Open(); err == nil {
        for sc := bufio.NewScanner(r); sc.Scan(); {
            if strings.HasPrefix(sc.Text(), "version=") {
                version = strings.TrimSpace(sc.Text()[len("version="):])
                break
            }
            r.Close() // BUG: 在第一个非匹配行就关闭了 reader
        }
    }
}
```

`r.Close()` 放在了 for 循环内部的 else 分支（非 break 路径），导致读取第一个非 `version=` 开头的行后，reader 就被关闭。后续的 `sc.Scan()` 将失败。

**修复方案**: 将 `r.Close()` 移到 for 循环之后：

```go
if version == "" && strings.HasSuffix(f.Name, "pom.properties") {
    if r, err := f.Open(); err == nil {
        sc := bufio.NewScanner(r)
        for sc.Scan() {
            if strings.HasPrefix(sc.Text(), "version=") {
                version = strings.TrimSpace(sc.Text()[len("version="):])
                break
            }
        }
        r.Close()
    }
}
```

注意：同文件中已有的 MANIFEST.MF 解析代码也存在同样的 bug，建议一并修复。

---

### 【中等】BUG-4: Redis 弱口令检查会匹配注释行

**文件**: `plugins/baseline/src/check/app_check.go` - `CheckRedisWeakPassword`

正则 `requirepass\s+(\S+)` 会匹配到被注释掉的行，如 `# requirepass foobared`。Redis 默认配置文件中通常包含注释掉的 `requirepass` 示例，会导致误报。

**修复方案**: 按行读取并跳过注释行，或修改正则排除注释：

```go
scanner := bufio.NewScanner(strings.NewReader(string(content)))
for scanner.Scan() {
    line := strings.TrimSpace(scanner.Text())
    if strings.HasPrefix(line, "#") || line == "" {
        continue
    }
    re := regexp.MustCompile(`^requirepass\s+(\S+)`)
    match := re.FindStringSubmatch(line)
    if len(match) > 1 {
        // ... 检查逻辑
    }
}
```

---

### 【中等】BUG-5: `CheckRedisWeakPassword` 只对第一个 Redis 实例返回结果

**文件**: `plugins/baseline/src/check/app_check.go`

函数遍历所有 Redis 进程，但在发现第一个有问题的进程时立即 `return false`，发现第一个无问题的进程时也在 `else` 分支中 `return false`（"No password set"）。如果机器上运行多个 Redis 实例，只有第一个被检查。

**影响**: 多 Redis 实例场景下只检查第一个。

**修复方案**: 收集所有进程的检查结果，或者改为遇到任何一个风险即返回失败（保持当前行为但修复逻辑使之明确）。如果 `confPath == ""` 则 `continue` 已经正确处理了无配置的情况，但需确保 `return false, errors.New("High Risk: No password set")` 只在确认该进程确实无密码时触发。

---

### 【中等】BUG-6: `FuncCheck` 中未知 func_name 会返回 `false, nil`

**文件**: `plugins/baseline/src/check/rules.go`

```go
var funcRes bool
var checkErr error
switch param[0] {
case "check_redis_weak_password":
    ...
}
if checkErr != nil {
    return false, checkErr
}
return funcRes, nil
```

如果 `param[0]` 不匹配任何 case，`funcRes` 默认为 `false`，`checkErr` 默认为 `nil`，函数返回 `false, nil`，表示检查失败。对于未知的检查函数名，应返回错误而非静默失败。

**修复方案**: 添加 `default` 分支：

```go
default:
    return false, fmt.Errorf("unknown func_check: %s", param[0])
```

---

### 【中等】BUG-7: Archery Debug 模式检查过于简单

**文件**: `plugins/baseline/src/check/app_check.go` - `CheckArcheryConfig`

```go
if strings.Contains(text, "DEBUG = True") {
```

只能匹配 `DEBUG = True` 这一种格式。Python settings.py 中可能出现 `DEBUG=True`、`DEBUG =True`、`DEBUG = env('DEBUG', default=True)` 等多种写法。

**修复方案**: 使用正则匹配：

```go
re := regexp.MustCompile(`(?m)^\s*DEBUG\s*=\s*.*True`)
if re.MatchString(text) {
    return false, errors.New("High Risk: Archery running in DEBUG mode")
}
```

---

### 【低】BUG-8: `&[]byte{}` 指针使用不当

**文件**: `plugins/collector/app.go`

多处使用 `return &[]byte{}, &App{...}` 返回了一个指向空字节切片的指针。`GenerateApp` 的返回类型是 `([]byte, *App)`，而 `&[]byte{}` 的类型是 `*[]byte`，**类型不匹配，编译应该会报错**。如果编译通过，说明可能使用了隐式转换或此处存在理解偏差。

**修复方案**: 改为 `return []byte{}, &App{...}` 或 `return nil, &App{...}`。

---

### 【低】BUG-9: 使用已废弃的 `ioutil` 包

**文件**: `plugins/baseline/src/check/app_check.go`

大量使用 `ioutil.ReadDir`、`ioutil.ReadFile`，这些函数在 Go 1.16 已被废弃。

**修复方案**: 替换为 `os.ReadDir`、`os.ReadFile`。

---

### 【低】BUG-10: 弱口令字典只增不减

**文件**: `plugins/baseline/src/check/app_check.go` - `UpdateWeakPassDict`

```go
func UpdateWeakPassDict(passwords []string) {
    weakPassMutex.Lock()
    defer weakPassMutex.Unlock()
    for _, p := range passwords {
        weakPasswords[p] = true
    }
}
```

只往内存字典中添加，无法移除。如果误添加了正常密码，无法修正。Server 端 `UpdateWeakPassList` 是全量替换，但 Agent 端是增量追加，两边语义不一致。

**修复方案**: Agent 端改为全量替换：

```go
func UpdateWeakPassDict(passwords []string) {
    weakPassMutex.Lock()
    defer weakPassMutex.Unlock()
    newDict := map[string]bool{
        "123456": true, "password": true, "admin": true, "root": true, "12345678": true,
    }
    for _, p := range passwords {
        newDict[p] = true
    }
    weakPasswords = newDict
}
```

---

## 二、需求覆盖分析

### 1. 资产指纹识别

| 需求项 | 状态 | 说明 |
|--------|------|------|
| 进程发现（PID、启动命令、运行用户） | ✅ 已实现 | 原有 DescribeProcess 已覆盖 |
| Jar 包 classpath/jar 参数扫描 | ✅ 已实现 | `parseClasspath` 解析 -jar、-cp、-classpath |
| Jar 递归扫描（深度 3） | ✅ 已实现 | `MaxRecursionLevel = 3` |
| 版本识别：MANIFEST.MF | ✅ 已实现 | 原有逻辑 |
| 版本识别：pom.properties | ⚠️ 有 Bug | 已实现但 Close 位置错误（BUG-3） |
| 版本识别：文件名解析 | ✅ 已实现 | `parseJarFilename` |
| DescribeSoftware 新增 path 字段 | ✅ 已实现 | Software 结构体已添加 Path |
| Jar 扫描最大数量限制 | ❌ 未实现 | 技术方案提到"最大扫描数量确定，避免性能影响"，但代码中无此限制 |
| 应用扫描 lib 子目录 | ⚠️ 部分实现 | 仅扫描 classpath 中的目录，未主动扫描 -jar 同级 lib/ 目录 |

### 2. 应用识别（DescribeApp）

| 需求应用 | 状态 | 说明 |
|----------|------|------|
| httpd / Apache | ✅ | 原有 |
| Nginx | ✅ | 原有 |
| Redis | ✅ | 原有 |
| Rabbitmq | ✅ | 原有 |
| Grafana | ✅ | 原有 |
| Mysql | ✅ | 原有 |
| Postgresql | ✅ | 原有 |
| Mongodb | ✅ | 原有 |
| etcd | ✅ | 原有 |
| Prometheus | ✅ | 原有 |
| Sqlserver | ✅ | 原有 |
| Dockerd | ✅ | 原有 |
| Containerd | ✅ | 原有 |
| Kubelet | ✅ | 原有 |
| Logstash | ✅ | 新增（Java dispatch） |
| Ansible | ✅ | 新增（Python dispatch） |
| **Apache APISIX** | ❌ | matchFunc 未被调用（BUG-1） |
| Apache Kafka | ⚠️ | 已识别但版本提取失败（BUG-2） |
| Apache RocketMQ | ⚠️ | 已识别但无版本提取 |
| Archery | ✅ | Python dispatch |
| Canal | ⚠️ | 已识别但无版本无配置 |
| Django | ✅ | 新增 |
| Doris | ⚠️ | 已识别但无版本无配置 |
| Druid | ⚠️ | 已识别但无版本无配置 |
| Hadoop | ⚠️ | 已识别但无版本无配置 |
| Jenkins | ⚠️ | 已识别但版本提取失败（BUG-2） |
| Jumpserver | ✅ | 新增 |
| **Kibana** | ❌ | matchFunc 未被调用（BUG-1） |
| Logbase | ⚠️ | 已识别但无版本无配置 |
| Nacos | ⚠️ | 已识别但版本提取失败（BUG-2） |
| Nexus | ⚠️ | 已识别但无版本无配置 |
| Rancher | ✅ | 新增 |
| Ruoyi | ⚠️ | 已识别但无版本无配置 |
| Saltstack | ✅ | 新增 |
| Skywalking | ⚠️ | 已识别但无版本无配置 |
| Tidb | ✅ | 新增 |
| Xxl-job | ⚠️ | 已识别但无版本无配置 |
| Zabbix | ✅ | 新增 |
| ambari | ⚠️ | 已识别但无版本无配置 |

### 3. 弱口令扫描

| 需求项 | 状态 | 说明 |
|--------|------|------|
| Redis 弱口令检查 | ⚠️ 有 Bug | 会匹配注释行（BUG-4），缺少 masterauth 检查 |
| MySQL 弱口令检查 | ⚠️ 受限 | 技术方案已知限制：密码通常不在配置文件中。缺少需求中的部分默认路径 |
| PostgreSQL 弱口令检查 | ⚠️ 受限 | 仅检查 trust 认证，缺少需求中的带版本号路径 |
| Nacos 弱口令检查 | ✅ | 基本实现 |
| 弱口令字典在线管理（Server 端） | ✅ | UpdateWeakPassDict / GetWeakPassDict 接口已实现 |
| 弱口令字典下发至 Agent | ✅ | SyncWeakPassTask 已实现 |
| Agent 内存中维护弱口令字典 | ⚠️ | 已实现但只增不减（BUG-10） |

### 4. 应用安全基线扫描

| 需求项 | 状态 | 说明 |
|--------|------|------|
| Nacos: `nacos.core.auth.enabled` | ✅ | 已检查 |
| Nacos: `nacos.core.auth.admin.enabled` | ✅ | 已检查 |
| Nacos: `nacos.core.auth.console.enabled` | ✅ | 已检查 |
| Nacos: `nacos.core.auth.enable.userAgentAuthWhite` | ✅ | 已检查 |
| Nacos: `nacos.core.auth.plugin.nacos.token.secret.key` | ✅ | 已检查默认密钥和短密钥 |
| Nacos: `nacos.core.auth.server.identity.key` | ✅ | 已检查默认值 serverIdentity |
| Nacos: `nacos.core.auth.server.identity.value` | ✅ | 已检查默认值 security |
| Nacos: `management.endpoints.web.exposure.include` | ✅ | 已检查 `*` |
| Nacos: `management.endpoints.web.exposure.exclude` | ❌ | 代码中有注释但未实际检查，需求要求确认是否配置为 `*` |
| **Nacos: `nacos.core.auth.default.token.secret.key`** | ❌ | 需求文档明确要求检查（1.2.0~2.0.4 版本），代码中未实现 |
| Nacos: mysql-schema.sql 默认密码 | ✅ | 已检查 |
| Nacos: derby-schema.sql 默认密码 | ✅ | 已检查（在 CheckNacosConfig 中） |
| Archery: SECRET_KEY 默认值 | ✅ | 已检查 |
| Archery: Debug 模式 | ⚠️ 有 Bug | 匹配逻辑过于简单（BUG-7） |
| XXL-Job: `xxl.job.accessToken` | ✅ | 已检查空值和弱密码 |
| XXL-Job: `spring.datasource.password` | ✅ | 已检查空值和弱密码 |

### 5. 数据上报字段完整性

| 需求字段 | 指纹上报 | 弱口令/基线上报 |
|----------|----------|-----------------|
| 主机 ID / 容器 ID | ✅ | ✅（通过 baseline 框架） |
| 组件名称 | ✅ | N/A |
| 版本号 | ⚠️ 多数 Java 应用为空 | N/A |
| 文件路径 | ✅ path 字段已新增 | N/A |
| 采集时间 | ✅ | ✅ |
| 服务类型 | N/A | ✅ |
| 风险类型 | N/A | ✅ |
| 风险等级 | N/A | ✅ |
| 修复建议 | N/A | ✅（YAML solution 字段） |

---

## 三、架构/设计问题

### DESIGN-1: Java/Python 应用分发逻辑重复

`app.go` 中的 Java/Python 应用分发逻辑在 `confFunc` 和 `GenerateApp` 中**各写了一遍**。如果新增应用，需要同时修改两处，容易遗漏。

**建议**: 统一使用一个调度映射表，或将分发逻辑集中到 `GenerateApp` 中。

### DESIGN-2: `CheckNacosWeakPassword` 与 `CheckNacosConfig` 大量重复代码

两个函数共享了 Nacos 进程发现、配置文件查找、properties 解析等逻辑，且 `nacos.core.auth.enabled` 在两个函数中都检查了。

**建议**: 提取公共的 Nacos 配置获取函数，两个检查函数复用。

### DESIGN-3: 基线检查函数只能返回一个风险

所有 Check 函数（如 `CheckNacosConfig`）遇到第一个风险即 return，无法报告同一应用存在的多个风险。例如 Nacos 同时存在鉴权未开启和默认密钥的情况，只会报告第一个。

**建议**: 改为收集所有风险项后一起返回，或改为每个配置项拆分为独立的 check_id。

### DESIGN-4: 1400.yaml 中删除了 SSH Protocol 2 检查

Commit 中 1400.yaml 删除了 `check_id: 13`（Ensure SSH Protocol is set to 2），并修改了 LogLevel 检查的 filter/result。这与 baseline/collector 功能无关，应拆分为独立 commit。

---

## 四、总结

### 必须修复（阻塞上线）

| 编号 | 问题 | 优先级 |
|------|------|--------|
| BUG-1 | matchFunc 未被调用，APISIX/Kibana 无法识别 | P0 |
| BUG-2 | Java 应用版本提取逻辑完全失效 | P0 |
| BUG-3 | pom.properties 中 Close 位置错误 | P1 |
| BUG-4 | Redis 弱口令匹配注释行导致误报 | P1 |
| BUG-8 | `&[]byte{}` 类型不匹配，可能编译失败 | P0 |

### 建议修复（可排期）

| 编号 | 问题 | 优先级 |
|------|------|--------|
| BUG-5 | 多 Redis 实例只检查第一个 | P2 |
| BUG-6 | 未知 func_check 静默失败 | P2 |
| BUG-7 | Archery Debug 检查过于简单 | P2 |
| BUG-9 | 使用废弃的 ioutil 包 | P3 |
| BUG-10 | 弱口令字典只增不减 | P2 |
| 需求缺失 | Nacos `default.token.secret.key` 未检查 | P2 |
| 需求缺失 | `management.endpoints.web.exposure.exclude` 未检查 | P2 |
| 需求缺失 | Jar 扫描无最大数量限制 | P2 |
| 需求缺失 | 未主动扫描 -jar 同级 lib/ 子目录 | P2 |
| DESIGN-4 | SSH Protocol 检查删除应拆分 commit | P3 |

---

## 五、修复工作日志

| 编号 | 问题 | 修复文件 | 状态 |
|------|------|----------|------|
| BUG-1 | matchFunc 未被调用，APISIX/Kibana 无法识别 | `plugins/collector/app.go` | ✅ 已修复 |
| BUG-2 | Java 应用版本提取逻辑失效 | `plugins/collector/app.go` | ✅ 已修复 |
| BUG-3 | pom.properties 中 Close 位置错误 | `plugins/collector/software.go` | ✅ 已修复 |
| BUG-4 | Redis 弱口令匹配注释行 | `plugins/baseline/src/check/app_check.go` | ✅ 已修复 |
| BUG-5 | 多 Redis 实例只检查第一个 | `plugins/baseline/src/check/app_check.go` | ✅ 已修复 |
| BUG-6 | 未知 func_check 静默失败 | `plugins/baseline/src/check/rules.go` | ✅ 已修复 |
| BUG-7 | Archery Debug 检查过于简单 | `plugins/baseline/src/check/app_check.go` | ✅ 已修复 |
| BUG-8 | `&[]byte{}` 类型不匹配 | `plugins/collector/app.go` | ✅ 已修复 |
| BUG-9 | 使用废弃的 ioutil 包 | `plugins/baseline/src/check/app_check.go` | ✅ 已修复 |
| BUG-10 | 弱口令字典只增不减 | `plugins/baseline/src/check/app_check.go` | ✅ 已修复 |
| MISS-1 | Nacos default.token.secret.key 未检查 | `plugins/baseline/src/check/app_check.go` | ✅ 已修复 |
| MISS-2 | management.endpoints.web.exposure.exclude 未检查 | `plugins/baseline/src/check/app_check.go` | ✅ 已修复 |
| MISS-3 | Jar 扫描无最大数量限制 | `plugins/collector/software.go` | ✅ 已修复 |
| MISS-4 | 未主动扫描 -jar 同级 lib/ 子目录 | `plugins/collector/software.go` | ✅ 已修复 |
| DESIGN-1 | Java/Python 分发逻辑重复 | `plugins/collector/app.go` | ✅ 已修复 |
| DESIGN-2 | Nacos 检查函数重复代码 | `plugins/baseline/src/check/app_check.go` | ✅ 已修复 |
| DESIGN-3 | 基线检查只能返回一个风险 | `plugins/baseline/src/check/app_check.go` | ✅ 已修复 |

---

## 六、最终需求覆盖对照（修复后）

### 1. 资产指纹识别

| 需求项 | 实现状态 | 说明 |
|--------|----------|------|
| 进程发现（PID、启动命令、运行用户） | ✅ 完成 | 原有 DescribeProcess |
| Jar 包扫描：从 -jar/-cp/-classpath 提取路径 | ✅ 完成 | `parseClasspath` |
| Jar 包扫描：扫描 lib 子目录 | ✅ 完成 | 已修复，-jar 同级 lib/ 自动追加 |
| Jar 包扫描：递归深度 3 | ✅ 完成 | `MaxRecursionLevel = 3` |
| Jar 包扫描：最大数量限制 | ✅ 完成 | 已修复，`MaxJarPerProcess = 500` |
| 版本识别：文件名解析 | ✅ 完成 | `parseJarFilename` |
| 版本识别：MANIFEST.MF | ✅ 完成 | `Implementation-Version` |
| 版本识别：pom.properties | ✅ 完成 | 已修复 Close 位置 |
| 上报字段：path | ✅ 完成 | Software 结构体新增 Path |
| 上报字段：container_id | ✅ 完成 | 原有支持 |
| 上报字段：采集时间 | ✅ 完成 | Timestamp |

### 2. 基础应用识别（全部 30+ 应用）

| 应用 | 状态 | 版本提取 | 配置路径 |
|------|------|----------|----------|
| httpd / Apache | ✅ | ✅ `-v` | ✅ cmdline/-f/默认路径 |
| Nginx | ✅ | ✅ `-v` | ✅ cmdline/-c/默认路径 |
| Redis | ✅ | ✅ `-v` | ✅ cmdline positional arg |
| Rabbitmq | ✅ | ❌ | ❌ |
| Grafana | ✅ | ✅ `-v` | ✅ cmdline/默认路径 |
| Mysql | ✅ | ✅ `-V` | ✅ --defaults-file/默认路径 |
| Postgresql | ✅ | ✅ `-V` | ✅ config_file/-D/PGDATA |
| Mongodb | ✅ | ✅ `--version` | ✅ --config/-f |
| etcd | ✅ | ✅ `--version` | ✅ --config-file/env |
| Prometheus | ✅ | ✅ `--version` | ✅ --config.file/默认路径 |
| Sqlserver | ✅ | ✅ `-v` | ✅ 默认路径 |
| Dockerd | ✅ | ✅ `-v` | ✅ --config-file/默认路径 |
| Containerd | ✅ | ✅ `-v` | ✅ --config/-c/默认路径 |
| Kubelet | ✅ | ✅ `--version` | ✅ --config/默认路径 |
| Apache APISIX | ✅ | ❌ | ✅ (nginx conf) |
| Apache Kafka | ✅ | ✅ cmdline regex | ✅ server.properties |
| Apache RocketMQ | ✅ | ❌ | ❌ |
| Archery | ✅ | ❌ | ❌ |
| Canal | ✅ | ❌ | ❌ |
| Django | ✅ | ❌ | ✅ --settings/env |
| Doris | ✅ | ❌ | ❌ |
| Druid | ✅ | ❌ | ❌ |
| Hadoop | ✅ | ❌ | ❌ |
| Jenkins | ✅ | ✅ cmdline regex | ✅ JENKINS_HOME |
| Jumpserver | ✅ | ❌ | ❌ |
| Kibana | ✅ | ❌ | ❌ |
| Logbase | ✅ | ❌ | ❌ |
| Logstash | ✅ | ❌ | ❌ |
| Nacos | ✅ | ✅ cmdline regex | ✅ -Dnacos.home |
| Nexus | ✅ | ❌ | ❌ |
| Rancher | ✅ | ❌ | ❌ |
| Ruoyi | ✅ | ❌ | ❌ |
| Saltstack | ✅ | ❌ | ❌ |
| Skywalking | ✅ | ❌ | ❌ |
| Tidb | ✅ | ❌ | ❌ |
| Xxl-job | ✅ | ❌ | ❌ |
| Zabbix | ✅ | ❌ | ❌ |
| ambari | ✅ | ❌ | ❌ |

> 注：需求文档中"基础应用软件识别"要求"仅用于服务类型标记，不强制要求精确版本"，因此大部分简单应用无版本提取属于符合需求。

### 3. 应用服务漏洞扫描

| 需求项 | 状态 | 说明 |
|--------|------|------|
| 复用指纹识别数据 | ✅ | Server 端消费 DescribeSoftware/DescribeApp 上报数据 |
| 漏洞规则匹配 | ✅ | Server 端实现（HUB 规则），Agent 不需要额外改动 |

### 4. 弱口令扫描

| 需求项 | 状态 | 说明 |
|--------|------|------|
| Redis: requirepass 检查 | ✅ | 含注释行过滤、默认/弱口令判断 |
| Redis: masterauth 检查 | ✅ | 已补充 |
| MySQL: 配置文件密码检查 | ✅ | 含 4 个默认路径 |
| PostgreSQL: trust 认证检查 | ✅ | 含版本化路径 glob |
| Nacos: 鉴权+密钥+默认密码 | ✅ | 含 default.token.secret.key |
| 弱口令字典内置 | ✅ | 5 个基础弱口令 |
| 弱口令字典 Server 下发 | ✅ | UpdateWeakPassDict + SyncWeakPassTask |
| Agent 内存维护字典 | ✅ | 全量替换模式 |
| 多实例检查 | ✅ | 所有 Check 函数遍历全部进程 |
| 风险类型区分 | ✅ | High Risk / Medium Risk |
| 修复建议 | ✅ | YAML solution/solution_cn 字段 |

### 5. 应用安全基线扫描

| Nacos 配置项 | 状态 |
|-------------|------|
| nacos.core.auth.enabled | ✅ |
| nacos.core.auth.admin.enabled | ✅ |
| nacos.core.auth.console.enabled | ✅ |
| nacos.core.auth.enable.userAgentAuthWhite | ✅ |
| nacos.core.auth.plugin.nacos.token.secret.key | ✅ |
| nacos.core.auth.default.token.secret.key | ✅ |
| nacos.core.auth.server.identity.key | ✅ |
| nacos.core.auth.server.identity.value | ✅ |
| management.endpoints.web.exposure.include | ✅ |
| management.endpoints.web.exposure.exclude | ✅ |
| mysql-schema.sql 默认密码 | ✅ |
| derby-schema.sql 默认密码 | ✅ |

| Archery 配置项 | 状态 |
|---------------|------|
| SECRET_KEY 默认值检查 | ✅ |
| Debug 模式检查 | ✅ |

| XXL-Job 配置项 | 状态 |
|---------------|------|
| xxl.job.accessToken | ✅ |
| spring.datasource.password | ✅ |

### 6. 已知限制（非 Bug，需求文档/技术方案中已说明）

| 限制 | 说明 |
|------|------|
| MySQL 密码检查受限 | 密码通常不在配置文件中以明文存在，仅覆盖特定部署场景 |
| PostgreSQL 仅检查 trust 认证 | 无法从配置文件获取实际密码 hash |
| 容器中配置文件路径可能复杂 | 通过 /proc/pid/root 前缀访问，但容器编排工具注入的环境变量场景可能遗漏 |
| 部分 Java 应用缺少版本提取 | 需求文档中说明"不强制要求精确版本"，后续可逐步增强 |

### 结论

**需求文档中描述的所有功能项均已实现**。代码中的所有 Bug 已修复，需求文档中列出的全部 30+ 应用识别规则、4 类弱口令检查、3 类应用安全基线检查（覆盖需求文档中的全部配置项）均已完成。
