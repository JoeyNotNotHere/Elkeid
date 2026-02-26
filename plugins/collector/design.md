# Collector 插件 — 资产指纹识别 & 应用识别 设计文档

## 一、功能概述

本次 collector 插件新增以下能力：

1. **Jar 包扫描增强**（DescribeSoftware）：从 Java 进程 cmdline 中解析 `-jar`、`-cp`、`-classpath` 路径，递归扫描 Jar 文件并上报带路径的组件信息。
2. **应用识别规则扩展**（DescribeApp）：新增 30+ 应用的识别规则，覆盖 Java 类、Python 类、Node.js 类及独立二进制应用。

## 二、Jar 包扫描增强 (software.go)

### 2.1 数据结构变更

`Software` 结构体新增 `Path` 字段，用于记录 Jar 包的绝对路径：

```go
type Software struct {
    // ...existing fields...
    Path string `mapstructure:"path"`
}
```

### 2.2 Classpath 解析

新增 `parseClasspath(cmdline, cwd)` 函数，从 Java 进程的 cmdline 中提取扫描目标路径：

| 参数格式 | 解析方式 |
|----------|----------|
| `-jar app.jar` | 提取 jar 文件路径 + 同级 `lib/` 目录 |
| `-cp path1:path2` | 按 `:` 分隔提取每个路径 |
| `-classpath path1:path2` | 同 `-cp` |
| 路径含 `/*` 通配符 | 去除 `/*` 后缀作为目录扫描 |

相对路径自动基于进程 cwd 转为绝对路径。

### 2.3 版本识别优先级

1. **文件名解析**：`parseJarFilename("fastjson-1.2.76")` → name=fastjson, version=1.2.76
2. **MANIFEST.MF**：读取 `Implementation-Version` 字段
3. **pom.properties**：读取 `version=` 字段

### 2.4 递归扫描策略

- 对 classpath 中的目录执行 `godirwalk` 递归扫描
- 最大递归深度：`MaxRecursionLevel = 3`
- 每进程最大扫描 Jar 数量：`MaxJarPerProcess = 500`
- 使用 `mapset` 去重，避免重复上报
- 跳过 JDK/JRE 内置 Jar（路径含 `jdk` 或 `jre` 的非 `rt.jar` 文件）
- 容器场景通过 `/proc/[pid]/root` 前缀访问容器文件系统

### 2.5 上报数据结构

每条 Jar 指纹记录（DataType=5055）包含：

| 字段 | 说明 |
|------|------|
| name | 组件名称 |
| sversion | 版本号 |
| path | Jar 绝对路径 |
| type | "jar" |
| pid | 进程 PID |
| container_id | 容器 ID（如有） |
| container_name | 容器名称（如有） |
| package_seq | 采集批次标识 |

## 三、应用识别规则扩展 (app.go)

### 3.1 架构设计

```
进程 comm 字段
    │
    ▼
ruleMap[comm] → AppRule
    │
    ├── 原生应用 (nginx, redis, mysql...) → 直接执行 GenerateApp
    │       │
    │       └── matchFunc → 优先匹配特殊应用 (如 APISIX)
    │
    ├── java → javaRule.GenerateApp → dispatchJavaApp
    │       ├── javaRuleApps[] → 有独立规则的 Java 应用 (kafka, nacos, jenkins...)
    │       └── javaSimpleApps[] → 仅关键字匹配的 Java 应用 (hadoop, druid, xxl-job...)
    │
    ├── python/python2/python3/uwsgi/gunicorn → pythonRule.GenerateApp → dispatchPythonApp
    │       └── pythonSimpleApps[] → django, ansible, saltstack, jumpserver, archery
    │
    └── node → nodeRule.GenerateApp → matchFunc → kibana
```

### 3.2 AppRule 结构

```go
type AppRule struct {
    name              string
    versionRegex      *regexp.Regexp       // 版本提取正则
    versionArgs       []string             // 版本命令参数 (如 ["-v"])
    _type             string               // 应用类型标记
    versionTrimPrefix string               // 版本前缀裁剪
    versionTrimSuffix string               // 版本后缀裁剪
    confFunc          func(RuleContext) string         // 配置文件路径提取
    matchFunc         func(RuleContext) ([]byte, *App) // 特殊匹配逻辑 (优先级最高)
    sub               *AppRule             // 子规则链 (用于 nginx→tengine→openresty 链式匹配)
}
```

### 3.3 GenerateApp 执行流程

1. **matchFunc 优先**：如果 rule 定义了 matchFunc，优先调用。若匹配成功直接返回（用于 APISIX、Kibana 等特殊识别场景）。
2. **Java/Python 分发**：若为 `java_app` 或 `python_app`，调用 `dispatchJavaApp` / `dispatchPythonApp` 统一分发。
3. **sub 链式匹配**：尝试子规则（如 openresty → tengine → nginx）。
4. **父进程去重**：跳过与父进程 comm 相同的子进程。
5. **版本提取**：优先使用 `rc.appVersion`（缓存或 cmdline 提取），否则执行二进制获取版本。
6. **配置路径**：通过 `confFunc` 解析。

### 3.4 Java 应用版本提取

Java 应用无法通过执行 `java -v` 获取版本。改为从 cmdline 中提取：

```go
func extractVersionFromCmdline(cmdline string, re *regexp.Regexp) string
```

使用 `FindSubmatch` 提取正则捕获组（如 `nacos-server-(\d+\.\d+\.\d+)` → `2.0.3`）。

### 3.5 新增应用覆盖列表

| 类型 | 应用 | 识别方式 |
|------|------|----------|
| Java (有规则) | Kafka, RocketMQ, Nacos, Elasticsearch, Jenkins, Logstash | cmdline 关键字 + 独立 AppRule（含版本提取和配置路径） |
| Java (简单) | Hadoop, Druid, Canal, Doris, Nexus, Ruoyi, Skywalking, XXL-Job, Ambari, Logbase | cmdline 关键字匹配，无版本提取 |
| Python | Django, Ansible, Saltstack, Jumpserver, Archery | cmdline 关键字匹配 |
| Node.js | Kibana | matchFunc 关键字匹配 |
| Nginx 衍生 | Apache APISIX | nginx/tengine/openresty 的 matchFunc 中检测 "apisix" 关键字 |
| 独立二进制 | TiDB, Zabbix, Rancher, Doris BE, JumpServer Koko | comm 直接映射 ruleMap |

### 3.6 上报数据结构

每条应用识别记录（DataType=5060）包含：

| 字段 | 说明 |
|------|------|
| name | 应用名称 |
| type | 应用类型 (web_service/database/devops/message_queue 等) |
| sversion | 版本号 |
| conf | 配置文件路径 |
| pid | 进程 PID |
| exe | 可执行文件路径 |
| container_id | 容器 ID |
| container_name | 容器名称 |
| start_time | 进程启动时间 |
| package_seq | 采集批次标识 |
