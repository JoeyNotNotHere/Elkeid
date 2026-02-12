# Baseline & Collector 功能实现对照表

| 功能点 | 技术方案中实现方案 | 代码实现方式 | 是否完成 | 是否有未完成点 | 是否有相关风险 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. 资产指纹 - Jar包扫描增强** | 1. 解析进程 cmdline (`-jar`, `-cp`)<br>2. 递归扫描路径（最大深度3）<br>3. 识别 Manifest/POM/文件名<br>4. 新增 `path` 字段 | **文件**: `plugins/collector/software.go`<br>**逻辑**: `parseClasspath` 提取路径，`godirwalk.Walk` 递归扫描 (深度限制3)，`findJar` 解析版本与路径，数据结构包含 `path`。 | 是 | 无 | 递归扫描若目录过大可能影响性能（已通过深度限制缓解） |
| **2. 资产指纹 - 应用识别扩展** | 1. 基于 `cmdline`/`exe`/`comm` 正则匹配<br>2. 覆盖 Java/Native/Python 等多类应用<br>3. 提取 Version 和 Config 路径 | **文件**: `plugins/collector/app.go`<br>**逻辑**: 定义 `AppRule` 结构体与 `ruleMap`，实现 `nginx`, `redis`, `mysql`, `nacos` 等30+种应用的正则匹配与版本命令执行逻辑。 | 是 | 无 | 无 |
| **3. 弱口令 - 服务端字典管理** | 1. 新增上传/查询接口<br>2. MongoDB 存储<br>3. 下发 `SyncWeakPassTask` 任务 | **文件**: `server/manager/internal/baseline/weak_pass.go`<br>**逻辑**: 实现 `UpdateWeakPassList` (存库) 和 `SyncWeakPassTask` (分发任务至在线 Agent)。 | 是 | 无 | 无 |
| **4. 弱口令 - Agent端扫描逻辑** | 1. 使用 `func_check` 扩展基线检查<br>2. 解析 Redis/MySQL/Postgre/Nacos 配置文件<br>3. 检查空口令/默认口令/弱口令字典 | **文件**: `plugins/baseline/src/check/app_check.go`<br>**逻辑**: 实现 `CheckRedisWeakPassword`, `CheckMysqlWeakPassword` 等函数，读取配置文件并正则匹配关键配置项（如 `requirepass`）。 | 是 | 无 | 配置文件权限不足或非标准路径启动可能导致检测跳过 |
| **5. 应用安全基线扫描** | 1. 复用 `func_check` 机制<br>2. 检查 Nacos/Archery/XXL-Job 特定安全配置 (Token, Debug模式等) | **文件**: `plugins/baseline/src/check/app_check.go`<br>**逻辑**: 实现 `CheckArcheryConfig` (检查DEBUG/SECRET_KEY), `CheckXxlJobConfig` (检查AccessToken), `CheckNacosConfig`。 | 是 | 无 | 同上（配置文件可读性依赖） |
| **6. 应用漏洞扫描支持** | 1. 依赖 Collector 上报的精准指纹数据<br>2. Server 端进行 CVE/CNVD 匹配（无需 Agent 额外扫描） | **文件**: `plugins/collector/software.go` & `app.go`<br>**逻辑**: Agent 端已完成 Name, Version, Path 的精准采集与上报，为 Server 端漏洞匹配提供了必要数据源。 | 是 | 无 | 版本解析的正则准确性直接影响漏洞匹配结果 |

### 总结
代码已**完全覆盖**技术方案中的核心需求，包括 Collector 的指纹深度采集（Jar包路径、应用识别）以及 Baseline 的应用层弱口令与配置基线检查。所有新增功能均已通过代码实现。
