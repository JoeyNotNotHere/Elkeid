# Elkeid Driver 模块架构总结

本文档基于对 `plugins/driver` (用户态插件) 和 `driver/LKM` (内核模块) 的代码分析，总结了 Driver 模块的架构、职责、数据流及交互方式。

## 1. 架构分层

Driver 模块采用经典的 **内核态 (Kernel Space) + 用户态 (User Space)** 分离架构，通过 RingBuffer 进行高效通信。

### 内核层 (LKM - Loadable Kernel Module)
*   **位置**: `driver/LKM/` (C语言实现)
*   **核心机制**: 使用 **Kprobes** 和 **Tracepoints** 技术 Hook 系统调用和关键内核函数。
*   **职责**: 负责最底层的事件捕获、初步过滤和数据缓冲。它不直接处理复杂的业务逻辑，而是将原始事件写入 RingBuffer。
*   **接口**:
    *   数据输出: `/proc/elkeid-endpoint` (RingBuffer 消费者接口)
    *   控制接口: `/dev/hids_driver_allowlist` (用于下发过滤规则)

### 用户层 (Driver Plugin)
*   **位置**: `plugins/driver/` (Rust语言实现)
*   **核心机制**: 作为 Elkeid Agent 的插件运行，负责管理内核模块的生命周期和数据处理。
*   **职责**:
    1.  **生命周期管理**: 自动根据内核版本下载并加载对应的 `.ko` 模块。
    2.  **数据消费**: 从 `/proc/elkeid-endpoint` 读取原始二进制数据。
    3.  **数据处理**: 解析二进制数据，富化上下文信息 (如容器信息、进程树)，并执行基于策略的过滤。
    4.  **上报**: 将处理后的数据序列化 (Protobuf/JSON) 发送给 Agent 主进程。

## 2. 核心模块职责

### 用户态插件 (`plugins/driver/src/`)

| 模块 | 文件 | 职责 |
| :--- | :--- | :--- |
| **入口** | `main.rs` | 初始化 Logger 和 Client；启动 `task_receive` (指令接收) 和 `record_send` (数据上报) 线程。 |
| **内核管理** | `kmod.rs` | 1. **版本适配**: 检查内核版本 (`uname`)，从远程服务器 (`DOWNLOAD_HOSTS`) 下载适配的 `.ko` 文件。<br>2. **加载/卸载**: 使用 `finit_module`/`insmod` 加载模块；在崩溃或版本更新时卸载。<br>3. **规则控制**: 向 `/dev/hids_driver_allowlist` 写入白名单规则 (如过滤特定 `exe` 或 `argv`)。<br>4. **心跳**: 定期上报插件状态和过滤规则统计。 |
| **数据转换** | `transformer.rs` | 1. **解析**: 将内核传递的二进制流解析为结构化数据 (基于 `schema.rs` 定义)。<br>2. **富化**: 补充 `pod_name` (容器信息)、`username`、`pid_tree` (进程树)、`exe_hash` 等上下文。<br>3. **过滤**: 实现基于 LRU/TTL 的本地缓存和限流 (Quota)，防止数据洪峰。 |
| **数据定义** | `transformer/schema.rs` | 定义了不同 `data_type` (事件ID) 对应的字段结构，用于解析内核数据。 |

### 内核态模块 (`driver/LKM/src/`)

| 模块 | 文件 | 职责 |
| :--- | :--- | :--- |
| **Hook 核心** | `smith_hook.c` | 定义了所有被 Hook 的系统调用 (如 `sys_execve`, `sys_connect`, `sys_bind`) 的前后处理函数 (Kprobe/Kretprobe)。 |
| **数据缓冲** | `trace.c` / `trace_buffer.c` | 实现了一个基于 RingBuffer 的无锁高性能数据队列，供用户态读取。 |
| **反 Rootkit** | `anti_rootkit.c` | 检测隐藏进程、隐藏模块、系统调用表劫持等异常行为。 |

## 3. 依赖关系

*   **系统依赖**:
    *   Linux Kernel Headers (编译 LKM 需对应内核版本)。
    *   `musl-gcc` (用户态插件静态链接，确保跨发行版兼容性)。
*   **Rust Crate 依赖**:
    *   `plugins`: 内部共享库 (`path = "../lib/rust"`)，提供与 Agent 通信的 `Client` 和 `Record` 结构。
    *   `nix`: 用于系统调用 (如模块加载)。
    *   `ureq`: HTTP 客户端，用于下载内核模块。
    *   `protobuf`/`serde`: 数据序列化。
*   **外部服务**:
    *   **Nginx 文件服务器**: `DOWNLOAD_HOSTS` 配置指向的服务器，用于托管编译好的 `.ko` 文件。

## 4. 产出数据内容

Driver 覆盖了主机安全的各个关键领域。主要事件 ID 及含义如下：

### 进程行为
*   **59**: `execve` (进程执行) - 核心事件，包含命令行、父进程、环境变量、TTY 等。
*   **60 / 200**: `exit` (进程退出)。
*   **101**: `ptrace` (进程调试/注入)。
*   **112**: `setsid` (会话 ID 设置)。
*   **157**: `prctl` (进程控制)。
*   **607**: `call_usermodehelper` (内核调用用户态程序)。

### 网络行为
*   **42**: `connect` (IPv4 对外连接)。
*   **43**: `accept` (IPv4 接收连接)。
*   **49**: `bind` (IPv4 端口绑定)。
*   **601**: `dns_query` (DNS 查询)。
*   **602**: `connect` (IPv6 相关)。

### 文件操作
*   **2**: `open` (文件打开/创建)。
*   **1**: `write` (文件写入，通常用于检测 WebShell 或敏感文件修改)。
*   **82**: `link` (创建硬链接)。
*   **603**: `rename` (文件重命名)。
*   **606**: `unlink` (删除文件)。
*   **611**: `memfd_create` (内存文件创建，常用于无文件攻击)。

### 安全与异常检测
*   **604**: `module_load` (内核模块加载)。
*   **610**: `privilege_escalation` (提权检测)。
*   **165**: USB 设备插入。
*   **700-703**: Rootkit 检测相关事件 (隐藏模块、系统调用表异常等)。

**通用字段**: 大多数事件都包含 `uid`, `pid`, `ppid`, `pgid`, `comm` (命令名), `exe_path` (可执行文件路径), `argv`, `socket_pid`, `pod_name` (容器标识) 等上下文信息。

## 5. 与 Agent 交互方式

*   **通信通道**: 使用 `plugins` crate 提供的 `Client` 接口。底层通常封装了 IPC (如 Unix Domain Socket 或 Pipe)。
*   **数据上报 (Plugin -> Agent)**:
    *   **流式事件**: `record_send` 线程持续将处理后的 `Record` 发送给 Agent。
    *   **心跳保活**: `heartbeat` 线程每 30 秒发送一次状态，包含当前过滤规则统计 (`filtered_exe_entries`) 和模块参数。
*   **指令接收 (Agent -> Plugin)**:
    *   `task_receive` 线程监听 Agent 下发的 Task。
    *   虽然代码框架存在，但目前 `main.rs` 中的 `handle task` 逻辑为空，表明复杂的动态指令处理可能在 `Client` 内部实现，或依赖于文件系统接口 (`/dev/hids_driver_allowlist`) 进行控制。

## 6. 待确认事项

1.  **IPC 具体协议**: `Client` 的具体实现位于 `../lib/rust`，未在此次分析范围内。Agent 与 Plugin 的通信细节 (协议格式) 尚不明确。
2.  **动态指令处理**: `main.rs` 中 `handle task` 为空，需要确认 Agent 如何下发复杂的动态配置（除了简单的黑白名单）。
3.  **部分 Event ID**: 少量 Event ID (如 `10`, `356`) 的具体触发场景需结合更深层的内核代码确认。
