# Elkeid Driver eBPF 迁移技术方案 (基于 Tracee 二次开发)

本文档详细描述了基于开源项目 **Tracee** 进行二次开发，将 Elkeid Driver 从 LKM 迁移至 eBPF 的技术实施方案。

## 1. 方案概述

本方案采用 **"异构插件替换"** 策略：
*   **内核态**: 复用 Tracee 的 eBPF 探针代码（`tracee.bpf.c`）和核心库（`libbpfgo`），利用其成熟的 CO-RE 适配能力。
*   **用户态**: 放弃原有的 Rust 插件，新建 **Go 语言插件 (`driver-ebpf`)**。该插件负责加载 eBPF、接收 Tracee 事件、将其转换为 Elkeid 私有二进制协议，并与 Agent 通信。
*   **部署**: 利用 Elkeid 的多版本灰度机制，新旧 Driver 并行存在，按需下发。

## 2. 架构设计

```mermaid
graph TD
    subgraph "Kernel Space (eBPF)"
        A[Tracee Hooks (kprobes/tracepoints)] -->|Capture| B[PerfBuffer / RingBuffer]
        C[eBPF Maps] -->|Filter Policy| A
    end

    subgraph "User Space (New Go Plugin)"
        D[Libbpfgo / Tracee-Lib] -->|Poll| B
        D -->|Raw Event| E[Event Engine]
        E -->|Tracee Event Struct| F[Protocol Adapter]
        F -->|Elkeid Binary Record| G[Elkeid Client (Go)]
        H[Task Handler] -->|Update Maps| C
    end

    subgraph "Elkeid Agent"
        G -->|IPC / Pipe| I[Agent Core]
        I -->|Task / Policy| H
    end
```

## 3. 功能点实现方案

### 3.1 事件采集与映射 (Event Collection)

利用 Tracee 现有的 Event 定义，建立与 Elkeid Event ID 的映射关系。

| Elkeid ID | Elkeid 事件 | Tracee Event ID (参考) | 实现策略 |
| :--- | :--- | :--- | :--- |
| **59** | `execve` | `sched_process_exec` | 复用 Tracee 逻辑，提取 `cmd`, `argv`, `env`。 |
| **60/200** | `exit` | `sched_process_exit` | 复用。 |
| **42/602** | `connect` | `security_socket_connect` | 复用。需注意 IPv4/IPv6 区分。 |
| **2** | `open` | `openat` / `open` | 复用。需过滤高频无关路径。 |
| **604** | `module_load` | `module_load` | 复用。 |
| **611** | `memfd_create` | `memfd_create` | 复用。 |
| **101** | `ptrace` | `ptrace` | 复用。 |

*   **差异处理**: 若 Tracee 缺少某些特定字段（如 Elkeid 特有的 `root_pid_inum`），需修改 Tracee 的 BPF C 代码进行补充，重新编译 BPF Object。

### 3.2 协议适配层 (Protocol Adapter)

这是本方案的核心。原 Rust 代码 (`transformer.rs`) 使用了一套自定义的序列化逻辑（类似 Protobuf 但非标准）。需要在 Go 中**完全复刻**这套逻辑。

*   **输入**: `tracee.Event` (Go Struct)
*   **输出**: `[]byte` (符合 Elkeid Server 解析标准)
*   **逻辑**:
    1.  定义 `Encoder` 接口。
    2.  实现 `EncodeVarint` (变长整数编码)。
    3.  实现 `WriteField(key, value)`。
    4.  针对每个 Event ID 编写转换函数，例如 `ConvertExecve(evt *tracee.Event) []byte`，严格按照 `schema.rs` 的字段顺序写入数据。

### 3.3 进程树与容器富化

*   **容器信息**: Tracee 原生支持从 Cgroup 提取 Container ID 和 Pod Name，直接使用其 `Context` 字段。
*   **进程树 (`pid_tree`)**:
    *   Elkeid LKM 在内核态或用户态维护了父子进程关系。
    *   **实现**: 在 Go 插件中维护一个 LRU Cache (`map[pid]ProcessInfo`)。监听 `fork`/`exec`/`exit` 事件来更新这个 Cache。当上报 `execve` 时，从 Cache 中递归查找父进程信息构建 `pid_tree` 字符串。

### 3.4 通信与管控 (Client & IPC)

*   **数据上报**: Elkeid Agent 通常通过 Pipe 或 Socket 接收数据。需阅读 Rust `plugins` 库源码，用 Go 实现对应的写入逻辑（通常是带长度头的二进制流）。
*   **策略下发**: 实现 Task 接收线程。解析 Agent 下发的白名单（如 `exe_whitelist`），调用 `libbpfgo` 更新内核态的 eBPF Map，实现过滤。

## 4. 改动点与文件清单

**注意**: 不修改原 `plugins/driver` (Rust) 目录，新建目录开发。

### 新增模块: `plugins/driver-ebpf/` (Go Project)

| 文件/目录 | 描述 |
| :--- | :--- |
| `go.mod` | Go 依赖定义 (引入 `github.com/aquasecurity/tracee`, `libbpfgo`)。 |
| `main.go` | 程序入口。初始化 Logger, Client, 加载 BPF。 |
| `bpf/` | 存放修改后的 Tracee BPF 源码 (`.c`) 和编译后的 CO-RE Object (`.o`)。 |
| `pkg/adapter/` | **核心**: 包含 `encoder.go` (序列化) 和 `converter.go` (事件转换)。 |
| `pkg/client/` | 实现与 Elkeid Agent 的 IPC 通信协议。 |
| `pkg/cache/` | 进程树 (`pid_tree`) 和容器信息的本地缓存实现。 |
| `pkg/manager/` | 负责 eBPF 的加载、挂载、Map 管理。 |
| `Makefile` | 包含 `go build` 和 `clang` 编译 BPF 的指令。 |

## 5. 开发行动项 (Action Items)

### Phase 1: 基础设施搭建 (1周)
1.  [ ] 搭建 Go 开发环境，引入 Tracee 依赖。
2.  [ ] 编写 `main.go`，实现加载 Tracee 的 `tracee.bpf.o` 并成功打印原始事件到控制台。
3.  [ ] 验证 CO-RE 在目标测试机（如 Ubuntu 20.04）上的有效性。

### Phase 2: 协议逆向与适配 (2周)
1.  [ ] 深入阅读 `plugins/driver/src/transformer.rs` 和 `schema.rs`。
2.  [ ] 在 Go 中实现 `Encoder`，编写单元测试确保序列化结果与 Rust 版本**字节级一致**。
3.  [ ] 实现 `execve` (ID 59) 和 `connect` (ID 42) 的转换逻辑。

### Phase 3: 核心功能完善 (2周)
1.  [ ] 实现 `pkg/client`，打通与 Agent 的数据通道。
2.  [ ] 实现 `pkg/cache`，构建进程树逻辑。
3.  [ ] 移植白名单过滤逻辑，对接 eBPF Map。

### Phase 4: 测试与优化 (1周)
1.  [ ] 进行压力测试，对比 LKM 版本的 CPU/内存占用。
2.  [ ] 使用 `strip` 和 `upx` 压缩 Go 二进制体积。
3.  [ ] 编写集成测试脚本。

## 6. 约束与风险

### 6.1 约束遵守
*   **协议一致性**: 必须通过“录制 LKM 数据 -> 录制 eBPF 数据 -> 二进制对比”的方式严格验证。
*   **权限**: Go 插件运行时需 `root` 权限（由 Agent 保证）。

### 6.2 风险点
1.  **包体积过大**: Go 二进制包含 Runtime，可能达 10MB+。
    *   *缓解*: 使用 `-ldflags="-s -w"` 编译，并使用 UPX 压缩。
2.  **字段缺失**: Tracee 可能不采集某些冷门字段（如 `sessionid`）。
    *   *缓解*: 修改 `bpf/tracee.bpf.c`，添加 `bpf_get_current_pid_tgid` 等辅助函数获取缺失字段。
3.  **性能开销**: Go 的 GC 可能在高并发事件下导致延迟。
    *   *缓解*: 优化对象复用 (`sync.Pool`)，减少内存分配；在内核态尽可能多地过滤无效事件。

## 7. 测试方案

### 7.1 单元测试
*   **Adapter 测试**: 构造一个 Mock 的 Tracee Event，经过 Adapter 转换后，断言生成的 `[]byte` 是否符合预期（可与 Rust 生成的 Hex 串对比）。

### 7.2 集成测试
*   **行为触发**: 编写脚本触发 `curl`, `ls`, `cat /etc/passwd` 等操作。
*   **数据验证**: 在 Agent 端（或 Mock Server）接收数据，验证是否收到了对应的 Event ID 59, 42, 2 等，且字段解析正常。

### 7.3 兼容性测试
*   **内核版本**: 覆盖 Kernel 4.18 (CentOS 8), 5.4 (Ubuntu 20.04), 5.15+ (Debian 11)。
*   **架构**: 验证 x86_64 和 ARM64。
