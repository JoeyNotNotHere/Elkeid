# Driver 模块 eBPF 迁移需求理解与功能点整理

本文档基于 `ARCHITECTURE_SUMMARY.md`（现有架构）和 `EBPF_RESEARCH.md`（技术调研）的分析，整理了将 Elkeid Driver 从 LKM 迁移至 eBPF 模式的需求、功能点及潜在风险。

## 1. 功能点 (Functional Requirements)

核心目标是**使用 eBPF 技术栈替换原有的 LKM 实现，同时保持对上层业务的数据供给不变**。

### 事件采集迁移 (Kernel Space)
需在 eBPF 中重新实现对关键系统调用的 Hook，保持 Event ID 一致：
*   **Hook 机制替换**: 使用 `Tracepoints` (首选) 或 `Kprobes` 替换原有的 LKM Kprobe/Kretprobe 挂载点。
*   **核心事件覆盖**:
    *   **进程类**: `execve` (59), `exit` (60/200), `ptrace` (101), `setsid` (112), `prctl` (157)。
    *   **网络类**: `connect` (42/602), `accept` (43), `bind` (49), `dns_query` (601)。
    *   **文件类**: `open` (2), `write` (1), `link` (82), `rename` (603), `unlink` (606), `memfd_create` (611)。
    *   **模块类**: `module_load` (604)。
*   **上下文获取**: 必须在 eBPF 探针中获取与 LKM 一致的上下文字段：`uid`, `pid`, `ppid`, `pgid`, `tgid`, `comm`, `sessionid`, `nodename`。

### 数据传输升级 (Kernel <-> User)
*   **RingBuffer 替换**: 使用 eBPF 原生的 **RingBuffer** (Kernel 5.8+) 或 **PerfBuffer** (旧内核兼容) 替代原有的 `/proc/elkeid-endpoint` 自定义字符设备通信机制。
*   **数据序列化**: 在 eBPF 程序中将采集的数据打包成符合用户态解析要求的二进制格式。

### 内核态过滤 (In-Kernel Filtering)
*   **Map 机制**: 使用 eBPF Maps (如 `BPF_MAP_TYPE_HASH`) 替代 LKM 中的全局变量/链表，用于存储过滤规则（如白名单路径、IP、Hash）。
*   **动态更新**: 支持用户态程序在运行时动态更新 Map 中的规则，实现不重启 Agent 即可生效的策略变更。

### 用户态适配 (User Space)
*   **加载器 (Loader)**: 实现基于 `libbpf` (或 Go/Rust 对应库) 的加载逻辑，替代原有的 `insmod/rmmod` 内核模块管理逻辑。
*   **生命周期管理**: 处理 eBPF 程序的加载、验证 (Verifier)、挂载 (Attach) 和卸载 (Detach)。
*   **CO-RE 支持**: 利用 BTF 信息，实现“一次编译，到处运行”，自动适配不同内核版本的结构体偏移。

## 2. 非功能需求 (Non-functional Requirements)

*   **安全性 (Safety)**:
    *   **Verifier 通过**: 所有 eBPF 代码必须通过内核验证器的检查，确保无死循环、无越界访问，彻底消除 Kernel Panic 风险。
*   **兼容性 (Compatibility)**:
    *   **多内核支持**: 需同时支持支持 BTF 的新内核 (CO-RE 模式) 和不支持 BTF 的旧内核 (可能需要 Legacy 模式或外部 BTF 支持)。
*   **性能 (Performance)**:
    *   **低开销**: eBPF 探针执行时间需极短，避免阻塞系统调用。
    *   **高吞吐**: 能够处理高并发下的事件流，避免 RingBuffer 溢出丢包。

## 3. 改动模块 (Modified Modules)

根据现有架构文档，迁移将涉及以下模块的重大变更：

| 模块位置 | 类型 | 变更性质 | 描述 |
| :--- | :--- | :--- | :--- |
| `driver/LKM/` | **废弃/替换** | **重写** | 原 C 语言 LKM 代码将被新的 **eBPF C 代码工程** 替代。包含 `*.bpf.c` 源码及 Map 定义。 |
| `plugins/driver/src/kmod.rs` | **修改** | **重构** | 原有的内核模块下载、`insmod` 加载、版本检查逻辑，需替换为 **eBPF Object 加载器** (使用 `libbpf-rs` 或 `cilium/ebpf` 等库)。 |
| `plugins/driver/src/main.rs` | **修改** | **逻辑变更** | `record_send` 线程中的数据源需从 `File::open("/proc/elkeid-endpoint")` 更改为 **消费 eBPF RingBuffer/PerfBuffer**。 |
| `plugins/driver/src/transformer.rs` | **修改** | **适配** | 虽然输出格式不变，但输入数据的二进制布局可能因 eBPF 结构体定义而改变，需适配新的解码逻辑。 |
| `plugins/driver/src/config.rs` | **修改** | **配置变更** | 需更新下载地址 (从 `.ko` 改为 `.o` 或 `.tar.gz`)，以及可能的 Map 大小配置。 |

## 4. 隐含约束 (Implicit Constraints)

*   **输出协议严格一致**: 上报给 Server 的数据结构（即 `transformer/schema.rs` 中定义的 Event ID 和字段组合）**绝对不能变更**。后端分析服务依赖这些特定的格式。
*   **权限要求**: Agent 进程仍需保留 `root` 权限或拥有 `CAP_SYS_ADMIN` / `CAP_BPF` 能力以加载 eBPF 程序。
*   **栈空间限制**: eBPF 虚拟机栈空间仅 512 字节，这限制了在内核态处理复杂字符串或深层嵌套结构体的能力，需改用 Per-CPU Map 等堆内存方案。

## 5. 可能风险 (Potential Risks)

*   **反 Rootkit 能力缺失**:
    *   原 LKM 中的 `anti_rootkit.c` 涉及扫描系统调用表、IDT 等底层内存。eBPF 安全机制**严禁**读取任意内核内存或进行此类扫描。**风险：Rootkit 检测功能可能无法迁移，导致能力降级。**
*   **长参数截断**:
    *   LKM 可以分配大块内存读取完整的长命令行 (`argv`)。eBPF 对循环次数和单次数据读取量有限制。**风险：超长命令行或环境变量可能被截断，影响告警准确性。**
*   **CentOS 7 (Kernel 3.10) 适配陷阱**:
    *   该版本内核对 eBPF 支持极弱（不支持 CO-RE，不支持 RingBuffer，甚至 Tracepoint 支持也有限）。**风险：可能需要维护两套代码路径（eBPF for New Kernel + LKM for Old Kernel），或者投入巨大精力做低版本适配。**
*   **阻断能力变弱**:
    *   LKM 可直接修改 syscall 返回值阻断操作。普通 eBPF (非 LSM) 通常只能监控不能阻断。**风险：如果原 Driver 有主动防御/阻断功能，迁移后可能失效。**
