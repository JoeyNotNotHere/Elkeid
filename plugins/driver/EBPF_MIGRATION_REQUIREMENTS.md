# Driver 模块 eBPF 迁移需求拆解

本文档基于 `plugins/driver/ARCHITECTURE_SUMMARY.md` 对现有 LKM 架构的分析，结合 eBPF 技术特性，将“Driver 从 LKM 迁移至 eBPF”的需求拆解如下。

## 1. 功能点 (Functional Requirements)

核心目标是**使用 eBPF 技术栈（Progs + Maps）替换原有的 LKM（Kprobes + RingBuffer）**，同时保持上层业务逻辑无感知。

### 事件采集迁移 (Kernel Space)
需在 eBPF 中重新实现对以下关键系统调用的 Hook（建议优先使用 Tracepoints，辅以 Kprobes）：
*   **进程类**: `sys_execve` / `sys_execveat` (对应 Event 59), `sys_exit` / `sys_exit_group` (对应 Event 60/200), `sys_ptrace` (101), `sys_setsid` (112), `sys_prctl` (157)。
*   **网络类**: `sys_connect` (42/602), `sys_accept` / `sys_accept4` (43), `sys_bind` (49)。
*   **文件类**: `sys_open` / `sys_openat` (2), `sys_write` (1, 需过滤特定fd或路径), `sys_link` / `sys_linkat` (82), `sys_rename` / `sys_renameat` (603), `sys_unlink` / `sys_unlinkat` (606), `sys_memfd_create` (611)。
*   **其他**: `sys_init_module` / `sys_finit_module` (604)。
*   **数据获取**: 必须在内核态获取与 LKM 一致的上下文信息，包括：`uid`, `pid`, `ppid`, `pgid`, `tgid`, `comm`, `sessionid`, `nodename`。

### 上下文富化 (Kernel Space)
*   **容器信息**: 获取 `cgroup id` 或路径，以便用户态关联 Pod 信息。
*   **参数读取**: 读取用户态指针指向的数据（如 `argv`, `envp`, 文件路径），需处理跨页读取和长度限制。

### 内核态过滤 (Kernel Space)
*   **白名单机制**: 使用 eBPF Maps (Hash Map / LPM Trie) 存储过滤规则（如特定路径、IP、PID、Comm），在内核态直接丢弃无关事件，替代原 LKM 的过滤逻辑。
*   **动态配置**: 支持用户态动态更新 Maps 中的规则，无需重启 eBPF 程序。

### 数据传输 (Kernel <-> User)
*   使用 **PerfBuffer** (兼容旧内核) 或 **RingBuffer** (高性能，5.8+) 替代原有的自定义 RingBuffer 机制。
*   实现高效的数据序列化格式，确保传输给用户态的数据结构可被解析。

### 用户态适配 (User Space)
*   **加载器**: 实现 eBPF 字节码的加载、验证、挂载 (Attach) 和卸载。
*   **消费端**: 适配新的数据源（从 PerfBuffer/RingBuffer 读取），替代原有的 `/proc/elkeid-endpoint` 读取逻辑。
*   **协议转换**: 将 eBPF 采集的数据转换为与原 LKM 输出完全一致的 `Record` 格式（保持 Event ID 和字段定义不变），以便复用现有的 `transformer.rs` 逻辑或保持后端兼容。

## 2. 非功能需求 (Non-functional Requirements)

*   **内核兼容性**:
    *   **CO-RE 支持**: 在支持 BTF 的高版本内核上实现“一次编译，到处运行”。
    *   **低版本适配**: 针对不支持 BTF 或 eBPF 功能受限的低版本内核（如 CentOS 7 的 3.10 内核），需提供降级方案。
*   **性能指标**:
    *   **低侵入**: eBPF 程序的执行时间必须极短，避免拖慢系统调用响应。
    *   **资源占用**: CPU 和内存占用率不应高于原 LKM 模块。
*   **稳定性**:
    *   **Verifier 通过率**: 保证代码逻辑符合验证器规范，无死循环、无越界访问。
    *   **安全退出**: 用户态进程 crash 后，内核态的 eBPF Probe 应自动 detach 或变为无操作状态，不影响系统运行。

## 3. 隐含约束 (Implicit Constraints)

*   **数据协议一致性**: 上报给 Agent 的数据结构（如 `plugins/driver/src/transformer/schema.rs` 中定义的字段）**不能变更**。后端依赖这些特定的 Event ID 和字段组合。
*   **权限要求**: eBPF 需要 `CAP_SYS_ADMIN` (或 `CAP_BPF` 等组合权限)，这与加载 LKM 的权限要求类似。
*   **栈空间限制**: eBPF 栈空间仅 512 字节，处理深层函数调用或大结构体时需使用 Per-CPU Array 等堆内存替代方案。

## 4. 可能风险 (Potential Risks)

*   **长参数截断**: LKM 可以分配较大内存读取完整的长命令行 (`argv`) 或长路径。eBPF 对单次数据读取大小和循环次数有限制，可能导致**长参数被截断**，影响告警准确性。
*   **反 Rootkit 能力缺失**: 原 LKM 包含 `anti_rootkit.c`，可能涉及扫描系统调用表、IDT 等底层内存。eBPF 基于安全性设计，**严禁读取任意内核内存或进行扫描**，这部分功能可能无法在 eBPF 中实现，导致能力降级。
*   **阻断能力变弱**: LKM 可以直接修改 syscall 返回值来阻断操作。eBPF 在非 LSM 挂载点（如 Kprobes/Tracepoints）通常**无法阻断**系统调用，仅能作为旁路监控。
*   **复杂逻辑实现难度**: 原 LKM 中若有复杂的字符串处理或多步逻辑，在 eBPF 的受限 C 语言环境中可能难以移植或被 Verifier 拒绝。
*   **CentOS 7 兼容性陷阱**: 大量生产环境仍在使用 CentOS 7 (Kernel 3.10)，该版本对 eBPF 支持极弱。若必须支持该版本，可能需要维护两套完全不同的技术栈。
