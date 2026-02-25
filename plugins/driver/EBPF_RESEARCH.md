# HIDS Driver eBPF 调研报告

## 1. eBPF 是什么

**eBPF (Extended Berkeley Packet Filter)** 是一种革命性的技术，起源于 Linux 内核，它允许在特权上下文（如操作系统内核）中运行沙盒程序。

*   **核心定义**: eBPF 是一个在 Linux 内核中运行的虚拟机（Virtual Machine），它允许开发者在不修改内核源代码或加载内核模块的情况下，动态地向内核注入代码并执行。
*   **技术演进**: 最初用于网络包过滤（Classic BPF），现已扩展为通用的内核执行引擎，覆盖网络、可观测性（Observability）和安全（Security）等领域。
*   **工作原理**:
    1.  **编写**: 使用 C (受限子集) 或 Rust 等语言编写 eBPF 程序。
    2.  **编译**: 编译为 eBPF 字节码 (Bytecode)。
    3.  **加载**: 通过 `bpf()` 系统调用加载到内核。
    4.  **验证**: 内核 **Verifier** 对字节码进行严格的安全检查（无死循环、无越界访问、无非法指令）。
    5.  **JIT**: 即时编译器将字节码转换为本机机器码，以接近原生的速度执行。
    6.  **挂载**: 挂载到内核的特定 Hook 点（如 Tracepoints, Kprobes, Uprobes, XDP, TC 等）。

## 2. 对应的标准

eBPF 正在从 Linux 特有的技术走向标准化的通用技术。

*   **IETF 标准化**: 互联网工程任务组 (IETF) 成立了 BPF 工作组，致力于 BPF 指令集架构 (ISA) 和相关规范的标准化。
*   **核心规范**:
    *   **RFC 9669 (BPF ISA)**: 定义了 BPF 的指令集架构，包括寄存器、指令编码、算术运算等。
*   **关键生态标准**:
    *   **BTF (BPF Type Format)**: 一种紧凑的元数据格式，用于描述 BPF 程序和内核的数据结构。它是实现 **CO-RE (Compile Once – Run Everywhere)** 的基础，解决了 eBPF 程序在不同内核版本间的兼容性问题。
    *   **Libbpf**: 事实上的标准用户态库，用于加载和管理 eBPF 程序，支持 CO-RE。

## 3. eBPF 与 LKM (Loadable Kernel Module) 的区别

在 HIDS Driver 开发场景下，两者的核心对比如下：

| 特性 | eBPF (Modern) | LKM (Traditional) |
| :--- | :--- | :--- |
| **安全性** | **高**。经过 Verifier 严格检查，保证内存安全，不会导致 Kernel Panic。 | **低**。拥有内核最高权限，代码错误（如空指针解引用）直接导致系统崩溃 (Panic)。 |
| **稳定性** | **高**。沙盒运行，即使程序逻辑错误通常也只是报错或无数据，不影响系统运行。 | **低**。模块崩溃即系统崩溃。 |
| **兼容性** | **CO-RE**。利用 BTF 技术，一次编译即可在不同内核版本上运行（需内核支持 BTF，低版本需适配）。 | **差**。通常需针对每个内核版本重新编译，维护成本极高。 |
| **开发难度** | **中等**。受限于 Verifier（如循环次数限制、栈空间 512B 限制），复杂逻辑难以实现。 | **高**。需精通内核编程，但无逻辑限制，可随意访问内存和调用内核函数。 |
| **功能边界** | **受限**。只能通过 Helper 函数访问内核数据，严禁随意读写任意内存。反 Rootkit 能力较弱。 | **无限**。可访问任意内核内存、Hook 任意函数、修改系统调用表等。 |
| **发布/更新** | **热更新**。用户态程序加载即可，无需重启机器，无侵入。 | **需加载模块**。可能需要重启，且在某些安全加固的系统上被禁止加载未签名模块。 |
| **性能** | **极高**。JIT 编译后接近原生代码，但因安全检查和 Helper 调用，略低于极致优化的 LKM。 | **最高**。无额外开销，直接执行机器码。 |

**总结**: eBPF 是安全、稳定、可移植的现代选择，适合大规模生产环境；LKM 适合需要极深层内核控制（如强对抗、反 Rootkit）的特定场景。

## 4. 开源项目参考

以下是 HIDS 和安全可观测性领域优秀的 eBPF 开源项目，非常值得学习：

### 1. [Falco](https://falco.org/) (Sysdig)
*   **简介**: 云原生运行时安全的事实标准，CNCF 毕业项目。
*   **特点**:
    *   同时支持 **Kernel Module** 和 **eBPF Probe** 两种驱动模式（代码结构清晰，非常适合对比学习 LKM 和 eBPF 的实现差异）。
    *   拥有强大的规则引擎，定义了丰富的安全规则。
*   **学习点**: 如何抽象统一的事件接口层（`libscap` / `libsinsp`），使得上层逻辑可以无缝切换 LKM/eBPF 后端。

### 2. [Tracee](https://github.com/aquasecurity/tracee) (Aqua Security)
*   **简介**: 基于 eBPF 的轻量级安全追踪工具。
*   **特点**:
    *   纯 eBPF 实现，利用 CO-RE 技术。
    *   事件定义非常丰富，覆盖了系统调用、网络、文件等。
    *   引入了 **eBPF Signatures** 概念，在内核态/用户态进行行为模式匹配。
*   **学习点**: 如何使用 Go + Libbpfgo 构建现代化的 eBPF 安全工具；如何处理复杂的事件参数解析。

### 3. [Tetragon](https://github.com/cilium/tetragon) (Isovalent/Cilium)
*   **简介**: 基于 eBPF 的安全可观测性和阻断工具。
*   **特点**:
    *   **阻断能力 (Enforcement)**: 不仅能监控，还能利用 eBPF 实时阻断恶意行为（如 `kill` 进程、断开网络连接）。
    *   深度集成 Kubernetes，通过 CRD 配置策略。
    *   性能极高，利用 Cilium 的内核优化经验。
*   **学习点**: 如何实现高性能的内核态过滤和阻断逻辑；如何与 K8s 元数据深度关联。

### 4. [BCC](https://github.com/iovisor/bcc) & [Libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)
*   **BCC**: 早期的 eBPF 工具集，虽然现在推荐转向 Libbpf，但其包含的大量工具脚本（如 `execsnoop`, `opensnoop`）是理解 eBPF 监控逻辑的最佳入门教材。
*   **Libbpf-bootstrap**: eBPF 开发的脚手架工程，展示了如何使用 `libbpf` + `CO-RE` 开发标准的 eBPF 程序，是新项目开发的最佳起点。
