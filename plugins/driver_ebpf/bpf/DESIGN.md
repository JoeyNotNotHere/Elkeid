# Elkeid eBPF 采集层设计

## 1. 概述

本目录包含 Elkeid eBPF Driver 的 BPF C 代码，负责内核态事件采集。

## 2. 目录结构

```
bpf/
├── DESIGN.md           # 本文档
├── Makefile            # 编译脚本
├── elkeid.bpf.c        # 主 BPF 程序 (19 个 hooks)
└── common/             # 公共头文件
    ├── vmlinux.h       # 内核类型定义 (BTF)
    ├── types.h         # 事件结构体定义
    ├── maps.h          # BPF maps 定义
    └── helpers.h       # 工具函数
```

## 3. 技术选型

### 方案演进

| 阶段 | 方案 | 说明 |
|------|------|------|
| v1 | Tracee 库依赖 | 依赖重，定制性差 |
| v2 | 混合方案 | Tracee + 扩展 BPF |
| **v3** | **自研 BPF** | 从 Tracee 提取精简，完全自主可控 |

### 当前方案: 自研 BPF (v3)

**理由**:
1. **轻量**: 仅包含 Elkeid 需要的事件和字段
2. **可控**: 无外部依赖，便于调试和优化
3. **兼容**: 事件 ID 和字段与 LKM 版本完全对齐
4. **CO-RE**: 一次编译，支持多内核版本

## 4. 架构

```
┌─────────────────────────────────────────────────────────────┐
│                     Linux Kernel                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              elkeid.bpf.c (19 hooks)                │   │
│  │                                                     │   │
│  │  raw_tracepoint:                                    │   │
│  │    - sched_process_exec  → execve                   │   │
│  │    - sched_process_exit  → exit/exit_group         │   │
│  │                                                     │   │
│  │  kprobe:                                            │   │
│  │    - security_socket_connect  → connect             │   │
│  │    - security_socket_accept   → accept              │   │
│  │    - security_socket_bind     → bind                │   │
│  │    - security_file_open       → open                │   │
│  │    - security_inode_*         → rename/link/unlink  │   │
│  │    - security_sb_mount        → mount               │   │
│  │    - security_file_mprotect   → mprotect            │   │
│  │    - do_init_module           → module_load         │   │
│  │    - commit_creds             → update_cred         │   │
│  │    - call_usermodehelper      → usermodehelper      │   │
│  │                                                     │   │
│  │  tracepoint (syscalls):                             │   │
│  │    - sys_enter_kill/tkill     → kill                │   │
│  │    - sys_enter_ptrace         → ptrace              │   │
│  │    - sys_enter_prctl          → prctl               │   │
│  │    - sys_enter_memfd_create   → memfd_create        │   │
│  │                                                     │   │
│  └─────────────────────────┬───────────────────────────┘   │
│                            │                                │
│                   Perf Ring Buffer                         │
│                            │                                │
└────────────────────────────┼────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                   User Space (Go)                           │
│                                                             │
│  pkg/loader  →  pkg/manager  →  pkg/adapter  →  Agent      │
│  (读取事件)     (缓存更新)       (协议编码)                  │
└─────────────────────────────────────────────────────────────┘
```

## 5. 文件说明

### common/vmlinux.h
- 从内核 BTF 生成的类型定义
- 包含所有需要的内核结构体
- CO-RE 的基础

### common/types.h
- `elkeid_event_id`: 事件 ID 枚举 (与 LKM schema.rs 对齐)
- `event_header_t`: 公共事件头
- `execve_event_t`, `exit_event_t`, `net_event_t`, 等: 各事件结构体
- `elkeid_config_t`: BPF 运行时配置

### common/maps.h
- `events`: Perf buffer，事件输出通道
- `config_map`: 配置 map (root_pid_ns 等)
- `proc_info_map`: 进程信息缓存
- `task_info_map`: 任务信息 (kprobe 入口/出口传递)
- `bufs`: Per-CPU buffer，临时存储
- `args_map`: kretprobe 参数传递
- `pid_filter`, `comm_filter`: 过滤器

### common/helpers.h
- 任务信息读取: `get_task_pid`, `get_task_ppid`, `get_task_sid`, 等
- 文件路径读取: `get_file_path`, `get_dentry_path`
- TTY 信息: `get_tty_name`
- 凭证信息: `get_task_cred`
- 事件初始化: `init_event_header`

### elkeid.bpf.c
- 主 BPF 程序，实现所有 19 个 hooks
- 每个 hook 填充对应的事件结构体
- 通过 `bpf_perf_event_output` 发送事件

## 6. 编译

### 依赖

```bash
# Ubuntu/Debian
sudo apt install clang llvm libbpf-dev

# CentOS/RHEL
sudo yum install clang llvm libbpf-devel
```

### 编译命令

```bash
cd bpf
make        # 编译 BPF 程序
make clean  # 清理
make info   # 显示环境信息
```

### 生成 vmlinux.h (可选)

```bash
# 如果需要更新 vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > common/vmlinux.h
```

## 7. 事件采集详情

### Elkeid 特有字段

以下字段在 Tracee 中不直接提供，需要自行采集:

| 字段 | 采集位置 | 说明 |
|------|----------|------|
| stdout | BPF | `fget(1)` + `d_path` |
| tty | BPF | `task->signal->tty->name` |
| sid | BPF | `task_session_nr(current)` |
| pgid | BPF | `task_pgrp_nr(current)` |

### Go 层补充字段

以下字段在 Go 层通过缓存或 procfs 补充:

| 字段 | 来源 | 说明 |
|------|------|------|
| pid_tree | ProcTreeCache | 进程树字符串 |
| socket_pid | SocketCache | Socket 关联 PID |
| username | UserCache | UID → 用户名 |
| root_pns | 启动时读取 | `/proc/1/ns/pid` |

## 8. 调试

### 查看已加载的 BPF 程序

```bash
sudo bpftool prog list
sudo bpftool map list
```

### 查看 BPF 日志

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### 检查事件输出

```bash
# 使用 bpftool 读取 perf buffer (需要程序运行)
sudo bpftool map dump name events
```
