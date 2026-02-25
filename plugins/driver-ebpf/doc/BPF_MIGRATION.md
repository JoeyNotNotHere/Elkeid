# Elkeid eBPF 代码迁移文档

## 1. 迁移策略

### 1.1 设计决策

| 决策点 | 选择 | 理由 |
|--------|------|------|
| BPF 代码来源 | 从 Tracee 提取 | 成熟稳定，经过生产验证 |
| 依赖方式 | **复制代码，自维护** | 避免版本耦合，支持二次开发 |
| 精简策略 | 只保留 Elkeid 需要的事件 | 减少复杂度和维护成本 |
| 字段兼容 | C 层优先，Go 层兜底 | 性能最优 |

### 1.2 代码来源

- **Tracee 版本**: v0.22.0 (或当前 main 分支)
- **源码路径**: `/Users/joey/code/tracee/pkg/ebpf/c/`
- **目标路径**: `/Users/joey/code/Elkeid/plugins/driver-ebpf/bpf/`

## 2. 事件映射表

### 2.1 需要迁移的事件

| Elkeid 事件 | ID | Tracee Hook | 优先级 | 状态 |
|-------------|-----|-------------|--------|------|
| execve | 59 | `sched_process_exec` | P0 | 待迁移 |
| exit | 60 | `sched_process_exit` | P0 | 待迁移 |
| exit_group | 231 | `sched_process_exit` | P0 | 待迁移 |
| connect | 42 | `security_socket_connect` | P0 | 待迁移 |
| accept | 43 | `security_socket_accept` | P1 | 待迁移 |
| bind | 49 | `security_socket_bind` | P1 | 待迁移 |
| open | 2 | `security_file_open` | P1 | 待迁移 |
| kill | 62 | syscall hook | P1 | 待迁移 |
| tkill | 200 | syscall hook | P1 | 待迁移 |
| ptrace | 101 | syscall hook | P1 | 待迁移 |
| rename | 82 | `security_inode_rename` | P2 | 待迁移 |
| link | 86 | `security_inode_symlink` | P2 | 待迁移 |
| mount | 165 | `security_sb_mount` | P2 | 待迁移 |
| memfd_create | 356 | syscall hook | P2 | 待迁移 |
| module_load | 603 | `do_init_module` | P1 | 待迁移 |
| mprotect | 10 | `security_mmap_addr` | P2 | 待迁移 |
| write | 608/609 | `vfs_write` | P2 | 待迁移 |
| update_cred | 604 | `commit_creds` | P1 | 待迁移 |
| unlink | 606 | `security_inode_unlink` | P2 | 待迁移 |
| rmdir | 605 | `security_inode_unlink` | P2 | 待迁移 |
| usermodehelper | 607 | `call_usermodehelper` | P2 | 待迁移 |
| prctl | 112 | `security_task_prctl` | P2 | 待迁移 |
| dns | 601 | cgroup_skb / packet | P2 | 待迁移 |

### 2.2 不迁移的 Tracee 功能

| 功能 | 理由 |
|------|------|
| LSM hooks | Elkeid 不需要 |
| Signature 检测 | Elkeid 在上层实现 |
| Capabilities 检测 | Elkeid 不需要 |
| Container 检测 | 使用简化版本 |
| 大量调试功能 | 生产不需要 |

## 3. 文件结构规划

```
bpf/
├── BPF_MIGRATION.md       # 本文档
├── DESIGN.md              # 架构设计
├── README.md              # 使用说明
├── Makefile               # 编译脚本
│
├── vmlinux.h              # BTF 定义 (从 Tracee 复制)
├── types.h                # 类型定义 (精简版)
├── maps.h                 # BPF Maps (精简版)
│
├── common/                # 工具函数 (从 Tracee 提取)
│   ├── common.h           # 通用宏和函数
│   ├── task.h             # 进程相关
│   ├── filesystem.h       # 文件系统相关
│   ├── network.h          # 网络相关
│   ├── memory.h           # 内存相关
│   └── buffer.h           # 缓冲区操作
│
└── elkeid.bpf.c           # 主 BPF 程序 (整合所有事件)
```

## 4. 迁移步骤

### Phase 1: 基础框架 (当前)
- [x] 复制 `vmlinux.h` - 从 Tracee 复制
- [x] 精简 `types.h` - 定义 Elkeid 事件结构体
- [x] 精简 `maps.h` - 定义必要的 BPF maps
- [x] 提取 `common/helpers.h` - 整合 task/filesystem/tty 工具函数

### Phase 2: 核心事件
- [x] 迁移 `sched_process_exec` (execve) - 含 stdout, tty, sid
- [x] 迁移 `sched_process_exit` (exit/exit_group)
- [x] 迁移 `security_socket_connect` (connect)
- [x] 添加 Elkeid 特有字段 (stdout, sid, tty)

### Phase 3: 网络事件
- [x] 迁移 `security_socket_accept` - 含 kretprobe
- [x] 迁移 `security_socket_bind`
- [ ] DNS 解析 (简化版) - 待实现

### Phase 4: 文件事件
- [x] 迁移 `security_file_open` (open)
- [ ] 迁移 `vfs_write` - 待实现
- [x] 迁移 `security_inode_rename` (rename)
- [x] 迁移 `security_inode_unlink` (unlink)
- [x] 迁移 `security_inode_symlink` (link)
- [x] 迁移 `security_sb_mount` (mount)
- [x] 迁移 `security_file_mprotect` (mprotect)

### Phase 5: 其他事件
- [x] 迁移 `do_init_module` (module_load)
- [x] 迁移 `commit_creds` (update_cred)
- [x] 迁移 tracepoint `sys_enter_prctl` (prctl)
- [x] 迁移 tracepoint `sys_enter_kill` (kill)
- [x] 迁移 tracepoint `sys_enter_tkill` (tkill)
- [x] 迁移 tracepoint `sys_enter_ptrace` (ptrace)
- [x] 迁移 tracepoint `sys_enter_memfd_create` (memfd_create)
- [x] 迁移 `call_usermodehelper` (usermodehelper)

## 5. 字段兼容性

### 5.1 C 层直接实现

| 字段 | Tracee 状态 | 修改方案 |
|------|-------------|----------|
| stdout | ❌ 缺失 | 添加 `get_struct_file_from_fd(1)` |
| root_pns | ❌ 缺失 | 启动时读取，存入 map |
| sid | ❌ 缺失 | 从 `task->signal->pids[PIDTYPE_SID]` 读取 |
| tty | ❌ 缺失 | 从 `task->signal->tty` 读取 |

### 5.2 Go 层实现

| 字段 | 理由 |
|------|------|
| pid_tree | 需要遍历，BPF 循环限制 |
| socket_* | 需要 cache 关联 |
| username | 需要读取 /etc/passwd |
| exe_hash | 需要读取文件计算 |
| ppid_argv | 需要 cache |

## 6. 代码修改记录

### 6.1 从 Tracee 复制的文件

| 文件 | 源路径 | 修改说明 |
|------|--------|----------|
| vmlinux.h | tracee/pkg/ebpf/c/vmlinux.h | 原样复制 |

### 6.2 新创建的文件

| 文件 | 描述 | 日期 |
|------|------|------|
| types.h | Elkeid 事件类型定义 (精简) | 2026-02-26 |
| maps.h | BPF maps 定义 (精简) | 2026-02-26 |
| common/helpers.h | 工具函数 (task/fs/tty) | 2026-02-26 |
| elkeid.bpf.c | 主 BPF 程序 | 2026-02-26 |

### 6.3 自定义修改

| 修改点 | 描述 | 日期 |
|--------|------|------|
| stdout 采集 | execve 中添加 fd=1 路径采集 | 2026-02-26 |
| sid 采集 | 添加 session ID 获取函数 | 2026-02-26 |
| tty 采集 | 添加 TTY 名称获取函数 | 2026-02-26 |
| 精简事件结构 | 只保留 Elkeid 需要的字段 | 2026-02-26 |

### 6.4 实现的 Hooks

| Hook | 事件 | 状态 |
|------|------|------|
| raw_tracepoint/sched_process_exec | execve (59) | ✅ |
| raw_tracepoint/sched_process_exit | exit (60), exit_group (231) | ✅ |
| kprobe/security_socket_connect | connect (42) | ✅ |
| kprobe/security_socket_accept | accept (43) | ✅ |
| kprobe/security_socket_bind | bind (49) | ✅ |
| kprobe/security_file_open | open (2) | ✅ |
| kprobe/security_inode_unlink | unlink (606) | ✅ |
| kprobe/security_inode_rename | rename (82) | ✅ |
| kprobe/security_inode_symlink | link (86) | ✅ |
| kprobe/security_sb_mount | mount (165) | ✅ |
| kprobe/security_file_mprotect | mprotect (10) | ✅ |
| kprobe/do_init_module | module_load (603) | ✅ |
| kprobe/commit_creds | update_cred (604) | ✅ |
| kprobe/call_usermodehelper | usermodehelper (607) | ✅ |
| tracepoint/sys_enter_kill | kill (62) | ✅ |
| tracepoint/sys_enter_tkill | tkill (200) | ✅ |
| tracepoint/sys_enter_ptrace | ptrace (101) | ✅ |
| tracepoint/sys_enter_prctl | prctl (112) | ✅ |
| tracepoint/sys_enter_memfd_create | memfd_create (356) | ✅ |

### 6.5 待实现

| Hook | 事件 | 说明 |
|------|------|------|
| cgroup_skb/egress | dns (601) | DNS 查询，需要解析 UDP 包 |
| kprobe/vfs_write | write (608) | 文件写入监控 |
| kprobe/security_inode_rmdir | rmdir (605) | 目录删除 |
| kprobe/security_task_prctl | prctl (112) | 可选，作为 tracepoint 补充 |

## 7. Go 层集成状态

| 组件 | 文件 | 状态 |
|------|------|------|
| 事件结构体 | `pkg/loader/events.go` | ✅ |
| BPF 加载器 | `pkg/loader/loader.go` | ✅ |
| 事件读取器 | `pkg/loader/reader.go` | ✅ |
| 事件转换器 | `pkg/adapter/converter_native.go` | ✅ |
| 管理器 | `pkg/manager/manager.go` | ✅ |

## 8. 编译和测试

### 编译 BPF 程序 (Linux)
```bash
cd bpf/
make clean
make
# 输出: elkeid.bpf.o
```

### 编译 Go 程序
```bash
cd /path/to/driver-ebpf
go build -o elkeid-driver .
```

### 运行 (需要 root)
```bash
sudo ./elkeid-driver
```

---
**Last Updated**: 2026-02-26
