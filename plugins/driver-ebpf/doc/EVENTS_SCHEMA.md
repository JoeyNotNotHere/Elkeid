# Elkeid Driver 事件与字段定义 (Schema)

本文档基于 `plugins/driver/src/transformer/schema.rs` 整理，列出了 Elkeid LKM Driver 采集的所有事件及其字段定义。

## 1. 事件总览

| ID | 事件名称 | LKM Hook | Tracee 对应事件 | eBPF 状态 |
| :--- | :--- | :--- | :--- | :--- |
| **2** | `open` | `open_kprobe`, `openat_kprobe` | `openat`, `open` | ✅ BPF |
| **10** | `mprotect` | `mprotect_kprobe` | `mprotect` | ✅ BPF |
| **35** | `nanosleep` | `nanosleep_kprobe` | - (低优先级) | ⏭️ 跳过 |
| **42** | `connect` | `tcp_v4/v6_connect`, `ip4/6_datagram_connect` | `security_socket_connect` | ✅ BPF |
| **43** | `accept` | `accept_kretprobe`, `accept4_kretprobe` | `security_socket_accept` | ✅ BPF |
| **49** | `bind` | `bind_kprobe` | `security_socket_bind` | ✅ BPF |
| **59** | `execve` | `execve_kretprobe` | `sched_process_exec` | ✅ BPF |
| **60** | `exit` | `exit_kprobe` | `sched_process_exit` | ✅ BPF |
| **62** | `kill` | `kill_kprobe` | `kill`, `tkill` | ✅ BPF |
| **82** | `rename` | `rename_kprobe` | `rename`, `renameat` | ✅ BPF |
| **86** | `link` | `link_kprobe` | `link`, `linkat` | ✅ BPF |
| **101** | `ptrace` | `ptrace_kprobe` | `ptrace` | ✅ BPF |
| **112** | `prctl` | `prctl_kprobe` | `prctl` | ✅ BPF |
| **157** | `setsid` | `setsid_kprobe` | - | 📋 待实现 |
| **165** | `mount` | `mount_kprobe` | `mount` | ✅ BPF |
| **200** | `kill/tkill` | `kill_kprobe`, `tkill` | `kill`, `tkill` | ✅ BPF |
| **231** | `exit_group` | `exit_group_kprobe` | `sched_process_exit` | ✅ BPF |
| **356** | `memfd_create` | `memfd_create_kprobe` | `memfd_create` | ✅ BPF |
| **601** | `dns_query` | `dns_kprobe` (rawtp) | `net_packet_dns` | 📋 待实现 |
| **602** | `create_file` | `security_inode_create_kprobe` | `security_file_open` | 📋 待实现 |
| **603** | `module_load` | `do_init_module_kprobe` | `init_module` | ✅ BPF |
| **604** | `update_cred` | `update_cred_kprobe` | `commit_creds` | ✅ BPF |
| **605** | `rmdir` | `security_path_rmdir_kprobe` | `rmdir` | 📋 待实现 |
| **606** | `unlink` | `security_path_unlink_kprobe` | `unlink` | ✅ BPF |
| **607** | `usermodehelper` | `call_usermodehelper_exec_kprobe` | - | ✅ BPF |
| **608** | `write` | `write_kprobe` | `vfs_write` | 📋 待实现 |
| **609** | `write` (v2) | `write_kprobe` | `vfs_write` | 📋 待实现 |
| **610** | `udev` | `udev_kprobe` | - (UEvent) | 📋 待实现 |
| **611** | `privilege_escalation` | `check_cred` | - | 📋 待实现 |
| **700** | `rootkit_syscall` | `anti_rootkit` | - | ⏭️ 特殊 |
| **701** | `rootkit_syscall_table` | `anti_rootkit` | - | ⏭️ 特殊 |
| **702** | `rootkit_proc` | `anti_rootkit` | - | ⏭️ 特殊 |
| **703** | `rootkit_idt` | `anti_rootkit` | - | ⏭️ 特殊 |

**统计**: ✅ 已实现 19/34 事件 (56%) | 📋 待实现 9 个 | ⏭️ 跳过/特殊 6 个

## 2. 详细字段定义

### 公共字段 (Common Fields, Index 0-11)
大部分事件共享以下基础字段：
| Index | Key | 描述 | Tracee 来源 |
| :--- | :--- | :--- | :--- |
| 0 | `uid` | 用户 ID | `event.UserID` |
| 1 | `exe` | 可执行文件路径 | `pathname` arg |
| 2 | `pid` | 进程 ID | `event.ProcessID` |
| 3 | `ppid` | 父进程 ID | `event.ParentProcessID` |
| 4 | `pgid` | 进程组 ID | `event.ProcessGroupID` |
| 5 | `tgid` | 线程组 ID | `event.ThreadID` |
| 6 | `sid` | 会话 ID | 需补充 |
| 7 | `comm` | 进程名 | `event.ProcessName` |
| 8 | `nodename` | 主机名 | `os.Hostname()` |
| 9 | `sessionid` | 会话 ID (重复) | 需补充 |
| 10 | `pns` | PID Namespace | `event.MountNS` |
| 11 | `root_pns` | Root PID NS | `/proc/1/ns/pid` |

### ID 2: `open`
```
[uid, exe, pid, ppid, pgid, tgid, sid, comm, nodename, sessionid, pns, root_pns,
 flags, mode, file, argv, ppid_argv, pgid_argv, username, pod_name, exe_hash, pid_tree]
```

### ID 10: `mprotect`
```
[uid, exe, pid, ppid, pgid, tgid, sid, comm, nodename, sessionid, pns, root_pns,
 mprotect_prot, owner_pid, owner_file, vm_file, pid_tree, argv, ppid_argv, pgid_argv,
 username, pod_name, exe_hash]
```

### ID 42/43: `connect/accept`
```
[uid, exe, pid, ppid, pgid, tgid, sid, comm, nodename, sessionid, pns, root_pns,
 sa_family, dip, dport, sip, sport, res, argv, ppid_argv, pgid_argv, username,
 pod_name, exe_hash, pid_tree]
```

### ID 49: `bind`
```
[uid, exe, pid, ppid, pgid, tgid, sid, comm, nodename, sessionid, pns, root_pns,
 sa_family, sip, sport, res, argv, ppid_argv, pgid_argv, username, pod_name,
 exe_hash, pid_tree]
```

### ID 59: `execve`
```
[uid, exe, pid, ppid, pgid, tgid, sid, comm, nodename, sessionid, pns, root_pns,
 argv, run_path, stdin, stdout, dip, dport, sip, sport, sa_family, pid_tree, tty,
 socket_pid, ssh, ld_preload, res, socket_argv, ppid_argv, pgid_argv, username,
 pod_name, exe_hash]
```
**字段兼容性问题**:
- `stdout`: Tracee 未采集，通过 `/proc/<pid>/fd/1` 补充
- `dip/dport/sip/sport/sa_family/socket_pid`: Socket 关联逻辑，通过 SocketCache 实现
- `ssh/ld_preload`: 从 Tracee `env` 参数提取

### ID 60/231: `exit/exit_group`
```
[uid, exe, pid, ppid, pgid, tgid, sid, comm, nodename, sessionid, pns, root_pns,
 argv, ppid_argv, pgid_argv, username, pod_name, exe_hash, pid_tree]
```

### ID 62/200: `kill/tkill`
```
[uid, exe, pid, ppid, pgid, tgid, sid, comm, nodename, sessionid, pns, root_pns,
 target_pid, sig, argv, ppid_argv, pgid_argv, username, pod_name, exe_hash, pid_tree]
```

### ID 82/86: `rename/link`
```
[uid, exe, pid, ppid, pgid, tgid, sid, comm, nodename, sessionid, pns, root_pns,
 old_name, new_name, sb_id, argv, ppid_argv, pgid_argv, username, pod_name,
 exe_hash, pid_tree]
```

### ID 101: `ptrace`
```
[uid, exe, pid, ppid, pgid, tgid, sid, comm, nodename, sessionid, pns, root_pns,
 ptrace_request, target_pid, addr, data, pid_tree, argv, ppid_argv, pgid_argv,
 username, pod_name, exe_hash, target_argv]
```

### ID 356: `memfd_create`
```
[uid, exe, pid, ppid, pgid, tgid, sid, comm, nodename, sessionid, pns, root_pns,
 fd_name, flags, argv, ppid_argv, pgid_argv, username, pod_name, exe_hash, pid_tree]
```

### ID 601: `dns_query`
```
[uid, exe, pid, ppid, pgid, tgid, sid, comm, nodename, sessionid, pns, root_pns,
 query, sa_family, dip, dport, sip, sport, opcode, rcode, argv, ppid_argv,
 pgid_argv, username, pod_name, exe_hash, pid_tree]
```

### ID 602: `create_file`
```
[uid, exe, pid, ppid, pgid, tgid, sid, comm, nodename, sessionid, pns, root_pns,
 file_path, dip, dport, sip, sport, sa_family, socket_pid, sb_id, argv, ppid_argv,
 pgid_argv, username, pod_name, exe_hash, pid_tree, socket_argv]
```

### ID 603: `module_load`
```
[uid, exe, pid, ppid, pgid, tgid, sid, comm, nodename, sessionid, pns, root_pns,
 ko_file, pid_tree, run_path, argv, ppid_argv, pgid_argv, username, pod_name, exe_hash]
```

### ID 604: `update_cred`
```
[uid, exe, pid, ppid, pgid, tgid, sid, comm, nodename, sessionid, pns, root_pns,
 pid_tree, old_uid, res, argv, ppid_argv, pgid_argv, username, pod_name, exe_hash,
 old_username]
```

### ID 610: `udev`
```
[uid, exe, pid, ppid, pgid, tgid, sid, comm, nodename, sessionid, pns, root_pns,
 product_info, manufacturer, serial, action, argv, ppid_argv, pgid_argv, username,
 pod_name, exe_hash, pid_tree]
```

### ID 700-703: `rootkit` (Anti-Rootkit)
- 700: `[module_name]`
- 701: `[module_name, syscall_number]`
- 702: `[module_name]`
- 703: `[module_name, interrupt_number]`

**注意**: Rootkit 检测在 eBPF 中实现方式完全不同，需单独设计。

## 3. Tracee 事件映射表

| LKM Event | Tracee Event | 备注 |
| :--- | :--- | :--- |
| execve (59) | `sched_process_exec` | 已完成映射 |
| exit (60/231) | `sched_process_exit` | 直接映射 |
| connect (42) | `security_socket_connect` | 需提取 sockaddr |
| accept (43) | `security_socket_accept` | 需提取返回的 fd |
| bind (49) | `security_socket_bind` | 需提取 sockaddr |
| open (2) | `openat` / `security_file_open` | 需过滤 |
| kill (62/200) | `kill`, `tkill` | 直接映射 |
| ptrace (101) | `ptrace` | 直接映射 |
| rename (82) | `rename`, `renameat` | 直接映射 |
| link (86) | `link`, `linkat` | 直接映射 |
| mount (165) | `mount` | 直接映射 |
| memfd_create (356) | `memfd_create` | 直接映射 |
| dns (601) | `net_packet_dns` | 解析 DNS 包 |
| module_load (603) | `init_module` | 直接映射 |
| mprotect (10) | `mprotect` | 需补充 vm_file |

## 4. 兼容性问题记录

| 字段 | 问题描述 | 解决方案 | 优先级 |
| :--- | :--- | :--- | :--- |
| `stdout` | Tracee 未采集 | `/proc/<pid>/fd/1` | 中 |
| `root_pns` | Tracee 未提供 | 启动时读取 `/proc/1/ns/pid` | ✅ 已解决 |
| `sid` | Tracee 未直接提供 | `/proc/<pid>/stat` 字段 | 低 |
| `socket_*` | execve 中的 socket 关联 | SocketCache + ProcTree | 高 |
| `pid_tree` | 格式不同 | ProcTreeCache 自建 | ✅ 已解决 |
| `tty` | Tracee 未提供 | `/proc/<pid>/stat` 字段 7 | 低 |
| `exe_hash` | 需计算文件哈希 | 后台异步计算 | 低 |
| `vm_file` | mprotect 的映射文件 | 需从 Tracee 参数提取 | 中 |

---
**Last Updated**: 2026-02-26 15:00
