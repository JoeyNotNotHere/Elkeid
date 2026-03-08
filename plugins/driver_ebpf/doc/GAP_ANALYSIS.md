# Elkeid Driver 采集字段映射与 GAP 分析

## 1. 概览
本文档对比 Elkeid LKM Driver (C) 与 Tracee eBPF (C/Go) 的数据采集能力，找出迁移过程中需要补充或修改的字段。

## 2. 核心事件分析: `execve` (ID=59)

### 2.1 Tracee `sched_process_exec` 已采集字段

| 参数索引 | 字段名 | 描述 | Elkeid 对应 |
| :--- | :--- | :--- | :--- |
| 0 | filename | 可执行文件名 (argv[0]) | (部分 argv) |
| 1 | pathname | 可执行文件完整路径 | `exe` ✅ |
| 2 | dev | 设备号 | - |
| 3 | inode | inode 号 | - |
| 4 | ctime | 修改时间 | - |
| 5 | inode_mode | inode 模式 | - |
| 6-9 | interpreter_* | 解释器信息 | - |
| 10 | argv | 命令行参数数组 | `argv` ✅ |
| 11 | interp | 解释器路径 | - |
| 12 | stdin_type | stdin 文件类型 | - |
| 13 | stdin_path | stdin 重定向路径 | `stdin` ✅ |
| 14 | invoked_from_kernel | 是否内核调用 | - |
| 15 | prev_comm | 执行前进程名 | - |
| 16 | env | 环境变量 (可选) | (部分: ld_preload, ssh) |
| 17 | cwd | 当前工作目录 | `run_path` ✅ |

**Tracee Context 自动提供:**
- `uid`, `pid`, `ppid`, `pgid`, `tgid`, `comm`, `pidNs`, `mntNs`, `cgroupId` 等

### 2.2 Elkeid LKM 独有字段 (需补充)

| 字段名 | 描述 | LKM 获取方式 | 补充方案 | 层级 |
| :--- | :--- | :--- | :--- | :--- |
| **stdout** | 标准输出重定向路径 | `fget(1)` + `d_path` | 修改 BPF: `get_struct_file_from_fd(1)` | **eBPF** |
| **root_pns** | Root PID Namespace inum | 模块初始化时获取 PID 1 的 ns inum | Go 启动时读取 `/proc/1/ns/pid` | **Go** |
| **sid** | Session ID | `task_session_nr(current)` | BPF: `task->signal->__session` 或 Go 层 `/proc/<pid>/stat` | **Go/BPF** |
| **nodename** | 主机名 | `utsname()->nodename` | Go: `os.Hostname()` | **Go** |
| **sessionid** | (重复?) | 同上 | - | - |
| **tty_name** | TTY 设备名 | `get_current_tty()->name` | Go: `/proc/<pid>/stat` 字段 7 | **Go** |
| **dip/dport/sip/sport** | Socket 连接信息 | `get_process_socket()` 遍历进程树 FD | Go: 维护 socket cache + 进程关联 | **Go Cache** |
| **socket_pid** | 持有 socket 的进程 PID | 同上 | 同上 | **Go Cache** |
| **sa_family** | Socket 地址族 | 同上 | 同上 | **Go Cache** |
| **pid_tree** | 进程树字符串 | `smith_get_pid_tree()` 遍历父进程 | Go: Tracee proctree 或自建 cache | **Go Cache** |
| **socket_argv** | Socket 进程 argv | 用户态关联 | Go: pid_tree 关联 | **Go Cache** |
| **ppid_argv** | 父进程 argv | 用户态关联 | Go: proctree cache | **Go Cache** |
| **pgid_argv** | 进程组 argv | 用户态关联 | Go: proctree cache | **Go Cache** |
| **username** | 用户名 | 用户态 `/etc/passwd` | Go: `user.LookupId()` | **Go** |
| **pod_name** | K8s Pod 名称 | 用户态关联 | Tracee 已有 `podName` ✅ | **Tracee** |
| **exe_hash** | 文件 Hash | 用户态计算 | Go: `sha256.Sum256()` | **Go** |
| **ld_preload** | LD_PRELOAD 环境变量 | 内核态解析 env | Go: 从 Tracee env 提取 | **Go** |
| **ssh_connection** | SSH_CONNECTION 环境变量 | 内核态解析 env | Go: 从 Tracee env 提取 | **Go** |

## 3. 关键发现

### 3.1 内核态差异
1. **stdout**: Tracee 只采集 `stdin`，未采集 `stdout`。需在 BPF 中添加。
2. **session id**: Tracee 未直接暴露 session id，需从 task_struct 获取。

### 3.2 用户态富化
LKM 的很多"采集"实际上是在用户态完成的：
- `pid_tree`, `socket_argv`, `ppid_argv`, `pgid_argv` - 进程树关联
- `username`, `exe_hash` - 用户信息/文件哈希计算
- `dip`, `dport`, `sip`, `sport` - **Socket 关联** (重要！见下文)

### 3.3 Socket 关联逻辑 (重要)
Elkeid LKM 的 `get_process_socket()` 是一个特殊逻辑：
- 在 `execve` 时，从当前进程开始向上遍历父进程
- 检查每个进程的前 N 个 FD，寻找 CONNECTED/CONNECTING 状态的 socket
- 找到后记录 `socket_pid` 和网络四元组
- **目的**: 将 execve 事件与网络连接关联，用于检测可疑的远程执行

**eBPF 迁移方案:**
在 Go 层维护 `SocketCache`:
- 监听 `connect`/`accept` 事件，记录 `pid -> (sip, sport, dip, dport)`
- 在 `execve` 事件处理时，查找当前进程及父进程的 socket 信息

## 4. 行动计划 (Action Plan)

### Phase A: eBPF 层修改 (可选，优先级低)
1. [ ] 在 `tracee.bpf.c` 的 `sched_process_exec_event_submit_tail` 中添加 `stdout` 采集逻辑

### Phase B: Go 层实现 (核心)
1. [x] `pkg/adapter/encoder.go` - 协议编码器 (已完成)
2. [ ] `pkg/adapter/converter.go` - 事件转换器 (骨架已有)
3. [ ] `pkg/cache/proctree.go` - 进程树缓存
4. [ ] `pkg/cache/socket.go` - Socket 关联缓存
5. [ ] `pkg/cache/user.go` - 用户信息缓存
6. [ ] `pkg/manager/manager.go` - 集成 Tracee

### Phase C: 测试与验证
1. [ ] 对比 LKM 与 eBPF 输出，验证字段完整性
2. [ ] 性能测试 (吞吐量、CPU 占用)

## 5. 附录: LKM 源码关键函数

### 5.1 stdin/stdout 获取
```c
// driver/LKM/src/smith_hook.c:1442-1456
file = smith_fget_raw(0);  // fd=0 stdin
tmp_stdin = smith_d_path(&(file->f_path), stdin_buf, 256);

file = smith_fget_raw(1);  // fd=1 stdout
tmp_stdout = smith_d_path(&(file->f_path), stdout_buf, 256);
```

### 5.2 Root PID NS 获取
```c
// driver/LKM/src/smith_hook.c:162-183
// 模块初始化时，获取 PID 1 的 namespace inum
ROOT_PID_NS_INUM = task->nsproxy->pid_ns_for_children->ns.inum;  // >= 3.19
```

### 5.3 Socket 关联
```c
// driver/LKM/src/smith_hook.c:679-778
get_process_socket(&sip4, &sip6, &sport, &dip4, &dip6, &dport, &socket_pid, &sa_family);
// 遍历当前进程及父进程的 FD，查找 socket
```

### 5.4 进程树构建
```c
// driver/LKM/src/smith_hook.c:599-673
// 格式: "pid1.comm1<pid2.comm2<pid3.comm3"
static char *smith_get_pid_tree(int limit) {
    while (task && task->pid != 1 && it++ < limit) {
        strcat(tmp_data, "<");
        strcat(tmp_data, pid);
        strcat(tmp_data, ".");
        strcat(tmp_data, task->comm);
        task = rcu_dereference(task->real_parent);
    }
}
```

---
**Last Updated**: 2026-02-26 14:30
