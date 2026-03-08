# driver_ebpf Code Review

> Review Date: 2026-02-26
> Scope: `plugins/driver_ebpf/` vs `driver/LKM/` + `plugins/driver/`

---

## 1. 架构与流程

### 1.1 整体架构

driver_ebpf 是 Elkeid 原始 LKM 内核模块 (`driver/LKM/`) + Rust 用户态插件 (`plugins/driver/`) 的 eBPF 替代实现，使用 Go + cilium/ebpf 库。

```
┌─────────────────────────────────────────────────────────────────┐
│                        Kernel Space                             │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │               elkeid.bpf.c  (BPF Programs)               │   │
│  │                                                          │   │
│  │  ┌────────────┐  ┌──────────┐  ┌───────────────────┐    │   │
│  │  │ Raw TP     │  │ Kprobes  │  │ Tracepoints       │    │   │
│  │  │            │  │          │  │                   │    │   │
│  │  │ exec  ─────│  │ connect  │  │ kill  tkill       │    │   │
│  │  │ exit  ─────│  │ accept   │  │ ptrace  prctl     │    │   │
│  │  │            │  │ bind     │  │ memfd_create      │    │   │
│  │  │            │  │ open     │  │ setsid            │    │   │
│  │  │            │  │ rename   │  │                   │    │   │
│  │  │            │  │ unlink   │  └───────────────────┘    │   │
│  │  │            │  │ symlink  │                            │   │
│  │  │            │  │ mount    │                            │   │
│  │  │            │  │ mprotect │                            │   │
│  │  │            │  │ module   │                            │   │
│  │  │            │  │ cred     │                            │   │
│  │  │            │  │ rmdir    │                            │   │
│  │  │            │  │ write    │                            │   │
│  │  │            │  │ dns(udp) │                            │   │
│  │  │            │  │ usermode │                            │   │
│  │  └────────────┘  └──────────┘                            │   │
│  │                       │                                   │   │
│  │            ┌──────────▼──────────┐                        │   │
│  │            │   Per-CPU Buffers   │                        │   │
│  │            │   (BPF_MAP bufs)    │                        │   │
│  │            └──────────┬──────────┘                        │   │
│  │                       │                                   │   │
│  │            ┌──────────▼──────────┐  ┌──────────────────┐  │   │
│  │            │ Perf Event Buffer   │  │  proc_info_map   │  │   │
│  │            │   (events map)      │  │  (LRU Hash)      │  │   │
│  │            └──────────┬──────────┘  └──────────────────┘  │   │
│  └───────────────────────┼──────────────────────────────────┘   │
└──────────────────────────┼──────────────────────────────────────┘
                           │ perf_event_output
┌──────────────────────────▼──────────────────────────────────────┐
│                       User Space (Go)                           │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                     main.go                               │   │
│  │              signal.NotifyContext                          │   │
│  │                       │                                   │   │
│  │              ┌────────▼────────┐                          │   │
│  │              │    Manager      │                          │   │
│  │              │  (manager.go)   │                          │   │
│  │              └────────┬────────┘                          │   │
│  │                       │                                   │   │
│  │     ┌─────────────────┼──────────────────┐               │   │
│  │     │                 │                  │               │   │
│  │     ▼                 ▼                  ▼               │   │
│  │  ┌──────┐      ┌───────────┐      ┌───────────┐         │   │
│  │  │Loader│      │EventReader│      │  Caches   │         │   │
│  │  │      │      │           │      │           │         │   │
│  │  │Load  │      │PerfBuffer │      │ProcTree   │         │   │
│  │  │Attach│      │→ParseEvent│      │Socket     │         │   │
│  │  │Config│      │→Callback  │      │User       │         │   │
│  │  └──────┘      └─────┬─────┘      └───────────┘         │   │
│  │                      │                                   │   │
│  │              ┌───────▼───────┐                           │   │
│  │              │NativeConverter│                           │   │
│  │              │ (adapter pkg) │                           │   │
│  │              │               │                           │   │
│  │              │ ConvertToRecord ──→ plugins.Client.Send   │   │
│  │              │ Convert ─────────→ output chan []byte     │   │
│  │              └───────────────┘                           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   Elkeid Agent                            │   │
│  │              (via plugins.Client)                         │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 数据流

```
1. Kernel Hook 触发
   ↓
2. BPF Program 从 task_struct 提取进程信息，填充 event struct
   ↓
3. bpf_perf_event_output() 写入 Perf Event Buffer
   ↓
4. EventReader.readLoop() 从 perf.Reader.Read() 读取原始字节
   ↓
5. ParseEvent() 根据 event_id 反序列化为对应 Go struct
   ↓
6. Manager.processEvents() 更新 caches + 转换事件
   ↓
7. NativeConverter.ConvertToRecord() → plugins.Record → Agent
   NativeConverter.Convert() → []byte (Elkeid 二进制协议) → output chan
```

### 1.3 与原架构的对比

| 维度 | 原 LKM + plugins/driver | driver_ebpf |
|------|------------------------|-------------|
| 内核采集 | 内核模块 (kprobes, smith_hook.c) | eBPF programs (elkeid.bpf.c) |
| 用户态语言 | Rust | Go |
| 通信机制 | Named pipe (trace_buffer → /proc/hids_driver/1) + 0x17 分隔符 | Perf Event Buffer (cilium/ebpf) |
| 事件序列化 | 内核 printk 风格文本 → Rust 解析转换 | BPF 结构体二进制 → Go binary.Read |
| 过滤机制 | 内核态 exe/argv 白名单 + 用户态控制 | 仅定义了 filter map，未实际使用 |
| 内核模块管理 | 自动下载/安装/卸载 .ko 文件 | 无 (eBPF 不需要) |
| 协议输出 | Rust 直接写 Elkeid protobuf 二进制 | Go Encoder 实现 Elkeid 二进制协议 |

---

## 2. 逻辑问题 (Bugs)

### 2.1 [严重] init_event_header 中 PID/TID 反转

`helpers.h` 第 250-251 行：

```c
hdr->pid = get_task_pid(task);   // 实际获取 task->pid (内核线程ID)
hdr->tid = get_task_tgid(task);  // 实际获取 task->tgid (内核进程ID)
```

在 Linux 内核中，`task->pid` 是线程 ID，`task->tgid` 才是用户态进程 ID。**这里赋值完全反了**。

仅 `sched_process_exec` 和 `sched_process_exit` 两个事件在 init_event_header 之后做了正确的覆写：

```c
event->header.pid = BPF_CORE_READ(task, tgid);  // 正确
event->header.tid = BPF_CORE_READ(task, pid);    // 正确
```

**其余所有事件（connect, bind, open, kill, ptrace, prctl, rename, mount 等 ~20 个钩子）的 pid/tid 字段都是反的。**

影响范围：所有非 exec/exit 事件的 pid 和 tgid(tid) 字段值互换，会导致下游规则引擎误判。

**修复方案：**
```c
hdr->pid = get_task_tgid(task);  // tgid = 进程ID
hdr->tid = get_task_pid(task);   // pid = 线程ID
```

### 2.2 [严重] Accept 事件读取了错误的 Socket

`elkeid.bpf.c` 第 535-605 行的 accept 实现：

```c
SEC("kprobe/security_socket_accept")
int BPF_KPROBE(elkeid_security_socket_accept, struct socket *sock)
```

`security_socket_accept(struct socket *sock, struct socket *newsock)` 的第一个参数 `sock` 是**监听 socket**，不是新连接的 socket。在 kretprobe 中从 `sock->sk` 读到的是**监听地址**，而非远端客户端地址。

原 LKM 通过 hook `sys_accept` / `sys_accept4` 的返回值获取正确的新连接 fd，再从 fd 读取 socket 信息。

**修复方案：** 改为 hook `inet_csk_accept` (返回 `struct sock *`)，或 hook `sys_accept`/`sys_accept4` 系统调用的 kretprobe 并从返回的 fd 获取 socket 信息。

### 2.3 [严重] C/Go 结构体对齐不匹配风险

`event_header_t` 在 C 中因第一个成员是 `u64`，sizeof 会被 padding 到 64 字节 (自然对齐)。但 Go 的 `EventHeader` 计算为 60 字节（Go 不自动添加尾部 padding）。

这意味着通过 `bpf_perf_event_output` 发送的数据和 Go 端 `binary.Read` 解析的数据**可能存在偏移**，导致所有后续字段解析错误。

涉及的结构体对：
- `event_header_t` (C: 64B?) vs `EventHeader` (Go: 60B)
- `exit_event_t` vs `ExitEvent` (Go 加了 `[4]byte` padding 但可能不对)
- `net_event_t` vs `NetEvent`
- 所有 event 类型

**修复方案：**
1. 在 C 端使用 `__attribute__((packed))` 消除 padding
2. 或在 Go 端添加精确匹配的 padding 字段
3. 必须通过实际编译 BPF 代码后打印 sizeof 验证

### 2.4 [中等] DNS 事件不解析查询内容

`elkeid.bpf.c` 第 1041-1087 行 DNS hook:

```c
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(elkeid_udp_sendmsg, ...)
```

仅检测到目标端口是 53 就发送事件，但 `dns_event_t.query` 字段**从未被填充**。原 LKM 通过 netfilter hook 实际解析 DNS 报文提取查询域名。

当前实现只能告知「某进程发了 UDP 包到端口 53」，无法提供 DNS 查询域名，**对安全检测价值有限**。

### 2.5 [中等] vfs_write 过滤逻辑过于简陋

```c
if (path_buf[0] != '/' || path_buf[1] != 'e' || path_buf[2] != 't' || path_buf[3] != 'c')
    return 0;
```

问题：
- 仅匹配以 `/etc` 开头的路径，但也会匹配 `/etcetera`, `/etc_backup` 等
- 遗漏其他敏感路径：`/root/.ssh/`, `/var/spool/cron/`, `/etc/ld.so.preload`
- 原 LKM 使用 map-based 过滤（可通过 sysfs 动态配置），更灵活

### 2.6 [低] security_file_open 无过滤 —— 高性能风险

`security_file_open` kprobe 对**每次文件打开**都触发事件提交。在实际生产环境中，每秒数万次 open 调用的系统上，这会导致：
- Perf buffer 溢出，大量事件丢失
- CPU 开销显著增加

原 LKM 中 OPEN hook 默认关闭（`SMITH_HOOK(OPEN, SANDBOX)`），仅在沙箱模式启用。

### 2.7 [低] Connect 事件未捕获返回值

eBPF 使用 `kprobe/security_socket_connect`（entry hook），无法获得连接是否成功的返回值。原 LKM 使用 `kretprobe`（`tcp_v4_connect` 等）捕获实际返回值。

当前 connect 事件的 `ret` 字段始终为 0。

---

## 3. 功能兼容性对比

### 3.1 事件覆盖矩阵

| Event ID | 事件名 | LKM 状态 | eBPF 状态 | 兼容性 | 备注 |
|----------|--------|----------|-----------|--------|------|
| 2 | open | SANDBOX (默认关闭) | **已实现** | ⚠️ 部分 | 无过滤，高 volume |
| 10 | mprotect | SANDBOX (默认关闭) | **已实现** | ⚠️ 部分 | 缺少 owner_pid, owner_file |
| 35 | nanosleep | 默认关闭 | ❌ 未实现 | N/A | 低优先级 |
| 42 | connect | 默认开启 | **已实现** | ⚠️ 部分 | 不同 hook 点；缺 ret；缺 sip/sport |
| 43 | accept | SANDBOX (默认关闭) | **已实现** | ❌ Bug | 读取了监听 socket 而非新连接 |
| 49 | bind | 默认开启 | **已实现** | ✅ 基本兼容 | |
| 59 | execve | 默认开启 | **已实现** | ⚠️ 部分 | 缺 ssh/ld_preload/env 解析；缺 exe_hash |
| 60 | exit | SANDBOX (默认关闭) | **已实现** | ✅ 基本兼容 | |
| 62 | kill | SANDBOX (默认关闭) | **已实现** | ⚠️ 部分 | 缺 target_argv |
| 82 | rename | 默认开启 | **已实现** | ⚠️ 部分 | 缺 sb_id |
| 86 | link | 默认开启 | **已实现** | ⚠️ 部分 | 仅实现 symlink，缺 hard link；缺 sb_id |
| 101 | ptrace | 默认开启 | **已实现** | ⚠️ 部分 | 缺 addr, data, target_argv |
| 112 | prctl | 默认开启 | **已实现** | ⚠️ 部分 | 仅采集 option，缺其他参数 |
| 157 | setsid | 默认开启 | **已实现** | ✅ 基本兼容 | |
| 165 | mount | 默认开启 | **已实现** | ⚠️ 部分 | 缺 fstype |
| 200 | tkill | SANDBOX (默认关闭) | **已实现** | ⚠️ 部分 | |
| 231 | exit_group | SANDBOX (默认关闭) | **已实现** | ✅ 基本兼容 | |
| 356 | memfd_create | 默认开启 | **已实现** | ✅ 基本兼容 | |
| 601 | dns | 内核>=5.5默认开启 | **已实现** | ❌ 不兼容 | query 字段未填充 |
| 602 | create_file | 默认开启 | ❌ 未实现 | ❌ 缺失 | LKM 的 security_inode_create |
| 603 | module_load | 默认开启 | **已实现** | ⚠️ 部分 | 缺 ko_file (模块文件路径) |
| 604 | update_cred | 默认开启 | **已实现** | ⚠️ 部分 | 缺 old_username, res |
| 605 | rmdir | SANDBOX (默认关闭) | **已实现** | ✅ 基本兼容 | |
| 606 | unlink | SANDBOX (默认关闭) | **已实现** | ✅ 基本兼容 | |
| 607 | usermodehelper | 默认开启 | **已实现** | ⚠️ 部分 | 缺 argv, wait 参数 |
| 608 | write | SANDBOX (默认关闭) | **已实现** | ⚠️ 部分 | 过滤逻辑过于简陋 |
| 610 | udev | 默认开启 | ❌ 未实现 | ❌ 缺失 | USB 设备监控 |
| 611 | privilege_escalation | 自动检测 | ❌ 未实现 | ❌ 缺失 | 提权检测 |
| 700-703 | anti_rootkit | 定时检测 | ❌ 未实现 | ❌ 缺失 | rootkit 检测 |
| - | chmod | 默认开启 | ❌ 未实现 | ❌ 缺失 | 文件权限变更 |

### 3.2 兼容性总结

- **已实现且基本兼容**: 7 个事件 (bind, exit, exit_group, setsid, memfd_create, rmdir, unlink)
- **已实现但部分兼容**: 14 个事件 (字段不完整或行为差异)
- **已实现但有 Bug**: 1 个 (accept)
- **已实现但不兼容**: 1 个 (dns)
- **完全未实现**: 6 个 (create_file, nanosleep, udev, chmod, privilege_escalation, anti_rootkit)

### 3.3 字段完整性问题

多数已实现事件缺失以下字段：

| 缺失字段 | 涉及事件 | 原因 |
|----------|---------|------|
| `argv` | 大部分非 execve 事件 | 需从 /proc 或 BPF map 获取 |
| `exe_hash` | 所有事件 | 需要用户态计算文件 hash |
| `pod_name` | 所有事件 | 需要容器运行时集成 |
| `pid_tree` | 部分事件 | 已在用户态 Go cache 实现，但依赖 cache 命中 |
| `ppid_argv` / `pgid_argv` | 部分事件 | 依赖 ProcTreeCache 命中率 |
| `username` | 部分事件 | 已在 UserCache 实现 |
| `ssh` / `ld_preload` | execve | 需要环境变量解析 |
| `socket_pid` / `socket_argv` | execve | 需要 socket cache 关联 |

---

## 4. 改进建议

### P0 (必须修复 —— 正确性)

1. **修复 pid/tid 反转 Bug**
   - 修改 `helpers.h` 中 `init_event_header` 的 pid/tid 赋值
   - 影响几乎所有事件的核心字段

2. **修复 Accept 事件 Socket 读取错误**
   - 改为 hook `inet_csk_accept` 或 `sys_accept`/`sys_accept4` kretprobe
   - 从返回的 `struct sock *` 读取远端地址

3. **验证并修复 C/Go 结构体对齐**
   - 实际编译 BPF 代码，打印各 struct sizeof
   - 使用 `__attribute__((packed))` 或在 Go 端精确匹配 padding
   - 编写单元测试验证序列化/反序列化的一致性

4. **修复 Connect 事件缺少返回值**
   - 增加 kretprobe 捕获 `security_socket_connect` 返回值
   - 或改为 hook `tcp_v4_connect` / `tcp_v6_connect` 的 kretprobe（与 LKM 一致）

### P1 (高优先级 —— 功能完整性)

5. **实现 create_file 事件 (ID 602)**
   - LKM 默认启用，很多安全规则依赖此事件
   - Hook `security_inode_create` 或类似入口

6. **实现 DNS query 解析**
   - 从 `msghdr` 或 `sk_buff` 中读取 DNS 报文
   - 解析 QNAME 填充到 `dns_event_t.query` 字段
   - 或改用 `cgroup/skb` 方式截获 DNS 包

7. **实现事件过滤机制**
   - 启用已定义但未使用的 `pid_filter` 和 `comm_filter` maps
   - 在所有 BPF hook 开头添加过滤检查
   - 提供用户态接口动态更新过滤规则（对标 LKM 的 exe/argv whitelist）

8. **给 security_file_open 增加过滤**
   - 默认关闭或添加路径前缀过滤
   - 否则生产环境性能不可接受

9. **完善 execve 事件缺失字段**
   - 解析环境变量获取 `SSH_CONNECTION` → `ssh` 字段
   - 解析 `LD_PRELOAD` → `ld_preload` 字段
   - 计算 exe 文件 hash → `exe_hash` 字段

### P2 (中优先级 —— 功能增强)

10. **实现 Privilege Escalation 检测 (ID 611)**
    - 对标 LKM 的 `commit_creds` + old/new uid 比较逻辑
    - 当前 `update_cred` 事件仅记录变更，未做提权判断

11. **实现 Anti-Rootkit 检测 (IDs 700-703)**
    - 系统调用表完整性检查
    - 内核模块隐藏检测
    - IDT 中断表劫持检测
    - /proc 文件隐藏检测
    - 可通过定时 BPF 程序或用户态扫描实现

12. **实现 UDEV 事件 (ID 610)**
    - USB 设备插入/拔出监控
    - Hook `usb_register_dev` 或 uevent 相关入口

13. **实现 chmod 事件**
    - Hook `security_inode_setattr` 或 `chmod` 系统调用

14. **完善 vfs_write 过滤**
    - 使用 BPF map 存储监控路径列表
    - 支持用户态动态配置
    - 覆盖 `/etc/`, `/root/.ssh/`, `/var/spool/cron/` 等敏感路径

15. **Link 事件同时覆盖 hard link**
    - 当前仅 hook `security_inode_symlink`
    - 需增加 `security_inode_link` hook

### P3 (低优先级 —— 工程质量)

16. **消除 Manager 双重转换**
    - `processEvents` 中同时调用 `ConvertToRecord` 和 `Convert`，每个事件转换两次
    - 应选择一种输出路径或统一转换

17. **添加 Cache 定期清理**
    - `ProcTreeCache`, `SocketCache`, `UserCache` 的 `Cleanup()` 方法从未被调用
    - 需要在 Manager 中启动定时清理 goroutine

18. **优化 ProcTreeCache 淘汰策略**
    - 当前 `evictOldest()` 是 O(n) 全表扫描
    - 建议改用 LRU 链表或 `container/heap`

19. **改用 Ring Buffer 替代 Perf Buffer**
    - 内核 5.8+ 支持 `BPF_MAP_TYPE_RINGBUF`
    - 比 perf event buffer 更高效，无 per-CPU 碎片化问题
    - 应保留 perf buffer 作为低版本内核的 fallback

20. **增加指标暴露和日志**
    - 当前仅通过 `fmt.Printf` 输出警告
    - 应集成结构化日志 (zerolog/zap)
    - 暴露 Prometheus 指标：event rate, lost events, parse errors, cache hit rate

21. **增加集成测试**
    - 编写 BPF 程序加载/attach 测试
    - 编写事件触发→解析→转换的端到端测试
    - 使用 `bpf2go -test` 生成测试代码

22. **完善 bpf2go 生成流程**
    - 当前 `loadEmbeddedSpec()` 是 placeholder
    - 完善 `go generate` → 编译 → 嵌入的 CI 流程
    - `loader_linux.go` 需在生成后切换到实际 embedded 加载

23. **补充 Usermodehelper 事件字段**
    - 当前缺少 `argv` 和 `wait` 参数
    - Schema 定义了这些字段但 BPF 端未采集

24. **Mount 事件缺少 fstype**
    - Schema 中包含 `fstype` 字段
    - BPF hook `security_sb_mount` 有 `type` 参数但未采集

25. **增加 BPF 程序的 BTF 和 CO-RE 兼容性测试**
    - 在不同内核版本上测试 BPF_CORE_READ 的兼容性
    - 特别关注 `start_boottime` vs `start_time` 等字段的存在性

---

## 5. 总结

### 5.1 整体评价

driver_ebpf 项目的架构设计合理，模块划分清晰（loader/reader/adapter/cache/manager），代码组织符合 Go 项目规范。BPF 程序覆盖了大部分核心安全事件，schema 与原 LKM 保持了一致的 Event ID 定义。

但当前代码存在几个严重的正确性问题（pid/tid 反转、accept socket 读取错误、结构体对齐风险），**在修复这些 Bug 之前不应上线生产环境**。

### 5.2 完成度估计

| 维度 | 完成度 | 说明 |
|------|--------|------|
| 架构/框架 | 85% | 核心管线完整，缺少日志/监控/配置热更新 |
| BPF 程序 | 60% | 核心钩子已有但有 Bug，缺少 6 类事件，过滤未实现 |
| 事件解析 | 70% | 结构体定义完整但存在对齐风险，padding 待验证 |
| 协议转换 | 75% | Schema 对齐了 Rust 版本，但多数字段为空 |
| 缓存/增强 | 60% | 基本框架有了，但缺少清理机制和效率优化 |
| 测试 | 10% | 仅有 Encoder 单元测试，无集成测试 |
| 生产就绪 | 30% | 需要修复 P0 Bug + 补充核心功能 + 性能验证 |

### 5.3 建议下一步

1. 修复 3 个 P0 Bug（pid/tid, accept, struct alignment）
2. 实际编译运行 BPF 程序，验证所有事件的数据正确性
3. 实现 create_file 和 DNS query 解析
4. 添加事件过滤机制
5. 在测试环境对比 LKM 与 eBPF 版本的事件输出差异
