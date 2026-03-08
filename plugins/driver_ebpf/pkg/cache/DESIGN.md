# Cache 模块设计

## 概述

`pkg/cache` 提供内存缓存层，用于补充 BPF 无法直接采集的字段，如 `pid_tree`、`username`、socket 关联等。

## 文件说明

| 文件 | 职责 |
|------|------|
| `proctree.go` | 进程树缓存，用于构建 pid_tree 字符串 |
| `socket.go` | Socket 连接缓存，实现进程-连接关联 |
| `user.go` | 用户名缓存，UID → Username 映射 |

## 各缓存详解

### ProcTreeCache (proctree.go)

**用途**: 构建 Elkeid 的 `pid_tree` 字段，格式为 `pid.comm<pid.comm<...`

**主要方法**:
- `NewProcTreeCache(maxSize, ttl)` - 创建缓存
- `Update(*ProcInfo)` - 更新进程信息
- `Get(pid)` - 获取进程信息
- `Delete(pid)` - 删除进程
- `BuildPidTree(pid, limit)` - 构建 pid_tree 字符串
- `GetRootPidNs()` - 获取根 PID 命名空间 ID

**数据结构**:
```go
type ProcInfo struct {
    PID       int
    PPID      int
    PGID      int
    SID       int
    UID       int
    Comm      string
    Exe       string
    Argv      string
    TTY       string
    StartTime int64
}
```

### SocketCache (socket.go)

**用途**: 实现 Elkeid LKM 的 `get_process_socket` 逻辑，关联 execve 与网络连接

**主要方法**:
- `NewSocketCache(maxPerPID, ttl)` - 创建缓存
- `Add(*SocketInfo)` - 添加 socket
- `Remove(pid)` - 移除 PID 的所有 socket
- `FindProcessSocket(pid, procTree, limit)` - 查找进程关联的 socket

**查找逻辑** (模拟 LKM):
1. 从当前 PID 开始
2. 检查是否有活跃的 socket 连接
3. 如果没有，向上遍历父进程
4. 最多遍历 `limit` 层
5. 返回找到的 socket 和拥有它的 PID (socket_pid)

### UserCache (user.go)

**用途**: 缓存 UID 到用户名的映射，避免频繁调用 `user.LookupId`

**主要方法**:
- `NewUserCache(maxSize, ttl)` - 创建缓存
- `GetUsername(uid)` - 获取用户名 (自动查找并缓存)

## 使用示例

```go
// 初始化缓存
procTree := cache.NewProcTreeCache(10000, 30*time.Minute)
socketCache := cache.NewSocketCache(100, 5*time.Minute)
userCache := cache.NewUserCache(1000, 1*time.Hour)

// 更新进程信息 (execve 事件)
procTree.Update(&cache.ProcInfo{
    PID:  1234,
    PPID: 1000,
    Comm: "bash",
    Exe:  "/bin/bash",
})

// 构建 pid_tree
pidTree := procTree.BuildPidTree(1234, 10)
// 结果: "1234.bash<1000.sshd<1.systemd"

// 获取用户名
username := userCache.GetUsername(1000)
// 结果: "joey"

// 查找关联 socket
sockInfo, socketPID := socketCache.FindProcessSocket(1234, procTree, 4)
```

## 内存管理

所有缓存都有:
- **maxSize**: 最大条目数，超过时自动淘汰最旧条目
- **ttl**: 条目过期时间
- **Cleanup()**: 手动清理过期条目

建议定期调用 Cleanup() 或依赖 LRU 淘汰机制。
