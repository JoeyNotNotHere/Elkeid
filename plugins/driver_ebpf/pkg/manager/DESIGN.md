# Manager 模块设计

## 概述

`pkg/manager` 是 Elkeid eBPF Driver 的核心管理器，负责整合所有组件并管理生命周期。

## 文件说明

| 文件 | 职责 |
|------|------|
| `manager.go` | 主管理器，协调 BPF 加载、事件处理、协议转换 |

## 架构

```
┌─────────────────────────────────────────────────────────────────┐
│                         Manager                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Components                             │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────┐  │   │
│  │  │ Loader  │  │ Reader  │  │ Caches  │  │  Converter  │  │   │
│  │  │ (BPF)   │  │ (Perf)  │  │         │  │  (Native)   │  │   │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────────┘  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                  Output Channel                           │   │
│  │              (Elkeid 协议数据)                            │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## 主要流程

### 1. 初始化

```go
mgr, err := manager.NewManager()
// 或自定义配置
mgr, err := manager.NewManagerWithConfig(&manager.Config{
    BPFObjectPath:  "/path/to/elkeid.bpf.o",
    PerfBufferSize: 128,
    EventChanSize:  1000,
    OutputChanSize: 1000,
})
```

初始化过程:
1. 创建 ProcTreeCache, SocketCache, UserCache
2. 创建 NativeConverter
3. 准备 Output channel

### 2. 启动

```go
ctx, cancel := context.WithCancel(context.Background())
err := mgr.Start(ctx)
```

启动过程:
1. 加载 BPF 对象文件
2. 设置 BPF 配置 (root_pid_ns)
3. Attach 所有 BPF 程序
4. 启动事件读取器
5. 启动事件处理协程

### 3. 事件处理循环

```
Reader.Events() → updateCaches() → Converter.Convert() → Output channel
```

- 从 Perf buffer 读取原始事件
- 更新内部缓存 (进程树、socket)
- 转换为 Elkeid 协议格式
- 发送到 Output channel

### 4. 停止

```go
mgr.Stop()
```

停止过程:
1. 停止事件读取器
2. 等待处理协程结束
3. 关闭 BPF 加载器
4. 关闭 Output channel

## 配置说明

| 参数 | 默认值 | 说明 |
|------|--------|------|
| BPFObjectPath | `/usr/local/share/elkeid/bpf/elkeid.bpf.o` | BPF 对象文件路径 |
| PerfBufferSize | 128 | Perf buffer 页数 |
| EventChanSize | 1000 | 内部事件 channel 大小 |
| OutputChanSize | 1000 | 输出 channel 大小 |

## 使用示例

```go
package main

import (
    "context"
    "driver_ebpf/pkg/manager"
    "os/signal"
    "syscall"
)

func main() {
    mgr, err := manager.NewManager()
    if err != nil {
        panic(err)
    }

    ctx, cancel := signal.NotifyContext(context.Background(), 
        syscall.SIGINT, syscall.SIGTERM)
    defer cancel()

    if err := mgr.Start(ctx); err != nil {
        panic(err)
    }

    // 消费输出
    go func() {
        for data := range mgr.Output() {
            // 发送到 Elkeid Agent
            sendToAgent(data)
        }
    }()

    <-ctx.Done()
    mgr.Stop()
}
```

## 统计信息

```go
stats := mgr.Stats()
fmt.Printf("Total: %d, Lost: %d, Errors: %d\n", 
    stats.TotalEvents, stats.LostEvents, stats.ParseErrors)
```
