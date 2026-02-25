# Go BPF Loader 设计文档

## 1. 架构概览

```
┌─────────────────────────────────────────────────────────────┐
│                    BPF 程序 (Kernel)                        │
│  elkeid.bpf.c → elkeid.bpf.o                               │
│  - 19 个 hooks (execve, exit, connect, ...)                │
│  - 事件通过 perf buffer 发送到用户态                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ Perf Buffer
┌─────────────────────────────────────────────────────────────┐
│                    pkg/loader/                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ loader.go   │  │ events.go   │  │ reader.go   │         │
│  │ - Load BPF  │  │ - Go 事件   │  │ - 读取 perf │         │
│  │ - Attach    │  │   结构体    │  │ - 解析事件  │         │
│  │ - Close     │  │ - 与 C 对应 │  │ - 回调分发  │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ Event Channel
┌─────────────────────────────────────────────────────────────┐
│                    pkg/adapter/                             │
│  converter_native.go (新)                                   │
│  - 接收 loader.Event (我们自己的结构体)                     │
│  - 转换为 Elkeid 二进制协议                                 │
│  - 使用 cache 层补充字段                                    │
└─────────────────────────────────────────────────────────────┘
```

## 2. 事件结构体对应关系

### BPF C 侧 (types.h)
```c
typedef struct event_header {
    u64 timestamp;
    u32 event_id;
    u32 pid, tid, ppid, uid, gid, pgid, sid, pid_ns;
    char comm[16];
} event_header_t;

typedef struct execve_event {
    event_header_t header;
    char exe[256], cwd[256], stdin_path[256], stdout_path[256];
    char tty[32], argv[256];
    int argc, ret;
    u32 stdin_type, stdout_type;
} execve_event_t;
```

### Go 侧 (events.go)
```go
type EventHeader struct {
    Timestamp uint64
    EventID   uint32
    PID       uint32
    TID       uint32
    // ... 与 C 结构体字段对齐
}

type ExecveEvent struct {
    Header     EventHeader
    Exe        [256]byte
    Cwd        [256]byte
    StdinPath  [256]byte
    StdoutPath [256]byte
    TTY        [32]byte
    Argv       [256]byte
    Argc       int32
    Ret        int32
    StdinType  uint32
    StdoutType uint32
}
```

## 3. 文件职责

### loader.go
- `type Loader struct` - BPF 加载器主结构
- `func NewLoader(bpfPath string) (*Loader, error)` - 加载 BPF 对象文件
- `func (l *Loader) Attach() error` - 附加所有 BPF 程序到 hooks
- `func (l *Loader) Close() error` - 清理资源

### events.go
- 定义所有事件的 Go 结构体
- 与 BPF C 代码中的结构体一一对应
- 提供 `ParseEvent(data []byte) (Event, error)` 解析函数

### reader.go
- `type EventReader struct` - Perf buffer 读取器
- `func (r *EventReader) Start(ctx context.Context)` - 开始读取事件
- `func (r *EventReader) Events() <-chan Event` - 事件通道

## 4. 依赖

- `github.com/cilium/ebpf` - BPF 程序加载
- `github.com/cilium/ebpf/link` - 程序附加
- `github.com/cilium/ebpf/perf` - Perf buffer 读取

## 5. 与 Converter 对接

### 方案 A: 新建 converter_native.go (推荐)
保留原有 `converter.go` (Tracee 兼容)，新建处理我们自己事件的转换器。

### 方案 B: 修改 converter.go
用接口抽象事件结构，同时支持 Tracee 和 Native 事件。

选择 **方案 A**，更清晰，不影响原有代码。

## 6. 实现顺序

1. `events.go` - 定义事件结构体
2. `loader.go` - BPF 加载器
3. `reader.go` - 事件读取器
4. `converter_native.go` - Native 事件转换器
5. 集成测试
