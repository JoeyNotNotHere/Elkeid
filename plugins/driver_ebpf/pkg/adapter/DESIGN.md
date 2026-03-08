# Adapter 模块设计

## 概述

`pkg/adapter` 负责将 BPF 采集的事件转换为 Elkeid 二进制协议格式。

## 文件说明

| 文件 | 职责 |
|------|------|
| `encoder.go` | 实现 Elkeid 二进制协议编码 (Varint + TLV) |
| `schema.go` | 定义事件 ID 和字段名称映射 |
| `converter_native.go` | 将 BPF 原生事件转换为 Elkeid 协议 |
| `converter.go` | (已废弃) Tracee 事件转换器，仅作参考 |

## 架构

```
┌─────────────────────────────────────────────────┐
│              loader.Event (BPF 事件)            │
└─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│           NativeConverter.Convert()             │
│  - 提取事件字段                                 │
│  - 通过 cache 补充 pid_tree, username 等        │
│  - 调用 Encoder 编码                            │
└─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│              Encoder.Encode()                   │
│  - 根据 Schema 获取字段名                       │
│  - 编码为 Varint + TLV 格式                     │
└─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│            []byte (Elkeid 协议数据)             │
└─────────────────────────────────────────────────┘
```

## Elkeid 协议格式

```
[4 bytes Length (LE)] [Payload]

Payload:
  [DataType (Varint)]
  [0x10] [Timestamp (Varint)]
  [0x1a] [Map Length (Varint)] [Map Entries...]

Map Entry:
  [0x0a] [Entry Length (Varint)]
    [0x0a] [Key Length (Varint)] [Key Bytes]
    [0x12] [Value Length (Varint)] [Value Bytes]
```

## 使用示例

```go
// 创建转换器
converter := adapter.NewNativeConverter(procTree, socketCache, userCache)

// 转换事件
data, err := converter.Convert(event)
if err != nil {
    log.Printf("conversion error: %v", err)
}

// data 可直接发送给 Elkeid Agent
```

## Schema 说明

`schema.go` 定义了每个事件的字段顺序，必须与 `plugins/driver/src/transformer/schema.rs` 保持一致。

常用事件字段索引 (0-11 为公共字段):
- 0: uid
- 1: exe
- 2: pid
- 3: ppid
- 4: pgid
- 5: tgid
- 6: sid
- 7: comm
- 8: nodename
- 9: sessionid
- 10: pns
- 11: root_pns
