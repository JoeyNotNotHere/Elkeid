# Elkeid eBPF Driver 设计文档

## 概述

`driver-ebpf` 是 Elkeid 主机入侵检测系统的 eBPF 版本内核数据采集插件，替代原有的 Linux Kernel Module (LKM) 实现。

## 目标

1. **功能对等**: 实现与 LKM 版本相同的事件采集能力
2. **兼容性好**: 使用 eBPF CO-RE 技术，无需为每个内核版本编译
3. **可维护性**: 自维护 BPF C 代码，不依赖外部运行时

## 架构

```
┌────────────────────────────────────────────────────────────────────┐
│                          driver-ebpf                                │
├────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐        │
│  │     main.go    │  │  pkg/manager   │  │  pkg/adapter   │        │
│  │  程序入口       │──│  生命周期管理   │──│  协议编码      │        │
│  └────────────────┘  └────────────────┘  └────────────────┘        │
│                              │                    │                 │
│                              ▼                    │                 │
│                     ┌────────────────┐            │                 │
│                     │  pkg/loader    │            │                 │
│                     │  BPF 加载/读取  │            │                 │
│                     └────────────────┘            │                 │
│                              │                    │                 │
│                              │                    ▼                 │
│                              │           ┌────────────────┐        │
│                              │           │  pkg/cache     │        │
│                              │           │  进程树/Socket │        │
│                              │           └────────────────┘        │
│                              │                                      │
├──────────────────────────────┼──────────────────────────────────────┤
│                              ▼                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                          bpf/                                 │  │
│  │  elkeid.bpf.c  -  19 个事件 hooks                             │  │
│  │  types.h       -  事件结构体定义                               │  │
│  │  maps.h        -  BPF maps 定义                               │  │
│  │  common/helpers.h  -  工具函数                                 │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                              │                                      │
│                    ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─  (内核边界)               │
│                              │                                      │
│                    ┌─────────┴─────────┐                           │
│                    │   Linux Kernel    │                           │
│                    │  tracepoints,     │                           │
│                    │  kprobes, etc.    │                           │
│                    └───────────────────┘                           │
└────────────────────────────────────────────────────────────────────┘
```

## 目录结构

```
plugins/driver-ebpf/
├── DESIGN.md              # 本文档
├── WORK_LOG.md            # 开发日志
├── Makefile               # 根编译脚本
├── main.go                # 程序入口
├── go.mod                 # Go 依赖
│
├── bpf/                   # BPF C 代码
│   ├── DESIGN.md          # BPF 层设计
│   ├── Makefile           # BPF 编译脚本
│   ├── elkeid.bpf.c       # 主 BPF 程序 (19 hooks)
│   └── common/            # 公共头文件
│       ├── vmlinux.h      # 内核类型定义 (BTF)
│       ├── types.h        # 事件结构体
│       ├── maps.h         # BPF maps
│       └── helpers.h      # 工具函数
│
├── pkg/
│   ├── adapter/           # 协议适配层
│   │   ├── DESIGN.md
│   │   ├── encoder.go     # Varint+TLV 编码
│   │   ├── schema.go      # 事件字段定义
│   │   └── converter_native.go  # 事件转换
│   │
│   ├── cache/             # 缓存层
│   │   ├── DESIGN.md
│   │   ├── proctree.go    # 进程树缓存
│   │   ├── socket.go      # Socket 缓存
│   │   └── user.go        # 用户名缓存
│   │
│   ├── loader/            # BPF 加载层
│   │   ├── DESIGN.md
│   │   ├── loader.go      # BPF 程序加载
│   │   ├── events.go      # Go 事件结构体
│   │   └── reader.go      # Perf buffer 读取
│   │
│   └── manager/           # 管理器
│       ├── DESIGN.md
│       └── manager.go     # 生命周期管理
│
└── doc/                   # 参考文档
    ├── EVENTS_SCHEMA.md   # 事件字段定义
    ├── GAP_ANALYSIS.md    # LKM 功能差距分析
    ├── PROTOCOL.md        # Elkeid 协议规范
    └── BPF_MIGRATION.md   # BPF 迁移技术文档
```

## 采集事件

| 类别 | 事件 | Hook 类型 |
|------|------|-----------|
| 进程 | execve, exit, exit_group | raw_tracepoint |
| 网络 | connect, accept, bind | kprobe |
| 文件 | open, rename, link, unlink, mount | kprobe |
| 安全 | ptrace, prctl, mprotect, memfd_create | tracepoint |
| 内核 | module_load, usermodehelper | kprobe |
| 凭证 | update_cred (commit_creds) | kprobe |

## 数据流

```
1. BPF 程序在内核中捕获事件
   ↓
2. 事件通过 Perf Buffer 发送到用户空间
   ↓
3. pkg/loader 解析事件为 Go 结构体
   ↓
4. pkg/manager 更新 cache (进程树、Socket)
   ↓
5. pkg/adapter 转换为 Elkeid 协议格式
   ↓
6. 发送给 Elkeid Agent
```

## 与 LKM 版本差异

| 功能 | LKM | eBPF | 说明 |
|------|-----|------|------|
| 内核版本支持 | 需要逐版本编译 | CO-RE 一次编译 | eBPF 更易部署 |
| 运行权限 | root + 内核模块签名 | root + CAP_BPF | eBPF 更安全 |
| stdout/stdin | 直接内核访问 | BPF 采集 | 已实现 |
| socket_pid | 内核遍历 | Go 缓存 | 已实现 |
| pid_tree | 内核构建 | Go 缓存 | 已实现 |
| DNS | 内核解析 | cgroup_skb | 待实现 |

---

## 编译架构对比

### LKM 版本编译流程

原 LKM 版本采用**分离编译 + CDN 分发**模式：

```
┌─────────────────────────────────────────────────────────────────┐
│                    LKM Driver 编译/部署流程                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  内核模块 (hids_driver.ko)          用户态程序 (Rust)            │
│  ━━━━━━━━━━━━━━━━━━━━━━━            ━━━━━━━━━━━━━━━━━━           │
│                                                                  │
│  [独立仓库/CI系统]                   [plugins/driver/]           │
│       │                                   │                      │
│       │ 每个内核版本                       │ cargo build         │
│       │ 单独编译                           │                      │
│       ▼                                   ▼                      │
│  ┌─────────────────┐              ┌─────────────────┐           │
│  │ hids_driver_    │              │    driver       │           │
│  │ 1.7.0.6_        │              │   (可执行文件)   │           │
│  │ 5.4.0-xxx_      │              └────────┬────────┘           │
│  │ amd64.ko        │                       │                     │
│  └────────┬────────┘                       │ 运行时              │
│           │                                │                     │
│           │ 上传到 CDN                      │                     │
│           ▼                                ▼                     │
│  ┌─────────────────┐              ┌─────────────────┐           │
│  │ lf3-elkeid.     │ ◄───下载──── │  下载 .ko       │           │
│  │ bytetos.com/ko/ │              │  insmod 加载    │           │
│  └─────────────────┘              │  读 /proc/...   │           │
│                                   └─────────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

**LKM 版本的问题**:
- 内核模块需要为每个内核版本单独编译
- 运行时需要网络下载 .ko 文件
- 新内核发布需要重新编译并上传 CDN
- 部署复杂度高

### eBPF 版本编译优势

eBPF CO-RE (Compile Once - Run Everywhere) 解决了上述问题：

| 对比项 | LKM | eBPF (CO-RE) |
|--------|-----|--------------|
| 编译次数 | 每个内核版本一次 | **一次** |
| 分发方式 | CDN + 运行时下载 | **嵌入二进制** |
| 部署复杂度 | 需要网络下载 .ko | **单文件部署** |
| 新内核支持 | 需要重新编译发布 | **自动兼容** |
| 编译环境 | 需要内核头文件 | 只需 vmlinux.h |

---

## eBPF 编译方案

### 方案对比

| 方案 | 描述 | 优点 | 缺点 |
|------|------|------|------|
| 分离编译 | BPF 和 Go 独立编译 | 简单 | 部署需要两个文件 |
| go:embed | 手动嵌入 .o 文件 | 单文件 | 需要手动管理 |
| **bpf2go** | cilium/ebpf 官方工具 | 自动化、类型安全 | 需要学习 |

### 推荐方案: bpf2go

`bpf2go` 是 cilium/ebpf 官方推荐的编译方案，自动生成类型安全的 Go 代码。

```
┌─────────────────────────────────────────────────────────────────┐
│                   eBPF Driver 编译流程 (bpf2go)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Step 1: go generate (调用 bpf2go)                               │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━                               │
│                                                                  │
│     ┌─────────────────┐                                         │
│     │ elkeid.bpf.c    │                                         │
│     │ types.h         │                                         │
│     │ maps.h          │                                         │
│     │ helpers.h       │                                         │
│     └────────┬────────┘                                         │
│              │ clang (bpf2go 调用)                               │
│              ▼                                                   │
│     ┌─────────────────────────────────────┐                     │
│     │ elkeid_bpfel.o   (little endian)    │  BPF 字节码         │
│     │ elkeid_bpfeb.o   (big endian)       │                     │
│     │ elkeid_bpfel.go  (生成的 Go 代码)    │  类型绑定           │
│     │ elkeid_bpfeb.go                     │                     │
│     └─────────────────────────────────────┘                     │
│                                                                  │
│  Step 2: go build                                                │
│  ━━━━━━━━━━━━━━━━                                                │
│                                                                  │
│     ┌─────────────────┐     ┌─────────────────┐                 │
│     │ main.go         │     │ elkeid_bpfel.go │                 │
│     │ pkg/manager     │  +  │ (内嵌 .o 字节码) │                 │
│     │ pkg/adapter     │     └─────────────────┘                 │
│     │ pkg/loader      │            │                             │
│     │ pkg/cache       │            │                             │
│     └────────┬────────┘            │                             │
│              │                     │                             │
│              └──────────┬──────────┘                             │
│                         │ go build                               │
│                         ▼                                        │
│              ┌─────────────────────┐                             │
│              │    driver-ebpf      │  单一可执行文件              │
│              │  (内嵌 BPF 字节码)   │  约 10-15 MB               │
│              └─────────────────────┘                             │
│                         │                                        │
│                         │ 部署到任意 Linux 5.4+                   │
│                         ▼                                        │
│              ┌─────────────────────┐                             │
│              │     任意服务器       │  无需下载额外文件            │
│              └─────────────────────┘                             │
└─────────────────────────────────────────────────────────────────┘
```

### 实现步骤

#### 1. 安装 bpf2go

```bash
go install github.com/cilium/ebpf/cmd/bpf2go@latest
```

#### 2. 添加 go:generate 指令

在 `pkg/loader/gen.go` 中添加:

```go
package loader

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I../../bpf" -target amd64,arm64 elkeid ../../bpf/elkeid.bpf.c
```

#### 3. 生成代码

```bash
cd pkg/loader
go generate
# 生成:
#   elkeid_bpfel.go  (amd64)
#   elkeid_bpfel.o
#   elkeid_bpfeb.go  (arm64)
#   elkeid_bpfeb.o
```

#### 4. 修改 loader.go 使用生成的代码

```go
// 原来: 从文件加载
spec, err := ebpf.LoadCollectionSpec(cfg.BPFObjectPath)

// 改为: 使用嵌入的字节码
spec, err := loadElkeid()  // bpf2go 生成的函数
```

#### 5. 一键编译

```bash
# 完整编译流程
go generate ./...  # 编译 BPF 并生成 Go 代码
go build -o driver-ebpf .  # 编译最终可执行文件
```

### 目录结构 (使用 bpf2go 后)

```
plugins/driver-ebpf/
├── main.go
├── go.mod
├── bpf/
│   ├── elkeid.bpf.c      # BPF 源码
│   ├── types.h
│   ├── maps.h
│   └── common/helpers.h
│
└── pkg/loader/
    ├── gen.go            # go:generate 指令
    ├── loader.go         # 使用生成的代码加载 BPF
    ├── elkeid_bpfel.go   # [生成] amd64 类型绑定
    ├── elkeid_bpfel.o    # [生成] amd64 BPF 字节码
    ├── elkeid_bpfeb.go   # [生成] arm64 类型绑定
    └── elkeid_bpfeb.o    # [生成] arm64 BPF 字节码
```

---

## 当前编译方式 (临时)

在实现 bpf2go 之前，使用分离编译:

### 编译 BPF

```bash
cd bpf
make
# 生成 elkeid.bpf.o
```

### 编译 Go

```bash
go build -o driver-ebpf .
```

### 运行

```bash
# 需要将 .o 文件放到指定位置
sudo mkdir -p /usr/local/share/elkeid/bpf/
sudo cp bpf/elkeid.bpf.o /usr/local/share/elkeid/bpf/

# 运行
sudo ./driver-ebpf
```

---

## 配置

| 参数 | 默认值 | 说明 |
|------|--------|------|
| BPFObjectPath | /usr/local/share/elkeid/bpf/elkeid.bpf.o | BPF 对象文件路径 (分离编译时) |
| PerfBufferSize | 128 | Perf buffer 页数 |
| EventChanSize | 1000 | 事件 channel 大小 |
| OutputChanSize | 1000 | 输出 channel 大小 |

## 编译环境依赖

### 开发环境 (编译时)

- Go 1.21+
- clang 12+ (BPF 编译)
- bpftool (生成 vmlinux.h，可选)
- Linux 头文件 (可选，CO-RE 使用 vmlinux.h)

### 运行环境

- Linux Kernel 5.4+ (with BTF support)
- root 权限 或 CAP_BPF + CAP_PERFMON

### 检查 BTF 支持

```bash
# 检查内核是否支持 BTF
ls -la /sys/kernel/btf/vmlinux

# 检查内核配置
grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
```

## CI/CD 集成

```yaml
# .github/workflows/build.yml 示例
jobs:
  build:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y clang llvm
      
      - name: Generate BPF
        run: go generate ./...
      
      - name: Build
        run: go build -o driver-ebpf .
      
      - name: Upload artifact
        uses: actions/upload-artifact@v3
        with:
          name: driver-ebpf
          path: driver-ebpf
```
