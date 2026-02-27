# Elkeid eBPF Driver 设计文档

## 概述

`driver_ebpf` 是 Elkeid 主机入侵检测系统的 eBPF 版本内核数据采集插件，替代原有的 Linux Kernel Module (LKM) 实现。

---

## 技术选型说明：为什么选择 cilium/ebpf 而非 Tracee

### 背景

原技术调研方案预期：
- **Go 层**：复用 Tracee 项目使用的 [libbpfgo](https://github.com/aquasecurity/libbpfgo) 库来加载 BPF 程序
- **BPF 层**：自己编写 C 代码，参考/复制 Tracee 的 BPF 实现，没有的 hook 自己写

经过实际开发评估，**BPF 层方案保持不变**，Go 层选择使用 **cilium/ebpf** 替代 libbpfgo。

### 方案对比

| 对比维度 | 方案 A: libbpfgo (原方案) | 方案 B: cilium/ebpf (当前方案) |
|---------|--------------------------|-------------------------------|
| **Go BPF 加载库** | libbpfgo (CGO，Tracee 使用) | cilium/ebpf (纯 Go) |
| **BPF C 代码** | 自己写（参考/复制 Tracee） | 自己写（参考 Tracee） |
| **CGO 依赖** | ✅ 需要 | ❌ 不需要 |
| **运行时依赖** | libbpf.so, libelf.so, zlib | 无 |
| **交叉编译** | 困难 (需要目标平台 C 工具链) | 简单 (`GOOS=linux go build`) |
| **间接依赖数** | ~50 (libbpfgo 依赖链) | ~10 |
| **部署方式** | 需确保动态库存在 | 单文件部署 |
| **Go 层代码量** | 较少（复用 libbpfgo 封装） | 较多（需自己封装） |

**关键说明**：两个方案的 BPF C 代码都是自己维护的，区别在于 **Go 层用什么库来加载和管理 BPF 程序**。

### 选择 cilium/ebpf 的核心原因

#### 1. 消除 CGO 依赖

CGO (C Go 交互) 带来的问题：

```
编译时：
├─ 需要 gcc/clang C 编译器
├─ 需要 libbpf-dev, libelf-dev, zlib-dev 头文件
└─ Mac 开发者无法直接编译 Linux 版本 (需要交叉编译工具链)

运行时：
├─ 需要 libbpf.so 动态库 (或静态链接增加 10MB+)
├─ 不同发行版库版本可能不兼容
└─ 目标机器需要安装依赖

调试时：
├─ C 代码崩溃难以定位 (无 Go 堆栈)
├─ 内存泄漏难以检测 (Go GC 不管理 C 内存)
└─ 混合调试复杂
```

cilium/ebpf 是**纯 Go 实现**，直接通过 `syscall` 与内核 BPF 子系统交互，无需 CGO：

```go
// cilium/ebpf 内部实现 (简化)
func loadProgram(bytecode []byte) {
    syscall.Syscall(SYS_BPF, BPF_PROG_LOAD, ...)  // 纯 Go
}
```

#### 2. 单文件部署

```bash
# 当前方案：部署一个文件
scp driver_ebpf server:/usr/local/bin/
ssh server "sudo /usr/local/bin/driver_ebpf"

# Tracee 方案：需要确保依赖存在
scp driver_ebpf server:/usr/local/bin/
ssh server "sudo apt install -y libbpf0 libelf1 zlib1g"  # 或携带动态库
ssh server "sudo /usr/local/bin/driver_ebpf"
```

#### 3. 更轻量的依赖链

```
libbpfgo 依赖链：
├─ github.com/aquasecurity/libbpfgo
│   ├─ CGO → libbpf (C 库)
│   │        ├─ libelf
│   │        └─ zlib
│   └─ 其他 Go 依赖...
│
│ 编译时需要: gcc, libbpf-dev, libelf-dev, zlib-dev
│ 运行时需要: libbpf.so, libelf.so, zlib.so (或静态链接)

cilium/ebpf 依赖链：
├─ github.com/cilium/ebpf
│   └─ golang.org/x/sys (标准库扩展)
│
│ 编译时需要: 无额外依赖
│ 运行时需要: 无
```

#### 4. 避免 libbpfgo 版本问题

```
libbpfgo 的已知问题：
├─ 版本与 libbpf C 库版本强绑定
├─ 不同 Linux 发行版 libbpf 版本不一致
├─ 静态链接时二进制增大 10MB+
└─ CGO 构建在某些环境下不稳定
```

#### 5. 业界趋势

**Go 语言 eBPF 项目的库选择**：

| 项目 | 语言 | BPF 库 |
|------|------|--------|
| Cilium (网络) | Go | cilium/ebpf ✅ |
| Tetragon (安全) | Go | cilium/ebpf ✅ |
| Pixie (观测) | Go | cilium/ebpf ✅ |
| Parca (性能分析) | Go | cilium/ebpf ✅ |
| Tracee (安全) | Go | libbpfgo (CGO) |

**非 Go 项目参考**（不适用于我们）：

| 项目 | 语言 | BPF 库 |
|------|------|--------|
| Falco | C++ | libbpf (C 库) |
| bcc | Python/C++ | libbcc |

cilium/ebpf 已成为 **Go 生态**中 eBPF 开发的事实标准。

### 关于"BPF 代码在内核运行的安全性"

无论使用哪种方案，BPF 代码都在内核执行。但 eBPF 有**验证器 (Verifier)** 保护：

```
BPF 程序加载流程：
                    ┌─────────────────────┐
用户提交 BPF 代码 ──►│   内核 BPF 验证器    │
                    │  ├─ 检查无限循环      │
                    │  ├─ 检查内存越界      │
                    │  ├─ 检查空指针        │
                    │  └─ 限制可调用函数    │
                    └──────────┬──────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
        验证通过                            验证失败
              │                                 │
              ▼                                 ▼
    ┌─────────────────┐              ┌─────────────────┐
    │ 加载到 BPF VM   │              │ 拒绝加载        │
    │ 安全执行        │              │ 返回错误        │
    └─────────────────┘              └─────────────────┘
```

BPF 验证器确保了**即使 BPF 代码有 bug，也不会导致内核崩溃**——最多是验证失败无法加载。这比 LKM 内核模块安全得多。

### 与原技术调研方案的关系

原方案意图：
> "复用 Tracee 项目的 client 端代码（libbpfgo 加载库），内核层 BPF 代码如果 Tracee 有就复制过来，没有就自己写 hook"

```
原方案架构：
┌─────────────────────────────────────┐
│  Go 层: libbpfgo (复用 Tracee 用的) │  ← CGO
├─────────────────────────────────────┤
│  BPF 层: 自己写 C 代码              │  ← 自己维护
│  (参考/复制 Tracee，按需扩展)       │
└─────────────────────────────────────┘

当前方案架构：
┌─────────────────────────────────────┐
│  Go 层: cilium/ebpf (纯 Go)         │  ← 无 CGO
├─────────────────────────────────────┤
│  BPF 层: 自己写 C 代码              │  ← 自己维护 (不变)
│  (参考 Tracee，按需扩展)            │
└─────────────────────────────────────┘
```

**变化点**：Go 层的 BPF 加载库从 libbpfgo 改为 cilium/ebpf

**不变点**：BPF C 代码始终是自己维护的

当前实现：
- ✅ BPF C 代码自己写，**与原方案一致**
- ✅ 参考 Tracee BPF 实现（vmlinux.h、部分 helper），**与原方案一致**
- ✅ Go 层改用 **cilium/ebpf** 替代 libbpfgo，**优化点**

这是对原方案 Go 层的**技术优化**——BPF 层方案不变，Go 层选择了更优的加载库。

### 总结

选择 cilium/ebpf 替代 libbpfgo 的理由：

| 选型理由 | 说明 |
|---------|------|
| **无 CGO** | 编译简单、交叉编译容易、Mac 开发者友好 |
| **无运行时依赖** | 单文件部署，无需 libbpf.so 等动态库 |
| **依赖链轻量** | ~10 个依赖 vs libbpfgo 的 ~50 个依赖 |
| **业界标准** | cilium/ebpf 是 Go eBPF 的主流选择 |
| **纯 Go 调试** | 无 C 代码混合，崩溃堆栈清晰 |

**注意**：BPF C 代码层面与原方案一致，都是自己维护。变化仅在 Go 层的 BPF 加载库选择。

---

## 目标

1. **功能对等**: 实现与 LKM 版本相同的事件采集能力
2. **兼容性好**: 使用 eBPF CO-RE 技术，无需为每个内核版本编译
3. **可维护性**: 自维护 BPF C 代码，不依赖外部运行时

## 架构

```
┌────────────────────────────────────────────────────────────────────┐
│                          driver_ebpf                                │
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
plugins/driver_ebpf/
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
│              │    driver_ebpf      │  单一可执行文件              │
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
go build -o driver_ebpf .  # 编译最终可执行文件
```

### 目录结构 (使用 bpf2go 后)

```
plugins/driver_ebpf/
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
go build -o driver_ebpf .
```

### 运行

```bash
# 需要将 .o 文件放到指定位置
sudo mkdir -p /usr/local/share/elkeid/bpf/
sudo cp bpf/elkeid.bpf.o /usr/local/share/elkeid/bpf/

# 运行
sudo ./driver_ebpf
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
        run: go build -o driver_ebpf .
      
      - name: Upload artifact
        uses: actions/upload-artifact@v3
        with:
          name: driver_ebpf
          path: driver_ebpf
```
