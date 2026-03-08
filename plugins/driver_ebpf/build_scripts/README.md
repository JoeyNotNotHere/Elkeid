# Docker 编译指南

在 macOS 上使用 Docker 编译 Linux 版本的 driver_ebpf。

## 前提条件

- Docker Desktop 已安装并运行

## 使用方法

### 完整编译（推荐）

```bash
cd plugins/driver_ebpf
./build_scripts/build-in-docker.sh
```

这会：
1. 构建 Docker 编译镜像
2. 编译 BPF C 代码 (`elkeid.bpf.o`)
3. 生成 Go 绑定 (bpf2go)
4. 编译 Linux amd64/arm64 二进制

### 只编译 BPF

```bash
./build_scripts/build-in-docker.sh bpf
```

### 只编译 Go 二进制

```bash
./build_scripts/build-in-docker.sh go
```

### 只生成 Go 绑定

```bash
./build_scripts/build-in-docker.sh generate
```

## 输出文件

编译产物在 `output/` 目录：

```
output/
├── driver_ebpf-linux-amd64    # Linux x86_64 二进制
├── driver_ebpf-linux-arm64    # Linux ARM64 二进制
├── elkeid.bpf.o               # BPF 字节码
└── elkeid_bpfel.o             # bpf2go 生成的嵌入式 BPF
```

## 部署到 Linux 服务器

```bash
# 复制二进制
scp output/driver_ebpf-linux-amd64 server:/usr/local/bin/driver_ebpf

# 复制 BPF 对象文件（如果使用分离加载模式）
ssh server "sudo mkdir -p /usr/local/share/elkeid/bpf"
scp output/elkeid.bpf.o server:/usr/local/share/elkeid/bpf/

# 运行
ssh server "sudo /usr/local/bin/driver_ebpf"
```

## 服务器要求

- Linux Kernel 5.4+ (with BTF support)
- root 权限

检查 BTF 支持：
```bash
ls -la /sys/kernel/btf/vmlinux
```
