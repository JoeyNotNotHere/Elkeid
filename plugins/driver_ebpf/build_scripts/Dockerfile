# Elkeid eBPF Driver 编译环境
# 基于 Go 官方镜像 + clang/llvm

FROM golang:1.21-bookworm

# 安装 BPF 编译依赖
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    make \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /build

# 默认命令
CMD ["bash"]
