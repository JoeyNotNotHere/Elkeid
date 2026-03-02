#!/bin/bash
#
# Elkeid eBPF Driver Docker 编译脚本
#
# 使用方法:
#   BUILD_VERSION=1.7.0.9 ./build-in-docker.sh
#
# 产出 (BPF .o 已嵌入二进制，无需额外文件):
#   output/driver-debian-x86_64-<version>.plg
#   output/driver-rhel-x86_64-<version>.plg
#   output/driver-debian-aarch64-<version>.plg
#   output/driver-rhel-aarch64-<version>.plg

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PLUGINS_DIR="$(dirname "$PROJECT_DIR")"
OUTPUT_DIR="$PROJECT_DIR/output"
BUILD_VERSION="${BUILD_VERSION:-1.0.0.0}"
IMAGE_NAME="elkeid-ebpf-builder"

log_info()  { echo -e "\033[0;32m[INFO]\033[0m $1"; }
log_error() { echo -e "\033[0;31m[ERROR]\033[0m $1"; }

# 检查 Docker
command -v docker &>/dev/null || { log_error "Docker not found"; exit 1; }
docker info &>/dev/null 2>&1 || { log_error "Docker not running"; exit 1; }

log_info "Elkeid eBPF Driver Build (BUILD_VERSION=$BUILD_VERSION)"

mkdir -p "$OUTPUT_DIR"

# 构建 Docker 镜像
log_info "Building Docker image..."
docker build -t "$IMAGE_NAME" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR"

# Step 1: bpf2go 生成嵌入了 BPF 字节码的 Go 文件
log_info "Generating BPF Go bindings (bpf2go)..."
docker run --rm \
    -v "$PLUGINS_DIR:/build/plugins" \
    -v elkeid-go-cache:/go/pkg \
    -w /build/plugins/driver_ebpf/pkg/loader \
    "$IMAGE_NAME" \
    bash -c 'set -e; go generate ./...; echo "==> Generated:"; ls -la elkeid_bpfel_*.go elkeid_bpfel_*.o'

# Step 2: 编译 x86_64
log_info "Building driver for x86_64..."
docker run --rm \
    -v "$PLUGINS_DIR:/build/plugins" \
    -v elkeid-go-cache:/go/pkg \
    -w /build/plugins/driver_ebpf \
    -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 \
    "$IMAGE_NAME" \
    bash -c "set -e; go build -o output/driver-debian-x86_64-${BUILD_VERSION}.plg ."

cp "$OUTPUT_DIR/driver-debian-x86_64-${BUILD_VERSION}.plg" \
   "$OUTPUT_DIR/driver-rhel-x86_64-${BUILD_VERSION}.plg"

# Step 3: 编译 aarch64
log_info "Building driver for aarch64..."
docker run --rm \
    -v "$PLUGINS_DIR:/build/plugins" \
    -v elkeid-go-cache:/go/pkg \
    -w /build/plugins/driver_ebpf \
    -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=arm64 \
    "$IMAGE_NAME" \
    bash -c "set -e; go build -o output/driver-debian-aarch64-${BUILD_VERSION}.plg ."

cp "$OUTPUT_DIR/driver-debian-aarch64-${BUILD_VERSION}.plg" \
   "$OUTPUT_DIR/driver-rhel-aarch64-${BUILD_VERSION}.plg"

log_info "Build complete!"
ls -lh "$OUTPUT_DIR"/driver-*.plg
