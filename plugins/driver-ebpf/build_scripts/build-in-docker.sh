#!/bin/bash
#
# Elkeid eBPF Driver Docker 编译脚本
# 在 Docker 容器中编译 BPF 和 Go 代码，输出到 output/ 目录
#
# 使用方法:
#   ./build/build-in-docker.sh          # 完整编译
#   ./build/build-in-docker.sh bpf      # 只编译 BPF
#   ./build/build-in-docker.sh go       # 只编译 Go (需要先编译 BPF)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_DIR/output"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查 Docker
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker not found. Please install Docker first."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon not running. Please start Docker."
        exit 1
    fi
}

# 构建 Docker 镜像
build_image() {
    local IMAGE_NAME="elkeid-ebpf-builder"
    
    log_info "Building Docker image: $IMAGE_NAME" >&2
    docker build -t "$IMAGE_NAME" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR" >&2
    
    echo "$IMAGE_NAME"
}

# 在 Docker 中编译 BPF
compile_bpf() {
    local IMAGE_NAME="$1"
    local PLUGINS_DIR="$PROJECT_DIR/.."
    
    log_info "Compiling BPF code..."
    
    docker run --rm \
        -v "$PLUGINS_DIR:/build/plugins" \
        -w /build/plugins/driver-ebpf \
        "$IMAGE_NAME" \
        bash -c '
            cd bpf
            echo "==> Compiling elkeid.bpf.c..."
            make clean 2>/dev/null || true
            make
            echo "==> BPF compilation done!"
            ls -la *.o 2>/dev/null || echo "No .o files generated"
        '
}

# 在 Docker 中生成 Go 绑定 (bpf2go)
generate_go_bindings() {
    local IMAGE_NAME="$1"
    local PLUGINS_DIR="$PROJECT_DIR/.."
    
    log_info "Generating Go bindings with bpf2go..."
    
    docker run --rm \
        -v "$PLUGINS_DIR:/build/plugins" \
        -w /build/plugins/driver-ebpf \
        "$IMAGE_NAME" \
        bash -c '
            # 安装与 go.mod 指定版本兼容的 bpf2go
            go install github.com/cilium/ebpf/cmd/bpf2go@v0.12.3
            
            # 运行 go generate
            cd pkg/loader
            echo "==> Running go generate..."
            go generate ./...
            
            echo "==> Generated files:"
            ls -la elkeid_*.go elkeid_*.o 2>/dev/null || echo "No generated files yet"
        '
}

# 在 Docker 中编译 Go 二进制
compile_go() {
    local IMAGE_NAME="$1"
    local OUTPUT="$2"
    local PLUGINS_DIR="$PROJECT_DIR/.."
    
    log_info "Compiling Go binary..."
    
    docker run --rm \
        -v "$PLUGINS_DIR:/build/plugins" \
        -w /build/plugins/driver-ebpf \
        -e CGO_ENABLED=0 \
        -e GOOS=linux \
        -e GOARCH=amd64 \
        "$IMAGE_NAME" \
        bash -c '
            echo "==> Building driver-ebpf for Linux amd64..."
            go build -o output/driver-ebpf-linux-amd64 .
            
            echo "==> Build info:"
            ls -la output/driver-ebpf-linux-amd64 2>/dev/null || echo "Build failed"
            file output/driver-ebpf-linux-amd64 2>/dev/null || true
        '
    
    # 同时编译 arm64 版本
    log_info "Compiling Go binary (arm64)..."
    
    docker run --rm \
        -v "$PLUGINS_DIR:/build/plugins" \
        -w /build/plugins/driver-ebpf \
        -e CGO_ENABLED=0 \
        -e GOOS=linux \
        -e GOARCH=arm64 \
        "$IMAGE_NAME" \
        bash -c '
            echo "==> Building driver-ebpf for Linux arm64..."
            go build -o output/driver-ebpf-linux-arm64 .
            
            echo "==> Build info:"
            ls -la output/driver-ebpf-linux-arm64 2>/dev/null || echo "Build failed"
            file output/driver-ebpf-linux-arm64 2>/dev/null || true
        '
}

# 复制 BPF 对象文件到输出目录
copy_bpf_artifacts() {
    log_info "Copying BPF artifacts to output/"
    
    mkdir -p "$OUTPUT_DIR"
    
    if [ -f "$PROJECT_DIR/bpf/elkeid.bpf.o" ]; then
        cp "$PROJECT_DIR/bpf/elkeid.bpf.o" "$OUTPUT_DIR/"
        log_info "Copied elkeid.bpf.o"
    fi
    
    # 复制 bpf2go 生成的文件
    for f in "$PROJECT_DIR/pkg/loader"/elkeid_*.o; do
        if [ -f "$f" ]; then
            cp "$f" "$OUTPUT_DIR/"
            log_info "Copied $(basename $f)"
        fi
    done
}

# 显示编译结果
show_results() {
    log_info "Build completed! Output files:"
    echo ""
    ls -la "$OUTPUT_DIR/" 2>/dev/null || echo "No output files"
    echo ""
    log_info "Deployment (单文件部署 - BPF 已嵌入二进制):"
    echo "  # 只需要复制一个文件"
    echo "  scp output/driver-ebpf-linux-amd64 server:/usr/local/bin/driver-ebpf"
    echo ""
    echo "  # 运行"
    echo "  sudo /usr/local/bin/driver-ebpf"
    echo ""
    echo "  # 注意: .o 文件仅供调试，部署不需要"
}

# 主函数
main() {
    local BUILD_TYPE="${1:-all}"
    local IMAGE_NAME="elkeid-ebpf-builder"
    
    log_info "Elkeid eBPF Driver Docker Build"
    log_info "Build type: $BUILD_TYPE"
    echo ""
    
    check_docker
    
    # 创建输出目录
    mkdir -p "$OUTPUT_DIR"
    
    # 构建 Docker 镜像
    log_info "Building Docker image: $IMAGE_NAME"
    docker build -t "$IMAGE_NAME" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR"
    
    case "$BUILD_TYPE" in
        bpf)
            compile_bpf "$IMAGE_NAME"
            copy_bpf_artifacts
            ;;
        go)
            compile_go "$IMAGE_NAME" "$OUTPUT_DIR"
            ;;
        generate)
            generate_go_bindings "$IMAGE_NAME"
            ;;
        all)
            compile_bpf "$IMAGE_NAME"
            generate_go_bindings "$IMAGE_NAME"
            compile_go "$IMAGE_NAME" "$OUTPUT_DIR"
            copy_bpf_artifacts
            ;;
        *)
            log_error "Unknown build type: $BUILD_TYPE"
            echo "Usage: $0 [all|bpf|go|generate]"
            exit 1
            ;;
    esac
    
    show_results
}

main "$@"
