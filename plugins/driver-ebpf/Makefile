# Elkeid eBPF Driver - Root Makefile

.PHONY: all build bpf clean install help

all: bpf build

# Build Go binary
build:
	@echo "Building Go binary..."
	CGO_ENABLED=0 go build -o driver-ebpf .

# Compile BPF program
bpf:
	@echo "Compiling BPF program..."
	$(MAKE) -C bpf

# Clean all artifacts
clean:
	rm -f driver-ebpf
	$(MAKE) -C bpf clean

# Install (requires root)
install: all
	$(MAKE) -C bpf install
	install -D -m 755 driver-ebpf /usr/local/bin/

# Generate code (bpf2go - future)
generate:
	go generate ./...

help:
	@echo "Elkeid eBPF Driver Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build BPF and Go binary (default)"
	@echo "  build    - Build Go binary only"
	@echo "  bpf      - Compile BPF program only"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to system (requires root)"
	@echo "  generate - Run go generate (bpf2go)"
	@echo ""
	@echo "Requirements:"
	@echo "  - Go 1.21+"
	@echo "  - clang 12+ (for BPF)"
	@echo "  - Linux 5.4+ with BTF (for running)"
