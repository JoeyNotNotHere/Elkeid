# Elkeid eBPF Driver Makefile

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool

# Detect architecture
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# BPF compile flags
BPF_CFLAGS := -O2 -g
BPF_CFLAGS += -target bpf
BPF_CFLAGS += -D__TARGET_ARCH_$(ARCH)
BPF_CFLAGS += -Wall -Wno-unused-value -Wno-pointer-sign
BPF_CFLAGS += -Wno-compare-distinct-pointer-types
BPF_CFLAGS += -Wno-address-of-packed-member
BPF_CFLAGS += -I. -Icommon

# Source files - Main BPF program
BPF_SRC := elkeid.bpf.c
BPF_OBJ := elkeid.bpf.o

# Header files in common/
HEADERS := common/vmlinux.h common/types.h common/maps.h common/helpers.h

.PHONY: all clean vmlinux check info install

all: $(BPF_OBJ)

# Generate vmlinux.h from kernel BTF (only if not exists)
common/vmlinux.h:
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		echo "Generating common/vmlinux.h from kernel BTF..."; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@; \
	else \
		echo "Warning: /sys/kernel/btf/vmlinux not found"; \
		echo "Using existing vmlinux.h or copy from Tracee"; \
	fi

# Compile BPF program
$(BPF_OBJ): $(BPF_SRC) $(HEADERS)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f *.bpf.o

# Install to system
install: $(BPF_OBJ)
	install -D -m 644 $(BPF_OBJ) /usr/local/share/elkeid/bpf/

# Development helpers
check:
	@echo "Checking BPF compilation environment..."
	@which $(CLANG) > /dev/null || (echo "clang not found"; exit 1)
	@echo "OK - Ready to compile"

info:
	@echo "Architecture: $(ARCH)"
	@echo "Clang: $(shell $(CLANG) --version | head -1)"
	@echo "Kernel: $(shell uname -r)"
	@echo "BTF: $(shell ls -la /sys/kernel/btf/vmlinux 2>/dev/null || echo 'not available')"
	@echo "Headers: $(HEADERS)"
