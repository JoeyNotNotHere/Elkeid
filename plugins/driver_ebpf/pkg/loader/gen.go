//go:build linux

package loader

// This file contains bpf2go generation command for Linux.
//
// Prerequisites:
//   - clang (12+)
//   - libbpf headers
//   - bpf2go: go install github.com/cilium/ebpf/cmd/bpf2go@latest
//
// Usage:
//   cd plugins/driver_ebpf/pkg/loader
//   go generate
//
// This will generate:
//   - elkeid_bpfel.go  (x86_64 little-endian)
//   - elkeid_bpfel.o   (embedded BPF bytecode)
//   - elkeid_bpfeb.go  (arm64 big-endian)
//   - elkeid_bpfeb.o
//
// After generation, modify loader_linux.go to use the generated loadElkeid().

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Wno-pass-failed" -target amd64,arm64 elkeid ../../bpf/elkeid.bpf.c -- -I../../bpf -I../../bpf/common
