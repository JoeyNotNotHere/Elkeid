//go:build !linux

package loader

import (
	"github.com/cilium/ebpf"
)

// loadEmbeddedSpec on non-Linux platforms always returns nil.
// BPF programs can only run on Linux, so embedded loading is not available.
// The loader will fall back to file-based loading for development purposes.
func loadEmbeddedSpec() (*ebpf.CollectionSpec, error) {
	return nil, nil
}
