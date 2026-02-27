//go:build linux

package loader

import (
	"github.com/cilium/ebpf"
)

// loadEmbeddedSpec loads the embedded BPF spec on Linux.
// Uses bpf2go generated loadElkeid() from elkeid_bpfel_*.go
func loadEmbeddedSpec() (*ebpf.CollectionSpec, error) {
	return loadElkeid()
}
