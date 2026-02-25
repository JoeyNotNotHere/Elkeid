//go:build linux

package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// loadEmbeddedSpec loads the embedded BPF spec on Linux.
//
// This function will be replaced by bpf2go generated code.
// After running `go generate` in pkg/loader/, the generated
// elkeid_bpfel.go will provide the actual implementation.
//
// To generate:
//   1. cd bpf && make                    # compile BPF C code
//   2. cd pkg/loader && go generate      # run bpf2go
//
// The generated code will include loadElkeidObjects() function.
func loadEmbeddedSpec() (*ebpf.CollectionSpec, error) {
	// Placeholder - will be replaced after running go generate
	// See gen.go for bpf2go generation command
	return nil, fmt.Errorf("embedded BPF not available: run 'go generate' in pkg/loader/")
}

// After `go generate`, create a new file loader_linux_generated.go:
//
// //go:build linux && bpf_generated
//
// package loader
//
// func loadEmbeddedSpec() (*ebpf.CollectionSpec, error) {
//     return loadElkeid()
// }
