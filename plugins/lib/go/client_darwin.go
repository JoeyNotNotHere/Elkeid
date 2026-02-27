//go:build darwin

package plugins

import (
	"bufio"
	"os"
	"sync"
)

// New creates a stub client for macOS (for development/compilation only).
// The actual eBPF driver only runs on Linux.
func New() (c *Client) {
	c = &Client{
		rx:     os.Stdin,
		tx:     os.Stdout,
		reader: bufio.NewReaderSize(os.Stdin, 1024*1024),
		writer: bufio.NewWriterSize(os.Stdout, 512*1024),
		rmu:    &sync.Mutex{},
		wmu:    &sync.Mutex{},
	}
	return
}
