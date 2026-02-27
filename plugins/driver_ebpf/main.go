package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"driver_ebpf/pkg/manager"
)

func main() {
	fmt.Println("Starting Elkeid Driver (eBPF) ...")

	// Create manager
	mgr, err := manager.NewManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create manager: %v\n", err)
		os.Exit(1)
	}

	// Create context that cancels on signal
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Start manager
	if err := mgr.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start manager: %v\n", err)
		os.Exit(1)
	}

	// Wait for signal
	<-ctx.Done()
	fmt.Println("Shutting down...")
	mgr.Stop()
}
