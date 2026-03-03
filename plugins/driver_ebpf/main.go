package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"driver_ebpf/pkg/manager"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	testMode := os.Getenv("ELKEID_TEST_MODE") == "1"

	if testMode {
		log.Println("Starting Elkeid Driver (eBPF) [TEST MODE] ...")
	} else {
		log.Println("Starting Elkeid Driver (eBPF) ...")
	}

	var mgr *manager.Manager
	var err error
	if testMode {
		mgr, err = manager.NewManagerForTest()
	} else {
		mgr, err = manager.NewManager()
	}
	if err != nil {
		log.Fatalf("Failed to create manager: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Println("starting manager...")
	if err := mgr.Start(ctx); err != nil {
		log.Fatalf("Failed to start manager: %v", err)
	}
	log.Println("manager started, waiting for signal...")

	<-ctx.Done()
	log.Println("shutting down...")
	mgr.Stop()
	log.Println("stopped")
}
