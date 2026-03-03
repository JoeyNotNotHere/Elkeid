package manager

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"driver_ebpf/pkg/adapter"
	"driver_ebpf/pkg/antirootkit"
	"driver_ebpf/pkg/cache"
	"driver_ebpf/pkg/loader"
	"plugins"
)

// Config holds manager configuration.
type Config struct {
	BPFObjectPath       string        // Path to compiled BPF object file
	PerfBufferSize      int           // Perf buffer size in pages
	EventChanSize       int           // Event channel size
	OutputChanSize      int           // Output channel size
	AntiRootkitEnabled  bool          // Enable Anti-Rootkit scanner
	AntiRootkitInterval time.Duration // Anti-Rootkit scan interval
}

// DefaultConfig returns default configuration.
func DefaultConfig() *Config {
	return &Config{
		BPFObjectPath:       "/usr/local/share/elkeid/bpf/elkeid.bpf.o",
		PerfBufferSize:      128,
		EventChanSize:       1000,
		OutputChanSize:      1000,
		AntiRootkitEnabled:  true,
		AntiRootkitInterval: 15 * time.Minute,
	}
}

// Manager handles the lifecycle of the eBPF driver.
type Manager struct {
	config *Config

	// BPF components
	loader *loader.Loader
	reader *loader.EventReader

	// Caches
	procTree    *cache.ProcTreeCache
	socketCache *cache.SocketCache
	userCache   *cache.UserCache

	// Converter
	converter *adapter.NativeConverter

	// Anti-Rootkit scanner
	rootkitScanner *antirootkit.Scanner

	// Agent client
	client *plugins.Client

	// Output channel for Elkeid protocol data
	output chan []byte

	// Test mode: log events to stderr instead of sending to agent
	testMode bool

	// State
	running bool
	mu      sync.Mutex
	wg      sync.WaitGroup
}

// NewManager creates a new Manager instance.
func NewManager() (*Manager, error) {
	return NewManagerWithConfig(DefaultConfig())
}

// NewManagerForTest creates a Manager in test mode (no agent client, events logged to stderr).
func NewManagerForTest() (*Manager, error) {
	mgr, err := NewManagerWithConfig(DefaultConfig())
	if err != nil {
		return nil, err
	}
	mgr.testMode = true
	mgr.client = nil
	return mgr, nil
}

// NewManagerWithConfig creates a new Manager with custom configuration.
func NewManagerWithConfig(cfg *Config) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Initialize caches
	procTree := cache.NewProcTreeCache(10000, 30*time.Minute)
	socketCache := cache.NewSocketCache(100, 5*time.Minute)
	userCache := cache.NewUserCache(1000, 1*time.Hour)

	// Create converter
	converter := adapter.NewNativeConverter(procTree, socketCache, userCache)

	// Initialize Agent client
	client := plugins.New()

	// Initialize Anti-Rootkit scanner
	rootkitCfg := &antirootkit.ScannerConfig{
		Enabled:      cfg.AntiRootkitEnabled,
		ScanInterval: cfg.AntiRootkitInterval,
	}
	rootkitScanner := antirootkit.NewScanner(rootkitCfg, client)

	return &Manager{
		config:         cfg,
		procTree:       procTree,
		socketCache:    socketCache,
		userCache:      userCache,
		converter:      converter,
		rootkitScanner: rootkitScanner,
		client:         client,
		output:         make(chan []byte, cfg.OutputChanSize),
	}, nil
}

// Start begins the eBPF event collection.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("manager already running")
	}

	log.Println("[manager] Starting Elkeid eBPF Driver...")

	// Create loader — prefer embedded BPF bytecode (compiled in via bpf2go),
	// fall back to file path only if embedded is not available.
	loaderCfg := &loader.LoaderConfig{
		BPFObjectPath:  m.config.BPFObjectPath,
		PerfBufferSize: m.config.PerfBufferSize,
		UseEmbedded:    true,
	}

	var err error
	m.loader, err = loader.NewLoader(loaderCfg)
	if err != nil {
		return fmt.Errorf("failed to create BPF loader: %w", err)
	}

	// Set config (root pid namespace)
	rootPidNS := uint32(m.procTree.GetRootPidNs())
	if err := m.loader.SetConfig(rootPidNS, 0); err != nil {
		log.Printf("[manager] Warning: failed to set BPF config: %v", err)
	}

	// Attach BPF programs
	if err := m.loader.Attach(); err != nil {
		m.loader.Close()
		return fmt.Errorf("failed to attach BPF programs: %w", err)
	}

	// Default-off high-volume events (matching LKM SANDBOX behavior)
	for _, evtID := range []uint32{
		loader.EventIDOpen,     // security_file_open: extremely high volume
		loader.EventIDMprotect, // mprotect: high volume
	} {
		if err := m.loader.SetEventEnabled(evtID, false); err != nil {
			log.Printf("[manager] Warning: failed to disable event %d: %v", evtID, err)
		}
	}

	// Whitelist own PID to avoid self-monitoring
	if err := m.loader.AddPIDWhitelist(uint32(os.Getpid())); err != nil {
		log.Printf("[manager] Warning: failed to whitelist own PID: %v", err)
	}

	log.Println("[manager] BPF programs attached successfully")

	// Create event reader
	readerCfg := &loader.ReaderConfig{
		ChannelSize: m.config.EventChanSize,
	}
	m.reader = loader.NewEventReader(m.loader, readerCfg)

	// Start event reader
	if err := m.reader.Start(ctx); err != nil {
		m.loader.Close()
		return fmt.Errorf("failed to start event reader: %w", err)
	}

	// Start event processing
	m.wg.Add(1)
	go m.processEvents(ctx)

	// Start periodic cache cleanup
	m.wg.Add(1)
	go m.cleanupCaches(ctx)

	// Start Anti-Rootkit scanner
	if m.rootkitScanner != nil {
		if err := m.rootkitScanner.Start(ctx); err != nil {
			log.Printf("[manager] Warning: failed to start Anti-Rootkit scanner: %v", err)
		}
	}

	m.running = true
	log.Println("[manager] Elkeid eBPF Driver started")

	return nil
}

// processEvents reads events and converts them to Elkeid protocol.
func (m *Manager) processEvents(ctx context.Context) {
	defer m.wg.Done()

	statsTicker := time.NewTicker(5 * time.Second)
	defer statsTicker.Stop()
	var eventCount uint64

	for {
		select {
		case <-ctx.Done():
			return
		case <-statsTicker.C:
			stats := m.reader.Stats()
			log.Printf("[manager] Stats: total=%d lost=%d errors=%d (batch=%d)",
				stats.TotalEvents, stats.LostEvents, stats.ParseErrors, eventCount)
			eventCount = 0
		case event, ok := <-m.reader.Events():
			if !ok {
				return
			}
			eventCount++

			if m.testMode {
				logEvent(event)
			}

			m.updateCaches(event)

			records := m.converter.ConvertToRecords(event)
			for _, record := range records {
				if m.client != nil {
					if err := m.client.SendRecord(record); err != nil {
						log.Printf("[manager] Warning: failed to send record: %v", err)
					}
				}
			}
		}
	}
}

// logEvent prints a human-readable summary of an event to stderr.
func logEvent(event loader.Event) {
	h := event.GetHeader()
	switch e := event.(type) {
	case *loader.ExecveEvent:
		log.Printf("[EVENT] execve pid=%d ppid=%d uid=%d comm=%s exe=%s argv=%s",
			h.PID, h.PPID, h.UID, h.GetComm(), e.GetExe(), e.GetArgv())
	case *loader.ExitEvent:
		log.Printf("[EVENT] exit pid=%d comm=%s code=%d", h.PID, h.GetComm(), e.ExitCode)
	case *loader.NetEvent:
		log.Printf("[EVENT] net(id=%d) pid=%d comm=%s exe=%s %s:%d -> %s:%d",
			h.EventID, h.PID, h.GetComm(), e.GetExe(),
			e.GetSrcIP(), e.SPort, e.GetDstIP(), e.DPort)
	case *loader.FileEvent:
		log.Printf("[EVENT] file(id=%d) pid=%d comm=%s exe=%s path=%s",
			h.EventID, h.PID, h.GetComm(), e.GetExe(), e.GetFilePath())
	case *loader.ModuleEvent:
		log.Printf("[EVENT] module pid=%d comm=%s name=%s", h.PID, h.GetComm(), e.GetModuleName())
	case *loader.CredEvent:
		log.Printf("[EVENT] cred pid=%d comm=%s old_uid=%d new_uid=%d",
			h.PID, h.GetComm(), e.OldUID, e.NewUID)
	case *loader.DNSEvent:
		log.Printf("[EVENT] dns pid=%d comm=%s query=%s", h.PID, h.GetComm(), e.GetQuery())
	default:
		log.Printf("[EVENT] unknown(id=%d) pid=%d comm=%s", h.EventID, h.PID, h.GetComm())
	}
}

// cleanupCaches periodically evicts expired entries from all caches.
func (m *Manager) cleanupCaches(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if m.procTree != nil {
				m.procTree.Cleanup()
			}
			if m.socketCache != nil {
				m.socketCache.Cleanup()
			}
			if m.userCache != nil {
				m.userCache.Cleanup()
			}
		}
	}
}

// updateCaches updates internal caches based on events.
func (m *Manager) updateCaches(event loader.Event) {
	header := event.GetHeader()

	switch e := event.(type) {
	case *loader.ExecveEvent:
		// Update process tree cache
		if m.procTree != nil {
			m.procTree.Update(&cache.ProcInfo{
				PID:       int(header.PID),
				PPID:      int(header.PPID),
				Comm:      header.GetComm(),
				Exe:       e.GetExe(),
				StartTime: int64(header.Timestamp),
			})
		}

	case *loader.ExitEvent:
		// Remove from caches
		if m.procTree != nil {
			m.procTree.Delete(int(header.PID))
		}
		if m.socketCache != nil {
			m.socketCache.Remove(int(header.PID))
		}

	case *loader.NetEvent:
		// Update socket cache for connect events
		if header.EventID == loader.EventIDConnect && e.Ret == 0 {
			if m.socketCache != nil {
				m.socketCache.Add(&cache.SocketInfo{
					PID:     int(header.PID),
					Family:  int(e.SaFamily),
					SrcIP:   net.IP(e.SIP[:]),
					DstIP:   net.IP(e.DIP[:]),
					SrcPort: e.SPort,
					DstPort: e.DPort,
					State:   cache.SocketStateConnected,
				})
			}
		}
	}
}

// Output returns the channel for receiving Elkeid protocol data.
func (m *Manager) Output() <-chan []byte {
	return m.output
}

// Stats returns current statistics.
func (m *Manager) Stats() Stats {
	var readerStats loader.ReaderStats
	if m.reader != nil {
		readerStats = m.reader.Stats()
	}

	return Stats{
		TotalEvents: readerStats.TotalEvents,
		LostEvents:  readerStats.LostEvents,
		ParseErrors: readerStats.ParseErrors,
	}
}

// Stats holds manager statistics.
type Stats struct {
	TotalEvents uint64
	LostEvents  uint64
	ParseErrors uint64
}

// Stop gracefully stops the manager.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}

	log.Println("[manager] Stopping Elkeid eBPF Driver...")

	// Stop Anti-Rootkit scanner
	if m.rootkitScanner != nil {
		m.rootkitScanner.Stop()
	}

	// Stop reader
	if m.reader != nil {
		m.reader.Stop()
	}

	// Wait for processing to finish
	m.wg.Wait()

	// Close loader
	if m.loader != nil {
		m.loader.Close()
	}

	// Close Agent client
	if m.client != nil {
		m.client.Close()
	}

	// Close output channel
	close(m.output)

	m.running = false
	log.Println("[manager] Elkeid eBPF Driver stopped")
}
