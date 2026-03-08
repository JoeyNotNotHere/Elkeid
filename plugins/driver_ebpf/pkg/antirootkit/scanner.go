package antirootkit

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"driver_ebpf/pkg/adapter"
	"plugins"
)

const (
	DefaultScanInterval = 15 * time.Minute
	ProcModulesPath     = "/proc/modules"
	SysModulePath       = "/sys/module"
	ProcKallsymsPath    = "/proc/kallsyms"
)

type ScannerConfig struct {
	ScanInterval time.Duration
	Enabled      bool
}

func DefaultScannerConfig() *ScannerConfig {
	return &ScannerConfig{
		ScanInterval: DefaultScanInterval,
		Enabled:      true,
	}
}

type RootkitEvent struct {
	EventID         int
	ModuleName      string
	SyscallNumber   int
	InterruptNumber int
	Timestamp       time.Time
}

type Scanner struct {
	config *ScannerConfig
	client *plugins.Client

	kallsyms   map[string]uint64
	kallsymsMu sync.RWMutex

	running bool
	mu      sync.Mutex
	wg      sync.WaitGroup
	cancel  context.CancelFunc
}

func NewScanner(cfg *ScannerConfig, client *plugins.Client) *Scanner {
	if cfg == nil {
		cfg = DefaultScannerConfig()
	}
	return &Scanner{
		config:   cfg,
		client:   client,
		kallsyms: make(map[string]uint64),
	}
}

func (s *Scanner) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("scanner already running")
	}

	if !s.config.Enabled {
		fmt.Println("[Anti-Rootkit] Scanner disabled")
		return nil
	}

	fmt.Println("[Anti-Rootkit] Starting rootkit scanner...")

	if err := s.loadKallsyms(); err != nil {
		fmt.Printf("[Anti-Rootkit] Warning: failed to load kallsyms: %v\n", err)
	}

	ctx, s.cancel = context.WithCancel(ctx)
	s.wg.Add(1)
	go s.scanLoop(ctx)

	s.running = true
	fmt.Printf("[Anti-Rootkit] Scanner started (interval: %v)\n", s.config.ScanInterval)
	return nil
}

func (s *Scanner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	fmt.Println("[Anti-Rootkit] Stopping scanner...")
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
	s.running = false
	fmt.Println("[Anti-Rootkit] Scanner stopped")
}

func (s *Scanner) scanLoop(ctx context.Context) {
	defer s.wg.Done()

	s.runScan()

	ticker := time.NewTicker(s.config.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runScan()
		}
	}
}

func (s *Scanner) runScan() {
	fmt.Println("[Anti-Rootkit] Running rootkit scan...")
	startTime := time.Now()

	events := make([]*RootkitEvent, 0)

	hiddenMods := s.detectHiddenModules()
	events = append(events, hiddenMods...)

	syscallHooks := s.detectSyscallHooks()
	events = append(events, syscallHooks...)

	procHooks := s.detectProcHooks()
	events = append(events, procHooks...)

	if runtime.GOARCH == "amd64" || runtime.GOARCH == "386" {
		idtHooks := s.detectInterruptHooks()
		events = append(events, idtHooks...)
	}

	for _, event := range events {
		s.reportEvent(event)
	}

	fmt.Printf("[Anti-Rootkit] Scan completed in %v, found %d suspicious items\n",
		time.Since(startTime), len(events))
}

func (s *Scanner) TriggerScan() {
	go s.runScan()
}

func (s *Scanner) loadKallsyms() error {
	file, err := os.Open(ProcKallsymsPath)
	if err != nil {
		return fmt.Errorf("failed to open kallsyms: %w", err)
	}
	defer file.Close()

	s.kallsymsMu.Lock()
	defer s.kallsymsMu.Unlock()

	s.kallsyms = make(map[string]uint64)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			continue
		}

		name := parts[2]
		if strings.Contains(name, "\t") {
			name = strings.Split(name, "\t")[0]
		}
		s.kallsyms[name] = addr
	}

	return scanner.Err()
}

func (s *Scanner) getKernelTextRange() (start, end uint64) {
	s.kallsymsMu.RLock()
	defer s.kallsymsMu.RUnlock()

	start = s.kallsyms["_stext"]
	end = s.kallsyms["_etext"]
	return
}

func (s *Scanner) isInKernelText(addr uint64) bool {
	start, end := s.getKernelTextRange()
	if start == 0 || end == 0 {
		return true
	}
	return addr >= start && addr <= end
}

func (s *Scanner) findModuleByAddr(addr uint64) string {
	file, err := os.Open(ProcModulesPath)
	if err != nil {
		return "-1"
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}

		modName := parts[0]
		modAddr, err := strconv.ParseUint(strings.TrimPrefix(parts[5], "0x"), 16, 64)
		if err != nil {
			continue
		}
		modSize, _ := strconv.ParseUint(parts[1], 10, 64)

		if addr >= modAddr && addr < modAddr+modSize {
			return modName
		}
	}

	return "-1"
}

func (s *Scanner) detectHiddenModules() []*RootkitEvent {
	events := make([]*RootkitEvent, 0)

	procModules := make(map[string]bool)
	file, err := os.Open(ProcModulesPath)
	if err != nil {
		fmt.Printf("[Anti-Rootkit] Warning: cannot read %s: %v\n", ProcModulesPath, err)
		return events
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) > 0 {
			procModules[parts[0]] = true
		}
	}

	entries, err := os.ReadDir(SysModulePath)
	if err != nil {
		fmt.Printf("[Anti-Rootkit] Warning: cannot read %s: %v\n", SysModulePath, err)
		return events
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		modName := entry.Name()

		sectionsPath := filepath.Join(SysModulePath, modName, "sections")
		if _, err := os.Stat(sectionsPath); os.IsNotExist(err) {
			continue
		}

		if !procModules[modName] {
			events = append(events, &RootkitEvent{
				EventID:    adapter.EventIDRootkitHidden, // 702 - LKM_HIDDEN
				ModuleName: modName,
				Timestamp:  time.Now(),
			})
			fmt.Printf("[Anti-Rootkit] ALERT: Hidden module detected: %s\n", modName)
		}
	}

	return events
}

func (s *Scanner) detectSyscallHooks() []*RootkitEvent {
	events := make([]*RootkitEvent, 0)

	s.kallsymsMu.RLock()
	sctAddr := s.kallsyms["sys_call_table"]
	s.kallsymsMu.RUnlock()

	if sctAddr == 0 {
		return events
	}

	s.kallsymsMu.RLock()
	syscallNames := []string{
		"__x64_sys_read", "__x64_sys_write", "__x64_sys_open", "__x64_sys_close",
		"__x64_sys_stat", "__x64_sys_fstat", "__x64_sys_lstat", "__x64_sys_poll",
		"__x64_sys_lseek", "__x64_sys_mmap", "__x64_sys_mprotect", "__x64_sys_munmap",
		"__x64_sys_brk", "__x64_sys_ioctl", "__x64_sys_access", "__x64_sys_pipe",
		"__x64_sys_select", "__x64_sys_sched_yield", "__x64_sys_mremap",
		"__x64_sys_msync", "__x64_sys_mincore", "__x64_sys_madvise",
		"__x64_sys_shmget", "__x64_sys_shmat", "__x64_sys_shmctl",
		"__x64_sys_dup", "__x64_sys_dup2", "__x64_sys_pause", "__x64_sys_nanosleep",
		"__x64_sys_getitimer", "__x64_sys_alarm", "__x64_sys_setitimer",
		"__x64_sys_getpid", "__x64_sys_sendfile", "__x64_sys_socket",
		"__x64_sys_connect", "__x64_sys_accept", "__x64_sys_sendto",
		"__x64_sys_recvfrom", "__x64_sys_sendmsg", "__x64_sys_recvmsg",
		"__x64_sys_shutdown", "__x64_sys_bind", "__x64_sys_listen",
		"__x64_sys_getsockname", "__x64_sys_getpeername", "__x64_sys_socketpair",
		"__x64_sys_setsockopt", "__x64_sys_getsockopt", "__x64_sys_clone",
		"__x64_sys_fork", "__x64_sys_vfork", "__x64_sys_execve", "__x64_sys_exit",
		"__x64_sys_wait4", "__x64_sys_kill", "__x64_sys_uname", "__x64_sys_semget",
		"__x64_sys_semop", "__x64_sys_semctl", "__x64_sys_shmdt", "__x64_sys_msgget",
		"__x64_sys_msgsnd", "__x64_sys_msgrcv", "__x64_sys_msgctl",
	}

	for i, name := range syscallNames {
		addr, exists := s.kallsyms[name]
		if !exists || addr == 0 {
			continue
		}

		if !s.isInKernelText(addr) {
			modName := s.findModuleByAddr(addr)
			events = append(events, &RootkitEvent{
				EventID:       adapter.EventIDRootkitSyscall, // 701
				ModuleName:    modName,
				SyscallNumber: i,
				Timestamp:     time.Now(),
			})
			fmt.Printf("[Anti-Rootkit] ALERT: Syscall hook detected: syscall %d (%s) -> module %s\n",
				i, name, modName)
		}
	}
	s.kallsymsMu.RUnlock()

	return events
}

func (s *Scanner) detectProcHooks() []*RootkitEvent {
	events := make([]*RootkitEvent, 0)

	s.kallsymsMu.RLock()
	procIterateAddr := s.kallsyms["proc_root_iterate"]
	if procIterateAddr == 0 {
		procIterateAddr = s.kallsyms["proc_readdir"]
	}
	s.kallsymsMu.RUnlock()

	if procIterateAddr != 0 && !s.isInKernelText(procIterateAddr) {
		modName := s.findModuleByAddr(procIterateAddr)
		events = append(events, &RootkitEvent{
			EventID:    adapter.EventIDRootkitProcHook, // 700 - PROC_FILE_HOOK
			ModuleName: modName,
			Timestamp:  time.Now(),
		})
		fmt.Printf("[Anti-Rootkit] ALERT: /proc hook detected: module %s\n", modName)
	}

	return events
}

func (s *Scanner) detectInterruptHooks() []*RootkitEvent {
	events := make([]*RootkitEvent, 0)

	s.kallsymsMu.RLock()
	idtSymbols := []string{
		"divide_error", "debug", "nmi", "int3", "overflow",
		"bounds", "invalid_op", "device_not_available",
		"double_fault", "coprocessor_segment_overrun",
		"invalid_TSS", "segment_not_present",
		"stack_segment", "general_protection", "page_fault",
		"spurious_interrupt_bug", "coprocessor_error",
		"alignment_check", "machine_check", "simd_coprocessor_error",
	}

	for i, name := range idtSymbols {
		addr, exists := s.kallsyms[name]
		if !exists || addr == 0 {
			continue
		}

		if !s.isInKernelText(addr) {
			modName := s.findModuleByAddr(addr)
			events = append(events, &RootkitEvent{
				EventID:         adapter.EventIDRootkitIDT, // 703
				ModuleName:      modName,
				InterruptNumber: i,
				Timestamp:       time.Now(),
			})
			fmt.Printf("[Anti-Rootkit] ALERT: Interrupt hook detected: int %d (%s) -> module %s\n",
				i, name, modName)
		}
	}
	s.kallsymsMu.RUnlock()

	return events
}

func (s *Scanner) reportEvent(event *RootkitEvent) {
	if s.client == nil {
		return
	}

	var record *plugins.Record

	switch event.EventID {
	case adapter.EventIDRootkitProcHook: // 700 - PROC_FILE_HOOK
		record = &plugins.Record{
			DataType:  int32(event.EventID),
			Timestamp: event.Timestamp.Unix(),
			Data: &plugins.Payload{
				Fields: map[string]string{
					"module_name": event.ModuleName,
				},
			},
		}

	case adapter.EventIDRootkitSyscall: // 701 - SYSCALL_HOOK
		record = &plugins.Record{
			DataType:  int32(event.EventID),
			Timestamp: event.Timestamp.Unix(),
			Data: &plugins.Payload{
				Fields: map[string]string{
					"module_name":    event.ModuleName,
					"syscall_number": strconv.Itoa(event.SyscallNumber),
				},
			},
		}

	case adapter.EventIDRootkitHidden: // 702 - LKM_HIDDEN
		record = &plugins.Record{
			DataType:  int32(event.EventID),
			Timestamp: event.Timestamp.Unix(),
			Data: &plugins.Payload{
				Fields: map[string]string{
					"module_name": event.ModuleName,
				},
			},
		}

	case adapter.EventIDRootkitIDT: // 703 - INTERRUPTS_HOOK
		record = &plugins.Record{
			DataType:  int32(event.EventID),
			Timestamp: event.Timestamp.Unix(),
			Data: &plugins.Payload{
				Fields: map[string]string{
					"module_name":      event.ModuleName,
					"interrupt_number": strconv.Itoa(event.InterruptNumber),
				},
			},
		}
	}

	if record != nil {
		if err := s.client.SendRecord(record); err != nil {
			fmt.Printf("[Anti-Rootkit] Warning: failed to send event: %v\n", err)
		}
	}
}
