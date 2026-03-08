package cache

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcInfo holds process information for the tree cache.
type ProcInfo struct {
	PID       int
	PPID      int
	PGID      int
	SID       int
	UID       int
	Comm      string
	Exe       string
	Argv      string
	TTY       string
	StartTime int64
	UpdatedAt time.Time
}

// ProcTreeCache maintains a cache of process information for building pid_tree.
type ProcTreeCache struct {
	mu        sync.RWMutex
	procs     map[int]*ProcInfo
	rootPidNs uint64
	maxSize   int
	ttl       time.Duration
}

// NewProcTreeCache creates a new process tree cache.
func NewProcTreeCache(maxSize int, ttl time.Duration) *ProcTreeCache {
	cache := &ProcTreeCache{
		procs:   make(map[int]*ProcInfo, maxSize),
		maxSize: maxSize,
		ttl:     ttl,
	}
	cache.initRootPidNs()
	return cache
}

// initRootPidNs reads the root PID namespace inum from /proc/1/ns/pid.
func (c *ProcTreeCache) initRootPidNs() {
	link, err := os.Readlink("/proc/1/ns/pid")
	if err != nil {
		c.rootPidNs = 0xEFFFFFFC // fallback to PROC_PID_INIT_INO
		return
	}
	// link format: "pid:[4026531836]"
	start := strings.Index(link, "[")
	end := strings.Index(link, "]")
	if start >= 0 && end > start {
		if inum, err := strconv.ParseUint(link[start+1:end], 10, 64); err == nil {
			c.rootPidNs = inum
			return
		}
	}
	c.rootPidNs = 0xEFFFFFFC
}

// GetRootPidNs returns the root PID namespace inum.
func (c *ProcTreeCache) GetRootPidNs() uint64 {
	return c.rootPidNs
}

// Update adds or updates a process in the cache.
func (c *ProcTreeCache) Update(info *ProcInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	info.UpdatedAt = time.Now()
	c.procs[info.PID] = info

	// Simple eviction: remove oldest entries if over capacity
	if len(c.procs) > c.maxSize {
		c.evictOldest()
	}
}

// Get retrieves a process from the cache.
func (c *ProcTreeCache) Get(pid int) (*ProcInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	info, ok := c.procs[pid]
	if !ok {
		return nil, false
	}
	// Check TTL
	if time.Since(info.UpdatedAt) > c.ttl {
		return nil, false
	}
	return info, true
}

// Delete removes a process from the cache.
func (c *ProcTreeCache) Delete(pid int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.procs, pid)
}

// BuildPidTree constructs the pid_tree string in Elkeid format: "pid1.comm1<pid2.comm2<..."
// Walks up the process tree from the given PID.
func (c *ProcTreeCache) BuildPidTree(pid int, limit int) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var parts []string
	visited := make(map[int]bool)
	currentPID := pid

	for i := 0; i < limit && currentPID > 1; i++ {
		if visited[currentPID] {
			break // avoid cycles
		}
		visited[currentPID] = true

		info, ok := c.procs[currentPID]
		if !ok {
			// Try to read from /proc if not in cache
			info = c.readProcInfo(currentPID)
			if info == nil {
				break
			}
		}

		parts = append(parts, fmt.Sprintf("%d.%s", info.PID, info.Comm))
		currentPID = info.PPID
	}

	return strings.Join(parts, "<")
}

// GetParentArgv returns the argv of the parent process.
func (c *ProcTreeCache) GetParentArgv(pid int) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	info, ok := c.procs[pid]
	if !ok {
		return ""
	}
	parentInfo, ok := c.procs[info.PPID]
	if !ok {
		return ""
	}
	return parentInfo.Argv
}

// readProcInfo reads process info from /proc/<pid>/stat (fallback).
func (c *ProcTreeCache) readProcInfo(pid int) *ProcInfo {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return nil
	}

	// Parse stat: pid (comm) state ppid pgrp session tty_nr ...
	str := string(data)
	commStart := strings.Index(str, "(")
	commEnd := strings.LastIndex(str, ")")
	if commStart < 0 || commEnd < 0 {
		return nil
	}

	comm := str[commStart+1 : commEnd]
	fields := strings.Fields(str[commEnd+2:])
	if len(fields) < 5 {
		return nil
	}

	ppid, _ := strconv.Atoi(fields[1])
	pgid, _ := strconv.Atoi(fields[2])
	sid, _ := strconv.Atoi(fields[3])
	ttyNr, _ := strconv.Atoi(fields[4])

	return &ProcInfo{
		PID:  pid,
		PPID: ppid,
		PGID: pgid,
		SID:  sid,
		Comm: comm,
		TTY:  formatTTY(ttyNr),
	}
}

// formatTTY converts tty_nr to device name.
func formatTTY(ttyNr int) string {
	if ttyNr == 0 {
		return "-1"
	}
	major := (ttyNr >> 8) & 0xff
	minor := ttyNr & 0xff
	// Common TTY types
	switch major {
	case 4:
		return fmt.Sprintf("tty%d", minor)
	case 136:
		return fmt.Sprintf("pts/%d", minor)
	default:
		return fmt.Sprintf("%d:%d", major, minor)
	}
}

// evictOldest removes ~10% of the oldest entries when cache is full.
// Batch eviction amortizes the O(n) scan cost.
func (c *ProcTreeCache) evictOldest() {
	evictCount := c.maxSize / 10
	if evictCount < 1 {
		evictCount = 1
	}

	type pidTime struct {
		pid int
		t   time.Time
	}
	candidates := make([]pidTime, 0, evictCount)

	for pid, info := range c.procs {
		if len(candidates) < evictCount {
			candidates = append(candidates, pidTime{pid, info.UpdatedAt})
		} else {
			maxIdx := 0
			for i := 1; i < len(candidates); i++ {
				if candidates[i].t.After(candidates[maxIdx].t) {
					maxIdx = i
				}
			}
			if info.UpdatedAt.Before(candidates[maxIdx].t) {
				candidates[maxIdx] = pidTime{pid, info.UpdatedAt}
			}
		}
	}

	for _, c2 := range candidates {
		delete(c.procs, c2.pid)
	}
}

// Cleanup removes expired entries from the cache.
func (c *ProcTreeCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for pid, info := range c.procs {
		if now.Sub(info.UpdatedAt) > c.ttl {
			delete(c.procs, pid)
		}
	}
}
