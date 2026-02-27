package cache

import (
	"net"
	"sync"
	"time"
)

// SocketInfo holds socket connection information.
type SocketInfo struct {
	PID      int
	FD       int
	Family   int    // AF_INET=2, AF_INET6=10
	SrcIP    net.IP
	SrcPort  uint16
	DstIP    net.IP
	DstPort  uint16
	State    int    // CONNECTING, CONNECTED, etc.
	UpdatedAt time.Time
}

// SocketCache maintains a cache of socket connections indexed by PID.
// Used to correlate execve events with network connections (Elkeid's get_process_socket logic).
type SocketCache struct {
	mu       sync.RWMutex
	sockets  map[int][]*SocketInfo // pid -> list of sockets
	maxPerPID int
	ttl      time.Duration
}

// Socket states (matching kernel values)
const (
	SocketStateConnecting    = 1
	SocketStateConnected     = 2
	SocketStateDisconnecting = 3
)

// Address families
const (
	AFInet  = 2
	AFInet6 = 10
)

// NewSocketCache creates a new socket cache.
func NewSocketCache(maxPerPID int, ttl time.Duration) *SocketCache {
	return &SocketCache{
		sockets:   make(map[int][]*SocketInfo),
		maxPerPID: maxPerPID,
		ttl:       ttl,
	}
}

// Add adds a socket connection to the cache.
func (c *SocketCache) Add(info *SocketInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	info.UpdatedAt = time.Now()
	
	sockets := c.sockets[info.PID]
	
	// Check if this socket already exists (same fd), update it
	for i, s := range sockets {
		if s.FD == info.FD {
			sockets[i] = info
			return
		}
	}
	
	// Add new socket, evict oldest if over limit
	if len(sockets) >= c.maxPerPID {
		sockets = sockets[1:] // remove oldest
	}
	c.sockets[info.PID] = append(sockets, info)
}

// Remove removes all sockets for a PID.
func (c *SocketCache) Remove(pid int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sockets, pid)
}

// RemoveByFD removes a specific socket by PID and FD.
func (c *SocketCache) RemoveByFD(pid, fd int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	sockets := c.sockets[pid]
	for i, s := range sockets {
		if s.FD == fd {
			c.sockets[pid] = append(sockets[:i], sockets[i+1:]...)
			return
		}
	}
}

// FindProcessSocket implements Elkeid's get_process_socket logic:
// Walk up the process tree and find the first connected socket.
// Returns socket info and the pid that owns it (socket_pid).
func (c *SocketCache) FindProcessSocket(pid int, procTree *ProcTreeCache, limit int) (*SocketInfo, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	visited := make(map[int]bool)
	currentPID := pid

	for i := 0; i < limit && currentPID > 1; i++ {
		if visited[currentPID] {
			break
		}
		visited[currentPID] = true

		// Check sockets for this process
		if sockets, ok := c.sockets[currentPID]; ok {
			for _, s := range sockets {
				// Only return connected/connecting sockets
				if s.State == SocketStateConnecting || 
				   s.State == SocketStateConnected || 
				   s.State == SocketStateDisconnecting {
					if !s.UpdatedAt.Add(c.ttl).Before(time.Now()) {
						return s, currentPID
					}
				}
			}
		}

		// Move to parent process
		if procTree != nil {
			if info, ok := procTree.Get(currentPID); ok {
				currentPID = info.PPID
			} else {
				break
			}
		} else {
			break
		}
	}

	return nil, -1
}

// GetSockets returns all sockets for a PID.
func (c *SocketCache) GetSockets(pid int) []*SocketInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	sockets := c.sockets[pid]
	if len(sockets) == 0 {
		return nil
	}

	// Return a copy to avoid race
	result := make([]*SocketInfo, len(sockets))
	copy(result, sockets)
	return result
}

// Cleanup removes expired entries.
func (c *SocketCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for pid, sockets := range c.sockets {
		valid := make([]*SocketInfo, 0, len(sockets))
		for _, s := range sockets {
			if now.Sub(s.UpdatedAt) <= c.ttl {
				valid = append(valid, s)
			}
		}
		if len(valid) == 0 {
			delete(c.sockets, pid)
		} else {
			c.sockets[pid] = valid
		}
	}
}

// FormatIPv4 formats an IPv4 address to string.
func FormatIPv4(ip net.IP) string {
	if ip == nil || len(ip) < 4 {
		return "0.0.0.0"
	}
	ip4 := ip.To4()
	if ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

// FormatIPv6 formats an IPv6 address to string.
func FormatIPv6(ip net.IP) string {
	if ip == nil {
		return "::"
	}
	return ip.String()
}
