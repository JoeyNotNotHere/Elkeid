package cache

import (
	"os/user"
	"strconv"
	"sync"
	"time"
)

// UserInfo holds cached user information.
type UserInfo struct {
	UID       int
	Username  string
	UpdatedAt time.Time
}

// UserCache caches UID to username mappings.
type UserCache struct {
	mu      sync.RWMutex
	users   map[int]*UserInfo
	maxSize int
	ttl     time.Duration
}

// NewUserCache creates a new user cache.
func NewUserCache(maxSize int, ttl time.Duration) *UserCache {
	return &UserCache{
		users:   make(map[int]*UserInfo, maxSize),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// GetUsername returns the username for a UID, looking up if not cached.
func (c *UserCache) GetUsername(uid int) string {
	c.mu.RLock()
	info, ok := c.users[uid]
	if ok && time.Since(info.UpdatedAt) <= c.ttl {
		c.mu.RUnlock()
		return info.Username
	}
	c.mu.RUnlock()

	// Lookup and cache
	username := c.lookupUsername(uid)
	c.mu.Lock()
	defer c.mu.Unlock()

	c.users[uid] = &UserInfo{
		UID:       uid,
		Username:  username,
		UpdatedAt: time.Now(),
	}

	// Evict if over capacity
	if len(c.users) > c.maxSize {
		c.evictOldest()
	}

	return username
}

// lookupUsername looks up username from system.
func (c *UserCache) lookupUsername(uid int) string {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return strconv.Itoa(uid) // fallback to UID string
	}
	return u.Username
}

// evictOldest removes the oldest entry.
func (c *UserCache) evictOldest() {
	var oldestUID int
	var oldestTime time.Time

	for uid, info := range c.users {
		if oldestTime.IsZero() || info.UpdatedAt.Before(oldestTime) {
			oldestTime = info.UpdatedAt
			oldestUID = uid
		}
	}

	delete(c.users, oldestUID)
}

// Cleanup removes expired entries.
func (c *UserCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for uid, info := range c.users {
		if now.Sub(info.UpdatedAt) > c.ttl {
			delete(c.users, uid)
		}
	}
}
