package ops

import (
	"sync"
	"time"

	"github.com/b070nd/cvewatch/app/src/inventory"
)

// staleTTL is how long a worked-out staleness is trusted when the files have
// not changed: another process (the daemon) may have revalidated meanwhile.
const staleTTL = 2 * time.Minute

// StaleCache keeps the last worked-out Staleness, which reads the lockfiles,
// so a viewer that re-reads often does not work it out every time. It is
// worked out again when the files the judgement depends on change
// (inventory.FilesStamp), after staleTTL, or after Invalidate. A nil cache
// works it out every time.
type StaleCache struct {
	mu    sync.Mutex
	stamp string
	st    Staleness
	at    time.Time
	ok    bool
}

// Invalidate makes the next Stale work the staleness out again.
func (c *StaleCache) Invalidate() {
	if c != nil {
		c.mu.Lock()
		c.ok = false
		c.mu.Unlock()
	}
}

// Stale is s.Stale through the cache. It also returns the stamp of the files
// it holds for, and false when the staleness could not be worked out.
func (c *StaleCache) Stale(s *Session) (Staleness, string, bool) {
	stamp := inventory.FilesStamp(s.Cfg)
	if c != nil {
		c.mu.Lock()
		if c.ok && c.stamp == stamp && time.Since(c.at) < staleTTL {
			st := c.st
			c.mu.Unlock()
			return st, stamp, true
		}
		c.mu.Unlock()
	}
	st, err := s.Stale()
	if err != nil {
		return Staleness{}, stamp, false
	}
	if c != nil {
		c.mu.Lock()
		c.stamp, c.st, c.at, c.ok = stamp, st, time.Now(), true
		c.mu.Unlock()
	}
	return st, stamp, true
}
