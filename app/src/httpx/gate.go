package httpx

import (
	"context"
	"sync"
	"time"
)

// gate paces requests to one host and applies the 429 cooldown.
type gate struct {
	interval time.Duration // minimum spacing between requests; 0 means unlimited

	mu      sync.Mutex
	next    time.Time // earliest start of the next request
	blocked time.Time // end of the current cooldown
	streak  int       // consecutive 429 responses
	limited time.Time // the host refused requests until then (a request limit)
}

func (g *gate) limitUntil(t time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.limited = t
}

func (g *gate) limitedUntil() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.limited
}

// wait reserves the next free slot and sleeps until it starts. Slots are
// handed out under the lock, so concurrent callers queue up in order.
func (g *gate) wait(ctx context.Context) error {
	g.mu.Lock()
	at := time.Now()
	if g.blocked.After(at) {
		at = g.blocked
	}
	if g.next.After(at) {
		at = g.next
	}
	g.next = at.Add(g.interval)
	g.mu.Unlock()
	return sleep(ctx, time.Until(at))
}

// observe records a response status. Reaching the threshold of consecutive
// 429s starts a cooldown; any other status ends the streak.
func (g *gate) observe(status, threshold int, cooldown time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if status != 429 {
		g.streak = 0
		return
	}
	g.streak++
	if threshold > 0 && cooldown > 0 && g.streak >= threshold {
		g.blocked = time.Now().Add(cooldown)
		g.streak = 0
	}
}

// sleep waits for d or until ctx is done.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
