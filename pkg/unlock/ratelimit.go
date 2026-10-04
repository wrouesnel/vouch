package unlock

import (
	"sync"
	"time"
)

// RateLimitConfig caps attempts per client address and per username.
type RateLimitConfig struct {
	// Attempts is how many attempts are allowed within Window. Zero disables the limit.
	Attempts int `yaml:"attempts"`
	// Window is the sliding window attempts are counted over.
	Window time.Duration `yaml:"window"`
}

// limiter is a sliding-window counter of attempts per key.
type limiter struct {
	cfg  RateLimitConfig
	now  func() time.Time
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newLimiter(cfg RateLimitConfig, now func() time.Time) *limiter {
	return &limiter{cfg: cfg, now: now, hits: map[string][]time.Time{}}
}

// recent returns the hits for key within the window, dropping older ones. mu must be held.
func (l *limiter) recent(key string, now time.Time) []time.Time {
	hits := l.hits[key]
	cutoff := now.Add(-l.cfg.Window)
	idx := 0
	for idx < len(hits) && !hits[idx].After(cutoff) {
		idx++
	}
	hits = hits[idx:]
	if len(hits) == 0 {
		delete(l.hits, key)
	} else {
		l.hits[key] = hits
	}
	return hits
}

// Allow records an attempt against every key, and reports whether all of them were within
// their limit beforehand. An attempt over the limit is still recorded, so hammering an
// endpoint keeps it locked.
func (l *limiter) Allow(keys ...string) bool {
	if l.cfg.Attempts <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	allowed := true
	for _, key := range keys {
		hits := l.recent(key, now)
		if len(hits) >= l.cfg.Attempts {
			allowed = false
		}
		l.hits[key] = append(hits, now)
	}
	return allowed
}

// Sweep forgets keys with no recent attempts.
func (l *limiter) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for key := range l.hits {
		l.recent(key, now)
	}
}
