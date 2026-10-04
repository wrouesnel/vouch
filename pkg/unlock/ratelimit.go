package unlock

import (
	"sync"
	"time"
)

// RateLimitConfig caps failed attempts per client address and per account.
type RateLimitConfig struct {
	// Attempts is how many failed attempts are allowed within Window. Zero disables the limit.
	Attempts int `yaml:"attempts"`
	// Window is the sliding window attempts are counted over.
	Window time.Duration `yaml:"window"`
}

// limiter is a sliding-window counter of failed attempts per key. Successes aren't counted,
// so a busy service desk machine isn't locked out by its own legitimate unlocks.
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

// Allowed reports whether every key is under its limit of failures.
func (l *limiter) Allowed(keys ...string) bool {
	if l.cfg.Attempts <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for _, key := range keys {
		if len(l.recent(key, now)) >= l.cfg.Attempts {
			return false
		}
	}
	return true
}

// Fail records a failed attempt against every key.
func (l *limiter) Fail(keys ...string) {
	if l.cfg.Attempts <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for _, key := range keys {
		l.hits[key] = append(l.recent(key, now), now)
	}
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
