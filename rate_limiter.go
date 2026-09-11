package flow

import (
	"sync"
	"time"
)

// RateLimiter is the contract used by the throttle middleware to count and
// check attempts for a key (Laravel: Illuminate\Cache\RateLimiter).
type RateLimiter interface {
	// TooManyAttempts reports whether the key has exceeded maxAttempts within
	// the decay window.
	TooManyAttempts(key string, maxAttempts int) bool
	// Hit records an attempt for the key with the given decay window.
	Hit(key string, decay time.Duration)
	// Attempts returns the current attempt count for the key.
	Attempts(key string) int
	// AvailableIn returns the seconds until the key is available again.
	AvailableIn(key string) int
	// Clear resets the counter for the key.
	Clear(key string)
}

type memoryHit struct {
	at    time.Time
	decay time.Duration
}

// MemoryRateLimiter is an in-process RateLimiter with per-hit decay windows.
type MemoryRateLimiter struct {
	mu   sync.Mutex
	hits map[string][]memoryHit
}

// NewMemoryRateLimiter creates an in-process rate limiter.
func NewMemoryRateLimiter() *MemoryRateLimiter {
	return &MemoryRateLimiter{hits: make(map[string][]memoryHit)}
}

func (m *MemoryRateLimiter) alive(key string, now time.Time) []memoryHit {
	hits := m.hits[key]
	alive := hits[:0]
	for _, h := range hits {
		if now.Sub(h.at) < h.decay {
			alive = append(alive, h)
		}
	}
	m.hits[key] = alive
	return alive
}

// TooManyAttempts implements RateLimiter.
func (m *MemoryRateLimiter) TooManyAttempts(key string, maxAttempts int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	alive := m.alive(key, now)
	if len(alive) == 0 {
		return false
	}
	decay := alive[len(alive)-1].decay
	relevant := 0
	for _, h := range alive {
		if now.Sub(h.at) < decay {
			relevant++
		}
	}
	return relevant > maxAttempts
}

// Hit implements RateLimiter.
func (m *MemoryRateLimiter) Hit(key string, decay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hits[key] = append(m.hits[key], memoryHit{at: time.Now(), decay: decay})
}

// Attempts implements RateLimiter.
func (m *MemoryRateLimiter) Attempts(key string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.alive(key, time.Now()))
}

// AvailableIn implements RateLimiter.
func (m *MemoryRateLimiter) AvailableIn(key string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	alive := m.alive(key, now)
	if len(alive) == 0 {
		return 0
	}
	decay := alive[len(alive)-1].decay
	secs := int(decay - now.Sub(alive[0].at))
	if secs < 0 {
		return 0
	}
	return secs
}

// Clear implements RateLimiter.
func (m *MemoryRateLimiter) Clear(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.hits, key)
}

var _ RateLimiter = (*MemoryRateLimiter)(nil)
