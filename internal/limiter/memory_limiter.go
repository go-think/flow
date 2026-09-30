package limiter

import (
	"html"
	"math"
	"regexp"
	"sync"
	"time"
)

var cleanKeyEntityPattern = regexp.MustCompile(`(?i)&([a-z])[a-z]+;`)

// CleanKey sanitizes a rate limiter key from unicode/HTML characters.
func CleanKey(key string) string {
	return cleanKeyEntityPattern.ReplaceAllString(html.EscapeString(key), "$1")
}

type memoryCounter struct {
	count     int
	expiresAt time.Time
}

// MemoryRateLimiter is an in-process RateLimiter implementing fixed-window semantics.
type MemoryRateLimiter struct {
	mu       sync.Mutex
	counters map[string]*memoryCounter
	timers   map[string]time.Time
}

// NewMemoryRateLimiter creates an in-process rate limiter.
func NewMemoryRateLimiter() *MemoryRateLimiter {
	return &MemoryRateLimiter{
		counters: make(map[string]*memoryCounter),
		timers:   make(map[string]time.Time),
	}
}

func (m *MemoryRateLimiter) counter(key string, now time.Time) *memoryCounter {
	c := m.counters[key]
	if c != nil && !now.Before(c.expiresAt) {
		delete(m.counters, key)
		return nil
	}
	return c
}

func (m *MemoryRateLimiter) hasTimer(key string, now time.Time) bool {
	timer, ok := m.timers[key]
	if !ok {
		return false
	}
	if !now.Before(timer) {
		delete(m.timers, key)
		return false
	}
	return true
}

// TooManyAttempts reports whether the key has exceeded maxAttempts within the decay window.
func (m *MemoryRateLimiter) TooManyAttempts(key string, maxAttempts int) bool {
	key = CleanKey(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if c := m.counter(key, now); c != nil && c.count >= maxAttempts {
		if m.hasTimer(key, now) {
			return true
		}
		delete(m.counters, key)
	}
	return false
}

// Hit increments the counter by one.
func (m *MemoryRateLimiter) Hit(key string, decay time.Duration) {
	m.Increment(key, decay, 1)
}

// Increment adds amount (default 1) to the counter for the key within a decay window.
func (m *MemoryRateLimiter) Increment(key string, decay time.Duration, amount ...int) int {
	n := 1
	if len(amount) > 0 {
		n = amount[0]
	}
	key = CleanKey(key)

	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()

	c := m.counter(key, now)
	if c == nil {
		c = &memoryCounter{expiresAt: now.Add(decay)}
		m.counters[key] = c
	}
	c.count += n

	if !m.hasTimer(key, now) {
		m.timers[key] = now.Add(decay)
	}

	return c.count
}

// Decrement subtracts amount (default 1) from the counter for the key within the given decay window.
func (m *MemoryRateLimiter) Decrement(key string, decay time.Duration, amount ...int) int {
	n := 1
	if len(amount) > 0 {
		n = amount[0]
	}
	return m.Increment(key, decay, -n)
}

// Attempts returns the current attempt count.
func (m *MemoryRateLimiter) Attempts(key string) int {
	key = CleanKey(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	if c := m.counter(key, time.Now()); c != nil {
		return c.count
	}
	return 0
}

// Remaining returns max(0, maxAttempts - attempts) for the key.
func (m *MemoryRateLimiter) Remaining(key string, maxAttempts int) int {
	remaining := maxAttempts - m.Attempts(key)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// RetriesLeft is an alias of Remaining.
func (m *MemoryRateLimiter) RetriesLeft(key string, maxAttempts int) int {
	return m.Remaining(key, maxAttempts)
}

// ResetAttempts clears the attempt counter for the key, reporting whether any state was removed.
func (m *MemoryRateLimiter) ResetAttempts(key string) bool {
	key = CleanKey(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.counters[key]; !ok {
		return false
	}
	delete(m.counters, key)
	return true
}

// AvailableIn returns the whole seconds until the lockout timer expires.
func (m *MemoryRateLimiter) AvailableIn(key string) int {
	key = CleanKey(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	timer, ok := m.timers[key]
	if !ok || !now.Before(timer) {
		delete(m.timers, key)
		return 0
	}
	secs := int(math.Ceil(timer.Sub(now).Seconds()))
	if secs < 0 {
		return 0
	}
	return secs
}

// Clear drops both the hits and the lockout timer for the key.
func (m *MemoryRateLimiter) Clear(key string) {
	key = CleanKey(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.counters, key)
	delete(m.timers, key)
}

// Attempt executes fn unless the key is limited, returning false when limited and fn's result otherwise.
func (m *MemoryRateLimiter) Attempt(key string, maxAttempts int, decay time.Duration, fn func() any) any {
	if m.TooManyAttempts(key, maxAttempts) {
		return false
	}
	result := fn()
	if result == nil {
		result = true
	}
	m.Hit(key, decay)
	return result
}
