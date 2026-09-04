package flow

import (
	"html"
	"math"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// RateLimiter is the contract used by the throttle middleware to count and
// check attempts for a key.
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

// cleanKeyEntityPattern strips HTML entities down to their first letter,
// mirroring the reference entity-decoding of the key.
var cleanKeyEntityPattern = regexp.MustCompile(`(?i)&([a-z])[a-z]+;`)

// CleanRateLimiterKey sanitizes a rate limiter key from unicode/HTML
// characters.
func CleanRateLimiterKey(key string) string {
	return cleanKeyEntityPattern.ReplaceAllString(html.EscapeString(key), "$1")
}

// memoryCounter is the fixed-window hit counter of one key, expiring decay
// after it was (re)created.
type memoryCounter struct {
	count     int
	expiresAt time.Time
}

// MemoryRateLimiter is an in-process RateLimiter implementing the reference implementation
// fixed-window semantics. It mirrors the two cache entries the reference implementation uses: the
// hit counter ("key") and the lockout timer ("key:timer"), both written with
// a decay TTL on the first hit and left alone by later hits. The timer alone
// decides AvailableIn and survives ResetAttempts; Clear drops both.
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

// counter returns the live counter for the key, dropping expired state.
// The caller must hold the mutex.
func (m *MemoryRateLimiter) counter(key string, now time.Time) *memoryCounter {
	c := m.counters[key]
	if c != nil && !now.Before(c.expiresAt) {
		delete(m.counters, key)
		return nil
	}
	return c
}

// hasTimer reports whether the lockout timer of the key is alive.
// The caller must hold the mutex.
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

// TooManyAttempts implements RateLimiter: the key is limited when the attempt
// count reached maxAttempts while the lockout timer is still alive; a count
// that reached the limit without a timer resets (the reference implementation: tooManyAttempts
// L128-139).
func (m *MemoryRateLimiter) TooManyAttempts(key string, maxAttempts int) bool {
	key = CleanRateLimiterKey(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if c := m.counter(key, now); c != nil && c.count >= maxAttempts {
		if m.hasTimer(key, now) {
			return true
		}
		// The count is over the limit but the timer expired: reset.
		delete(m.counters, key)
	}
	return false
}

// Hit implements RateLimiter, incrementing the counter by one
//.
func (m *MemoryRateLimiter) Hit(key string, decay time.Duration) {
	m.Increment(key, decay, 1)
}

// Increment adds amount (default 1) to the counter for the key within a decay
// window and returns the new count. On the first hit both the counter and the
// lockout timer are created with the decay window; later hits neither extend
// nor recreate them while they are alive (the timer is stored alongside the
// counter and both expire with the decay window).
func (m *MemoryRateLimiter) Increment(key string, decay time.Duration, amount ...int) int {
	n := 1
	if len(amount) > 0 {
		n = amount[0]
	}
	key = CleanRateLimiterKey(key)

	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()

	c := m.counter(key, now)
	if c == nil {
		c = &memoryCounter{expiresAt: now.Add(decay)}
		m.counters[key] = c
	}
	c.count += n

	// add(key:timer, availableAt(decay), decay): only written when absent.
	if !m.hasTimer(key, now) {
		m.timers[key] = now.Add(decay)
	}

	return c.count
}

// Decrement subtracts amount (default 1) from the counter for the key within
// the given decay window.
func (m *MemoryRateLimiter) Decrement(key string, decay time.Duration, amount ...int) int {
	n := 1
	if len(amount) > 0 {
		n = amount[0]
	}
	return m.Increment(key, decay, -n)
}

// Attempts implements RateLimiter, returning the current attempt count
//.
func (m *MemoryRateLimiter) Attempts(key string) int {
	key = CleanRateLimiterKey(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	if c := m.counter(key, time.Now()); c != nil {
		return c.count
	}
	return 0
}

// Remaining returns max(0, maxAttempts - attempts) for the key
//.
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

// ResetAttempts clears the attempt counter for the key, reporting whether any
// state was removed. The lockout timer is left alone
//.
func (m *MemoryRateLimiter) ResetAttempts(key string) bool {
	key = CleanRateLimiterKey(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.counters[key]; !ok {
		return false
	}
	delete(m.counters, key)
	return true
}

// AvailableIn implements RateLimiter: the whole seconds until the lockout
// timer expires, where the timer
// is set to first-hit time + decay).
func (m *MemoryRateLimiter) AvailableIn(key string) int {
	key = CleanRateLimiterKey(key)
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

// Clear implements RateLimiter: drops both the hits and the lockout timer for
// the key.
func (m *MemoryRateLimiter) Clear(key string) {
	key = CleanRateLimiterKey(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.counters, key)
	delete(m.timers, key)
}

// Attempt executes fn unless the key is limited, returning false when limited
// and fn's result otherwise (a nil result becomes true). The hit is only
// recorded when fn ran.
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

var _ RateLimiter = (*MemoryRateLimiter)(nil)

// Limit defines the rate limiting policy for an attempt window
//.
type Limit struct {
	// Key is the rate limit signature key.
	Key string
	// MaxAttempts is the number of attempts allowed within the decay window.
	MaxAttempts int
	// Decay is how long the window lasts.
	Decay time.Duration
	// AfterCallback, when set, decides after the response whether the request
	// still counts against the limit.
	AfterCallback ThrottleAfterCallback
	// ResponseCallback builds the response returned when the limit is
	// exceeded.
	ResponseCallback ThrottleResponseCallback
}

// PerSecond creates a new rate limit per second.
func PerSecond(maxAttempts int) *Limit {
	return &Limit{MaxAttempts: maxAttempts, Decay: time.Second}
}

// PerMinute creates a new rate limit per minute.
func PerMinute(maxAttempts int) *Limit {
	return &Limit{MaxAttempts: maxAttempts, Decay: time.Minute}
}

// PerMinutes creates a new rate limit per N minutes.
func PerMinutes(decayMinutes, maxAttempts int) *Limit {
	return &Limit{MaxAttempts: maxAttempts, Decay: time.Duration(decayMinutes) * time.Minute}
}

// PerHour creates a new rate limit per hour.
func PerHour(maxAttempts int) *Limit {
	return &Limit{MaxAttempts: maxAttempts, Decay: time.Hour}
}

// PerDay creates a new rate limit per day.
func PerDay(maxAttempts int) *Limit {
	return &Limit{MaxAttempts: maxAttempts, Decay: 24 * time.Hour}
}

// By sets the custom key for the rate limit.
func (l *Limit) By(key string) *Limit {
	l.Key = key
	return l
}

// After sets the callback deciding whether the limiter should be hit after
// the response was produced.
func (l *Limit) After(callback ThrottleAfterCallback) *Limit {
	l.AfterCallback = callback
	return l
}

// Response sets the callback that generates the response when the limit is
// exceeded.
func (l *Limit) Response(callback ThrottleResponseCallback) *Limit {
	l.ResponseCallback = callback
	return l
}

// FallbackKey returns a derived key used to disambiguate duplicate limit keys
//.
func (l *Limit) FallbackKey() string {
	prefix := ""
	if l.Key != "" {
		prefix = l.Key + ":"
	}
	return prefix + "attempts:" + strconv.Itoa(l.MaxAttempts) + ":decay:" + strconv.Itoa(int(l.Decay/time.Second))
}

// Unlimited marks a rate limit that never throttles
//.
type Unlimited struct {
	*Limit
}

// None creates a new unlimited rate limit.
func None() *Unlimited {
	return &Unlimited{Limit: &Limit{MaxAttempts: math.MaxInt, Decay: time.Minute}}
}

// RateLimiterRegistry manages named rate limiters.
type RateLimiterRegistry struct {
	mu       sync.RWMutex
	limiters map[string]func(request *Request) any
	backend  RateLimiter
}

// NewRateLimiterRegistry creates a new registry with the given backend.
func NewRateLimiterRegistry(backend RateLimiter) *RateLimiterRegistry {
	if backend == nil {
		backend = NewMemoryRateLimiter()
	}
	return &RateLimiterRegistry{
		limiters: make(map[string]func(request *Request) any),
		backend:  backend,
	}
}

var defaultRateLimiterRegistry = NewRateLimiterRegistry(NewMemoryRateLimiter())

// DefaultRateLimiterRegistry returns the default shared rate limiter registry.
func DefaultRateLimiterRegistry() *RateLimiterRegistry {
	return defaultRateLimiterRegistry
}

// For registers a named rate limiter.
func (r *RateLimiterRegistry) For(name string, callback func(request *Request) *Limit) {
	r.set(name, func(request *Request) any { return callback(request) })
}

// ForCallback registers a named rate limiter whose callback may return any of
// the supported results — *Limit, []*Limit (multiple buckets), *Unlimited (no
// limiting) or *Response (sent as-is) — mirroring the single Closure the reference implementation
// accepts from.
func (r *RateLimiterRegistry) ForCallback(name string, callback func(request *Request) any) {
	r.set(name, callback)
}

func (r *RateLimiterRegistry) set(name string, fn func(request *Request) any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.limiters == nil {
		r.limiters = make(map[string]func(request *Request) any)
	}
	r.limiters[name] = fn
}

// Limiter resolves a named rate limiter callback. The returned wrapper
// rewrites duplicate keys in []*Limit results to their fallback keys so every
// bucket stays addressable.
func (r *RateLimiterRegistry) Limiter(name string) (func(request *Request) any, bool) {
	r.mu.RLock()
	fn, ok := r.limiters[name]
	r.mu.RUnlock()
	if !ok || fn == nil {
		return nil, false
	}
	return func(request *Request) any {
		result := fn(request)
		limits, isSlice := result.([]*Limit)
		if !isSlice {
			return result
		}
		counts := make(map[string]int, len(limits))
		for _, l := range limits {
			if l != nil {
				counts[l.Key]++
			}
		}
		rewritten := make([]*Limit, len(limits))
		for i, l := range limits {
			if l != nil && counts[l.Key] > 1 {
				clone := *l
				clone.Key = l.FallbackKey()
				rewritten[i] = &clone
				continue
			}
			rewritten[i] = l
		}
		return rewritten
	}, true
}
