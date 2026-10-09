package flow

import (
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/go-think/flow/internal/limiter"
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

// CleanRateLimiterKey sanitizes a rate limiter key from unicode/HTML characters.
func CleanRateLimiterKey(key string) string {
	return limiter.CleanKey(key)
}

// MemoryRateLimiter is an in-process RateLimiter implementing fixed-window semantics.
type MemoryRateLimiter = limiter.MemoryRateLimiter

// NewMemoryRateLimiter creates an in-process rate limiter.
func NewMemoryRateLimiter() *MemoryRateLimiter {
	return limiter.NewMemoryRateLimiter()
}

var _ RateLimiter = (*MemoryRateLimiter)(nil)

// Limit defines the rate limiting policy for an attempt window.
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

// FallbackKey returns a derived key used to disambiguate duplicate limit keys.
func (l *Limit) FallbackKey() string {
	prefix := ""
	if l.Key != "" {
		prefix = l.Key + ":"
	}
	return prefix + "attempts:" + strconv.Itoa(l.MaxAttempts) + ":decay:" + strconv.Itoa(int(l.Decay/time.Second))
}

// Unlimited marks a rate limit that never throttles.
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
// the supported results: *Limit, []*Limit (multiple buckets), *Unlimited (no
// limiting) or *Response (sent as-is).
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
