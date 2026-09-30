package flow

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-think/flow/internal/limiter"
)

// RedisConnection represents the Redis command interface needed by DurationLimiter.
type RedisConnection = limiter.RedisConnection

// RedisFactory represents the Redis connection factory contract.
type RedisFactory interface {
	Connection(name ...string) RedisConnection
}

// DurationLimiter is a Redis-backed rate limiter implementing sliding-window duration locking.
type DurationLimiter = limiter.DurationLimiter

// NewDurationLimiter creates a DurationLimiter for the given key.
func NewDurationLimiter(redis RedisConnection, name string, maxLocks int, decaySeconds int) *DurationLimiter {
	return limiter.NewDurationLimiter(redis, name, maxLocks, decaySeconds)
}

// ThrottleRequestsWithRedis is a rate-limiting middleware backed by Redis.
type ThrottleRequestsWithRedis struct {
	redis        RedisConnection
	redisFactory RedisFactory
	connection   string
	maxAttempts  int
	decay        time.Duration
	decaysAt     map[string]int64
	remaining    map[string]int
	mu           sync.RWMutex
}

// NewThrottleRequestsWithRedis creates a new ThrottleRequestsWithRedis middleware.
func NewThrottleRequestsWithRedis(redis RedisConnection, maxAttempts int, decay time.Duration) *ThrottleRequestsWithRedis {
	return &ThrottleRequestsWithRedis{
		redis:       redis,
		maxAttempts: maxAttempts,
		decay:       decay,
		decaysAt:    make(map[string]int64),
		remaining:   make(map[string]int),
	}
}

// NewThrottleRequestsWithRedisFromFactory creates a new ThrottleRequestsWithRedis from a RedisFactory.
func NewThrottleRequestsWithRedisFromFactory(factory RedisFactory, connection string, maxAttempts int, decay time.Duration) *ThrottleRequestsWithRedis {
	return &ThrottleRequestsWithRedis{
		redisFactory: factory,
		connection:   connection,
		maxAttempts:  maxAttempts,
		decay:        decay,
		decaysAt:     make(map[string]int64),
		remaining:    make(map[string]int),
	}
}

// resolveConnection retrieves the Redis connection from direct instance, factory, or container.
func (m *ThrottleRequestsWithRedis) resolveConnection(req *Request) RedisConnection {
	if m.redis != nil {
		return m.redis
	}
	if m.redisFactory != nil {
		if m.connection != "" {
			return m.redisFactory.Connection(m.connection)
		}
		return m.redisFactory.Connection()
	}
	// Attempt resolving from Container
	if req != nil && req.Route() != nil && req.Route().Router() != nil {
		if r, ok := req.Route().Router().(*router); ok && r.container != nil {
			if r.container.Bound("redis") {
				raw := r.container.Make("redis")
				if conn, ok := raw.(RedisConnection); ok {
					return conn
				}
				if factory, ok := raw.(RedisFactory); ok {
					if m.connection != "" {
						return factory.Connection(m.connection)
					}
					return factory.Connection()
				}
			}
		}
	}
	return nil
}

// Process implements the Handler interface for middleware execution.
func (m *ThrottleRequestsWithRedis) Process(req *Request, next Closure) any {
	conn := m.resolveConnection(req)
	if conn == nil {
		// If Redis is not available or configured, pass through to avoid breaking requests
		return next(req)
	}

	ctx := req.Context()
	key := m.resolveRequestSignature(req)
	decaySeconds := int(m.decay.Seconds())
	if decaySeconds <= 0 {
		decaySeconds = 60
	}

	limiter := NewDurationLimiter(conn, key, m.maxAttempts, decaySeconds)

	// Check if already throttled
	tooMany, err := limiter.TooManyAttempts(ctx)
	if err == nil && tooMany {
		retryAfter := int(limiter.DecaysAt - time.Now().Unix())
		if retryAfter <= 0 {
			retryAfter = 1
		}
		res := NewResponse().SetCode(http.StatusTooManyRequests).SetContent("Too Many Attempts.")
		res.Header("Retry-After", strconv.Itoa(retryAfter))
		res.Header("X-RateLimit-Limit", strconv.Itoa(m.maxAttempts))
		res.Header("X-RateLimit-Remaining", "0")
		return res
	}

	// Acquire slot
	allowed, err := limiter.Acquire(ctx)
	if err == nil && !allowed {
		retryAfter := int(limiter.DecaysAt - time.Now().Unix())
		if retryAfter <= 0 {
			retryAfter = 1
		}
		res := NewResponse().SetCode(http.StatusTooManyRequests).SetContent("Too Many Attempts.")
		res.Header("Retry-After", strconv.Itoa(retryAfter))
		res.Header("X-RateLimit-Limit", strconv.Itoa(m.maxAttempts))
		res.Header("X-RateLimit-Remaining", "0")
		return res
	}

	result := next(req)

	// Add rate-limiting headers
	if resp, ok := result.(*Response); ok {
		resp.Header("X-RateLimit-Limit", strconv.Itoa(m.maxAttempts))
		resp.Header("X-RateLimit-Remaining", strconv.Itoa(limiter.Remaining))
	}
	return result
}

func (m *ThrottleRequestsWithRedis) resolveRequestSignature(req *Request) string {
	host := ""
	if httpReq := req.GetHttpRequest(); httpReq != nil {
		host = httpReq.Host
		if idx := strings.Index(host, ":"); idx != -1 {
			host = host[:idx]
		}
	}
	ip := req.ClientIP()
	if ip == "" {
		ip = "127.0.0.1"
	}
	return "flow:throttle:" + CleanRateLimiterKey(host+"|"+ip)
}
