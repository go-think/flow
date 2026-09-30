package limiter

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// RedisConnection represents the Redis command interface needed by DurationLimiter.
type RedisConnection interface {
	Eval(ctx context.Context, script string, keys []string, args ...any) (any, error)
}

const durationLimiterAcquireLua = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local now_sec = tonumber(ARGV[2])
local decay = tonumber(ARGV[3])
local max_locks = tonumber(ARGV[4])

-- Clean expired locks
redis.call('zremrangebyscore', key, '-inf', now - decay)

-- Count existing locks
local current = redis.call('zcard', key)

if current < max_locks then
    -- Add new lock
    redis.call('zadd', key, now, now)
    redis.call('expire', key, decay)
    return {1, now_sec + decay, max_locks - current - 1}
end

-- Get earliest lock timestamp for retry-after calculation
local earliest = redis.call('zrange', key, 0, 0, 'WITHSCORES')
local retry_after = decay
if #earliest > 0 then
    local earliest_time = tonumber(earliest[2])
    retry_after = math.max(0, math.ceil(earliest_time + decay - now))
end

return {0, now_sec + retry_after, 0}
`

const durationLimiterCheckLua = `
local key = KEYS[1]
local max_locks = tonumber(ARGV[1])
local now = tonumber(ARGV[2])

local current = redis.call('zcard', key)
if current >= max_locks then
    return 1
end

return 0
`

// DurationLimiter is a Redis-backed rate limiter implementing sliding-window duration locking.
type DurationLimiter struct {
	redis     RedisConnection
	name      string
	maxLocks  int
	decay     int
	DecaysAt  int64
	Remaining int
}

// NewDurationLimiter creates a DurationLimiter for the given key.
func NewDurationLimiter(redis RedisConnection, name string, maxLocks int, decaySeconds int) *DurationLimiter {
	return &DurationLimiter{
		redis:    redis,
		name:     name,
		maxLocks: maxLocks,
		decay:    decaySeconds,
	}
}

// Acquire attempts to acquire a slot and increments the counter via Redis Lua script.
func (d *DurationLimiter) Acquire(ctx context.Context) (bool, error) {
	now := time.Now()
	nowMicro := float64(now.UnixNano()) / 1e9
	nowSec := now.Unix()

	res, err := d.redis.Eval(ctx, durationLimiterAcquireLua, []string{d.name},
		fmt.Sprintf("%.4f", nowMicro),
		nowSec,
		d.decay,
		d.maxLocks,
	)
	if err != nil {
		return false, err
	}

	allowed, decaysAt, remaining := parseAcquireResult(res)
	d.DecaysAt = decaysAt
	if remaining < 0 {
		remaining = 0
	}
	d.Remaining = remaining
	return allowed, nil
}

// TooManyAttempts checks if the key has exceeded maxLocks without incrementing.
func (d *DurationLimiter) TooManyAttempts(ctx context.Context) (bool, error) {
	nowSec := time.Now().Unix()
	res, err := d.redis.Eval(ctx, durationLimiterCheckLua, []string{d.name},
		d.maxLocks,
		nowSec,
	)
	if err != nil {
		return false, err
	}
	val := toInt64(res)
	return val > 0, nil
}

func parseAcquireResult(res any) (bool, int64, int) {
	if slice, ok := res.([]any); ok && len(slice) >= 3 {
		allowed := toInt64(slice[0]) > 0
		decaysAt := toInt64(slice[1])
		remaining := int(toInt64(slice[2]))
		return allowed, decaysAt, remaining
	}
	return true, time.Now().Unix(), 0
}

func toInt64(v any) int64 {
	switch val := v.(type) {
	case int64:
		return val
	case int:
		return int64(val)
	case string:
		n, _ := strconv.ParseInt(val, 10, 64)
		return n
	case bool:
		if val {
			return 1
		}
		return 0
	default:
		return 0
	}
}
