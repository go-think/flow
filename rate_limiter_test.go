package flow

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryRateLimiter_FixedWindow(t *testing.T) {
	rl := NewMemoryRateLimiter()
	key := "fixed-window"

	// The window starts at the first hit: the timer is first-hit + decay and
	// later hits do not extend it — even when they pass a longer decay
	//.
	assert.Equal(t, 1, rl.Increment(key, 2*time.Second, 1))
	assert.Equal(t, 2, rl.Increment(key, 10*time.Second))
	assert.Equal(t, 2, rl.Attempts(key))

	availableIn := rl.AvailableIn(key)
	assert.GreaterOrEqual(t, availableIn, 1)
	assert.LessOrEqual(t, availableIn, 2)

	assert.True(t, rl.TooManyAttempts(key, 2))
	assert.False(t, rl.TooManyAttempts(key, 3))
	assert.Equal(t, 1, rl.Remaining(key, 3))
	assert.Equal(t, 1, rl.RetriesLeft(key, 3))

	// Once the window expired the counter and the timer are both gone:
	// attempts reset and no lockout remains.
	time.Sleep(2100 * time.Millisecond)
	assert.Equal(t, 0, rl.Attempts(key))
	assert.False(t, rl.TooManyAttempts(key, 2))
	assert.Equal(t, 0, rl.AvailableIn(key))
}

func TestMemoryRateLimiter_TooManyAttemptsRequiresTimer(t *testing.T) {
	rl := NewMemoryRateLimiter()
	key := "timer"

	rl.Increment(key, 250*time.Millisecond, 5)
	assert.True(t, rl.TooManyAttempts(key, 5))

	// After expiry the stale count disappears: not limited anymore, and the
	// counter is reset.
	time.Sleep(300 * time.Millisecond)
	assert.False(t, rl.TooManyAttempts(key, 5))
	assert.Equal(t, 0, rl.Attempts(key))
}

func TestMemoryRateLimiter_IncrementDecrementAmounts(t *testing.T) {
	rl := NewMemoryRateLimiter()
	key := "amounts"

	assert.Equal(t, 3, rl.Increment(key, time.Minute, 3))
	assert.Equal(t, 4, rl.Increment(key, time.Minute))
	assert.Equal(t, 2, rl.Decrement(key, time.Minute, 2))
	assert.Equal(t, 1, rl.Decrement(key, time.Minute))
	assert.Equal(t, 1, rl.Attempts(key))
}

func TestMemoryRateLimiter_ResetAttemptsKeepsTimerClearDropsIt(t *testing.T) {
	rl := NewMemoryRateLimiter()
	key := "reset-clear"

	rl.Increment(key, time.Minute, 2)
	require.True(t, rl.TooManyAttempts(key, 2))
	require.Positive(t, rl.AvailableIn(key))

	// resetAttempts only clears the counter, the timer survives
	//.
	assert.True(t, rl.ResetAttempts(key))
	assert.Equal(t, 0, rl.Attempts(key))
	assert.Greater(t, rl.AvailableIn(key), 0)
	assert.False(t, rl.ResetAttempts(key), "resetting again reports nothing was removed")

	// clear drops both the counter and the timer
	//.
	rl.Hit(key, time.Minute)
	rl.Clear(key)
	assert.Equal(t, 0, rl.Attempts(key))
	assert.Equal(t, 0, rl.AvailableIn(key))
}

func TestMemoryRateLimiter_Attempt(t *testing.T) {
	rl := NewMemoryRateLimiter()
	key := "attempt"

	result := rl.Attempt(key, 2, time.Minute, func() any { return "ran" })
	assert.Equal(t, "ran", result)
	assert.Equal(t, 1, rl.Attempts(key))

	result = rl.Attempt(key, 2, time.Minute, func() any { return "ran-again" })
	assert.Equal(t, "ran-again", result)
	assert.Equal(t, 2, rl.Attempts(key))

	// Limited: the callback must not run and nothing more is counted.
	called := false
	result = rl.Attempt(key, 2, time.Minute, func() any {
		called = true
		return "should-not-run"
	})
	assert.Equal(t, false, result)
	assert.False(t, called)
	assert.Equal(t, 2, rl.Attempts(key))

	// A nil callback result becomes true → true).
	result = rl.Attempt("other-key", 1, time.Minute, func() any { return nil })
	assert.Equal(t, true, result)
	assert.Equal(t, 1, rl.Attempts("other-key"))
}

func TestMemoryRateLimiter_KeysAreCleaned(t *testing.T) {
	rl := NewMemoryRateLimiter()

	// A key carrying HTML/unicode characters is sanitized before storage, so
	// both spellings address the same bucket.
	rl.Increment("a<b>", time.Minute, 1)
	assert.Equal(t, 1, rl.Attempts("albg"))
	assert.Equal(t, 1, rl.Attempts("a<b>"))
}

func TestCleanRateLimiterKey(t *testing.T) {
	assert.Equal(t, "albgac", CleanRateLimiterKey("a<b>&c"))
	assert.Equal(t, "user:1|10.0.0.1", CleanRateLimiterKey("user:1|10.0.0.1"))
	assert.Equal(t, "", CleanRateLimiterKey(""))
}

func TestLimit_ConstructorsAndFallbackKey(t *testing.T) {
	assert.Equal(t, &Limit{MaxAttempts: 5, Decay: time.Second}, PerSecond(5))
	assert.Equal(t, &Limit{MaxAttempts: 60, Decay: time.Minute}, PerMinute(60))
	assert.Equal(t, &Limit{MaxAttempts: 10, Decay: 5 * time.Minute}, PerMinutes(5, 10))
	assert.Equal(t, &Limit{MaxAttempts: 100, Decay: time.Hour}, PerHour(100))
	assert.Equal(t, &Limit{MaxAttempts: 1000, Decay: 24 * time.Hour}, PerDay(1000))

	unlimited := None()
	assert.Equal(t, math.MaxInt, unlimited.MaxAttempts)

	limit := PerMinute(2).By("user-upload")
	assert.Equal(t, "user-upload:attempts:2:decay:60", limit.FallbackKey())
	assert.Equal(t, "attempts:0:decay:0", (&Limit{}).FallbackKey())
	assert.Equal(t, "attempts:10:decay:1", PerSecond(10).FallbackKey())
}

func TestLimit_AfterAndResponseCallbacks(t *testing.T) {
	afterCalled := false
	responseCalled := false

	limit := PerMinute(5).
		After(func(response any) bool {
			afterCalled = true
			return true
		}).
		Response(func(request *Request, headers map[string]string) *Response {
			responseCalled = true
			return NewResponse().SetCode(429)
		})

	require.NotNil(t, limit.AfterCallback)
	assert.True(t, limit.AfterCallback(nil))
	require.NotNil(t, limit.ResponseCallback)
	limit.ResponseCallback(nil, map[string]string{})
	assert.True(t, afterCalled)
	assert.True(t, responseCalled)
}

func TestRateLimiterRegistry_NamedLimiterResults(t *testing.T) {
	registry := NewRateLimiterRegistry(nil)

	// For keeps accepting the plain *Limit callback shape.
	registry.For("plain", func(request *Request) *Limit {
		return PerMinute(3).By("plain-key")
	})
	limiterFn, found := registry.Limiter("plain")
	require.True(t, found)
	limit, ok := limiterFn(nil).(*Limit)
	require.True(t, ok)
	assert.Equal(t, 3, limit.MaxAttempts)
	assert.Equal(t, "plain-key", limit.Key)

	// Missing names resolve to found = false.
	_, found = registry.Limiter("flow-test-missing-registry-name")
	assert.False(t, found)
}

func TestRateLimiterRegistry_DuplicateKeysUseFallbackKeys(t *testing.T) {
	registry := NewRateLimiterRegistry(nil)
	registry.ForCallback("dup", func(request *Request) any {
		return []*Limit{
			PerMinute(1).By("same"),
			PerMinute(2).By("same"),
			PerMinute(3).By("unique"),
		}
	})

	limiterFn, found := registry.Limiter("dup")
	require.True(t, found)

	limits, ok := limiterFn(nil).([]*Limit)
	require.True(t, ok)
	require.Len(t, limits, 3)

	assert.Equal(t, "same:attempts:1:decay:60", limits[0].Key)
	assert.Equal(t, "same:attempts:2:decay:60", limits[1].Key)
	assert.Equal(t, "unique", limits[2].Key, "non-duplicated keys are untouched")
	assert.Equal(t, 1, limits[0].MaxAttempts)
	assert.Equal(t, 2, limits[1].MaxAttempts)

	// The rewritten keys are unique so every bucket stays addressable.
	assert.NotEqual(t, limits[0].Key, limits[1].Key)
}

func TestRateLimiterRegistry_DuplicateDetectionIsValueBased(t *testing.T) {
	registry := NewRateLimiterRegistry(nil)
	registry.ForCallback("dup-value", func(request *Request) any {
		first := PerMinute(1).By("same")
		second := PerMinute(1).By("same")
		return []*Limit{first, second}
	})

	limiterFn, _ := registry.Limiter("dup-value")
	limits, ok := limiterFn(nil).([]*Limit)
	require.True(t, ok)

	// Both occurrences of a duplicated key are rewritten
	//).
	assert.Equal(t, "same:attempts:1:decay:60", limits[0].Key)
	assert.Equal(t, "same:attempts:1:decay:60", limits[1].Key)
}
