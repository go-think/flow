package limiter

import (
	"context"
	"testing"
	"time"
)

type mockRedis struct {
	calls int
}

func (m *mockRedis) Eval(ctx context.Context, script string, keys []string, args ...any) (any, error) {
	m.calls++
	return []any{int64(1), time.Now().Unix() + 60, int64(9)}, nil
}

func TestMemoryLimiter(t *testing.T) {
	lim := NewMemoryRateLimiter()
	key := "test:user&amp;id"

	if lim.Attempts(key) != 0 {
		t.Fatalf("expected 0 attempts initially")
	}

	lim.Hit(key, time.Minute)
	if lim.Attempts(key) != 1 {
		t.Fatalf("expected 1 attempt after hit")
	}

	if lim.TooManyAttempts(key, 2) {
		t.Fatalf("expected not too many attempts")
	}

	lim.Hit(key, time.Minute)
	if !lim.TooManyAttempts(key, 2) {
		t.Fatalf("expected too many attempts after 2 hits")
	}

	lim.Clear(key)
	if lim.Attempts(key) != 0 {
		t.Fatalf("expected 0 attempts after clear")
	}
}

func TestDurationLimiter(t *testing.T) {
	redis := &mockRedis{}
	dl := NewDurationLimiter(redis, "test-limit", 10, 60)

	allowed, err := dl.Acquire(context.Background())
	if err != nil || !allowed {
		t.Fatalf("expected acquire to succeed: %v, %v", allowed, err)
	}
	if redis.calls != 1 {
		t.Fatalf("expected 1 redis call, got %d", redis.calls)
	}
}
