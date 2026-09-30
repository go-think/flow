package flow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type mockRedisContainer struct {
	instances map[string]any
}

func newMockRedisContainer() *mockRedisContainer {
	return &mockRedisContainer{instances: make(map[string]any)}
}

func (c *mockRedisContainer) Make(key string) any {
	return c.instances[key]
}

func (c *mockRedisContainer) Bound(key string) bool {
	_, ok := c.instances[key]
	return ok
}

func (c *mockRedisContainer) Instance(key string, instance any) {
	c.instances[key] = instance
}

type mockRedisConn struct {
	evalCalled int
	evalFunc   func(ctx context.Context, script string, keys []string, args ...any) (any, error)
}

func (m *mockRedisConn) Eval(ctx context.Context, script string, keys []string, args ...any) (any, error) {
	m.evalCalled++
	if m.evalFunc != nil {
		return m.evalFunc(ctx, script, keys, args...)
	}
	return []any{int64(1), time.Now().Unix() + 60, int64(1)}, nil
}

func TestThrottleRequestsWithRedis_DirectConnection(t *testing.T) {
	redisMock := &mockRedisConn{}
	r := NewRouter(nil, nil)

	r.Middleware(NewThrottleRequestsWithRedis(redisMock, 2, time.Minute)).
		Get("/redis-test", func() string {
			return "redis-ok"
		})

	req := httptest.NewRequest("GET", "/redis-test", nil)
	resp := r.Dispatch(req)

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode())
	}
	if resp.GetContent() != "redis-ok" {
		t.Fatalf("expected 'redis-ok', got '%s'", resp.GetContent())
	}
	if redisMock.evalCalled == 0 {
		t.Fatalf("expected Redis Eval to be called, got 0")
	}
	if resp.Headers().Get("X-RateLimit-Limit") != "2" {
		t.Fatalf("expected X-RateLimit-Limit: 2, got %s", resp.Headers().Get("X-RateLimit-Limit"))
	}
}

func TestThrottleRequestsWithRedis_ResolvedFromContainer(t *testing.T) {
	container := newMockRedisContainer()
	redisMock := &mockRedisConn{}
	container.Instance("redis", redisMock)

	r := NewRouter(nil, container)

	r.Middleware(NewThrottleRequestsWithRedis(nil, 5, time.Minute)).
		Get("/container-redis", func() string {
			return "container-ok"
		})

	req := httptest.NewRequest("GET", "/container-redis", nil)
	resp := r.Dispatch(req)

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode())
	}
	if resp.GetContent() != "container-ok" {
		t.Fatalf("expected 'container-ok', got '%s'", resp.GetContent())
	}
	if redisMock.evalCalled == 0 {
		t.Fatalf("expected Redis connection from container to be invoked")
	}
}

func TestThrottleRequestsWithRedis_LimitExceeded(t *testing.T) {
	redisMock := &mockRedisConn{
		evalFunc: func(ctx context.Context, script string, keys []string, args ...any) (any, error) {
			return []any{int64(0), time.Now().Unix() + 30, int64(0)}, nil
		},
	}
	r := NewRouter(nil, nil)

	r.Middleware(NewThrottleRequestsWithRedis(redisMock, 1, time.Minute)).
		Get("/blocked", func() string {
			return "should-not-reach"
		})

	req := httptest.NewRequest("GET", "/blocked", nil)
	resp := r.Dispatch(req)

	if resp.StatusCode() != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests, got %d", resp.StatusCode())
	}
	if resp.Headers().Get("X-RateLimit-Remaining") != "0" {
		t.Fatalf("expected remaining: 0, got %s", resp.Headers().Get("X-RateLimit-Remaining"))
	}
	if resp.Headers().Get("Retry-After") == "" {
		t.Fatalf("expected Retry-After header")
	}
}

type testContainerRateLimiter struct {
	called bool
}

func (l *testContainerRateLimiter) TooManyAttempts(key string, maxAttempts int) bool {
	l.called = true
	return false
}
func (l *testContainerRateLimiter) Hit(key string, decay time.Duration) {}
func (l *testContainerRateLimiter) Attempts(key string) int             { return 1 }
func (l *testContainerRateLimiter) AvailableIn(key string) int          { return 0 }
func (l *testContainerRateLimiter) Clear(key string)                    {}

func TestThrottleMiddleware_RateLimiterFromContainer(t *testing.T) {
	container := newMockRedisContainer()
	customLimiter := &testContainerRateLimiter{}
	container.Instance("rate.limiter", customLimiter)

	r := NewRouter(nil, container)

	r.Middleware(NewThrottleMiddleware(nil, 10, time.Minute)).
		Get("/custom-limiter", func() string {
			return "ok"
		})

	req := httptest.NewRequest("GET", "/custom-limiter", nil)
	resp := r.Dispatch(req)

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode())
	}
	if !customLimiter.called {
		t.Fatalf("expected custom RateLimiter from container to be used")
	}
}
