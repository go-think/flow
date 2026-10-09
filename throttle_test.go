package flow

import (
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newThrottleRequest builds a request with a fixed host and client address so
// the throttle key ("host|ip") is deterministic.
func newThrottleRequest(target, remoteAddr string) *Request {
	httpReq, err := http.NewRequest("GET", target, nil)
	if err != nil {
		panic(err)
	}
	httpReq.RemoteAddr = remoteAddr
	return NewRequest(httpReq)
}

func throttleNext() (Closure, *int) {
	calls := 0
	return func(req *Request) any {
		calls++
		return NewResponse().SetContent("ok")
	}, &calls
}

func TestThrottle_HeadersOnSuccessAndLimit(t *testing.T) {
	rl := NewMemoryRateLimiter()
	h := NewThrottleMiddleware(rl, 2, time.Minute)

	next, calls := throttleNext()

	// 1st request: allowed, remaining 1, no retry headers.
	res1 := h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), next).(*Response)
	assert.Equal(t, http.StatusOK, res1.GetCode())
	assert.Equal(t, "2", res1.Headers().Get("X-RateLimit-Limit"))
	assert.Equal(t, "1", res1.Headers().Get("X-RateLimit-Remaining"))
	assert.Empty(t, res1.Headers().Get("Retry-After"))
	assert.Empty(t, res1.Headers().Get("X-RateLimit-Reset"))

	// 2nd request: allowed, remaining 0.
	res2 := h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), next).(*Response)
	assert.Equal(t, http.StatusOK, res2.GetCode())
	assert.Equal(t, "0", res2.Headers().Get("X-RateLimit-Remaining"))

	// 3rd request: 429 with Retry-After and X-RateLimit-Reset = now + retryAfter.
	before := time.Now().Unix()
	res3 := h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), next).(*Response)
	assert.Equal(t, http.StatusTooManyRequests, res3.GetCode())
	assert.Equal(t, "Too Many Attempts.", res3.GetContent())
	assert.Equal(t, "2", res3.Headers().Get("X-RateLimit-Limit"))
	assert.Equal(t, "0", res3.Headers().Get("X-RateLimit-Remaining"))

	retryAfter, err := strconv.Atoi(res3.Headers().Get("Retry-After"))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, retryAfter, 1)
	assert.LessOrEqual(t, retryAfter, 60)

	reset, err := strconv.Atoi(res3.Headers().Get("X-RateLimit-Reset"))
	require.NoError(t, err)
	assert.Equal(t, before+int64(retryAfter), int64(reset))
	assert.Equal(t, 2, *calls, "throttled request must not reach the handler")
}

func TestThrottle_KeyIsHostAndIPNotPathOrMethod(t *testing.T) {
	rl := NewMemoryRateLimiter()
	h := NewThrottleMiddleware(rl, 1, time.Minute)
	next, _ := throttleNext()

	// Same client, different path/method: one shared bucket.
	res1 := h.Process(newThrottleRequest("http://example.com/one", "10.0.0.1:1111"), next).(*Response)
	assert.Equal(t, http.StatusOK, res1.GetCode())

	res2 := h.Process(newThrottleRequest("http://example.com/two", "10.0.0.1:1111"), next).(*Response)
	assert.Equal(t, http.StatusTooManyRequests, res2.GetCode())

	// Different client IP: separate bucket.
	res3 := h.Process(newThrottleRequest("http://example.com/one", "10.0.0.2:2222"), next).(*Response)
	assert.Equal(t, http.StatusOK, res3.GetCode())
}

func TestThrottle_RequestSignatureHashing(t *testing.T) {
	rl := NewMemoryRateLimiter()
	h := NewThrottleMiddleware(rl, 5, time.Minute).(*ThrottleMiddleware)

	// Keys are hashed by default.
	req := newThrottleRequest("http://example.com:8080/api", "10.0.0.9:5555")
	hashed := h.resolveRequestSignature(req)
	sum := sha1.Sum([]byte("example.com|10.0.0.9"))
	assert.Equal(t, hex.EncodeToString(sum[:]), hashed)

	// Disabling hashing keeps the raw "host|ip" identifier, with the port
	// stripped from the Host header.
	raw := h.ShouldHashKeys(false).resolveRequestSignature(req)
	assert.Equal(t, "example.com|10.0.0.9", raw)
}

func TestThrottle_StringPolicySpec(t *testing.T) {
	rl := NewMemoryRateLimiter()
	// "guest|user" resolves to the guest segment without an auth component.
	h := NewThrottleMiddlewareWith(rl, "2|10", time.Minute, "spec:")
	next, _ := throttleNext()

	res1 := h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), next).(*Response)
	res2 := h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), next).(*Response)
	res3 := h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), next).(*Response)
	assert.Equal(t, http.StatusOK, res1.GetCode())
	assert.Equal(t, http.StatusOK, res2.GetCode())
	assert.Equal(t, http.StatusTooManyRequests, res3.GetCode())
	assert.Equal(t, "2", res3.Headers().Get("X-RateLimit-Limit"))
}

func TestThrottle_NonNumericSpecPanicsMissingLimiter(t *testing.T) {
	h := NewThrottleMiddlewareWith(NewMemoryRateLimiter(), "gold", time.Minute, "")
	assert.Panics(t, func() {
		h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), func(req *Request) any {
			return NewResponse()
		})
	})
}

func TestThrottle_NamedLimiterUnlimited(t *testing.T) {
	registry := DefaultRateLimiterRegistry()
	registry.ForCallback("flow-test-unlimited", func(request *Request) any {
		return None()
	})

	h := NewNamedThrottleMiddleware("flow-test-unlimited")
	next, calls := throttleNext()

	for i := 0; i < 5; i++ {
		res := h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), next).(*Response)
		assert.Equal(t, http.StatusOK, res.GetCode())
		assert.Empty(t, res.Headers().Get("X-RateLimit-Limit"), "unlimited requests are not counted nor decorated")
	}
	assert.Equal(t, 5, *calls)
}

func TestThrottle_NamedLimiterResponsePassthrough(t *testing.T) {
	registry := DefaultRateLimiterRegistry()
	registry.ForCallback("flow-test-response", func(request *Request) any {
		return NewResponse().SetCode(http.StatusTeapot).SetContent("teapot")
	})

	h := NewNamedThrottleMiddleware("flow-test-response")
	next, calls := throttleNext()

	res := h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), next).(*Response)
	assert.Equal(t, http.StatusTeapot, res.GetCode())
	assert.Equal(t, "teapot", res.GetContent())
	assert.Equal(t, 0, *calls, "the response short-circuits the pipeline")
}

func TestThrottle_MultipleLimitsAreAllCheckedThenHit(t *testing.T) {
	registry := DefaultRateLimiterRegistry()
	registry.ForCallback("flow-test-multi", func(request *Request) any {
		return []*Limit{
			PerMinute(1).By("guest"),
			PerMinute(5).By("member"),
		}
	})

	h := NewNamedThrottleMiddleware("flow-test-multi").(*ThrottleMiddleware)
	h.ShouldHashKeys(false) // predictable bucket keys: "name:key"
	next, _ := throttleNext()

	res1 := h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), next).(*Response)
	assert.Equal(t, http.StatusOK, res1.GetCode())

	// All buckets are checked before any hit: the exhausted "guest" bucket
	// aborts the request without touching "member".
	res2 := h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), next).(*Response)
	assert.Equal(t, http.StatusTooManyRequests, res2.GetCode())
	backend := DefaultRateLimiterRegistry().backend
	assert.Equal(t, 1, backend.Attempts("flow-test-multi:guest"))
	assert.Equal(t, 1, backend.Attempts("flow-test-multi:member"), "no hit may be recorded once a bucket is over the limit")
}

func TestThrottle_DuplicateLimitKeysFallBack(t *testing.T) {
	registry := DefaultRateLimiterRegistry()
	registry.ForCallback("flow-test-dup", func(request *Request) any {
		return []*Limit{
			PerMinute(1).By("same"),
			PerMinute(3).By("same"),
		}
	})

	limiterFn, found := registry.Limiter("flow-test-dup")
	require.True(t, found)

	result := limiterFn(nil)
	limits, ok := result.([]*Limit)
	require.True(t, ok)
	require.Len(t, limits, 2)
	assert.Equal(t, "same:attempts:1:decay:60", limits[0].Key)
	assert.Equal(t, "same:attempts:3:decay:60", limits[1].Key)
	assert.Equal(t, 1, limits[0].MaxAttempts)
	assert.Equal(t, 3, limits[1].MaxAttempts)
}

func TestThrottle_LimitResponseCallbackBuilds429(t *testing.T) {
	registry := DefaultRateLimiterRegistry()
	registry.ForCallback("flow-test-resp-cb", func(request *Request) any {
		return PerMinute(1).By("cb").Response(func(request *Request, headers map[string]string) *Response {
			res := NewResponse().SetCode(http.StatusTooManyRequests).
				SetContent("custom:" + headers["Retry-After"])
			for name, value := range headers {
				res.Header(name, value)
			}
			return res
		})
	})

	h := NewNamedThrottleMiddleware("flow-test-resp-cb")
	next, calls := throttleNext()

	res1 := h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), next).(*Response)
	assert.Equal(t, http.StatusOK, res1.GetCode())

	res2 := h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), next).(*Response)
	assert.Equal(t, http.StatusTooManyRequests, res2.GetCode())
	assert.Contains(t, res2.GetContent(), "custom:")
	retryAfter, err := strconv.Atoi(res2.Headers().Get("Retry-After"))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, retryAfter, 1)
	assert.Equal(t, 1, *calls, "the custom response replaces the throttled request")
}

func TestThrottle_LimitAfterCallbackControlsCounting(t *testing.T) {
	registry := DefaultRateLimiterRegistry()

	// afterCallback returning false: the request is never counted.
	registry.ForCallback("flow-test-after-no", func(request *Request) any {
		return PerMinute(1).By("no").After(func(response any) bool { return false })
	})
	hNo := NewNamedThrottleMiddleware("flow-test-after-no")
	nextNo, _ := throttleNext()
	for i := 0; i < 5; i++ {
		res := hNo.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), nextNo).(*Response)
		assert.Equal(t, http.StatusOK, res.GetCode())
	}

	// afterCallback returning true: the request counts after the response.
	registry.ForCallback("flow-test-after-yes", func(request *Request) any {
		return PerMinute(2).By("yes").After(func(response any) bool { return true })
	})
	hYes := NewNamedThrottleMiddleware("flow-test-after-yes")
	nextYes, _ := throttleNext()
	res1 := hYes.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), nextYes).(*Response)
	assert.Equal(t, http.StatusOK, res1.GetCode())
	assert.Equal(t, "1", res1.Headers().Get("X-RateLimit-Remaining"))
	res2 := hYes.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), nextYes).(*Response)
	assert.Equal(t, http.StatusOK, res2.GetCode())
	res3 := hYes.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), nextYes).(*Response)
	assert.Equal(t, http.StatusTooManyRequests, res3.GetCode())
}

func TestThrottle_NamedLimiterMissingPanics(t *testing.T) {
	h := NewNamedThrottleMiddleware("flow-test-never-registered")
	assert.Panics(t, func() {
		h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), func(req *Request) any {
			return NewResponse()
		})
	})
}

func TestThrottle_NamedLimiterMissingWithExplicitPolicyPanics(t *testing.T) {
	// A non-numeric limiter name that is not registered always panics with
	// MissingRateLimiterError — even when an explicit maxAttempts was provided
	// alongside; there is no silent fallback to the plain policy.
	rl := NewMemoryRateLimiter()
	h := NewThrottleMiddlewareNamed(rl, "flow-test-fallback", 1, time.Minute)

	defer func() {
		r := recover()
		require.NotNil(t, r, "an unregistered named limiter must panic")
		err, ok := r.(*MissingRateLimiterError)
		require.True(t, ok, "panic value must be a MissingRateLimiterError, got %T", r)
		assert.Equal(t, "Rate limiter [flow-test-fallback] is not defined.", err.Error())
	}()
	h.Process(newThrottleRequest("http://example.com/api", "10.0.0.31:1111"), func(req *Request) any {
		return NewResponse()
	})
	t.Fatal("the request must not reach the plain throttle path")
}

func TestThrottle_NumericSpecInNameSlotIsPlainPolicy(t *testing.T) {
	// A numeric spec ("3", "4,2") is not a limiter name: it never triggers the
	// MissingRateLimiter panic and resolves as a plain maxAttempts policy from
	// the first numeric segment.
	for _, tc := range []struct{ spec, limit string }{{"3", "3"}, {"4,2", "4"}} {
		h := NewThrottleMiddlewareNamed(NewMemoryRateLimiter(), tc.spec, 0, time.Minute)
		next, _ := throttleNext()

		var last any
		for i := 0; i < 5; i++ {
			last = h.Process(newThrottleRequest("http://example.com/api", "10.0.0.32:1111"), next)
		}
		res := last.(*Response)
		assert.Equal(t, http.StatusTooManyRequests, res.GetCode(), "spec %q", tc.spec)
		assert.Equal(t, tc.limit, res.Headers().Get("X-RateLimit-Limit"), "spec %q resolves to the first numeric segment", tc.spec)
	}
}

func TestThrottle_RegisteredNamedLimiterOverridesExplicitPolicy(t *testing.T) {
	registry := DefaultRateLimiterRegistry()
	registry.For("flow-test-override", func(request *Request) *Limit {
		return PerMinute(1).By("override")
	})

	// When the name is registered, its callback decides the policy — the
	// explicit maxAttempts/decay are ignored.
	rl := NewMemoryRateLimiter()
	h := NewThrottleMiddlewareNamed(rl, "flow-test-override", 100, time.Hour)
	next, _ := throttleNext()

	res1 := h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), next).(*Response)
	res2 := h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), next).(*Response)
	assert.Equal(t, http.StatusOK, res1.GetCode())
	assert.Equal(t, http.StatusTooManyRequests, res2.GetCode())
	assert.Equal(t, "1", res2.Headers().Get("X-RateLimit-Limit"), "the named limiter policy wins over the explicit 100")
}

func TestThrottle_AddHeadersDoNotOverwriteSmallerRemaining(t *testing.T) {
	rl := NewMemoryRateLimiter()
	h := NewThrottleMiddleware(rl, 10, time.Minute).(*ThrottleMiddleware)

	res := NewResponse()
	res.Header("X-RateLimit-Remaining", "0")

	// A response already advertising a smaller remaining attempts value is
	// left untouched.
	got := h.addHeaders(res, 10, 9, -1).(*Response)
	assert.Equal(t, "0", got.Headers().Get("X-RateLimit-Remaining"))
	assert.Empty(t, got.Headers().Get("X-RateLimit-Limit"))

	// A larger existing value is refreshed.
	res2 := NewResponse().Header("X-RateLimit-Remaining", "42")
	got2 := h.addHeaders(res2, 10, 9, -1).(*Response)
	assert.Equal(t, "9", got2.Headers().Get("X-RateLimit-Remaining"))
	assert.Equal(t, "10", got2.Headers().Get("X-RateLimit-Limit"))
}

func TestForMissingRateLimiterAndUserMessageOrder(t *testing.T) {
	err := ForMissingRateLimiterAndUser("gold", "App\\Models\\User")
	assert.Equal(t, "App\\Models\\User::gold", err.Limiter)
	assert.Contains(t, err.Error(), "[App\\Models\\User::gold]")
	assert.Contains(t, err.Error(), "is not defined")
}

func TestThrottle_NonResponseResultStillThrottles(t *testing.T) {
	// The pipeline may return non-*Response results; the throttle middleware
	// must not panic while decorating them (headers are simply skipped).
	rl := NewMemoryRateLimiter()
	h := NewThrottleMiddleware(rl, 1, time.Minute)

	res1 := h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), func(req *Request) any {
		return "plain"
	})
	assert.Equal(t, "plain", res1)

	res2 := h.Process(newThrottleRequest("http://example.com/api", "10.0.0.1:1111"), func(req *Request) any {
		return "plain"
	}).(*Response)
	assert.Equal(t, http.StatusTooManyRequests, res2.GetCode())
}

func TestThrottle_MemoryBackendIsAvailableByDefault(t *testing.T) {
	// A throttle middleware without an explicit limiter falls back to the
	// default registry backend.
	h := NewThrottleMiddleware(nil, 1, time.Minute)
	next, _ := throttleNext()
	res1 := h.Process(newThrottleRequest("http://default-backend.test/api", "10.0.0.7:1111"), next).(*Response)
	res2 := h.Process(newThrottleRequest("http://default-backend.test/api", "10.0.0.7:1111"), next).(*Response)
	assert.Equal(t, http.StatusOK, res1.GetCode())
	assert.Equal(t, http.StatusTooManyRequests, res2.GetCode())
}

// --- Begin throttle alignment tests ---

func TestForMissingRateLimiterMessage(t *testing.T) {
	// The message reads "Rate limiter [name] is not defined.".
	assert.Equal(t, "Rate limiter [gold] is not defined.", ForMissingRateLimiter("gold").Error())
	assert.Equal(t, "Rate limiter [App\\Models\\User::gold] is not defined.", ForMissingRateLimiterAndUser("gold", "App\\Models\\User").Error())
}

func TestThrottleRequestsExceptionRender(t *testing.T) {
	// ThrottleRequestsException renders a 429 response carrying Retry-After and
	// the X-RateLimit-* headers.
	exception := &ThrottleRequestsException{
		Message:    "Too Many Attempts.",
		RetryAfter: 30,
		Headers: map[string]string{
			"X-RateLimit-Limit":     "5",
			"X-RateLimit-Remaining": "0",
			"Retry-After":           "30",
		},
	}
	assert.Equal(t, "Too Many Attempts.", exception.Error())

	res := exception.Render()
	assert.Equal(t, http.StatusTooManyRequests, res.GetCode())
	assert.Equal(t, "5", res.Headers().Get("X-RateLimit-Limit"))
	assert.Equal(t, "0", res.Headers().Get("X-RateLimit-Remaining"))
	assert.Equal(t, "30", res.Headers().Get("Retry-After"))
}

func TestThrottle_PipeSpecUsesGuestSegment(t *testing.T) {
	// resolveMaxAttempts picks the guest segment (index 0) of
	// the "maxAttempts,userKey" spec — without an auth component the guest
	// segment (7) applies.
	rl := NewMemoryRateLimiter()
	h := NewThrottleMiddlewareWith(rl, "7|99", time.Minute, "")

	next, calls := throttleNext()
	for i := 0; i < 7; i++ {
		h.Process(newThrottleRequest("http://example.com/api", "10.0.0.5:1234"), next)
	}
	assert.Equal(t, 7, *calls)

	res := h.Process(newThrottleRequest("http://example.com/api", "10.0.0.5:1234"), next).(*Response)
	assert.Equal(t, http.StatusTooManyRequests, res.GetCode())
	assert.Equal(t, "7", res.Headers().Get("X-RateLimit-Limit"), "the guest segment (7), not the user segment (99), is enforced")
}

func TestSetRateLimiterShouldHashKeys(t *testing.T) {
	original := shouldHashThrottleKeys
	defer SetRateLimiterShouldHashKeys(original)

	// shouldHashKeys is a static toggle affecting every middleware.
	SetRateLimiterShouldHashKeys(false)
	h := NewThrottleMiddleware(NewMemoryRateLimiter(), 5, time.Minute).(*ThrottleMiddleware)
	assert.False(t, h.shouldHashKeys)
	assert.Equal(t, "host|ip", h.formatIdentifier("host|ip"))

	// The per-instance override (this port's variant) still wins.
	assert.NotEqual(t, "host|ip", h.ShouldHashKeys(true).formatIdentifier("host|ip"))
}
