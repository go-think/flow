package flow

import (
	"net/http"
	"strconv"
	"time"
)

// ThrottleMiddleware limits request throughput per client key
// (Laravel: Middleware\ThrottleRequests).
type ThrottleMiddleware struct {
	limiter     RateLimiter
	name        string
	maxAttempts int
	decay       time.Duration
}

// NewThrottleMiddleware throttles by client fingerprint with the given
// max attempts per decay window.
func NewThrottleMiddleware(limiter RateLimiter, maxAttempts int, decay time.Duration) Handler {
	return &ThrottleMiddleware{limiter: limiter, maxAttempts: maxAttempts, decay: decay}
}

// NewThrottleMiddlewareNamed throttles using a named limiter bucket
// (Laravel: ThrottleRequests::using).
func NewThrottleMiddlewareNamed(limiter RateLimiter, name string, maxAttempts int, decay time.Duration) Handler {
	return &ThrottleMiddleware{limiter: limiter, name: name, maxAttempts: maxAttempts, decay: decay}
}

// Process implements Handler.
func (h *ThrottleMiddleware) Process(req *Request, next Closure) any {
	key := h.name
	if key == "" {
		key = req.Fingerprint()
	}
	bucket := key
	if h.name != "" {
		bucket = h.name + ":" + key
	}
	maxAttempts := h.maxAttempts

	if h.limiter.TooManyAttempts(bucket, maxAttempts) {
		retryAfter := h.limiter.AvailableIn(bucket)
		res := NewResponse().SetCode(http.StatusTooManyRequests).
			SetContent("Too Many Attempts.")
		res.Header("Retry-After", strconv.Itoa(retryAfter))
		h.addHeaders(res, maxAttempts, 0, retryAfter)
		return res
	}

	h.limiter.Hit(bucket, h.decay)
	res := next(req)
	if response, ok := res.(*Response); ok {
		remaining := maxAttempts - h.limiter.Attempts(bucket)
		if remaining < 0 {
			remaining = 0
		}
		h.addHeaders(response, maxAttempts, remaining, -1)
	}
	return res
}

// addHeaders writes the standard rate-limit headers.
func (h *ThrottleMiddleware) addHeaders(res *Response, maxAttempts, remainingAttempts, retryAfter int) {
	res.Header("X-RateLimit-Limit", strconv.Itoa(maxAttempts))
	res.Header("X-RateLimit-Remaining", strconv.Itoa(remainingAttempts))
	if retryAfter > 0 {
		res.Header("Retry-After", strconv.Itoa(retryAfter))
	}
}
