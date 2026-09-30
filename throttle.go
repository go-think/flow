package flow

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"time"
)

// shouldHashThrottleKeys is the package-level default deciding whether throttle
// keys are hashed (the reference implementation:, static, default
// true; affects formatIdentifier and named limiter bucket keys).
var shouldHashThrottleKeys = true

// SetShouldHashThrottleKeys sets the default key-hashing behavior applied to
// newly created throttle middleware.

// Deprecated: Use SetRateLimiterShouldHashKeys, the name aligned with the
// the reference implementation static property, instead.
func SetShouldHashThrottleKeys(should bool) {
	shouldHashThrottleKeys = should
}

// SetRateLimiterShouldHashKeys toggles the global key-hashing behavior of the
// throttle middleware (the reference implementation: is a static
// property toggled via a global setter, so it applies to every
// middleware — the package-level variable here plays that role). Individual
// middleware may still override it with ThrottleMiddleware.ShouldHashKeys,
// the per-instance variant kept for this port.
func SetRateLimiterShouldHashKeys(should bool) {
	shouldHashThrottleKeys = should
}

// ThrottleResponseCallback builds the response returned when a rate limit is
// exceeded (the reference implementation: callback; it receives the request and
// the computed rate-limit headers).
type ThrottleResponseCallback func(request *Request, headers map[string]string) *Response

// ThrottleAfterCallback decides, after the response was produced, whether the
// request still counts against the limit (the reference implementation: callback; it
// receives the raw pipeline result).
type ThrottleAfterCallback func(response any) bool

// throttleLimit is a single enforced bucket (the reference implementation: the anonymous limit
// objects iterates over).
type throttleLimit struct {
	key              string
	maxAttempts      int
	decay            time.Duration
	afterCallback    ThrottleAfterCallback
	responseCallback ThrottleResponseCallback
}

// ThrottleMiddleware limits request throughput per client key
// .
type ThrottleMiddleware struct {
	limiter        RateLimiter
	name           string // named limiter to resolve
	prefix         string // key prefix
	maxAttempts    int
	maxAttemptsRaw string // string policy spec ("60" or "60|120")
	decay          time.Duration
	shouldHashKeys bool
}

// NewThrottleMiddleware throttles by client signature ("host|ip") with the
// given max attempts per decay window.
func NewThrottleMiddleware(limiter RateLimiter, maxAttempts int, decay time.Duration) Handler {
	return &ThrottleMiddleware{
		limiter:        limiter,
		maxAttempts:    maxAttempts,
		decay:          decay,
		shouldHashKeys: shouldHashThrottleKeys,
	}
}

// NewThrottleMiddlewareWith throttles using a string policy spec plus key
// prefix. spec may be a plain number ("60") or a guest|user pair ("60|120" —
// without an auth component the guest segment applies)
// .
func NewThrottleMiddlewareWith(limiter RateLimiter, spec string, decay time.Duration, prefix string) Handler {
	return &ThrottleMiddleware{
		limiter:        limiter,
		maxAttemptsRaw: spec,
		decay:          decay,
		prefix:         prefix,
		shouldHashKeys: shouldHashThrottleKeys,
	}
}

// NewThrottleMiddlewareNamed throttles using a named limiter bucket
// . When the name is registered on the
// default registry its callback decides the policy. When the name is not
// registered the request panics with MissingRateLimiterError — like the reference implementation,
// where a non-numeric limiter reference is re-resolved in resolveMaxAttempts
// and always throws MissingRateLimiterException, even when an explicit
// maxAttempts was provided alongside (, 207-211).
// Only a numeric spec ("60", "10,1") keeps the plain path.
func NewThrottleMiddlewareNamed(limiter RateLimiter, name string, maxAttempts int, decay time.Duration) Handler {
	return &ThrottleMiddleware{
		limiter:        limiter,
		name:           name,
		maxAttempts:    maxAttempts,
		decay:          decay,
		shouldHashKeys: shouldHashThrottleKeys,
	}
}

// NewNamedThrottleMiddleware creates a throttle middleware that resolves its
// policy dynamically from the named rate limiter registry
// . An unregistered name panics with
// MissingRateLimiterError.
func NewNamedThrottleMiddleware(name string) Handler {
	return &ThrottleMiddleware{name: name, shouldHashKeys: shouldHashThrottleKeys}
}

// ShouldHashKeys enables/disables hashing of throttle keys for this middleware
// .
func (h *ThrottleMiddleware) ShouldHashKeys(should bool) *ThrottleMiddleware {
	h.shouldHashKeys = should
	return h
}

// Process implements Handler.
func (h *ThrottleMiddleware) Process(req *Request, next Closure) any {
	limiter := h.limiter
	if limiter == nil {
		if req != nil && req.Route() != nil && req.Route().Router() != nil {
			if r, ok := req.Route().Router().(*router); ok && r.container != nil {
				if r.container.Bound("rate.limiter") {
					if cl, ok := r.container.Make("rate.limiter").(RateLimiter); ok {
						limiter = cl
					}
				}
			}
		}
	}
	if limiter == nil {
		limiter = defaultRateLimiterRegistry.backend
	}

	// Named limiter resolution.
	if h.name != "" {
		if limiterFn, found := defaultRateLimiterRegistry.Limiter(h.name); found {
			return h.handleRequestUsingNamedLimiter(req, next, limiter, h.name, limiterFn)
		}
		// the reference implementation ( + resolveMaxAttempts L207-211):
		// a non-numeric limiter name that is not registered always throws
		// MissingRateLimiterException — even when an explicit maxAttempts was
		// provided alongside (resolveMaxAttempts re-checks the registry and
		// throws for every non-numeric value). A numeric spec ("60", "10,1",
		// "60|120") is not a limiter name and keeps the plain path.
		if !isNumericThrottleSpec(h.name) {
			panic(ForMissingRateLimiter(h.name))
		}
	}

	// Plain path: one bucket keyed by the request signature, with an optional
	// prefix.
	maxAttempts := h.maxAttempts
	if h.maxAttemptsRaw != "" {
		maxAttempts = h.resolveMaxAttempts(h.maxAttemptsRaw)
	} else if maxAttempts == 0 && isNumericThrottleSpec(h.name) {
		// A numeric spec given in the limiter-name slot ("60", "10,1") is a
		// plain maxAttempts policy, not a limiter reference (the reference implementation:
		// throttle:60,1 — the numeric first parameter resolves through
		// resolveMaxAttempts and never names a limiter).
		maxAttempts = h.resolveMaxAttempts(strings.SplitN(h.name, ",", 2)[0])
	}
	prefix := h.prefix
	if prefix == "" && h.name != "" {
		prefix = h.name + ":"
	}

	return h.handleRequest(req, next, limiter, []throttleLimit{{
		key:         prefix + h.resolveRequestSignature(req),
		maxAttempts: maxAttempts,
		decay:       h.decay,
	}})
}

// handleRequestUsingNamedLimiter resolves the policy from a named limiter
// callback, which may return *Limit, []*Limit, *Unlimited or *Response
// .
func (h *ThrottleMiddleware) handleRequestUsingNamedLimiter(req *Request, next Closure, limiter RateLimiter, limiterName string, limiterFn func(*Request) any) any {
	result := limiterFn(req)

	// A raw response is returned as-is and never throttles.
	if res, ok := result.(*Response); ok {
		return res
	}

	// Unlimited requests pass through without counting.
	if _, ok := result.(*Unlimited); ok {
		return next(req)
	}

	var raw []*Limit
	switch v := result.(type) {
	case *Limit:
		raw = []*Limit{v}
	case []*Limit:
		raw = v
	default:
		// nil or unknown results enforce no limits
		// → empty limits).
		raw = nil
	}

	limits := make([]throttleLimit, 0, len(raw))
	for _, l := range raw {
		if l == nil {
			continue
		}
		limits = append(limits, throttleLimit{
			key:              h.namedBucketKey(limiterName, l.Key),
			maxAttempts:      l.MaxAttempts,
			decay:            l.Decay,
			afterCallback:    l.AfterCallback,
			responseCallback: l.ResponseCallback,
		})
	}

	return h.handleRequest(req, next, limiter, limits)
}

// namedBucketKey derives the counter bucket for a named limiter
// when keys are hashed,
// "limiterName:limitKey" otherwise).
func (h *ThrottleMiddleware) namedBucketKey(limiterName, limitKey string) string {
	if h.shouldHashKeys {
		sum := md5.Sum([]byte(limiterName + limitKey))
		return hex.EncodeToString(sum[:])
	}
	return limiterName + ":" + limitKey
}

// handleRequest checks every bucket before the request runs, counts the hits,
// then runs after-callbacks and adds headers on the way out
// .
func (h *ThrottleMiddleware) handleRequest(req *Request, next Closure, limiter RateLimiter, limits []throttleLimit) any {
	for i := range limits {
		if limiter.TooManyAttempts(limits[i].key, limits[i].maxAttempts) {
			return h.buildException(req, limiter, limits[i])
		}
	}

	for i := range limits {
		if limits[i].afterCallback == nil {
			limiter.Hit(limits[i].key, limits[i].decay)
		}
	}

	response := next(req)

	for i := range limits {
		if limits[i].afterCallback != nil && limits[i].afterCallback(response) {
			limiter.Hit(limits[i].key, limits[i].decay)
		}
		response = h.addHeaders(response, limits[i].maxAttempts, h.remainingAttempts(limiter, limits[i].key, limits[i].maxAttempts), -1)
	}

	return response
}

// remainingAttempts calculates the attempts left for a key
// .
func (h *ThrottleMiddleware) remainingAttempts(limiter RateLimiter, key string, maxAttempts int) int {
	remaining := maxAttempts - limiter.Attempts(key)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// resolveMaxAttempts resolves a string policy spec to a concrete number. A
// "maxAttempts,userKey" pair separated by "|" (the reference implementation:
// resolveMaxAttempts L194-214) resolves to the guest segment (index 0): this
// port has no auth component, so the user resolution is always empty and the reference implementation
// itself would pick the guest segment; an application can still resolve the
// user segment itself by inspecting the spec inside its named limiter
// callbacks. A non-numeric segment means no matching rate limiter exists
// (the reference implementation: — the reference implementation also resolves a
// non-numeric value as an authenticated user attribute, which has no
// equivalent here).
func (h *ThrottleMiddleware) resolveMaxAttempts(spec string) int {
	if strings.Contains(spec, "|") {
		spec = strings.SplitN(spec, "|", 2)[0]
	}
	if max, err := strconv.Atoi(strings.TrimSpace(spec)); err == nil {
		return max
	}
	panic(ForMissingRateLimiter(spec))
}

// isNumericThrottleSpec reports whether the given throttle spec is purely
// numeric (the reference implementation: is_numeric on the middleware's maxAttempts parameter —
// e.g. "60", "10,1" or "60|120" where every comma/pipe separated segment is a
// number), i.e. not a named rate limiter reference.
func isNumericThrottleSpec(spec string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return false
	}
	for _, part := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == '|' }) {
		if _, err := strconv.Atoi(strings.TrimSpace(part)); err != nil {
			return false
		}
	}
	return true
}

// resolveRequestSignature builds the per-client throttle key: "host|ip" from
// the request (port stripped from the Host header, plus the client IP), hashed
// when key hashing is enabled (the reference implementation: resolveRequestSignature —
// authenticated user id, else route domain + request ip; this port has no auth
// component, so the request host and client IP are used — no method, path or
// user-agent participates).
func (h *ThrottleMiddleware) resolveRequestSignature(req *Request) string {
	host := ""
	if httpReq := req.GetHttpRequest(); httpReq != nil {
		host = httpReq.Host
		if hostname, _, err := net.SplitHostPort(host); err == nil {
			host = hostname
		}
	}
	return h.formatIdentifier(host + "|" + req.ClientIP())
}

// formatIdentifier hashes the identifier when key hashing is enabled
// .
func (h *ThrottleMiddleware) formatIdentifier(value string) string {
	if !h.shouldHashKeys {
		return value
	}
	sum := sha1.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

// buildException creates the "too many attempts" result
// (the reference implementation: buildException — throws ThrottleRequestsException('Too Many
// Attempts.', headers) carrying the rate-limit headers, or wraps the limit's
// responseCallback result in an HttpResponseException). The exception is
// rendered immediately so the pipeline keeps observing a *Response; use the
// returned response's headers for introspection. When the limit carries a
// responseCallback the callback builds the response from the computed headers.
func (h *ThrottleMiddleware) buildException(req *Request, limiter RateLimiter, limit throttleLimit) any {
	retryAfter := limiter.AvailableIn(limit.key)
	headers := map[string]string{
		"X-RateLimit-Limit":     strconv.Itoa(limit.maxAttempts),
		"X-RateLimit-Remaining": "0",
		"Retry-After":           strconv.Itoa(retryAfter),
		"X-RateLimit-Reset":     strconv.FormatInt(time.Now().Unix()+int64(retryAfter), 10),
	}
	if limit.responseCallback != nil {
		return limit.responseCallback(req, headers)
	}
	exception := &ThrottleRequestsException{
		Message:    "Too Many Attempts.",
		RetryAfter: retryAfter,
		Headers:    headers,
	}
	return exception.Render()
}

// addHeaders attaches the rate-limit headers to a *Response result,
// preserving an already-smaller X-RateLimit-Remaining (the reference implementation: addHeaders +
// getHeaders protection branch L302-306). retryAfter < 0 means the request was
// not limited, so no Retry-After / X-RateLimit-Reset are emitted.
func (h *ThrottleMiddleware) addHeaders(result any, maxAttempts, remainingAttempts, retryAfter int) any {
	res, ok := result.(*Response)
	if !ok {
		return result
	}
	if existing := res.Headers().Get("X-RateLimit-Remaining"); existing != "" {
		if current, err := strconv.Atoi(existing); err == nil && current <= remainingAttempts {
			return res
		}
	}
	res.Header("X-RateLimit-Limit", strconv.Itoa(maxAttempts))
	res.Header("X-RateLimit-Remaining", strconv.Itoa(remainingAttempts))
	if retryAfter >= 0 {
		res.Header("Retry-After", strconv.Itoa(retryAfter))
		res.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Unix()+int64(retryAfter), 10))
	}
	return res
}
