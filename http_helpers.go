package flow

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- Begin trusted proxies ---

// globalTrustedProxies is the package-level trusted proxy configuration shared
// by every request. A nil (empty) configuration honors forwarded headers
// unconditionally.
var (
	globalTrustedProxiesMu sync.RWMutex
	globalTrustedProxies   []string
)

// SetGlobalTrustedProxies configures the package-level trusted proxy table
// (CIDRs, plain IPs, or "*" to trust every proxy).
func SetGlobalTrustedProxies(proxies []string) {
	globalTrustedProxiesMu.Lock()
	defer globalTrustedProxiesMu.Unlock()
	globalTrustedProxies = proxies
}

// ResetGlobalTrustedProxies clears the package-level trusted proxy table,
// restoring the legacy "honor forwarded headers" behavior.
func ResetGlobalTrustedProxies() {
	globalTrustedProxiesMu.Lock()
	defer globalTrustedProxiesMu.Unlock()
	globalTrustedProxies = nil
}

// effectiveTrustedProxies returns the trusted proxy specs in effect for the
// request: the per-request table when configured, otherwise the global one.
func (r *Request) effectiveTrustedProxies() []string {
	if r.trustedProxies != nil {
		return r.trustedProxies
	}
	globalTrustedProxiesMu.RLock()
	defer globalTrustedProxiesMu.RUnlock()
	return globalTrustedProxies
}

// trustedProxyConfigured reports whether any trusted proxy spec is in effect.
func (r *Request) trustedProxyConfigured() bool {
	return len(r.effectiveTrustedProxies()) > 0
}

// SetTrustedProxies configures the trusted proxies for this request. When
// configured, forwarded headers (X-Forwarded-For, X-Forwarded-Proto,
// X-Forwarded-Host, X-Real-Ip) are honored only when the immediate peer is a
// trusted proxy.
func (r *Request) SetTrustedProxies(proxies []string) *Request {
	r.trustedProxies = proxies
	return r
}

// IsFromTrustedProxy reports whether the request's immediate peer (RemoteAddr)
// matches one of the configured trusted proxies. Without configuration it
// reports false.
func (r *Request) IsFromTrustedProxy() bool {
	if !r.trustedProxyConfigured() || r.Request == nil {
		return false
	}
	return r.isTrustedProxyIP(remoteAddrHost(r.Request.RemoteAddr))
}

// forwardedHeadersAllowed reports whether forwarded headers may be honored:
// always under the legacy unconfigured mode, and only from a trusted peer
// once trusted proxies are configured.
func (r *Request) forwardedHeadersAllowed() bool {
	if !r.trustedProxyConfigured() {
		return true
	}
	return r.IsFromTrustedProxy()
}

// isTrustedProxyIP reports whether the IP matches a trusted proxy spec
// ("*", CIDR, or plain IP). Invalid specs and IPs never match.
func (r *Request) isTrustedProxyIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, spec := range r.effectiveTrustedProxies() {
		spec = strings.TrimSpace(spec)
		if spec == "*" {
			return true
		}
		if strings.Contains(spec, "/") {
			if _, network, err := net.ParseCIDR(spec); err == nil && network.Contains(ip) {
				return true
			}
			continue
		}
		if candidate := net.ParseIP(spec); candidate != nil && candidate.Equal(ip) {
			return true
		}
	}
	return false
}

// parseForwardedList splits a comma-separated forwarded header value into IP
// entries, trimming whitespace and stripping optional ports; empty entries are
// dropped.
func parseForwardedList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if ip := normalizeForwardedIP(part); ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

// normalizeForwardedIP trims and strips the port from a single forwarded IP
// entry ("203.0.113.195:8080" -> "203.0.113.195").
func normalizeForwardedIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return host
	}
	return value
}

// remoteAddrHost extracts the host part of a socket address ("10.0.0.1:1234"
// -> "10.0.0.1"), returning the input unchanged when it carries no port.
func remoteAddrHost(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// IPs returns every entry of the X-Forwarded-For header with ports stripped,
// or nil when the header is absent.
func (r *Request) IPs() []string {
	xff := r.Header("X-Forwarded-For")
	if xff == "" {
		return nil
	}
	ips := parseForwardedList(xff)
	if len(ips) == 0 {
		return nil
	}
	return ips
}

// ID returns the request identifier: the incoming X-Request-Id header when
// present, otherwise a generated identifier persisted on the request.
func (r *Request) ID() string {
	if r.requestID != "" {
		return r.requestID
	}
	if id := r.Header("X-Request-Id"); id != "" {
		r.requestID = id
		return id
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		r.requestID = strconv.FormatInt(time.Now().UnixNano(), 36)
		return r.requestID
	}
	r.requestID = hex.EncodeToString(buf)
	return r.requestID
}

// TrustProxiesMiddleware configures trusted proxies on the incoming request
// before the rest of the pipeline runs.
type TrustProxiesMiddleware struct {
	proxies []string
}

// NewTrustProxiesMiddleware creates a middleware setting the given trusted
// proxy specs (CIDRs, plain IPs, or "*") on every processed request.
func NewTrustProxiesMiddleware(proxies ...string) Handler {
	return &TrustProxiesMiddleware{proxies: proxies}
}

// Process applies the trusted proxy configuration and forwards to the next
// handler.
func (h *TrustProxiesMiddleware) Process(req *Request, next Closure) any {
	req.SetTrustedProxies(h.proxies)
	return next(req)
}

// --- End trusted proxies ---

// --- Begin flash & old input ---

// flashInput stores the given input map as the session's old input, replacing
// any previous flash entirely.
func (r *Request) flashInput(input map[string]string) *Request {
	if sess := r.Session(); sess != nil {
		sess.Flash("_old_input", input)
	}
	return r
}

// Flash flashes the current input to the session as old input.
func (r *Request) Flash() *Request {
	return r.flashInput(r.All())
}

// FlashOnly flashes only the given input keys to the session as old input.
func (r *Request) FlashOnly(keys ...string) *Request {
	all := r.All()
	filtered := make(map[string]string, len(keys))
	for _, key := range keys {
		if value, ok := all[key]; ok {
			filtered[key] = value
		}
	}
	return r.flashInput(filtered)
}

// FlashExcept flashes the current input, except the given keys, to the session
// as old input.
func (r *Request) FlashExcept(keys ...string) *Request {
	all := r.All()
	for _, key := range keys {
		delete(all, key)
	}
	return r.flashInput(all)
}

// oldInput returns the flashed old input map, or nil when none exists.
func (r *Request) oldInput() map[string]string {
	sess := r.Session()
	if sess == nil {
		return nil
	}
	raw := sess.Get("_old_input")
	if input, ok := raw.(map[string]string); ok {
		return input
	}
	return nil
}

// Old retrieves an item from the old input flashed by the previous request,
// falling back to the given default.
func (r *Request) Old(key string, defaults ...string) string {
	if input := r.oldInput(); input != nil {
		if value, ok := input[key]; ok {
			return value
		}
	}
	if len(defaults) > 0 {
		return defaults[0]
	}
	return ""
}

// HasOldInput reports whether old input exists; with a key it reports whether
// that key was flashed.
func (r *Request) HasOldInput(keys ...string) bool {
	input := r.oldInput()
	if len(keys) == 0 {
		return len(input) > 0
	}
	for _, key := range keys {
		if _, ok := input[key]; !ok {
			return false
		}
	}
	return true
}

// With flashes a key/value pair to the session.
func (r *Response) With(key string, value interface{}) *Response {
	if r.Request != nil {
		if sess := r.Request.Session(); sess != nil {
			sess.Flash(key, value)
		}
	}
	return r
}

// WithInput flashes the bound request's input as old input; with keys only
// those inputs are flashed, without keys everything is.
func (r *Response) WithInput(keys ...string) *Response {
	if r.Request == nil {
		return r
	}
	if len(keys) > 0 {
		r.Request.FlashOnly(keys...)
		return r
	}
	r.Request.Flash()
	return r
}

// WithErrors flashes validation errors to the session.
func (r *Response) WithErrors(errors map[string]string) *Response {
	return r.With("errors", errors)
}

// --- End flash & old input ---

// --- Begin http cache ---

// SetEtag sets the ETag header on the response, quoting the value and
// prefixing W/ for weak validators.
func (r *Response) SetEtag(etag string, weak ...bool) *Response {
	value := `"` + etag + `"`
	if len(weak) > 0 && weak[0] {
		value = `W/` + value
	}
	r.Header("ETag", value)
	return r
}

// SetCacheControl sets the Cache-Control header from the given directives.
func (r *Response) SetCacheControl(directives ...string) *Response {
	r.Header("Cache-Control", strings.Join(directives, ", "))
	return r
}

// SetLastModified sets the Last-Modified header from the given time.
func (r *Response) SetLastModified(t time.Time) *Response {
	if t.IsZero() {
		return r
	}
	r.Header("Last-Modified", t.UTC().Format(http.TimeFormat))
	return r
}

// IsNotModified compares the response validators against the request's
// If-None-Match / If-Modified-Since conditions; on a match the response is
// transformed into an empty 304 and true is returned.
func (r *Response) IsNotModified(req *Request) bool {
	if req == nil || req.Request == nil {
		return false
	}
	if etag := r.Headers().Get("ETag"); etag != "" {
		if req.Header("If-None-Match") == etag {
			r.setNotModified()
			return true
		}
		return false
	}
	if lastModified := r.Headers().Get("Last-Modified"); lastModified != "" {
		if req.Header("If-Modified-Since") == lastModified {
			r.setNotModified()
			return true
		}
	}
	return false
}

// setNotModified converts the response into an empty 304 Not Modified.
func (r *Response) setNotModified() {
	r.SetCode(http.StatusNotModified)
	r.SetContent("")
}

// --- End http cache ---

// --- Begin file hash name ---

// HashName generates a unique 40-character hash name for the upload, keeping
// the original (or given) extension.
func (f *File) HashName(extension ...string) string {
	ext := ""
	if len(extension) > 0 && extension[0] != "" {
		ext = extension[0]
	} else if f.FileHeader != nil {
		ext = strings.TrimPrefix(strings.ToLower(path.Ext(f.FileHeader.Filename)), ".")
	}
	if ext == "" {
		ext = "bin"
	}
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		sum := sha1.Sum([]byte(f.FileHeader.Filename + time.Now().String()))
		return hex.EncodeToString(sum[:]) + "." + ext
	}
	sum := sha1.Sum(buf)
	return hex.EncodeToString(sum[:]) + "." + ext
}

// --- End file hash name ---

// --- Begin convert empty strings to null middleware ---

// ConvertEmptyStringsToNullMiddleware trims input values and removes entries
// that become empty.
type ConvertEmptyStringsToNullMiddleware struct {
	except []string
}

// NewConvertEmptyStringsToNullMiddleware creates a middleware converting
// empty (or whitespace-only) input values to null; the excepted keys are left
// untouched.
func NewConvertEmptyStringsToNullMiddleware(except ...string) Handler {
	return &ConvertEmptyStringsToNullMiddleware{except: except}
}

// Process cleans the request input, then forwards to the next handler.
func (h *ConvertEmptyStringsToNullMiddleware) Process(req *Request, next Closure) any {
	req.All() // force input parsing before cleaning the underlying maps
	req.removeEmptyInputs(h.except)
	return next(req)
}

// removeEmptyInputs trims every parsed input value and deletes the entries
// that become empty, skipping the excepted keys.
func (r *Request) removeEmptyInputs(except []string) {
	isExcepted := func(key string) bool {
		for _, name := range except {
			if name == key {
				return true
			}
		}
		return false
	}
	clean := func(values map[string]string, raw url.Values) {
		for key, value := range values {
			if isExcepted(key) {
				continue
			}
			trimmed := strings.TrimSpace(value)
			if trimmed == "" {
				delete(values, key)
				raw.Del(key)
				continue
			}
			if trimmed != value {
				values[key] = trimmed
				raw.Set(key, trimmed)
			}
		}
	}
	clean(r.post, r.postValues)
	clean(r.query, r.queryValues)
}

// --- End convert empty strings to null middleware ---

// --- Begin verify csrf token middleware ---

// VerifyCsrfTokenMiddleware validates the session CSRF token on every
// state-changing request: reading methods and excepted URIs skip verification,
// successful responses carry the XSRF-TOKEN cookie, and failures render 419
// Page Expired (or a JSON CSRF mismatch message).
type VerifyCsrfTokenMiddleware struct {
	except []string
}

// NewVerifyCsrfTokenMiddleware creates a CSRF validation middleware skipping
// the given URI patterns (e.g. "webhook/*").
func NewVerifyCsrfTokenMiddleware(except ...string) Handler {
	return &VerifyCsrfTokenMiddleware{except: except}
}

// Process runs the token check and decorates successful responses with the
// XSRF-TOKEN cookie.
func (h *VerifyCsrfTokenMiddleware) Process(req *Request, next Closure) any {
	if h.shouldPass(req) {
		result := next(req)
		if res, ok := result.(*Response); ok {
			h.attachXsrfCookie(req, res)
		}
		return result
	}
	return h.reject(req)
}

// shouldPass reports whether the request skips or passes validation: reading
// methods, excepted URIs, or a matching token.
func (h *VerifyCsrfTokenMiddleware) shouldPass(req *Request) bool {
	if h.isReading(req) || h.isExcepted(req) {
		return true
	}
	return h.tokensMatch(req)
}

// isReading reports whether the method never mutates state (GET/HEAD/OPTIONS).
func (h *VerifyCsrfTokenMiddleware) isReading(req *Request) bool {
	switch req.Method() {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// isExcepted reports whether the request path matches an except pattern.
func (h *VerifyCsrfTokenMiddleware) isExcepted(req *Request) bool {
	if req.Request == nil || req.Request.URL == nil {
		return false
	}
	requestPath := strings.TrimPrefix(req.Request.URL.Path, "/")
	for _, pattern := range h.except {
		pattern = strings.TrimPrefix(pattern, "/")
		if strings.HasSuffix(pattern, "*") {
			if strings.HasPrefix(requestPath, strings.TrimSuffix(pattern, "*")) {
				return true
			}
			continue
		}
		if pattern == requestPath {
			return true
		}
	}
	return false
}

// tokensMatch compares the session token against the X-CSRF-TOKEN header, the
// (url-encoded) X-XSRF-TOKEN header, and the _token form input.
func (h *VerifyCsrfTokenMiddleware) tokensMatch(req *Request) bool {
	sess := req.Session()
	if sess == nil {
		return false
	}
	token, _ := sess.Get("_token").(string)
	if token == "" {
		return false
	}
	if req.Header("X-CSRF-TOKEN") == token {
		return true
	}
	if xsrf := req.Header("X-XSRF-TOKEN"); xsrf != "" {
		if decoded, err := url.QueryUnescape(xsrf); err == nil && decoded == token {
			return true
		}
	}
	if formToken, err := req.Input("_token"); err == nil && formToken == token {
		return true
	}
	return false
}

// attachXsrfCookie adds the XSRF-TOKEN cookie carrying the session token so
// JavaScript frameworks can echo it back.
func (h *VerifyCsrfTokenMiddleware) attachXsrfCookie(req *Request, res *Response) {
	sess := req.Session()
	if sess == nil {
		return
	}
	token, _ := sess.Get("_token").(string)
	if token == "" {
		return
	}
	if res.cookies == nil {
		res.cookies = make(map[string]*http.Cookie)
	}
	res.cookies["XSRF-TOKEN"] = &http.Cookie{Name: "XSRF-TOKEN", Value: token, Path: "/"}
}

// reject renders the 419 failure response: a JSON CSRF mismatch message for
// requests expecting JSON, "Page Expired" otherwise.
func (h *VerifyCsrfTokenMiddleware) reject(req *Request) *Response {
	if req.ExpectsJson() {
		return NewResponse().SetCode(419).SetContent(`{"message":"CSRF token mismatch."}`)
	}
	return NewResponse().SetCode(419).SetContent("Page Expired")
}

// --- End verify csrf token middleware ---

// --- Begin request id middleware ---

// RequestIDMiddleware guarantees every request carries an identifier and every
// response exposes it via the X-Request-Id header.
type RequestIDMiddleware struct{}

// NewRequestIDMiddleware creates the request identifier middleware.
func NewRequestIDMiddleware() Handler {
	return &RequestIDMiddleware{}
}

// Process resolves (or generates) the request ID, stamps the response header,
// and forwards to the next handler.
func (h *RequestIDMiddleware) Process(req *Request, next Closure) any {
	id := req.ID()
	result := next(req)
	if res, ok := result.(*Response); ok {
		res.Header("X-Request-Id", id)
	}
	return result
}

// --- End request id middleware ---

// --- Begin request body limit middleware ---

// RequestBodyLimitMiddleware rejects request bodies larger than the configured
// limit with 413 Payload Too Large.
type RequestBodyLimitMiddleware struct {
	limit int64
}

// NewRequestBodyLimitMiddleware creates a middleware rejecting bodies larger
// than limit bytes.
func NewRequestBodyLimitMiddleware(limit int64) Handler {
	return &RequestBodyLimitMiddleware{limit: limit}
}

// Process checks the declared ContentLength and short-circuits oversized
// requests with 413.
func (h *RequestBodyLimitMiddleware) Process(req *Request, next Closure) any {
	if req.Request != nil && req.Request.ContentLength > h.limit {
		return NewResponse().SetCode(http.StatusRequestEntityTooLarge).SetContent("Payload Too Large")
	}
	return next(req)
}

// --- End request body limit middleware ---

// --- Begin secure headers middleware ---

// SecureHeadersMiddleware adds a set of conservative security headers to every
// response.
type SecureHeadersMiddleware struct{}

// NewSecureHeadersMiddleware creates the security headers middleware.
func NewSecureHeadersMiddleware() Handler {
	return &SecureHeadersMiddleware{}
}

// Process stamps the standard security headers onto the outgoing response.
func (h *SecureHeadersMiddleware) Process(req *Request, next Closure) any {
	result := next(req)
	if res, ok := result.(*Response); ok {
		res.Header("X-Content-Type-Options", "nosniff")
		res.Header("X-Frame-Options", "SAMEORIGIN")
		res.Header("X-XSS-Protection", "1; mode=block")
		res.Header("Referrer-Policy", "strict-origin-when-cross-origin")
	}
	return result
}

// --- End secure headers middleware ---

// --- Begin gzip middleware ---

// GzipMiddleware compresses response bodies exceeding a threshold when the
// client accepts gzip encoding.
type GzipMiddleware struct {
	threshold int
}

// NewGzipMiddleware creates a response compression middleware activating on
// bodies of threshold bytes or more.
func NewGzipMiddleware(threshold int) Handler {
	return &GzipMiddleware{threshold: threshold}
}

// Process compresses the response body when the client sends Accept-Encoding:
// gzip and the body reaches the threshold.
func (h *GzipMiddleware) Process(req *Request, next Closure) any {
	result := next(req)
	if !strings.Contains(req.Header("Accept-Encoding"), "gzip") {
		return result
	}
	res, ok := result.(*Response)
	if !ok {
		return result
	}
	body := res.GetContent()
	if len(body) < h.threshold {
		return result
	}
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write([]byte(body)); err != nil {
		return result
	}
	if err := writer.Close(); err != nil {
		return result
	}
	res.SetContent(buf.String())
	res.Header("Content-Encoding", "gzip")
	res.Header("Vary", "Accept-Encoding")
	return result
}

// --- End gzip middleware ---

// --- Begin maintenance mode middleware ---

// MaintenanceModeConfig defines the maintenance mode behavior: the bypass
// secret, the allowed client IPs, the Retry-After seconds, and the response
// message.
type MaintenanceModeConfig struct {
	Enabled    bool
	Secret     string
	AllowedIPs []string
	RetryAfter int
	Message    string
}

// MaintenanceModeMiddleware serves a 503 maintenance response unless the
// request carries the bypass secret or originates from an allowed IP.
type MaintenanceModeMiddleware struct {
	config *MaintenanceModeConfig
}

// NewMaintenanceModeMiddleware creates a middleware enforcing the given
// maintenance mode configuration.
func NewMaintenanceModeMiddleware(cfg *MaintenanceModeConfig) Handler {
	return &MaintenanceModeMiddleware{config: cfg}
}

// Process serves the 503 response for regular requests and lets bypassing
// requests through.
func (h *MaintenanceModeMiddleware) Process(req *Request, next Closure) any {
	if h.config == nil || !h.config.Enabled || h.bypasses(req) {
		return next(req)
	}
	res := NewResponse().SetCode(http.StatusServiceUnavailable).SetContent(h.config.Message)
	if h.config.RetryAfter > 0 {
		res.Header("Retry-After", strconv.Itoa(h.config.RetryAfter))
	}
	return res
}

// bypasses reports whether the request carries the secret query parameter or
// originates from an allowed IP.
func (h *MaintenanceModeMiddleware) bypasses(req *Request) bool {
	if h.config.Secret != "" && req.Request != nil && req.Request.URL != nil {
		if req.Request.URL.Query().Get("secret") == h.config.Secret {
			return true
		}
	}
	clientIP := req.ClientIP()
	for _, allowed := range h.config.AllowedIPs {
		if allowed == clientIP {
			return true
		}
	}
	return false
}

// --- End maintenance mode middleware ---
