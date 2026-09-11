package flow

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// remainingParamRegex detects unresolved placeholders in a generated URL.
var remainingParamRegex = regexp.MustCompile(`\{[^}]+\}`)

// NamedRouteSource provides read access to a router's named routes for URL
// generation. The built-in Router implements it; custom routers can too by
// exposing their named patterns through the same method.
type NamedRouteSource interface {
	// NamedRoutePattern returns the raw path pattern of a named route
	// (e.g. "/users/{id}"). ok is false when no route carries the name.
	NamedRoutePattern(name string) (pattern string, ok bool)
}

// ActionRouteSource provides lookup of routes by controller action string (e.g. "UserController@index").
type ActionRouteSource interface {
	ActionRoutePattern(action string) (pattern string, ok bool)
}

// UrlGenerator builds URLs for named routes and creates/verifies signed URLs.
//
// The key resolver is consulted on every call: the first key signs new URLs,
// and every returned key is accepted during validation, which enables key
// rotation via previous keys. With no usable keys the generator fails closed
// — SignedRoute returns "" and HasValidSignature rejects everything.
type UrlGenerator struct {
	routes                    NamedRouteSource
	keyResolver               func() []string
	missingNamedRouteResolver func(name string, params map[string]string) string
	requestProvider           func() *Request
	baseURL                   string
}

// NewUrlGenerator creates a UrlGenerator bound to the given named-route
// source (typically the router, or any of its group routers). A nil source is
// a programming error and panics.
func NewUrlGenerator(routes NamedRouteSource, baseURL string) *UrlGenerator {
	if routes == nil {
		panic("flow: NewUrlGenerator requires a named route source (a router created by New)")
	}
	return &UrlGenerator{routes: routes, baseURL: baseURL}
}

// SetKeyResolver sets the lazy key source, evaluated on every call so runtime
// config changes take effect immediately without rebuilding the generator.
func (u *UrlGenerator) SetKeyResolver(fn func() []string) *UrlGenerator {
	u.keyResolver = fn
	return u
}

// keys returns the currently usable (non-empty) signature keys.
func (u *UrlGenerator) keys() []string {
	if u.keyResolver == nil {
		return nil
	}
	var keys []string
	for _, k := range u.keyResolver() {
		if k != "" {
			keys = append(keys, k)
		}
	}
	return keys
}

// RouteNotFoundError reports that a named route is not defined.
type RouteNotFoundError struct {
	RouteName string
}

func (e *RouteNotFoundError) Error() string {
	return "flow: route [" + e.RouteName + "] not defined"
}

// Route resolves a named route into a path with its parameters interpolated.
//
// The lookup consults the route source first; on a miss, the missing-route
// resolver (SetMissingNamedRouteResolver) gets a chance to produce the URL;
// otherwise a RouteNotFoundError is returned.
//
// Parameter values are percent-encoded per '/'-separated path segment (slashes
// themselves are preserved). Parameters that match no placeholder in the
// pattern are appended to the query string, sorted by key. Optional
// parameters ("{name?}") are stripped when not supplied. The generator holds
// no request context, so only relative paths are produced.
func (u *UrlGenerator) Route(name string, params map[string]string) (string, error) {
	if u == nil || u.routes == nil {
		return "", &RouteNotFoundError{RouteName: name}
	}
	if pattern, ok := u.routes.NamedRoutePattern(name); ok {
		return u.toRoute(name, pattern, params)
	}
	if u.missingNamedRouteResolver != nil {
		if url := u.missingNamedRouteResolver(name, params); url != "" {
			return url, nil
		}
	}
	return "", &RouteNotFoundError{RouteName: name}
}

// Action resolves a controller action string into a path with its parameters interpolated.
func (u *UrlGenerator) Action(action string, params map[string]string) (string, error) {
	if u == nil || u.routes == nil {
		return "", fmt.Errorf("flow: action [%s] not defined", action)
	}
	if actionSource, ok := u.routes.(ActionRouteSource); ok {
		if pattern, found := actionSource.ActionRoutePattern(action); found {
			url, err := u.toRoute(action, pattern, params)
			if err != nil {
				return "", err
			}
			if u.baseURL != "" {
				url = strings.TrimSuffix(u.baseURL, "/") + url
			}
			return url, nil
		}
	}
	return "", fmt.Errorf("flow: action [%s] not defined", action)
}

// toRoute interpolates parameters into a resolved route pattern. A
// UrlGenerationError is returned when required parameters are missing.
func (u *UrlGenerator) toRoute(name string, pattern string, params map[string]string) (string, error) {
	path := pattern
	query := url.Values{}
	for k, v := range params {
		switch {
		case strings.Contains(path, "{"+k+"}"):
			path = strings.ReplaceAll(path, "{"+k+"}", escapeRouteParam(v))
		case strings.Contains(path, "{"+k+"?}"):
			path = strings.ReplaceAll(path, "{"+k+"?}", escapeRouteParam(v))
		default:
			// Parameters that match no placeholder belong in the query
			// string instead of being dropped.
			query.Set(k, v)
		}
	}

	path = optionalParamRegex.ReplaceAllString(path, "")
	if path == "" {
		path = "/"
	}
	if len(query) > 0 {
		path = path + "?" + query.Encode()
	}
	if remainingParamRegex.MatchString(path) {
		return "", &UrlGenerationError{RouteName: name, Missing: remainingParamRegex.FindAllString(path, -1)}
	}
	return path, nil
}

// SetMissingNamedRouteResolver registers a fallback consulted when a named
// route is not defined: the resolver returns the URL to use, or "" to fall
// through to a RouteNotFoundError.
func (u *UrlGenerator) SetMissingNamedRouteResolver(fn func(name string, params map[string]string) string) *UrlGenerator {
	u.missingNamedRouteResolver = fn
	return u
}

// SetRequestProvider registers the accessor for the request being handled. It
// powers the request-dependent helpers (Current, Previous) and is wired by the
// framework to the router's current request.
func (u *UrlGenerator) SetRequestProvider(fn func() *Request) *UrlGenerator {
	u.requestProvider = fn
	return u
}

// currentRequest returns the request from the provider, if configured.
func (u *UrlGenerator) currentRequest() *Request {
	if u.requestProvider == nil {
		return nil
	}
	return u.requestProvider()
}

// To resolves a path into a normalized, router-relative URL (leading slash).
func (u *UrlGenerator) To(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

// Current returns the path of the request being handled, without the query
// string. Returns "" when no request provider is configured or no request is
// being handled.
func (u *UrlGenerator) Current() string {
	req := u.currentRequest()
	if req == nil {
		return ""
	}
	return req.Path()
}

// Previous returns the previous URL recorded in the session, falling back to
// the given fallback (or "/") when unavailable.
func (u *UrlGenerator) Previous(fallback string) string {
	req := u.currentRequest()
	if req != nil {
		if session := req.Session(); session != nil {
			if prev := session.PreviousUrl(); prev != "" {
				return prev
			}
		}
	}
	if fallback == "" {
		return "/"
	}
	return fallback
}

// escapeRouteParam encodes a parameter value for safe interpolation into the
// route path: each '/'-separated segment is percent-encoded, slashes are
// preserved. This also prevents values from injecting "{placeholder}" tokens
// into the pattern.
func escapeRouteParam(v string) string {
	segments := strings.Split(v, "/")
	for i, s := range segments {
		segments[i] = rawURLEncode(s)
	}
	return strings.Join(segments, "/")
}

// rawURLEncode percent-encodes every byte except the RFC 3986 unreserved
// characters (' ' becomes %20).
func rawURLEncode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// SignedRoute creates a signed URL for a named route. Without an expiration
// the URL never expires; with one it is valid until the given duration has
// passed. Signed with the first usable key; returns "" when the route or a
// signing key is unavailable (fail closed).
func (u *UrlGenerator) SignedRoute(name string, params map[string]string, expiration ...time.Duration) string {
	urlPath, err := u.Route(name, params)
	if err != nil {
		// The route (or the route source) is unavailable: fail closed.
		return ""
	}
	keys := u.keys()
	if len(keys) == 0 {
		// Fail closed: without a key there is nothing to sign with.
		return ""
	}

	payload := urlPath
	if len(expiration) > 0 || strings.Contains(urlPath, "?") {
		// Canonicalize the query (sorted, matching how the verification side
		// replays it) so extra route parameters and expires are covered by
		// the HMAC.
		parsed, err := url.Parse(urlPath)
		if err != nil {
			return ""
		}
		q := parsed.Query()
		if len(expiration) > 0 {
			q.Set("expires", strconv.FormatInt(time.Now().Add(expiration[0]).Unix(), 10))
		}
		payload = parsed.Path
		if len(q) > 0 {
			payload = payload + "?" + q.Encode()
		}
	}

	return addQueryParam(payload, "signature", signHMAC(payload, keys[0]))
}

// addQueryParam appends a single query parameter, choosing '?' or '&'
// depending on whether the URL already carries a query string.
func addQueryParam(u, key, value string) string {
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	return u + sep + key + "=" + url.QueryEscape(value)
}

// TemporarySignedRoute creates a signed URL for a named route that expires
// after the given duration.
func (u *UrlGenerator) TemporarySignedRoute(name string, expiration time.Duration, params map[string]string) string {
	return u.SignedRoute(name, params, expiration)
}

// SignedRouteAbsolute creates a signed URL over the absolute form
// (scheme://host/path?query) of the named route. It requires a request
// provider to determine scheme and host.
func (u *UrlGenerator) SignedRouteAbsolute(name string, params map[string]string, expiration ...time.Duration) string {
	urlPath, err := u.Route(name, params)
	if err != nil {
		return ""
	}
	keys := u.keys()
	if len(keys) == 0 {
		return ""
	}
	req := u.currentRequest()
	if req == nil {
		return ""
	}
	payload := u.absoluteURL(req, urlPath)
	if len(expiration) > 0 {
		expires := strconv.FormatInt(time.Now().Add(expiration[0]).Unix(), 10)
		payload = addQueryParam(payload, "expires", expires)
	}
	return addQueryParam(payload, "signature", signHMAC(payload, keys[0]))
}

// HasValidSignatureAbsolute verifies a signature computed over the absolute
// form of the request URL.
func (u *UrlGenerator) HasValidSignatureAbsolute(req *Request) bool {
	if req == nil || req.Request == nil || req.Request.URL == nil {
		return false
	}
	sig, err := req.Query("signature")
	if err != nil || sig == "" {
		return false
	}
	expiresStr, _ := req.Query("expires")
	if expiresStr != "" {
		expires, err := strconv.ParseInt(expiresStr, 10, 64)
		if err != nil || time.Now().Unix() > expires {
			return false
		}
	}
	keys := u.keys()
	if len(keys) == 0 {
		return false
	}

	pathQuery := signedPayloadFromRequest(req, nil)
	target := u.absoluteURL(req, pathQuery)
	for _, key := range keys {
		if hmac.Equal([]byte(sig), []byte(signHMAC(target, key))) {
			return true
		}
	}
	return false
}

// absoluteURL joins scheme and host with a path (and its query, if present).
func (u *UrlGenerator) absoluteURL(req *Request, pathWithQuery string) string {
	if u.baseURL != "" {
		return strings.TrimSuffix(u.baseURL, "/") + pathWithQuery
	}
	scheme := "http"
	if req.Request.TLS != nil || strings.EqualFold(req.Header("X-Forwarded-Proto"), "https") || req.Request.URL != nil && req.Request.URL.Scheme == "https" {
		scheme = "https"
	}
	host := req.Request.Host
	return scheme + "://" + host + pathWithQuery
}

// HasValidSignature checks whether the request carries a valid, unexpired
// signature, accepting any of the currently configured keys (current +
// previous). A URL without an expires parameter never expires.
func (u *UrlGenerator) HasValidSignature(req *Request) bool {
	return u.HasValidSignatureWhileIgnoring(req)
}

// HasValidSignatureWhileIgnoring behaves like HasValidSignature but skips the
// given query parameter names when rebuilding the signed payload. This lets
// extra parameters (tracking tags, cache busters) be appended after signing
// without breaking the signature.
func (u *UrlGenerator) HasValidSignatureWhileIgnoring(req *Request, ignore ...string) bool {
	if req == nil || req.Request == nil || req.Request.URL == nil {
		return false
	}

	sig, err := req.Query("signature")
	if err != nil || sig == "" {
		return false
	}

	// An absent expires parameter means the signature never expires.
	expiresStr, _ := req.Query("expires")
	if expiresStr != "" {
		expires, err := strconv.ParseInt(expiresStr, 10, 64)
		if err != nil || time.Now().Unix() > expires {
			return false
		}
	}

	keys := u.keys()
	if len(keys) == 0 {
		// Fail closed: no keys configured, nothing can be valid.
		return false
	}

	target := signedPayloadFromRequest(req, ignore)
	for _, key := range keys {
		if hmac.Equal([]byte(sig), []byte(signHMAC(target, key))) {
			return true
		}
	}
	return false
}

// signedPayloadFromRequest rebuilds the canonical "path?sorted_query" string
// (without the signature parameter, and without ignored parameters) that was
// originally signed. Trailing separators are trimmed so permanent signatures
// over a bare path verify correctly.
func signedPayloadFromRequest(req *Request, ignore []string) string {
	u := req.Request.URL
	rawQuery := u.Query()
	rawQuery.Del("signature")

	ignored := make(map[string]struct{}, len(ignore))
	for _, k := range ignore {
		ignored[k] = struct{}{}
	}

	keys := make([]string, 0, len(rawQuery))
	for k := range rawQuery {
		if _, skip := ignored[k]; skip {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var pairs []string
	for _, k := range keys {
		for _, v := range rawQuery[k] {
			pairs = append(pairs, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}

	return strings.TrimSuffix(u.Path+"?"+strings.Join(pairs, "&"), "?")
}

// signHMAC computes the hex-encoded HMAC-SHA256 signature of the payload.
func signHMAC(payload, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
