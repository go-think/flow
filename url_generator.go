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

// routeParamDontEncode maps the percent-encoded forms of characters that are
// kept raw in route parameters back to their literal forms: '%2F', '%40',
// '%3A', '%3B', '%2C', '%3D', '%2B', '%21', '%2A', '%7C', '%3F', '%26',
// '%23' and '%25' (the latter prevents already-encoded input from being
// encoded twice). The replacer applies all substitutions in a single pass, so
// restored output is never re-matched.
var routeParamDontEncode = strings.NewReplacer(
	"%2F", "/",
	"%40", "@",
	"%3A", ":",
	"%3B", ";",
	"%2C", ",",
	"%3D", "=",
	"%2B", "+",
	"%21", "!",
	"%2A", "*",
	"%7C", "|",
	"%3F", "?",
	"%26", "&",
	"%23", "#",
	"%25", "%",
)

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

// DomainNamedRouteSource provides lookup of route domains for URL generation.
type DomainNamedRouteSource interface {
	NamedRouteDomain(name string) (domain string, ok bool)
}

// UrlGenerator builds URLs for named routes and creates/verifies signed URLs.

// The key resolver is consulted on every call: the first key signs new URLs,
// and every returned key is accepted during validation, which enables key
// rotation via previous keys. With no usable keys the generator fails closed
// — SignedRoute returns "" and HasValidSignature rejects everything.
type UrlGenerator struct {
	routes                    NamedRouteSource
	keyResolver               func() []string
	missingNamedRouteResolver func(name string, params map[string]string) string
	missingActionResolver     func(action string, params map[string]string) string
	requestProvider           func() *Request
	baseURL                   string
	forcedScheme              string
	forcedRootURL             string
	assetOrigin               string
	rootControllerNamespace   string
	hostFormatter             func(host string) string
	pathFormatter             func(path string) string
	defaultParameters         map[string]string
}

// NewUrlGenerator creates a UrlGenerator bound to the given named-route
// source (typically the router, or any of its group routers). A nil source is
// a programming error and panics.
func NewUrlGenerator(routes NamedRouteSource, baseURL string) *UrlGenerator {
	if routes == nil {
		panic("flow: NewUrlGenerator requires a named route source (a router created by New)")
	}
	return &UrlGenerator{routes: routes, baseURL: strings.TrimSuffix(baseURL, "/"), defaultParameters: make(map[string]string)}
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
	return "Route [" + e.RouteName + "] not defined."
}

// Route resolves a named route into a URL with its parameters interpolated.
// The lookup consults the route source first; on a miss, the missing-route
// resolver (SetMissingNamedRouteResolver) gets a chance to produce the URL;
// otherwise a RouteNotFoundError is returned.
//
// Parameter values are percent-encoded per '/'-separated path segment (slashes
// themselves are preserved), with reserved characters restored afterwards.
// Parameters that match no placeholder in the pattern are appended to the query
// string. Optional parameters ("{name?}") are stripped when not supplied; empty
// parameter values count as missing.
func (u *UrlGenerator) Route(name string, params map[string]string, absolute ...bool) (string, error) {
	if u == nil || u.routes == nil {
		return "", &RouteNotFoundError{RouteName: name}
	}
	isAbsolute := true
	if len(absolute) > 0 {
		isAbsolute = absolute[0]
	}
	if pattern, ok := u.routes.NamedRoutePattern(name); ok {
		return u.toRoute(name, pattern, params, isAbsolute)
	}
	if u.missingNamedRouteResolver != nil {
		if url := u.missingNamedRouteResolver(name, params); url != "" {
			return url, nil
		}
	}
	return "", &RouteNotFoundError{RouteName: name}
}

// Action resolves a controller action string into a path with its parameters
// interpolated. When a root controller namespace is set, the action is prefixed
// before lookup, falling back to the raw action string when the prefixed form
// matches no route. On a miss the missing-action resolver
// (SetMissingActionRouteResolver) gets a chance to produce the URL; otherwise an
// error is returned.
func (u *UrlGenerator) Action(action string, params map[string]string, absolute ...bool) (string, error) {
	if u == nil || u.routes == nil {
		return "", fmt.Errorf("Action [%s] not defined.", action)
	}
	isAbsolute := true
	if len(absolute) > 0 {
		isAbsolute = absolute[0]
	}
	actionSource, ok := u.routes.(ActionRouteSource)
	if !ok {
		return "", fmt.Errorf("Action [%s] not defined.", action)
	}
	candidates := []string{u.formatAction(action)}
	if candidates[0] != action {
		candidates = append(candidates, action)
	}
	for _, candidate := range candidates {
		if pattern, found := actionSource.ActionRoutePattern(candidate); found {
			return u.toRoute(candidate, pattern, params, isAbsolute)
		}
	}
	if u.missingActionResolver != nil {
		if url := u.missingActionResolver(action, params); url != "" {
			return url, nil
		}
	}
	return "", fmt.Errorf("Action [%s] not defined.", action)
}

// formatAction prefixes the root controller namespace onto the action unless
// it is already fully qualified.
func (u *UrlGenerator) formatAction(action string) string {
	if u.rootControllerNamespace != "" && !strings.HasPrefix(action, "\\") {
		return u.rootControllerNamespace + "\\" + action
	}
	return strings.Trim(action, "\\")
}

// queryPair keeps one key/value pair so query order can be preserved.
type queryPair struct {
	key   string
	value string
}

// toRoute interpolates parameters into a resolved route pattern and formats
// absolute/relative URLs. Missing required
// parameters — including empty-string values — yield a UrlGenerationError.
func (u *UrlGenerator) toRoute(name string, pattern string, params map[string]string, absolute ...bool) (string, error) {
	isAbsolute := true
	if len(absolute) > 0 {
		isAbsolute = absolute[0]
	}

	// Format a copy so URL generation does not mutate the caller's map.
	effective := make(map[string]string, len(params)+len(u.defaultParameters))
	for k, v := range params {
		effective[k] = v
	}

	domainHost := ""
	if domainSource, ok := u.routes.(DomainNamedRouteSource); ok {
		if d, ok := domainSource.NamedRouteDomain(name); ok && d != "" {
			domainHost = d
		}
	}

	// Defaults fill placeholders that were not supplied with a non-empty value.
	// When the caller supplied an empty value, the default still fills the
	// placeholder but the empty parameter is not consumed, so it survives and
	// resurfaces in the query string as "k=". Only genuinely missing parameters
	// are filled into the map here; default-filled-but-supplied-empty ones are
	// tracked separately.
	defaultFill := make(map[string]string)
	for k, v := range u.defaultParameters {
		supplied, ok := effective[k]
		if ok && supplied != "" {
			continue
		}
		if strings.Contains(pattern, "{"+k+"}") || strings.Contains(pattern, "{"+k+"?}") ||
			(domainHost != "" && strings.Contains(domainHost, "{"+k+"}")) {
			if ok {
				defaultFill[k] = v
			} else {
				effective[k] = v
			}
		}
	}

	// Resolve the route entity when the source exposes the collection, for the
	// per-route scheme and the URI used in error messages.
	routeEntity := u.routeEntity(name)
	routeURI := pattern
	if routeEntity != nil {
		routeURI = routeEntity.URI()
	}

	path := pattern
	var queryPairs []queryPair
	keys := make([]string, 0, len(effective))
	for k := range effective {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := effective[k]
		matched := false
		if domainHost != "" && strings.Contains(domainHost, "{"+k+"}") {
			if fill := fillValue(v, defaultFill[k]); fill != "" {
				domainHost = strings.ReplaceAll(domainHost, "{"+k+"}", fill)
			}
			matched = true
		}
		switch {
		case strings.Contains(path, "{"+k+"}"):
			if fill := fillValue(v, defaultFill[k]); fill != "" {
				path = strings.ReplaceAll(path, "{"+k+"}", escapeRouteParam(fill))
			}
			matched = true
		case strings.Contains(path, "{"+k+"?}"):
			if fill := fillValue(v, defaultFill[k]); fill != "" {
				path = strings.ReplaceAll(path, "{"+k+"?}", escapeRouteParam(fill))
			}
			matched = true
		}
		if _, filled := defaultFill[k]; filled {
			// The default filled the placeholder but the empty supplied
			// parameter was not consumed: it lands in the query string as "k=".
			queryPairs = append(queryPairs, queryPair{k, v})
			continue
		}
		if !matched {
			// Parameters matching no placeholder become the query string.
			queryPairs = append(queryPairs, queryPair{k, v})
		}
	}

	// Unprovided optional parameters are stripped.
	domainHost = optionalParamRegex.ReplaceAllString(domainHost, "")
	path = optionalParamRegex.ReplaceAllString(path, "")
	if path == "" {
		path = "/"
	}

	// Any remaining placeholder is a missing required parameter (empty values
	// never silently produce empty URL segments).
	missing := remainingParamRegex.FindAllString(domainHost, -1)
	missing = append(missing, remainingParamRegex.FindAllString(path, -1)...)
	if len(missing) > 0 {
		return "", ForMissingParameters(name, routeURI, missing)
	}

	// A URI fragment must come after any query string, so it is split off the
	// path and appended at the very end of the generated URL.
	fragment := ""
	if idx := strings.Index(path, "#"); idx != -1 {
		fragment = path[idx+1:]
		path = path[:idx]
	}

	querySuffix := ""
	if encoded := encodeQueryPairs(queryPairs); encoded != "" {
		querySuffix = "?" + encoded
	}
	if fragment != "" {
		querySuffix += "#" + fragment
	}

	if isAbsolute {
		if domainHost != "" {
			scheme := GetRouteScheme(routeEntity)
			if scheme == "" {
				scheme = u.formatScheme(nil)
			}
			root := scheme + u.addRequestPort(domainHost)
			return u.Format(root, path) + querySuffix, nil
		}
		if root := u.resolveRoot(nil); root != "" {
			return u.Format(root, path) + querySuffix, nil
		}
	}
	return path + querySuffix, nil
}

// fillValue prefers the supplied parameter value, falling back to the route
// default that backfilled the placeholder.
func fillValue(supplied, def string) string {
	if supplied != "" {
		return supplied
	}
	return def
}

// routeEntity resolves the underlying *Route for a named route when the route
// source can provide it (the built-in router can).
func (u *UrlGenerator) routeEntity(name string) *Route {
	switch src := u.routes.(type) {
	case interface {
		Routes() RouteCollectionInterface
	}:
		if rc := src.Routes(); rc != nil {
			return rc.GetByName(name)
		}
	}
	return nil
}

// addRequestPort appends the current request's non-standard port to a route
// domain. The standard-port decision uses the request scheme, not the route's
// scheme.
func (u *UrlGenerator) addRequestPort(domain string) string {
	req := u.currentRequest()
	if req == nil {
		return domain
	}
	httpReq := req.GetHttpRequest()
	if httpReq == nil || httpReq.Host == "" {
		return domain
	}
	port := 0
	if idx := strings.LastIndex(httpReq.Host, ":"); idx != -1 {
		if p, err := strconv.Atoi(httpReq.Host[idx+1:]); err == nil {
			port = p
		}
	}
	return AddPortToDomain(domain, port, u.requestScheme(req) == "https")
}

// encodeQueryPairs renders ordered query pairs as a query string, encoding
// spaces as "+".
func encodeQueryPairs(pairs []queryPair) string {
	if len(pairs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, url.QueryEscape(p.key)+"="+url.QueryEscape(p.value))
	}
	return strings.Join(parts, "&")
}

// SetMissingNamedRouteResolver registers a fallback consulted when a named
// route is not defined: the resolver returns the URL to use, or "" to fall
// through to a RouteNotFoundError.
func (u *UrlGenerator) SetMissingNamedRouteResolver(fn func(name string, params map[string]string) string) *UrlGenerator {
	u.missingNamedRouteResolver = fn
	return u
}

// SetMissingActionRouteResolver registers a fallback consulted when a
// controller action is not defined: the resolver returns the URL to use, or
// "" to fall through to an "action not defined" error.
func (u *UrlGenerator) SetMissingActionRouteResolver(fn func(action string, params map[string]string) string) *UrlGenerator {
	u.missingActionResolver = fn
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

// GetRequest returns the request currently bound to the generator, or nil when
// no request provider is configured.
func (u *UrlGenerator) GetRequest() *Request {
	return u.currentRequest()
}

// To generates an absolute URL for the given path. Paths that already are valid
// URLs ("#", "//", "http(s)://", "mailto:", "tel:", "sms:") are returned
// unchanged. Otherwise the path is joined with the resolved root (forced root
// URL, base URL or the current request) into an absolute URL. The variadic extra
// values become additional percent-encoded path segments appended after the
// path. A query string embedded in the path is preserved verbatim, in its
// original order.
//
// When no root can be resolved (no forced root, base URL or request host), the
// normalized relative path is returned instead.
func (u *UrlGenerator) To(path string, extra ...string) string {
	return u.to(path, extra, nil)
}

// to implements To with an optional secure override.
func (u *UrlGenerator) to(path string, extra []string, secure *bool) string {
	if u.IsValidUrl(path) {
		return path
	}
	p, query := splitQueryString(path)
	if len(extra) > 0 {
		segments := make([]string, 0, len(extra))
		for _, e := range extra {
			segments = append(segments, rawURLEncode(e))
		}
		p = p + "/" + strings.Join(segments, "/")
	}
	var root string
	if secure != nil {
		// An explicit secure value decides the scheme outright.
		if *secure {
			root = u.formatRoot("https://", "")
		} else {
			root = u.formatRoot("http://", "")
		}
	} else {
		root = u.resolveRoot(nil)
	}
	formatted := u.Format(root, p)
	if root == "" {
		// Format trims the leading slash together with the root; a root-less
		// generator speaks in paths, so restore the slash here.
		formatted = "/" + formatted
	}
	return formatted + query
}

// resolveRoot determines the root URL (scheme://host[:port]) absolute URLs
// and signatures are built against: the forced root / base URL wins over the
// request root. The scheme comes from the forced scheme when set, otherwise
// from the root itself (base URL, then request). Deriving the scheme from the
// root instead of the request keeps signing and verification symmetric even
// when the signing side has no request bound.
func (u *UrlGenerator) resolveRoot(req *Request) string {
	if u.baseURL != "" {
		return u.applyForcedScheme(u.baseURL)
	}
	if req == nil {
		req = u.currentRequest()
	}
	if req == nil {
		return ""
	}
	root := u.requestRoot(req)
	if root == "" {
		return ""
	}
	return u.applyForcedScheme(root)
}

// applyForcedScheme replaces the root's scheme prefix with the forced scheme,
// leaving the root untouched when no scheme is forced.
func (u *UrlGenerator) applyForcedScheme(root string) string {
	if u.forcedScheme == "" {
		return root
	}
	start := "https://"
	if strings.HasPrefix(root, "http://") {
		start = "http://"
	}
	if u.forcedScheme == start {
		return root
	}
	return strings.Replace(root, start, u.forcedScheme, 1)
}

// splitQueryString splits a path at its first "?" into the path and the raw
// query substring (including the leading "?", if any).
func splitQueryString(path string) (string, string) {
	if idx := strings.Index(path, "?"); idx != -1 {
		return path[:idx], path[idx:]
	}
	return path, ""
}

// mergeQueryPairs merges new query parameters over the pairs parsed from an
// existing raw query string: existing pair order is preserved (values are
// overridden in place) and new keys are appended in sorted order.
func mergeQueryPairs(rawQuery string, query map[string]string) []queryPair {
	var pairs []queryPair
	index := make(map[string]int)
	if rawQuery != "" {
		for _, part := range strings.Split(rawQuery, "&") {
			if part == "" {
				continue
			}
			kv := strings.SplitN(part, "=", 2)
			key := decodeQueryComponent(kv[0])
			value := ""
			if len(kv) == 2 {
				value = decodeQueryComponent(kv[1])
			}
			if i, ok := index[key]; ok {
				pairs[i].value = value
			} else {
				index[key] = len(pairs)
				pairs = append(pairs, queryPair{key, value})
			}
		}
	}
	if len(query) > 0 {
		for k, v := range query {
			if i, ok := index[k]; ok {
				pairs[i].value = v
			}
		}
		newKeys := make([]string, 0, len(query))
		for k := range query {
			if _, exists := index[k]; !exists {
				newKeys = append(newKeys, k)
			}
		}
		sort.Strings(newKeys)
		for _, k := range newKeys {
			index[k] = len(pairs)
			pairs = append(pairs, queryPair{k, query[k]})
		}
	}
	return pairs
}

func decodeQueryComponent(s string) string {
	if decoded, err := url.QueryUnescape(s); err == nil {
		return decoded
	}
	return s
}

// Defaults sets named default parameters used by route URL generation.
func (u *UrlGenerator) Defaults(defaults map[string]string) *UrlGenerator {
	if u.defaultParameters == nil {
		u.defaultParameters = make(map[string]string)
	}
	for k, v := range defaults {
		u.defaultParameters[k] = v
	}
	return u
}

// Current returns the absolute URL of the request being handled, without the
// query string. Returns "" when no request provider is configured or no request
// is being handled.
func (u *UrlGenerator) Current() string {
	req := u.currentRequest()
	if req == nil {
		return ""
	}
	return u.to(req.Path(), nil, nil)
}

// Full returns the full URL of the request being handled, including the query
// string. The URL is absolutized when the request carries a host.
func (u *UrlGenerator) Full() string {
	req := u.currentRequest()
	if req == nil {
		return ""
	}
	httpReq := req.GetHttpRequest()
	if httpReq == nil || httpReq.URL == nil {
		return ""
	}
	full := httpReq.URL.String()
	if httpReq.Host != "" && !strings.HasPrefix(full, "http://") && !strings.HasPrefix(full, "https://") {
		if root := u.requestRoot(req); root != "" {
			full = root + full
		}
	}
	return full
}

// PreviousPath returns the path portion of the previous URL, with the base
// URL prefix stripped and trailing slashes trimmed.
// An empty result collapses to "/".
func (u *UrlGenerator) PreviousPath(fallback string) string {
	previousPath := u.Previous(fallback)
	parsed, err := url.Parse(previousPath)
	if err != nil {
		return "/"
	}
	path := parsed.Path
	if path == "" {
		return "/"
	}
	if basePath := u.To("/"); basePath != "" {
		if baseParsed, err := url.Parse(basePath); err == nil && baseParsed.Path != "" && baseParsed.Path != "/" {
			path = strings.TrimPrefix(path, baseParsed.Path)
		}
	}
	path = strings.TrimRight(path, "/")
	if path == "" {
		return "/"
	}
	return path
}

// Previous returns the URL of the previous request. The
// Referer header wins and is normalized through to(); otherwise the previous
// URL recorded in the session is used; otherwise the fallback (default "/")
// is generated.
func (u *UrlGenerator) Previous(fallback string) string {
	req := u.currentRequest()
	if req != nil {
		// Referer header takes priority over session and is run
		// through to() for normalization.
		if ref := req.Header("Referer"); ref != "" {
			return u.to(ref, nil, nil)
		}
		if session := req.Session(); session != nil {
			if prev := session.PreviousUrl(); prev != "" {
				return prev
			}
		}
	}
	if fallback == "" {
		return u.to("/", nil, nil)
	}
	return u.to(fallback, nil, nil)
}

// escapeRouteParam encodes a parameter value for safe interpolation into the
// route path: each '/'-separated segment is percent-encoded, slashes are
// preserved, and characters are restored
// afterwards so they are not double-encoded. This also prevents values from
// injecting "{placeholder}" tokens into the pattern.
func escapeRouteParam(v string) string {
	segments := strings.Split(v, "/")
	for i, s := range segments {
		segments[i] = routeParamDontEncode.Replace(rawURLEncode(s))
	}
	return strings.Join(segments, "/")
}

// rawURLEncode percent-encodes every byte except the RFC 3986 unreserved
// characters (' ' becomes %20).
func rawURLEncode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// SignedRoute creates a signed URL for a named route. The signature covers the
// absolute URL by default (scheme://host/path?query) and is computed with the
// first usable key; every configured key is accepted during validation.
//
// The variadic args accept an optional expiration (nil, time.Duration, int or
// int64 seconds, or a time.Time deadline — a zero duration means the URL never
// expires) and a trailing bool that turns the absolute form off:
//
//	SignedRoute("name", params)                   // absolute, never expires
//	SignedRoute("name", params, time.Hour)        // absolute, expiring
//	SignedRoute("name", params, time.Hour, false) // relative, expiring
//
// Without an expiration the URL never expires. Returns "" when the route or a
// signing key is unavailable (fail closed). Passing the reserved "signature" or
// "expires" parameters panics with an error. The "expires" value joins the route
// parameters (the query is emitted in sorted key order); a single route
// resolution produces the URL that is signed, and the signature is appended as a
// trailing "signature" query parameter.
func (u *UrlGenerator) SignedRoute(name string, params map[string]string, args ...any) string {
	// Reserved parameter check.
	for _, reserved := range []string{"signature", "expires"} {
		if _, ok := params[reserved]; ok {
			panic(fmt.Errorf("\"%s\" is a reserved parameter when generating signed routes. Please rename your route parameter.", strings.ToUpper(reserved[:1])+reserved[1:]))
		}
	}

	// Expiration handling.
	expires := ""
	hasExpiration := false
	absolute := true
	for _, arg := range args {
		switch v := arg.(type) {
		case nil:
		case bool:
			absolute = v
		case time.Duration:
			if v != 0 {
				expires, hasExpiration = strconv.FormatInt(time.Now().Add(v).Unix(), 10), true
			}
		case int:
			if v != 0 {
				expires, hasExpiration = strconv.FormatInt(time.Now().Add(time.Duration(v)*time.Second).Unix(), 10), true
			}
		case int64:
			if v != 0 {
				expires, hasExpiration = strconv.FormatInt(time.Now().Add(time.Duration(v)*time.Second).Unix(), 10), true
			}
		case time.Time:
			remaining := time.Until(v)
			if remaining < 0 {
				remaining = 0
			}
			expires, hasExpiration = strconv.FormatInt(time.Now().Add(remaining).Unix(), 10), true
		}
	}

	keys := u.keys()
	if len(keys) == 0 {
		// Fail closed: without a key there is nothing to sign with.
		return ""
	}

	// route resolution: expires travels with the other route
	// parameters; anything matching no placeholder lands in the (sorted)
	// query string. The HMAC input is this raw URL.
	effective := make(map[string]string, len(params)+1)
	for k, v := range params {
		effective[k] = v
	}
	if hasExpiration {
		effective["expires"] = expires
	}
	urlStr, err := u.Route(name, effective, absolute)
	if err != nil {
		// The route (or the route source) is unavailable: fail closed.
		return ""
	}

	return addQueryParam(urlStr, "signature", signHMAC(urlStr, keys[0]))
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
// after the given duration. The URL is signed
// over its absolute form unless absolute is false.
func (u *UrlGenerator) TemporarySignedRoute(name string, expiration any, params map[string]string, absolute ...bool) string {
	args := make([]any, 0, len(absolute)+1)
	args = append(args, expiration)
	for _, a := range absolute {
		args = append(args, a)
	}
	return u.SignedRoute(name, params, args...)
}

// SignedRouteAbsolute creates a signed URL over the absolute form
// (scheme://host/path?query) of the named route. It is an alias for
// SignedRoute with the absolute flag forced on.
func (u *UrlGenerator) SignedRouteAbsolute(name string, params map[string]string, expiration ...time.Duration) string {
	args := make([]any, 0, len(expiration)+1)
	for _, e := range expiration {
		args = append(args, e)
	}
	args = append(args, true)
	return u.SignedRoute(name, params, args...)
}

// HasValidSignature checks whether the request carries a valid, unexpired
// signature, accepting any of the currently configured keys (current +
// previous). The signature is verified against the ABSOLUTE request URL by
// default; pass false to verify the relative
// form. A URL without an expires parameter never expires. When no root can be
// resolved from the request (empty host and no base URL) the relative form is
// verified, keeping sign/verify symmetric for root-less generators.
func (u *UrlGenerator) HasValidSignature(req *Request, absolute ...bool) bool {
	isAbsolute := true
	if len(absolute) > 0 {
		isAbsolute = absolute[0]
	}
	return u.hasValidSignature(req, isAbsolute, nil)
}

// HasValidSignatureAbsolute verifies a signature computed over the absolute
// form of the request URL. Alias for HasValidSignature with absolute on.
func (u *UrlGenerator) HasValidSignatureAbsolute(req *Request) bool {
	return u.hasValidSignature(req, true, nil)
}

// HasValidRelativeSignature checks the signature using the relative path only.
func (u *UrlGenerator) HasValidRelativeSignature(req *Request, ignore ...string) bool {
	return u.hasValidSignature(req, false, ignore)
}

// HasValidSignatureWhileIgnoring behaves like HasValidSignature but skips the
// given query parameter names when rebuilding the signed payload. This lets
// extra parameters (tracking tags, cache busters) be appended after signing
// without breaking the signature.
func (u *UrlGenerator) HasValidSignatureWhileIgnoring(req *Request, ignore ...string) bool {
	return u.hasValidSignature(req, true, ignore)
}

// hasValidSignature combines the HMAC check with the expiry check.
func (u *UrlGenerator) hasValidSignature(req *Request, absolute bool, ignore []string) bool {
	if !u.correctSignature(req, absolute, ignore) {
		return false
	}
	return u.SignatureHasNotExpired(req)
}

// HasCorrectSignature checks only the HMAC hash, not the expiry. The signature
// is verified against the absolute request URL unless absolute is false.
func (u *UrlGenerator) HasCorrectSignature(req *Request, absolute ...bool) bool {
	isAbsolute := true
	if len(absolute) > 0 {
		isAbsolute = absolute[0]
	}
	return u.correctSignature(req, isAbsolute, nil)
}

// correctSignature rebuilds the signed payload from the request and compares
// it against the presented signature with every configured key using a
// constant-time comparison.
func (u *UrlGenerator) correctSignature(req *Request, absolute bool, ignore []string) bool {
	if req == nil || req.Request == nil || req.Request.URL == nil {
		return false
	}
	sig, err := req.Query("signature")
	if err != nil || sig == "" {
		return false
	}
	keys := u.keys()
	if len(keys) == 0 {
		return false
	}
	target := u.signedPayload(req, absolute, ignore)
	for _, key := range keys {
		if hmac.Equal([]byte(sig), []byte(signHMAC(target, key))) {
			return true
		}
	}
	return false
}

// SignatureHasNotExpired checks only the expires parameter. An absent expires
// parameter never expires, and so do "0" and "". "0.0" parses as the number 0
// and therefore counts as expired, as does any other numeric string that has
// already passed. A non-numeric value is treated as 0 and counts as expired.
func (u *UrlGenerator) SignatureHasNotExpired(req *Request) bool {
	if req == nil || req.Request == nil {
		return true
	}
	expiresStr, _ := req.Query("expires")
	switch expiresStr {
	case "", "0":
		// Never expires.
		return true
	}
	var expires int64
	if v, err := strconv.ParseInt(expiresStr, 10, 64); err == nil {
		expires = v
	} else if f, ferr := strconv.ParseFloat(expiresStr, 64); ferr == nil {
		// Numeric strings like "0.0" compare numerically.
		expires = int64(f)
	} else {
		// A non-numeric value compares as 0: expired.
		return false
	}
	return time.Now().Unix() <= expires
}

// signedPayload rebuilds the canonical string that was signed: the root
// (absolute form) joined with the request path and the raw query string
// (original order and encoding) minus the signature parameter and any ignored
// parameters.
func (u *UrlGenerator) signedPayload(req *Request, absolute bool, ignore []string) string {
	path, query := canonicalRequestPayload(req, ignore)
	root := ""
	if absolute {
		root = u.signatureRoot(req)
	}
	return joinSignedPayload(root, path, query)
}

// signatureRoot resolves the root URL signatures are computed against for the
// given request. It is resolveRoot: the forced root/base URL wins over the
// request root, and the scheme does not depend on request presence, keeping
// signing and verification symmetric. An empty result means the generator has
// no root and falls back to the relative form on both sides.
func (u *UrlGenerator) signatureRoot(req *Request) string {
	return u.resolveRoot(req)
}

// joinSignedPayload assembles root+path with the canonical query: the absolute
// URL is right-trimmed of path slashes, the relative form is '/'+request path
// (which trims slashes), and a final right-trim strips trailing '?' characters
// from the concatenation — never path slashes.
func joinSignedPayload(root, path, query string) string {
	var base string
	if root != "" {
		base = strings.TrimRight(root+path, "/")
	} else {
		// Relative form: '/'+request path — slashes are trimmed and the root
		// path collapses to "/".
		if trimmed := strings.Trim(path, "/"); trimmed == "" {
			base = "//" // an empty path resolves to "/", so '/'+"/" is "//"
		} else {
			base = "/" + trimmed
		}
	}
	return strings.TrimRight(base+"?"+query, "?")
}

// canonicalRequestPayload extracts the request path and the RAW query string
// minus the signature parameter and minus any ignored parameters. Segments keep
// their original order and encoding: they are only split on "&", keyed by the
// raw part before "=", and re-joined — never re-parsed, sorted or re-encoded.
// The empty query collapses to "" so permanent signatures over a bare path
// verify correctly.
func canonicalRequestPayload(req *Request, ignore []string) (string, string) {
	u := req.Request.URL

	ignored := make(map[string]struct{}, len(ignore))
	for _, k := range ignore {
		ignored[k] = struct{}{}
	}

	var kept []string
	for _, part := range strings.Split(u.RawQuery, "&") {
		key := part
		if idx := strings.Index(part, "="); idx != -1 {
			key = part[:idx]
		}
		if key == "signature" {
			continue
		}
		if _, skip := ignored[key]; skip {
			continue
		}
		kept = append(kept, part)
	}
	return u.Path, strings.Join(kept, "&")
}

// signHMAC computes the hex-encoded HMAC-SHA256 signature of the payload.
func signHMAC(payload, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// ForceScheme forces the URL scheme for all generated URLs. The scheme may be
// given bare ("https") or with its "://" suffix; "://" is appended only when the
// value does not already contain it.
func (u *UrlGenerator) ForceScheme(scheme string) *UrlGenerator {
	u.forcedScheme = normalizeScheme(scheme)
	return u
}

// normalizeScheme appends "://" to a bare scheme so scheme values are always
// directly concatenatable.
func normalizeScheme(scheme string) string {
	scheme = strings.TrimSpace(scheme)
	if scheme == "" {
		return ""
	}
	if !strings.Contains(scheme, "://") {
		scheme += "://"
	}
	return scheme
}

// ForceHttps forces the HTTPS scheme for all generated URLs. Passing false
// leaves the current scheme untouched.
func (u *UrlGenerator) ForceHttps(force ...bool) *UrlGenerator {
	should := true
	if len(force) > 0 {
		should = force[0]
	}
	if should {
		return u.ForceScheme("https")
	}
	return u
}

// ForceRootURL forces the root URL for all generated URLs. An empty root
// releases the force.
func (u *UrlGenerator) ForceRootURL(root string) *UrlGenerator {
	if u == nil {
		return u
	}
	if root == "" {
		u.baseURL = ""
		return u
	}
	u.baseURL = strings.TrimSuffix(root, "/")
	return u
}

// UseOrigin sets the URL origin for all generated URLs. Alias of ForceRootURL.
func (u *UrlGenerator) UseOrigin(root string) *UrlGenerator {
	return u.ForceRootURL(root)
}

// UseAssetOrigin sets a separate origin for asset URLs.
func (u *UrlGenerator) UseAssetOrigin(origin string) *UrlGenerator {
	u.assetOrigin = origin
	return u
}

// Asset resolves an asset path against the asset origin or base URL. Valid URLs
// are returned unchanged; the path is trimmed on both sides; the origin falls
// back to formatRoot built on the request scheme (http:// or https:// per TLS /
// X-Forwarded-Proto, or the secure override).
func (u *UrlGenerator) Asset(path string, secure ...bool) string {
	if u.IsValidUrl(path) {
		return path
	}
	var secureFlag *bool
	if len(secure) > 0 {
		secureFlag = &secure[0]
	}
	root := u.assetOrigin
	if root == "" {
		root = u.formatRoot(u.assetScheme(secureFlag), "")
	}
	return strings.TrimSuffix(u.removeIndex(root), "/") + "/" + strings.Trim(path, "/")
}

// SecureAsset resolves an asset path with HTTPS.
func (u *UrlGenerator) SecureAsset(path string) string {
	return u.Asset(path, true)
}

// AssetFrom resolves an asset path from a custom root such as a CDN. The root
// runs through formatRoot with the resolved scheme, then the trimmed path is
// appended.
func (u *UrlGenerator) AssetFrom(root, path string, secure ...bool) string {
	var secureFlag *bool
	if len(secure) > 0 {
		secureFlag = &secure[0]
	}
	root = u.formatRoot(u.assetScheme(secureFlag), root)
	return u.removeIndex(root) + "/" + strings.Trim(path, "/")
}

// assetScheme resolves the scheme for asset URLs:
// an explicit secure value wins, then the forced scheme, then the request
// scheme. Unlike formatScheme it returns "" when no scheme context exists at
// all (no secure flag, no forced scheme, no request) so custom roots keep
// their own scheme.
func (u *UrlGenerator) assetScheme(secure *bool) string {
	if secure != nil {
		if *secure {
			return "https://"
		}
		return "http://"
	}
	if u.forcedScheme != "" {
		return u.forcedScheme
	}
	if req := u.currentRequest(); req != nil {
		return u.requestScheme(req) + "://"
	}
	return ""
}

// removeIndex strips a trailing front-controller filename from a root URL.
func (u *UrlGenerator) removeIndex(root string) string {
	if strings.Contains(root, "index.php") {
		return strings.ReplaceAll(root, "/index.php", "")
	}
	return root
}

// Query builds the absolute URL for a path with the given query parameters
// merged over any query string already present in the path. Existing pair order
// is preserved and values from query override existing ones in place. New keys
// are appended in sorted order to keep URLs deterministic. Trailing '?'
// characters are trimmed off the final URL. The variadic extra values become
// additional percent-encoded path segments.
func (u *UrlGenerator) Query(path string, query map[string]string, extra ...string) string {
	p, rawQuery := splitQueryString(path)
	merged := mergeQueryPairs(strings.TrimPrefix(rawQuery, "?"), query)
	built := p
	if len(merged) > 0 {
		built = p + "?" + encodeQueryPairs(merged)
	}
	return strings.TrimRight(u.to(built, extra, nil), "?")
}

// Secure generates an absolute HTTPS URL for the given path; the variadic
// parameters become extra percent-encoded path tail segments appended after the
// path.
func (u *UrlGenerator) Secure(path string, parameters ...string) string {
	secure := true
	return u.to(path, parameters, &secure)
}

// WithKeyResolver returns a CLONE of the generator with the given key
// resolver; the receiver is left untouched.
func (u *UrlGenerator) WithKeyResolver(fn func() []string) *UrlGenerator {
	clone := *u
	return clone.SetKeyResolver(fn)
}

// GetRootControllerNamespace returns the root controller namespace.
func (u *UrlGenerator) GetRootControllerNamespace() string {
	return u.rootControllerNamespace
}

// SetRootControllerNamespace sets the root controller namespace consumed by
// Action lookups.
func (u *UrlGenerator) SetRootControllerNamespace(ns string) *UrlGenerator {
	u.rootControllerNamespace = ns
	return u
}

// formatScheme resolves the default scheme with a "://" suffix. An explicit
// secure value wins, then the forced scheme, then the current request's scheme,
// defaulting to http.
func (u *UrlGenerator) formatScheme(secure *bool) string {
	if secure != nil {
		if *secure {
			return "https://"
		}
		return "http://"
	}
	if u.forcedScheme != "" {
		return u.forcedScheme
	}
	if req := u.currentRequest(); req != nil {
		return u.requestScheme(req) + "://"
	}
	return "http://"
}

// requestScheme resolves the scheme of the given request, honoring TLS and
// the X-Forwarded-Proto header.
func (u *UrlGenerator) requestScheme(req *Request) string {
	httpReq := req.GetHttpRequest()
	if httpReq == nil {
		return "http"
	}
	if httpReq.TLS != nil ||
		strings.EqualFold(req.Header("X-Forwarded-Proto"), "https") ||
		(httpReq.URL != nil && httpReq.URL.Scheme == "https") {
		return "https"
	}
	return "http"
}

// requestRoot returns scheme://host for the given request. Non-standard ports
// are kept; the standard port for the scheme (80/443) is stripped. An empty
// result means no root is known.
func (u *UrlGenerator) requestRoot(req *Request) string {
	httpReq := req.GetHttpRequest()
	if httpReq == nil || httpReq.Host == "" {
		return ""
	}
	scheme := u.requestScheme(req)
	host := httpReq.Host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		port := host[idx+1:]
		if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
			host = host[:idx]
		}
	}
	return scheme + "://" + host
}

// FormatRoot formats the root URL with the given scheme. The scheme may be given
// bare ("https") or with its "://" suffix; when root is empty it defaults to the
// forced root URL / base URL and then the current request, and its scheme prefix
// is replaced with the given scheme. Non-standard ports are preserved.
func (u *UrlGenerator) FormatRoot(scheme, root string) string {
	return u.formatRoot(normalizeScheme(scheme), root)
}

// formatRoot implements FormatRoot: when root is empty it falls back to the
// forced root URL / base URL, then the current request root. The root's
// scheme prefix is replaced with the given scheme (no-op when empty).
func (u *UrlGenerator) formatRoot(scheme, root string) string {
	if root == "" {
		if u.baseURL != "" {
			root = u.baseURL
		} else if req := u.currentRequest(); req != nil {
			root = u.requestRoot(req)
		}
	}
	if root == "" {
		return ""
	}
	start := "https://"
	if strings.HasPrefix(root, "http://") {
		start = "http://"
	}
	if scheme == "" || scheme == start {
		return root
	}
	return strings.Replace(root, start, scheme, 1)
}

// Format formats a root URL and path into a complete URL. The path is normalized
// to '/'+trim(path,'/') first, and this normalized path is what the path
// formatter callback receives; the host formatter runs on the root. The result
// is trim(root+path, '/'): an empty root yields the normalized path without its
// leading slash.
func (u *UrlGenerator) Format(root, path string) string {
	path = "/" + strings.Trim(path, "/")
	if u.hostFormatter != nil {
		root = u.hostFormatter(root)
	}
	path = u.GetPathFormatter()(path)
	return strings.Trim(root+path, "/")
}

// SetHostFormatter sets a custom host formatting callback.
func (u *UrlGenerator) SetHostFormatter(fn func(host string) string) *UrlGenerator {
	u.hostFormatter = fn
	return u
}

// SetPathFormatter sets a custom path formatting callback.
func (u *UrlGenerator) SetPathFormatter(fn func(path string) string) *UrlGenerator {
	u.pathFormatter = fn
	return u
}

// GetPathFormatter returns the current path formatter, falling back to an
// identity function when none was configured.
func (u *UrlGenerator) GetPathFormatter() func(path string) string {
	if u.pathFormatter == nil {
		return func(path string) string { return path }
	}
	return u.pathFormatter
}
