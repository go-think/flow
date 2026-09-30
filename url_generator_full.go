package flow

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ═══ Router 补齐 ═══

// RespondWithRoute dispatches a request to a route resolved by its name.
func (r *router) RespondWithRoute(name string, request *Request) *Response {
	root := r.root()
	root.flushPending()
	route := root.collection.GetByName(name)
	if route == nil {
		return NotFoundResponse()
	}
	if request == nil {
		request = root.CurrentRequest()
	}
	if request == nil {
		return NotFoundResponse()
	}
	params := route.Bind(request, request.Path())
	return root.runRoute(request, route, params)
}

// GetValidators returns the default validator chain
// .
func (r *router) GetValidators() []RouteValidator {
	return defaultValidators()
}

// ═══ Route 补齐 ═══

// GetValidators returns the validator chain for this route, honoring a custom
// chain set via SetValidators (which is the single source of truth).
func (r *Route) GetValidators() []RouteValidator {
	return r.Validators()
}

// GetCompiled returns the compiled match patterns of this route
// .
func (r *Route) GetCompiled() []*compiledPattern {
	r.compile()
	return r.expanded
}

// SetURI replaces the route URI. It delegates to SetUri so the URI goes
// through (binding fields extracted, "{user:id}" rewritten to
// "{user}") and the compile cache is invalidated exactly like the primary
// spelling.
func (r *Route) SetURI(uri string) *Route {
	return r.SetUri(uri)
}

// ═══ RouteCollection 补齐 ═══

// Iterator returns all routes.
func (c *RouteCollection) Iterator() []*Route {
	return c.All()
}

// ═══ UrlGenerator 补齐 ═══

// IsValidUrl checks whether a string is a valid URL.
// Paths starting with "#", "//", "http(s)://", "mailto:", "tel:" or "sms:"
// are always valid; anything else must parse as an absolute URI with a
// scheme (url.ParseRequestURI plus a scheme check approximates PHP's
// FILTER_VALIDATE_URL).
func (u *UrlGenerator) IsValidUrl(path string) bool {
	for _, prefix := range []string{"#", "//", "http://", "https://", "mailto:", "tel:", "sms:"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	parsed, err := url.ParseRequestURI(path)
	if err != nil {
		return false
	}
	return parsed.Scheme != ""
}

// UrlRoutable is implemented by entities that expose their route key
// . FormatParameters substitutes
// such values with their route key.
type UrlRoutable interface {
	GetRouteKey() string
}

// FormatParameters formats route parameters: values implementing UrlRoutable
// are replaced by their route key, everything else is rendered with
// toStringValue. It returns the parameter map — it never builds a query
// string; Go maps cannot hold mixed value types, so the map is normalized
// to map[string]string).
func (u *UrlGenerator) FormatParameters(params map[string]any) map[string]string {
	out := make(map[string]string, len(params))
	for k, v := range params {
		if routable, ok := v.(UrlRoutable); ok {
			out[k] = routable.GetRouteKey()
			continue
		}
		out[k] = toStringValue(v)
	}
	return out
}

// AddPortToDomain adds the request's non-standard port to a route domain
// . The port is omitted only
// when it is the standard port for the scheme (443 when secure, 80 when not)
// or unknown (0).
func AddPortToDomain(domain string, port int, secure bool) string {
	if port == 0 {
		return domain
	}
	if (secure && port == 443) || (!secure && port == 80) {
		return domain
	}
	return domain + ":" + strconv.Itoa(port)
}

// GetRouteQueryString formats parameters into a query string including the
// leading "?". String-keyed parameters become "k=v" pairs; numeric-keyed
// parameters are appended as bare values, exactly like the reference
// implementation. Divergence note: the reference emits pairs in array
// insertion order; Go maps have no stable order, so pairs are emitted in
// sorted key order to keep URLs deterministic. An empty parameter set yields
// an empty string.
func GetRouteQueryString(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		if isNumericKey(k) {
			pairs = append(pairs, params[k])
			continue
		}
		pairs = append(pairs, url.QueryEscape(k)+"="+url.QueryEscape(params[k]))
	}
	return "?" + strings.Join(pairs, "&")
}

// isNumericKey reports whether a parameter key is numeric in the PHP sense
// (is_numeric): an integer or a float literal such as "42", "-7" or "1.5".
func isNumericKey(key string) bool {
	if _, err := strconv.ParseInt(key, 10, 64); err == nil {
		return true
	}
	_, err := strconv.ParseFloat(key, 64)
	return err == nil
}

// GetStringParameters filters parameters whose KEY is a (non-numeric) string
// (a key-name string check). Values are kept as-is.
func GetStringParameters(params map[string]any) map[string]any {
	out := make(map[string]any)
	for k, v := range params {
		if !isNumericKey(k) {
			out[k] = v
		}
	}
	return out
}

// GetNumericParameters filters parameters whose KEY is numeric, keeping the
// original values untouched (no float precision loss)
// (a numeric key-name check).
func GetNumericParameters(params map[string]any) map[string]any {
	out := make(map[string]any)
	for k, v := range params {
		if isNumericKey(k) {
			out[k] = v
		}
	}
	return out
}

// FormatDomain formats the scheme, domain and request port for a route
// (scheme + domain + request port). No parameter replacement happens here;
// that is
// ReplaceRootParameters' job. Routes without a domain yield "".
func (u *UrlGenerator) FormatDomain(route *Route) string {
	if route == nil || route.GetDomain() == "" {
		return ""
	}
	scheme := GetRouteScheme(route)
	if scheme == "" {
		scheme = u.formatScheme(nil)
	}
	// addRequestPort decides the standard port against the REQUEST scheme,
	// not the route scheme.
	return u.addRequestPort(scheme + route.GetDomain())
}

// GetRouteDomain returns the formatted domain (scheme + domain + request
// port) for the route, or "" when the route has no domain
// (the formatted domain string, not a regex). Domain pattern matching
// lives in compileDomainRegex below.
func (u *UrlGenerator) GetRouteDomain(route *Route) string {
	return u.FormatDomain(route)
}

// compileDomainRegex compiles a domain pattern such as "{account}.example.com"
// into a regex string with a named capture group per placeholder, returning
// the group names in order. This is flow's internal counterpart for matching
// request hosts against a route domain; the reference implementation keeps it inside
// /.
func compileDomainRegex(domain string) (string, []string) {
	if domain == "" || !strings.Contains(domain, "{") {
		return domain, nil
	}
	var names []string
	reg := regexp.MustCompile(`\{(\w+)\}`)
	regexStr := reg.ReplaceAllStringFunc(regexp.QuoteMeta(domain), func(m string) string {
		sub := reg.FindStringSubmatch(m)
		names = append(names, sub[1])
		return "([^.]*)"
	})
	return regexStr, names
}

// GetRouteScheme determines the scheme for a route with the "://" suffix
// appended. Routes marked HttpOnly force "http://"
// and secure routes force "https://"; a route with no scheme restriction
// returns "" and the caller falls back to formatScheme.
func GetRouteScheme(route *Route) string {
	if route == nil {
		return ""
	}
	if route.IsHttpOnly() {
		return "http://"
	}
	if route.IsSecure() {
		return "https://"
	}
	return ""
}

// ReplaceRouteParameters replaces named and positional parameters in a route
// pattern. Named parameters
// are consumed first (with defaults backfill), unprovided optional
// parameters are stripped, and the result is trimmed of slashes — it CAN be
// the empty string, exactly like the reference final path trim.
func (u *UrlGenerator) ReplaceRouteParameters(path string, params map[string]string) string {
	path = u.ReplaceNamedParameters(path, params)
	// Strip unmatched optional parameters.
	path = optionalParamRegex.ReplaceAllString(path, "")
	return strings.Trim(path, "/")
}

// ReplaceNamedParameters replaces named parameters in a pattern
// . Parameters are consumed in
// sorted key order (the reference implementation consumes in insertion order; Go maps are
// unordered, so sorted order keeps the result deterministic). Placeholders
// whose parameter is missing or empty fall back to the generator's default
// parameters); empty
// parameters without a default keep their placeholder.
func (u *UrlGenerator) ReplaceNamedParameters(path string, params map[string]string) string {
	// Supplied parameters first (empty values never fill a placeholder).
	for _, k := range sortedStringKeys(params) {
		v := params[k]
		if v == "" {
			continue
		}
		path = strings.ReplaceAll(path, "{"+k+"}", escapeRouteParam(v))
		path = strings.ReplaceAll(path, "{"+k+"?}", escapeRouteParam(v))
	}
	// Defaults fill placeholders whose parameter is missing or empty.
	for _, k := range sortedStringKeys(u.defaultParameters) {
		if v, ok := params[k]; ok && v != "" {
			continue
		}
		path = strings.ReplaceAll(path, "{"+k+"}", escapeRouteParam(u.defaultParameters[k]))
		path = strings.ReplaceAll(path, "{"+k+"?}", escapeRouteParam(u.defaultParameters[k]))
	}
	return path
}

// sortedStringKeys returns the map's keys in sorted order.
func sortedStringKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ReplaceRootParameters replaces the parameters on the root/domain path
// (replaceRouteParameters over the formatted root; the actual parameter
// replacement happens HERE,
// not in formatDomain). This package-level form runs without a generator, so
// no defaults are applied; use (*UrlGenerator).ReplaceRouteParameters for the
// defaults-aware variant.
func ReplaceRootParameters(domain string, params map[string]string) string {
	gen := &UrlGenerator{}
	return gen.ReplaceRouteParameters(domain, params)
}

// ═══ RouteGroup 补齐 ═══

// MergeMetadata merges two metadata maps.
func MergeMetadata(old, new map[string]any) map[string]any {
	out := make(map[string]any)
	for k, v := range old {
		out[k] = v
	}
	for k, v := range new {
		out[k] = v
	}
	return out
}

// ═══ RouteUri 补齐 ═══

// Sluggify converts a route name to a slug (helper for route naming).
func Sluggify(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), " ", "-")
}

// pregQuote escapes regex special characters.
func pregQuote(s string) string {
	return regexp.QuoteMeta(s)
}

var _ = fmt.Sprintf
var _ = http.StatusOK
var _ = reflect.TypeOf
var _ = sort.Strings
