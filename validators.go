package flow

import (
	"net/url"
	"strings"
)

// RouteValidator is the contract for the per-request route checks that run
// after a candidate route is located.
type RouteValidator interface {
	// Matches reports whether the candidate route satisfies this validator
	// for the request.
	Matches(route *Route, request *Request) bool
}

// UriValidator checks the request path against the compiled pattern.
type UriValidator struct{}

// Matches implements RouteValidator. The trailing slash is trimmed BEFORE
// decoding, so an encoded slash ("/users%2F") does not decode into a separator
// and match "/users".
func (UriValidator) Matches(route *Route, request *Request) bool {
	raw := request.GetPath()
	if req := request.Request; req != nil && req.URL != nil {
		if escaped := req.URL.EscapedPath(); escaped != "" {
			raw = escaped
		}
	}
	path := strings.TrimRight(raw, "/")
	if decoded, err := url.PathUnescape(path); err == nil {
		path = decoded
	}
	if path == "" {
		path = "/"
	}
	return route.matchesPath(path)
}

// MethodValidator checks the HTTP verb against the route methods.
type MethodValidator struct{}

// Matches implements RouteValidator.
func (MethodValidator) Matches(route *Route, request *Request) bool {
	return matchMethods(request.GetMethod(), route.Methods())
}

// SchemeValidator checks the http/https requirement of the route.
type SchemeValidator struct{}

// Matches implements RouteValidator.
func (SchemeValidator) Matches(route *Route, request *Request) bool {
	return routeMatchesScheme(route, request)
}

// HostValidator checks the host restriction of the route against the request
// host. Host parameter extraction happens in the RouteParameterBinder.
type HostValidator struct{}

// Matches implements RouteValidator.
func (HostValidator) Matches(route *Route, request *Request) bool {
	return routeMatchesDomain(route, request)
}

// defaultValidators is the validator chain applied to every candidate route, in
// the order uri, method, scheme, host.
func defaultValidators() []RouteValidator {
	return []RouteValidator{UriValidator{}, MethodValidator{}, SchemeValidator{}, HostValidator{}}
}
