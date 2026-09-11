package flow

// RouteValidator is the contract for the per-request route checks that run
// after a candidate route is located (Laravel: Matching\ValidatorInterface).
type RouteValidator interface {
	// Matches reports whether the candidate route satisfies this validator
	// for the request.
	Matches(route *Route, request *Request) bool
}

// UriValidator checks the request path against the compiled pattern.
type UriValidator struct{}

// Matches implements RouteValidator.
func (UriValidator) Matches(route *Route, request *Request) bool {
	return route.matchesPath(request.GetPath())
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

// HostValidator checks the host restriction. Unlike the other validators it
// also extracts host parameters; used directly by the collection matcher.
type HostValidator struct{}

// MatchesAndExtract implements the host check with parameter extraction.
func (HostValidator) MatchesAndExtract(route *Route, request *Request) (bool, []*parameter) {
	return routeMatchesDomain(route, request)
}

// defaultValidators is the validator chain applied to every candidate route,
// ordered like Laravel: scheme, method, uri (host is handled with parameter
// extraction by the collection matcher).
func defaultValidators() []RouteValidator {
	return []RouteValidator{SchemeValidator{}, MethodValidator{}, UriValidator{}}
}
