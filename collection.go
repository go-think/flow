package flow

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrRouteNotFound is returned when no route matches a request
//.
var ErrRouteNotFound = errors.New("route not found")

// NotFoundError reports that no route matched the request. The message mirrors
// the reference notFoundHttpException text.
type NotFoundError struct {
	Message string
}

func (e *NotFoundError) Error() string { return e.Message }

// Is makes errors.Is(err, ErrRouteNotFound) keep working for callers that
// checked the sentinel before the message was introduced.
func (e *NotFoundError) Is(target error) bool { return target == ErrRouteNotFound }

// MethodNotAllowedError is returned when the request path matches routes that
// exist for other HTTP verbs only.
// Allowed carries the verbs in Router verb order; Message mirrors the reference implementation
// exception text.
type MethodNotAllowedError struct {
	Allowed []string
	Message string
}

func (e *MethodNotAllowedError) Error() string { return e.Message }

// RouteCollection stores the registered routes with their lookup indexes,
// mirroring the reference routeCollection: per-method buckets keyed by
// "domain+uri" (a later registration with the same key replaces the earlier
// one in place), a separate domain bucket so domain routes are matched and
// listed first, and name/action lookup tables where the first registration
// wins.
type RouteCollection struct {
	// methodRoutes[method] holds non-domain routes for the verb in
	// registration order; methodIndexes[method] maps domainAndUri to its slot
	// so re-registration replaces the entry instead of appending.
	methodRoutes  map[string][]*Route
	methodIndexes map[string]map[string]int
	methodDomains map[string][]*Route
	domainIndexes map[string]map[string]int
	allRoutes     []*Route
	allIndexes    map[string]int
	allDomains    []*Route
	domainKeyIdx  map[string]int
	byName        map[string]*Route
	byAction      map[string]*Route
}

// NewRouteCollection creates an empty route collection.
func NewRouteCollection() *RouteCollection {
	return &RouteCollection{
		methodRoutes:  make(map[string][]*Route),
		methodIndexes: make(map[string]map[string]int),
		methodDomains: make(map[string][]*Route),
		domainIndexes: make(map[string]map[string]int),
		allIndexes:    make(map[string]int),
		domainKeyIdx:  make(map[string]int),
		byName:        make(map[string]*Route),
		byAction:      make(map[string]*Route),
	}
}

// Add indexes a route into the collection and returns it
//. Routes registered with the
// same methods+domain+uri replace the earlier registration, exactly like
// the reference keyed storage.
func (c *RouteCollection) Add(route *Route) *Route {
	methods := route.Methods()
	domainAndUri := route.GetDomain() + route.URI()
	allKey := strings.Join(methods, "|") + domainAndUri

	if route.GetDomain() != "" {
		for _, method := range methods {
			list := c.methodDomains[method]
			c.upsert(&list, c.registerIndex(c.domainIndexes, method), domainAndUri, route)
			c.methodDomains[method] = list
		}
		c.upsert(&c.allDomains, c.domainKeyIdx, allKey, route)
	} else {
		for _, method := range methods {
			list := c.methodRoutes[method]
			c.upsert(&list, c.registerIndex(c.methodIndexes, method), domainAndUri, route)
			c.methodRoutes[method] = list
		}
		c.upsert(&c.allRoutes, c.allIndexes, allKey, route)
	}

	// Name and action lookups keep the first registration, like
	//. The action list only holds string
	// controller references (the reference implementation: addToActionList indexes
	// action['controller'] exclusively — closures never enter it).
	if name := route.GetName(); name != "" {
		if _, ok := c.byName[name]; !ok {
			c.byName[name] = route
		}
	}
	if action := route.ActionName(); action != "" {
		if ca, ok := route.handler.(ControllerAction); ok {
			if _, isStr := ca.Controller.(string); isStr {
				if _, exists := c.byAction[action]; !exists {
					c.byAction[action] = route
				}
			}
		}
	}
	return route
}

// upsert replaces the entry at a known slot or appends a new one, keeping
// insertion order stable across re-registrations.
func (c *RouteCollection) upsert(list *[]*Route, index map[string]int, key string, route *Route) {
	if index == nil {
		index = make(map[string]int)
	}
	if slot, ok := index[key]; ok {
		(*list)[slot] = route
		return
	}
	index[key] = len(*list)
	*list = append(*list, route)
}

// registerIndex lazily creates the per-method index map.
func (c *RouteCollection) registerIndex(indexes map[string]map[string]int, method string) map[string]int {
	if idx, ok := indexes[method]; ok {
		return idx
	}
	idx := make(map[string]int)
	indexes[method] = idx
	return idx
}

// Match resolves a request to a route following the reference implementation
//: candidates for the request verb (domain
// routes first) are tried in registration order with fallback routes last;
// otherwise alternate verbs are probed for a 405, and finally a not-found
// error is produced.
func (c *RouteCollection) Match(request *Request) (*Route, []*parameter, error) {
	routes := c.Get(request.GetMethod())

	route := matchAgainstRoutes(routes, request, true)
	if route != nil {
		return route, route.Bind(request, request.GetPath()), nil
	}

	// the reference messages use the request path: the URI trimmed on both sides,
	// with the root path reported as "/" ().
	requestPath := request.GetPath()
	if trimmed := strings.Trim(requestPath, "/"); trimmed != "" {
		requestPath = trimmed
	} else {
		requestPath = "/"
	}

	// No route matched: probe the other verbs (the reference implementation: checkForAlternateVerbs,
	// in Router verb order) for a 405, or answer OPTIONS directly.
	others := c.CheckForAlternateVerbs(request)
	if len(others) > 0 {
		if request.GetMethod() == "OPTIONS" {
			allowRoute := &Route{
				methods: []string{"OPTIONS"},
				uri:     "/" + strings.TrimLeft(request.GetPath(), "/"),
			}
			allowRoute.handler = func() any {
				return NewResponse().SetCode(http.StatusOK).
					Header("Allow", strings.Join(others, ","))
			}
			// the reference implementation binds the synthetic OPTIONS route before returning it
			// ( → bind).
			params := allowRoute.Bind(request, request.GetPath())
			return allowRoute, params, nil
		}
		return nil, nil, &MethodNotAllowedError{
			Allowed: others,
			Message: fmt.Sprintf(
				"The %s method is not supported for route %s. Supported methods: %s.",
				request.GetMethod(), requestPath, strings.Join(others, ", "),
			),
		}
	}

	return nil, nil, &NotFoundError{
		Message: fmt.Sprintf("The route %s could not be found.", requestPath),
	}
}

// matchAgainstRoutes returns the first route matching the request, probing the
// candidates in the given order. Fallback routes never win over a regular
// match: the first fallback hit is remembered and only returned when nothing
// else matches.
func matchAgainstRoutes(routes []*Route, request *Request, includingMethod bool) *Route {
	var fallbackRoute *Route
	for _, route := range routes {
		if route.Matches(request, includingMethod) {
			if route.IsFallback() {
				if fallbackRoute == nil {
					fallbackRoute = route
				}
				continue
			}
			return route
		}
	}
	return fallbackRoute
}

// CheckForAlternateVerbs reports which other verbs have a route matching the
// request, in Router verb order.
func (c *RouteCollection) CheckForAlternateVerbs(request *Request) []string {
	method := request.GetMethod()
	var others []string
	for _, verb := range verbs {
		if verb == method {
			continue
		}
		if matchAgainstRoutes(c.Get(verb), request, false) != nil {
			others = append(others, verb)
		}
	}
	return others
}

// GetByName returns the route registered under the given name, or nil
//.
func (c *RouteCollection) GetByName(name string) *Route {
	return c.byName[name]
}

// GetByAction returns the route registered with the given controller action
// string (e.g. "UserController@index").
func (c *RouteCollection) GetByAction(action string) (*Route, bool) {
	route, ok := c.byAction[action]
	return route, ok
}

// ReindexName rebuilds the name and action lookups after a route was mutated
// post-registration.
func (c *RouteCollection) ReindexName(*Route) {
	c.RefreshNameLookups()
	c.RefreshActionLookups()
}

// RefreshNameLookups rebuilds the by-name index
//.
func (c *RouteCollection) RefreshNameLookups() {
	c.byName = make(map[string]*Route)
	for _, route := range c.All() {
		if name := route.GetName(); name != "" {
			if _, ok := c.byName[name]; !ok {
				c.byName[name] = route
			}
		}
	}
}

// RefreshActionLookups rebuilds the by-action index
//.
func (c *RouteCollection) RefreshActionLookups() {
	c.byAction = make(map[string]*Route)
	for _, route := range c.All() {
		if action := route.ActionName(); action != "" && action != "Closure" {
			if _, ok := c.byAction[action]; !ok {
				c.byAction[action] = route
			}
		}
	}
}

// GetByMethod returns all routes registered for a given HTTP verb, domain
// routes first).
func (c *RouteCollection) GetByMethod(method string) []*Route {
	return c.Get(method)
}

// Get mirrors the reference implementation. With a method it returns the
// routes indexed for that method, domain routes first; without one it returns
// the full collection.
func (c *RouteCollection) Get(method ...string) []*Route {
	if len(method) == 0 || method[0] == "" {
		return c.GetRoutes()
	}
	return append(append([]*Route(nil), c.methodDomains[method[0]]...), c.methodRoutes[method[0]]...)
}

// GetRoutesByMethod returns all routes grouped by HTTP verb, domain routes
// first.
func (c *RouteCollection) GetRoutesByMethod() map[string][]*Route {
	out := make(map[string][]*Route, len(c.methodRoutes)+len(c.methodDomains))
	for method := range c.methodRoutes {
		out[method] = c.Get(method)
	}
	for method := range c.methodDomains {
		if _, ok := out[method]; !ok {
			out[method] = c.Get(method)
		}
	}
	return out
}

// GetRoutesByName returns all named routes.
func (c *RouteCollection) GetRoutesByName() map[string]*Route {
	out := make(map[string]*Route, len(c.byName))
	for name, route := range c.byName {
		out[name] = route
	}
	return out
}

// GetRoutes returns every registered route, domain routes first
//.
func (c *RouteCollection) GetRoutes() []*Route {
	out := make([]*Route, 0, len(c.allDomains)+len(c.allRoutes))
	out = append(out, c.allDomains...)
	out = append(out, c.allRoutes...)
	return out
}

// All is the Go-style spelling of GetRoutes.
func (c *RouteCollection) All() []*Route {
	return c.GetRoutes()
}

// Count returns the total number of registered routes.
func (c *RouteCollection) Count() int {
	return len(c.allRoutes) + len(c.allDomains)
}

// HasNamedRoute reports whether a route with the given name exists.
func (c *RouteCollection) HasNamedRoute(name string) bool {
	return c.GetByName(name) != nil
}

// ActionRoutePattern implements the action lookup used by the URL generator.
func (c *RouteCollection) ActionRoutePattern(action string) (string, bool) {
	route, ok := c.GetByAction(action)
	if !ok || route == nil {
		return "", false
	}
	return route.URI(), true
}

// NamedRoutePattern implements NamedRouteSource for the collection.
func (c *RouteCollection) NamedRoutePattern(name string) (string, bool) {
	route := c.GetByName(name)
	if route == nil {
		return "", false
	}
	return route.URI(), true
}

// NamedRouteDomain returns the host/domain template of a named route if defined.
func (c *RouteCollection) NamedRouteDomain(name string) (string, bool) {
	route := c.GetByName(name)
	if route == nil {
		return "", false
	}
	return route.GetDomain(), route.GetDomain() != ""
}

// matchesPath reports whether the path matches any variant of the route,
// regardless of the verb.
func (r *Route) matchesPath(path string) bool {
	r.compile()
	for _, variant := range r.expanded {
		if variant.regex != nil && variant.regex.MatchString(path) {
			return true
		}
	}
	return false
}

// routeMatchesScheme checks the HTTPS or HTTP requirement of a route against the request.
func routeMatchesScheme(route *Route, request *Request) bool {
	httpReq := request.GetHttpRequest()
	isSecure := false
	if httpReq != nil {
		if httpReq.TLS != nil || strings.EqualFold(httpReq.Header.Get("X-Forwarded-Proto"), "https") {
			isSecure = true
		}
	}

	if route.IsSecure() && !isSecure {
		return false
	}
	if route.IsHttpOnly() && isSecure {
		return false
	}
	return true
}

// routeMatchesDomain checks the host restriction of a route against the
// request host. Host parameter extraction is
// performed by the RouteParameterBinder.
func routeMatchesDomain(route *Route, request *Request) bool {
	domain := route.GetDomain()
	if domain == "" {
		return true
	}
	httpReq := request.GetHttpRequest()
	if httpReq == nil {
		return true
	}
	host := httpReq.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	route.compile()

	// 1. Dynamic regex host
	if route.compiledHostRegex != nil {
		return route.compiledHostRegex.MatchString(host)
	}

	// 2. Exact static host match
	return strings.EqualFold(host, domain)
}
