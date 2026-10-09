package flow

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrRouteNotFound is returned when no route matches a request.
var ErrRouteNotFound = errors.New("route not found")

// NotFoundError reports that no route matched the request.
type NotFoundError struct {
	Message string
}

func (e *NotFoundError) Error() string { return e.Message }

// Is makes errors.Is(err, ErrRouteNotFound) keep working for callers that
// checked the sentinel before the message was introduced.
func (e *NotFoundError) Is(target error) bool { return target == ErrRouteNotFound }

// MethodNotAllowedError is returned when the request path matches routes that
// exist for other HTTP verbs only. Allowed holds the verbs in Router verb order.
type MethodNotAllowedError struct {
	Allowed []string
	Message string
}

func (e *MethodNotAllowedError) Error() string { return e.Message }

// RouteCollection stores the registered routes with their lookup indexes:
// per-method buckets keyed by "domain+uri" (a later registration with the same
// key replaces the earlier one in place), a separate domain bucket so domain
// routes match and list first, and name/action lookup tables where the first
// registration wins.
type RouteCollection struct {
	// routes[method] holds the non-domain routes for the verb in insertion
	// order; routesOrder maps each bucket key to its slot so re-registration
	// replaces the entry in place.
	routes               map[string][]*Route
	routesOrder          map[string]map[string]int
	domainRoutes         map[string][]*Route
	domainRoutesOrder    map[string]map[string]int
	allRoutes            []*Route
	allRoutesOrder       map[string]int
	allDomainRoutes      []*Route
	allDomainRoutesOrder map[string]int
	nameList             map[string]*Route
	actionList           map[string]*Route
}

// NewRouteCollection creates an empty route collection.
func NewRouteCollection() *RouteCollection {
	return &RouteCollection{
		routes:               make(map[string][]*Route),
		routesOrder:          make(map[string]map[string]int),
		domainRoutes:         make(map[string][]*Route),
		domainRoutesOrder:    make(map[string]map[string]int),
		allRoutesOrder:       make(map[string]int),
		allDomainRoutesOrder: make(map[string]int),
		nameList:             make(map[string]*Route),
		actionList:           make(map[string]*Route),
	}
}

// Add adds a Route to the collection. Routes registered with the same methods,
// domain and URI replace the earlier registration in place.
func (c *RouteCollection) Add(route *Route) *Route {
	c.addToCollections(route)

	c.addLookups(route)

	return route
}

// addToCollections adds the route to the lookup arrays: domain routes join the
// per-method domain buckets and the domain-flattened array; other routes join
// the per-method buckets and the flattened array.
func (c *RouteCollection) addToCollections(route *Route) {
	methods := route.Methods()
	domainAndUri := route.GetDomain() + route.URI()
	allRoutesKey := strings.Join(methods, "|") + domainAndUri

	if route.GetDomain() != "" {
		for _, method := range methods {
			list := c.domainRoutes[method]
			upsertRoute(&list, orderFor(c.domainRoutesOrder, method), domainAndUri, route)
			c.domainRoutes[method] = list
		}
		list := c.allDomainRoutes
		upsertRoute(&list, c.allDomainRoutesOrder, allRoutesKey, route)
		c.allDomainRoutes = list
	} else {
		for _, method := range methods {
			list := c.routes[method]
			upsertRoute(&list, orderFor(c.routesOrder, method), domainAndUri, route)
			c.routes[method] = list
		}
		list := c.allRoutes
		upsertRoute(&list, c.allRoutesOrder, allRoutesKey, route)
		c.allRoutes = list
	}
}

// addLookups adds the route to the name and action lookup tables. Both keep
// the first registration; only controller actions are indexed.
func (c *RouteCollection) addLookups(route *Route) {
	// Index the route by name for O(1) name lookups.
	if name := route.GetName(); name != "" && !c.inNameLookup(name) {
		c.nameList[name] = route
	}

	// Index the route by its controller action so controllers can be
	// reverse-resolved.
	action := route.getAction()

	if controller, ok := action["controller"].(string); ok && controller != "" && !c.inActionLookup(controller) {
		c.addToActionList(action, route)
	}
}

// addToActionList adds the route to the controller action dictionary.
func (c *RouteCollection) addToActionList(action map[string]any, route *Route) {
	controller, _ := action["controller"].(string)
	c.actionList[controller] = route
}

// inActionLookup reports whether the given controller is in the action lookup
// table.
func (c *RouteCollection) inActionLookup(action string) bool {
	_, ok := c.actionList[action]
	return ok
}

// inNameLookup reports whether the given name is in the name lookup table.
func (c *RouteCollection) inNameLookup(name string) bool {
	_, ok := c.nameList[name]
	return ok
}

// RefreshNameLookups rebuilds the name lookup table from the routes, keeping
// the first registration per name.
func (c *RouteCollection) RefreshNameLookups() {
	c.nameList = make(map[string]*Route)

	for _, route := range c.GetRoutes() {
		if name := route.GetName(); name != "" && !c.inNameLookup(name) {
			c.nameList[name] = route
		}
	}
}

// RefreshActionLookups rebuilds the action lookup table from the routes,
// indexing every route with a non-empty ActionName (including method-value
// handlers) and keeping the first registration per action.
func (c *RouteCollection) RefreshActionLookups() {
	c.actionList = make(map[string]*Route)

	for _, route := range c.GetRoutes() {
		action := route.getAction()
		if controller := route.ActionName(); controller != "" && controller != "Closure" && !c.inActionLookup(controller) {
			// Index method-value handlers too, so UrlGenerator.Action() can
			// resolve them.
			action["controller"] = controller
			c.addToActionList(action, route)
		}
	}
}

// Match finds the first route matching the request. Candidates for the request
// verb (domain routes first) are tried in registration order with fallback
// routes last, and the bound parameters are copied onto the request. It returns
// a MethodNotAllowedError or NotFoundError when nothing matches.
func (c *RouteCollection) Match(request *Request) (*Route, error) {
	routes := c.Get(request.GetMethod())

	// Try routes for the request verb first; on a miss, alternate verbs are
	// checked by handleMatchedRoute.
	route := c.matchAgainstRoutes(routes, request, true)

	return c.handleMatchedRoute(request, route)
}

// Get returns the routes for the given method, domain routes first; with no
// method it returns the full collection.
func (c *RouteCollection) Get(method ...string) []*Route {
	if len(method) == 0 {
		return c.GetRoutes()
	}
	return append(append([]*Route(nil), c.domainRoutes[method[0]]...), c.routes[method[0]]...)
}

// HasNamedRoute reports whether the collection contains a route with the given
// name.
func (c *RouteCollection) HasNamedRoute(name string) bool {
	return c.GetByName(name) != nil
}

// GetByName returns the route with the given name, or nil when absent.
func (c *RouteCollection) GetByName(name string) *Route {
	return c.nameList[name]
}

// GetByAction returns the route for the given controller action (e.g.
// "UserController@index"), or nil when no route uses the action.
func (c *RouteCollection) GetByAction(action string) *Route {
	return c.actionList[action]
}

// GetRoutes returns all routes in the collection, domain routes first.
func (c *RouteCollection) GetRoutes() []*Route {
	out := make([]*Route, 0, len(c.allDomainRoutes)+len(c.allRoutes))
	out = append(out, c.allDomainRoutes...)
	out = append(out, c.allRoutes...)
	return out
}

// GetRoutesByMethod returns all routes keyed by HTTP verb, domain routes first.
func (c *RouteCollection) GetRoutesByMethod() map[string][]*Route {
	result := make(map[string][]*Route, len(c.domainRoutes))
	for method := range c.domainRoutes {
		result[method] = c.Get(method)
	}
	for method := range c.routes {
		if _, ok := result[method]; !ok {
			result[method] = c.Get(method)
		}
	}
	return result
}

// GetRoutesByName returns all routes keyed by name.
func (c *RouteCollection) GetRoutesByName() map[string]*Route {
	out := make(map[string]*Route, len(c.nameList))
	for name, route := range c.nameList {
		out[name] = route
	}
	return out
}

// handleMatchedRoute binds a matched route to the request. On a miss it probes
// alternate verbs for a 405 and otherwise returns a NotFoundError.
func (c *RouteCollection) handleMatchedRoute(request *Request, route *Route) (*Route, error) {
	if route != nil {
		route.Bind(request)
		return route, nil
	}

	// If no route was found we will now check if a matching route is
	// specified by another HTTP verb. If it is we will need to throw a
	// MethodNotAllowed and inform the user agent of which HTTP verb it should
	// use for this route.
	others := c.checkForAlternateVerbs(request)

	if len(others) > 0 {
		return c.getRouteForMethods(request, others)
	}

	return nil, &NotFoundError{
		Message: fmt.Sprintf("The route %s could not be found.", requestPathOf(request)),
	}
}

// checkForAlternateVerbs returns the verbs, in Router order, for which a route
// matches the request path.
func (c *RouteCollection) checkForAlternateVerbs(request *Request) []string {
	method := request.GetMethod()
	var others []string
	for _, verb := range verbs {
		if verb == method {
			continue
		}
		if c.matchAgainstRoutes(c.Get(verb), request, false) != nil {
			others = append(others, verb)
		}
	}
	return others
}

// matchAgainstRoutes returns the first matching route. Fallback routes never
// win over a regular match: the first fallback hit is remembered and returned
// only when nothing else matches.
func (c *RouteCollection) matchAgainstRoutes(routes []*Route, request *Request, includingMethod bool) *Route {
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

// getRouteForMethods builds a route when other verbs are available: an OPTIONS
// request gets a synthetic route answering with the Allow header; any other
// verb gets a MethodNotAllowedError.
func (c *RouteCollection) getRouteForMethods(request *Request, methods []string) (*Route, error) {
	if request.GetMethod() == "OPTIONS" {
		allowRoute := &Route{
			methods: []string{"OPTIONS"},
			uri:     "/" + strings.TrimLeft(request.GetPath(), "/"),
		}
		allowRoute.handler = func() any {
			return NewResponse().SetCode(http.StatusOK).
				Header("Allow", strings.Join(methods, ","))
		}
		// Bind the synthetic OPTIONS route before returning it.
		allowRoute.Bind(request)
		return allowRoute, nil
	}

	return nil, c.requestMethodNotAllowed(request, methods, request.GetMethod())
}

// requestMethodNotAllowed returns a MethodNotAllowedError naming the route and
// its allowed methods.
func (c *RouteCollection) requestMethodNotAllowed(request *Request, others []string, method string) error {
	return &MethodNotAllowedError{
		Allowed: others,
		Message: fmt.Sprintf(
			"The %s method is not supported for route %s. Supported methods: %s.",
			method, requestPathOf(request), strings.Join(others, ", "),
		),
	}
}

// methodNotAllowed returns a MethodNotAllowedError.
//
// Deprecated: use requestMethodNotAllowed, whose message names the route.
func (c *RouteCollection) methodNotAllowed(others []string, method string) error {
	return &MethodNotAllowedError{
		Allowed: others,
		Message: fmt.Sprintf(
			"The %s method is not supported for this route. Supported methods: %s.",
			method, strings.Join(others, ", "),
		),
	}
}

// Iterator returns all routes.
func (c *RouteCollection) Iterator() []*Route {
	return c.GetRoutes()
}

// Count returns the number of routes in the collection.
func (c *RouteCollection) Count() int {
	return len(c.GetRoutes())
}

// isControllerActionHandler reports whether a handler is a controller action
// (value or pointer form). Plain function handlers report false.
func isControllerActionHandler(handler any) bool {
	switch h := handler.(type) {
	case ControllerAction:
		return true
	case *ControllerAction:
		return h != nil
	}
	return false
}

// upsertRoute replaces an existing key in place (keeping its position) or
// appends a new key in registration order.
func upsertRoute(bucket *[]*Route, order map[string]int, key string, route *Route) {
	if slot, ok := order[key]; ok {
		(*bucket)[slot] = route
		return
	}
	order[key] = len(*bucket)
	*bucket = append(*bucket, route)
}

// orderFor lazily creates the per-method key→slot index used by upsertRoute.
func orderFor(orders map[string]map[string]int, method string) map[string]int {
	if idx, ok := orders[method]; ok {
		return idx
	}
	idx := make(map[string]int)
	orders[method] = idx
	return idx
}

// requestPathOf renders the request path for messages: trimmed of surrounding
// slashes, with the root path reported as "/".
func requestPathOf(request *Request) string {
	if trimmed := strings.Trim(request.GetPath(), "/"); trimmed != "" {
		return trimmed
	}
	return "/"
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

// routeMatchesDomain reports whether the request host satisfies the route's
// domain restriction. Host parameter extraction is performed by
// RouteParameterBinder.
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
