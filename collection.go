package flow

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrRouteNotFound is returned when no route matches a request
// .
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
	// routes[method] holds the non-domain routes for the verb in registration
	// order, emulating the reference insertion-ordered array
	// ($this->routes[$method][$domainAndUri]); routesOrder maps the bucket key
	// to its slot so re-registration replaces the entry instead of appending.
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

// Add adds a Route instance to the collection (the reference implementation
// add → addToCollections + addLookups). Routes registered with the same
// methods+domain+uri replace the earlier registration, exactly like the
// reference keyed storage.
func (c *RouteCollection) Add(route *Route) *Route {
	c.addToCollections(route)

	c.addLookups(route)

	return route
}

// addToCollections adds the given route to the arrays of routes (the reference
// implementation protected addToCollections): domain routes join the
// per-method domain buckets and the domain-flattened array; everything else
// joins the per-method buckets and the flattened array.
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

// addLookups adds the route to any look-up tables if necessary (the reference
// implementation protected addLookups). The name and action lookups keep the
// first registration; the action list holds every controller action (the
// reference gates on action['controller'] ?? null, which RouteAction::parse
// sets for all controller actions and never for closures).
func (c *RouteCollection) addLookups(route *Route) {
	// If the route has a name, we will add it to the name look-up table, so
	// that we will quickly be able to find the route associated with a name
	// and not have to iterate through every route every time we need to find
	// a named route.
	if name := route.GetName(); name != "" && !c.inNameLookup(name) {
		c.nameList[name] = route
	}

	// When the route is routing to a controller we will also store the action
	// that is used by the route. This will let us reverse route to
	// controllers while processing a request and easily generate URLs to the
	// given controllers.
	action := route.getAction()

	if controller, ok := action["controller"].(string); ok && controller != "" && !c.inActionLookup(controller) {
		c.addToActionList(action, route)
	}
}

// addToActionList adds a route to the controller action dictionary (the
// reference implementation protected addToActionList). Deviation: the
// reference trims PHP namespace separators (leading backslashes) from the
// controller; Go controller names never carry them, so the trim is omitted.
func (c *RouteCollection) addToActionList(action map[string]any, route *Route) {
	controller, _ := action["controller"].(string)
	c.actionList[controller] = route
}

// inActionLookup determines if the given controller is in the action lookup
// table (the reference implementation protected inActionLookup).
func (c *RouteCollection) inActionLookup(action string) bool {
	_, ok := c.actionList[action]
	return ok
}

// inNameLookup determines if the given name is in the name lookup table (the
// reference implementation protected inNameLookup).
func (c *RouteCollection) inNameLookup(name string) bool {
	_, ok := c.nameList[name]
	return ok
}

// RefreshNameLookups refreshes the name look-up table. This is done in case
// any names are fluently defined or if routes are overwritten (the reference
// implementation refreshNameLookups).
func (c *RouteCollection) RefreshNameLookups() {
	c.nameList = make(map[string]*Route)

	for _, route := range c.GetRoutes() {
		if name := route.GetName(); name != "" && !c.inNameLookup(name) {
			c.nameList[name] = route
		}
	}
}

// RefreshActionLookups refreshes the action look-up table. This is done in
// case any actions are overwritten with new controllers (the reference
// implementation refreshActionLookups). Deviation: the reference only indexes
// action['controller'] (string controller actions), while this pass indexes
// every route with a non-empty ActionName — including method-value handlers
// ("Type.Method") — so UrlGenerator.Action() can resolve them after a fluent
// name set; the inherited "Closure" guard is kept but never fires.
func (c *RouteCollection) RefreshActionLookups() {
	c.actionList = make(map[string]*Route)

	for _, route := range c.GetRoutes() {
		action := route.getAction()
		if controller := route.ActionName(); controller != "" && controller != "Closure" && !c.inActionLookup(controller) {
			// Deviation carrier: inject the loose action name (e.g.
			// "Type.Method" for method-value handlers) into the bag so they
			// are indexed too and UrlGenerator.Action() can resolve them.
			action["controller"] = controller
			c.addToActionList(action, route)
		}
	}
}

// Match finds the first route matching a given request (the reference
// implementation match): candidates for the request verb (domain routes
// first) are tried in registration order with fallback routes last; the
// bound parameters are mirrored onto the request (the per-request state flow
// substitutes for the reference route-held parameters). The Go spelling
// returns an error instead of throwing the reference
// methodNotAllowed/notFound exceptions.
func (c *RouteCollection) Match(request *Request) (*Route, error) {
	routes := c.Get(request.GetMethod())

	// First, we will see if we can find a matching route for this current
	// request method. If we can, great, we can just return it so that it can
	// be called by the consumer. Otherwise we will check for routes with
	// another verb.
	route := c.matchAgainstRoutes(routes, request, true)

	return c.handleMatchedRoute(request, route)
}

// Get gets routes from the collection by method (the reference implementation
// get($method = null)): with a method it returns the routes indexed for that
// method, domain routes first; without one it returns the full collection.
func (c *RouteCollection) Get(method ...string) []*Route {
	if len(method) == 0 {
		return c.GetRoutes()
	}
	return append(append([]*Route(nil), c.domainRoutes[method[0]]...), c.routes[method[0]]...)
}

// HasNamedRoute determines if the route collection contains a given named
// route (the reference implementation hasNamedRoute).
func (c *RouteCollection) HasNamedRoute(name string) bool {
	return c.GetByName(name) != nil
}

// GetByName gets a route instance by its name (the reference implementation
// getByName), or nil when no route carries the name.
func (c *RouteCollection) GetByName(name string) *Route {
	return c.nameList[name]
}

// GetByAction gets a route instance by its controller action (the reference
// implementation getByAction — e.g. "UserController@index"), or nil when no
// route uses the action.
func (c *RouteCollection) GetByAction(action string) *Route {
	return c.actionList[action]
}

// GetRoutes gets all of the routes in the collection (the reference
// implementation getRoutes), domain routes first.
func (c *RouteCollection) GetRoutes() []*Route {
	out := make([]*Route, 0, len(c.allDomainRoutes)+len(c.allRoutes))
	out = append(out, c.allDomainRoutes...)
	out = append(out, c.allRoutes...)
	return out
}

// GetRoutesByMethod gets all of the routes keyed by their HTTP verb / method
// (the reference implementation getRoutesByMethod), domain routes first.
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

// GetRoutesByName gets all of the routes keyed by their name (the reference
// implementation getRoutesByName).
func (c *RouteCollection) GetRoutesByName() map[string]*Route {
	out := make(map[string]*Route, len(c.nameList))
	for name, route := range c.nameList {
		out[name] = route
	}
	return out
}

// The methods above mirror the reference RouteCollection class in its file
// order; the ones below mirror the parent AbstractRouteCollection, in that
// file's order. Its Symfony route-cache/serialization members (compile,
// dumper, toSymfonyRouteCollection, addToSymfonyRoutesCollection,
// generateRouteName) have no Go counterpart.

// handleMatchedRoute handles the matched route (the reference implementation
// protected handleMatchedRoute): a match is bound to the request; otherwise
// alternate verbs are probed for a 405 and finally a not-found error is
// produced.
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

// checkForAlternateVerbs determines if any routes match on another HTTP verb
// (the reference implementation protected checkForAlternateVerbs): every verb
// except the request verb is probed, in Router verb order.
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

// matchAgainstRoutes determines if a route in the array matches the request
// (the reference implementation protected matchAgainstRoutes). Fallback routes
// never win over a regular match: the first fallback hit is remembered and
// only returned when nothing else matches.
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

// getRouteForMethods gets a route (if necessary) that responds when other
// available methods are present (the reference implementation protected
// getRouteForMethods): an OPTIONS request gets a synthetic route answering
// with the Allow header; any other verb gets a method-not-allowed error.
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
		// the reference implementation binds the synthetic OPTIONS route
		// before returning it.
		allowRoute.Bind(request)
		return allowRoute, nil
	}

	return nil, c.requestMethodNotAllowed(request, methods, request.GetMethod())
}

// requestMethodNotAllowed reports a method not allowed error (the reference
// implementation protected requestMethodNotAllowed).
func (c *RouteCollection) requestMethodNotAllowed(request *Request, others []string, method string) error {
	return &MethodNotAllowedError{
		Allowed: others,
		Message: fmt.Sprintf(
			"The %s method is not supported for route %s. Supported methods: %s.",
			method, requestPathOf(request), strings.Join(others, ", "),
		),
	}
}

// methodNotAllowed reports a method not allowed error (the reference
// implementation protected methodNotAllowed).
//
// Deprecated: use requestMethodNotAllowed, which mirrors the current reference
// implementation (its message names the route).
func (c *RouteCollection) methodNotAllowed(others []string, method string) error {
	return &MethodNotAllowedError{
		Allowed: others,
		Message: fmt.Sprintf(
			"The %s method is not supported for this route. Supported methods: %s.",
			method, strings.Join(others, ", "),
		),
	}
}

// Iterator returns all routes (the reference getIterator wraps the route list
// in an ArrayIterator; returning the slice is the Go analog).
func (c *RouteCollection) Iterator() []*Route {
	return c.GetRoutes()
}

// Count counts the number of items in the collection (the reference
// implementation Countable::count).
func (c *RouteCollection) Count() int {
	return len(c.GetRoutes())
}

// isControllerActionHandler reports whether a route handler is a controller
// action (value or pointer form, class-name string or instance controller) —
// the Go analog of the reference action['controller'] key being present,
// which RouteAction::parse sets for every controller action and never for
// closures. Plain func handlers are therefore reported false.
func isControllerActionHandler(handler any) bool {
	switch h := handler.(type) {
	case ControllerAction:
		return true
	case *ControllerAction:
		return h != nil
	}
	return false
}

// upsertRoute emulates the reference implementation insertion-ordered array
// assignment $bucket[$key] = $route: an existing key is replaced in place
// (keeping its position), a new key is appended in registration order.
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

// requestPathOf renders the request path the way the reference implementation
// exception messages do: the URI trimmed on both sides, with the root path
// reported as "/".
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
