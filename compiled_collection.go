package flow

import (
	"strings"
	"sync"
)

// RouteCollectionInterface is the contract the router needs from a route store.
// Both RouteCollection (live routes) and CompiledRouteCollection (cached plus
// dynamically added routes) satisfy it.
type RouteCollectionInterface interface {
	// Add adds a Route instance to the collection.
	Add(route *Route) *Route
	// RefreshNameLookups refreshes the name look-up table.
	RefreshNameLookups()
	// RefreshActionLookups refreshes the action look-up table.
	RefreshActionLookups()
	// Match finds the first route matching a given request; the bound
	// parameters are copied onto the request.
	Match(request *Request) (*Route, error)
	// Get gets routes from the collection by method.
	Get(method ...string) []*Route
	// HasNamedRoute determines if the route collection contains a given named route.
	HasNamedRoute(name string) bool
	// GetByName gets a route instance by its name.
	GetByName(name string) *Route
	// GetByAction gets a route instance by its controller action.
	GetByAction(action string) *Route
	// GetRoutes gets all of the routes in the collection.
	GetRoutes() []*Route
	// GetRoutesByMethod gets all of the routes keyed by their HTTP verb / method.
	GetRoutesByMethod() map[string][]*Route
	// GetRoutesByName gets all of the routes keyed by their name.
	GetRoutesByName() map[string]*Route
	// Count counts the number of items in the collection.
	Count() int
}

var _ RouteCollectionInterface = (*RouteCollection)(nil)
var _ RouteCollectionInterface = (*CompiledRouteCollection)(nil)

// CompiledRouteCollection holds routes restored from the route cache apart from
// those registered after the restore (the dynamic sub-collection). Matching
// consults cached routes first, with the request path's trailing slashes
// trimmed; a cached miss or verb mismatch delegates to the dynamic routes, and
// a cached fallback match defers to a dynamic non-fallback match. Dynamic
// routes take precedence over cached routes with the same domain+uri, and name
// lookups consult a lazy cache over the cached routes before the dynamic ones.
type CompiledRouteCollection struct {
	mu        sync.RWMutex
	cached    []*Route
	dynamic   *RouteCollection
	nameCache map[string]*Route
}

// NewCompiledRouteCollection creates a collection from routes reconstructed from
// the route cache.
func NewCompiledRouteCollection(cached []*Route) *CompiledRouteCollection {
	return &CompiledRouteCollection{
		cached:    append([]*Route(nil), cached...),
		dynamic:   NewRouteCollection(),
		nameCache: make(map[string]*Route),
	}
}

// Add registers a post-restore route in the dynamic sub-collection.
func (c *CompiledRouteCollection) Add(route *Route) *Route {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dynamic.Add(route)
}

// Match finds the first route matching the request, consulting cached routes
// first.
func (c *CompiledRouteCollection) Match(request *Request) (*Route, error) {
	route := c.matchCached(request)
	if route == nil {
		// A cached miss or verb mismatch delegates to the dynamic routes; a
		// dynamic 404 surfaces as the final not-found error.
		return c.dynamic.Match(request)
	}
	if route.IsFallback() {
		// A cached fallback never wins over a dynamic non-fallback match.
		dynRoute, err := c.dynamic.Match(request)
		if err == nil && dynRoute != nil && !dynRoute.IsFallback() {
			return dynRoute, err
		}
	}
	return route, nil
}

// matchCached matches the cached routes against the request path with trailing
// slashes trimmed. It returns nil on a miss, deferring to the dynamic routes.
func (c *CompiledRouteCollection) matchCached(request *Request) *Route {
	c.mu.RLock()
	cached := c.cached
	c.mu.RUnlock()

	trimmed := strings.TrimRight(rawRequestPath(request), "/")
	if trimmed == "" {
		trimmed = "/"
	}
	// Build a lightweight copy of the request (never copy the struct: it
	// embeds a mutex) carrying the trailing-slash-trimmed path.
	dup := NewRequest(request.Request)
	dup.method = request.method
	dup.path = trimmed
	dup.ctx = request.ctx

	routes := cachedForMethod(cached, dup.GetMethod())
	route := c.dynamic.matchAgainstRoutes(routes, dup, true)
	if route == nil {
		return nil
	}
	// Bind against the trimmed copy, then copy the bound parameters back onto the
	// original request, which is what Run and middleware read.
	params := route.Bind(dup)
	for _, p := range params {
		request.SetRouteParam(p.name, p.value)
	}
	request.SetOriginalParams(params)
	return route
}

// Get returns the routes for the given verb, with dynamic routes taking
// precedence over cached routes with the same domain+uri.
func (c *CompiledRouteCollection) Get(method ...string) []*Route {
	if len(method) == 0 {
		return c.GetRoutes()
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	verb := method[0]
	seen := make(map[string]bool, len(c.cached))
	out := make([]*Route, 0, len(c.cached))
	for _, route := range c.dynamic.Get(verb) {
		seen[route.GetDomain()+route.URI()] = true
		out = append(out, route)
	}
	for _, route := range cachedForMethod(c.cached, verb) {
		key := route.GetDomain() + route.URI()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, route)
	}
	return out
}

// GetRoutes returns the cached routes followed by the dynamic additions.
func (c *CompiledRouteCollection) GetRoutes() []*Route {
	c.mu.RLock()
	defer c.mu.RUnlock()
	seen := make(map[string]bool, len(c.cached))
	out := make([]*Route, 0, len(c.cached)+c.dynamic.Count())
	for _, route := range c.cached {
		key := route.GetDomain() + route.URI()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, route)
	}
	for _, route := range c.dynamic.GetRoutes() {
		key := route.GetDomain() + route.URI()
		if seen[key] {
			// Dynamic routes take precedence over cached routes with the
			// same domain+uri: replace the cached entry in place.
			for i, existing := range out {
				if existing.GetDomain()+existing.URI() == key {
					out[i] = route
					break
				}
			}
			continue
		}
		seen[key] = true
		out = append(out, route)
	}
	return out
}

// GetRoutesByMethod groups the routes by verb.
func (c *CompiledRouteCollection) GetRoutesByMethod() map[string][]*Route {
	out := make(map[string][]*Route)
	for _, route := range c.GetRoutes() {
		for _, verb := range route.Methods() {
			out[verb] = append(out[verb], route)
		}
	}
	return out
}

// GetRoutesByName indexes the routes by name.
func (c *CompiledRouteCollection) GetRoutesByName() map[string]*Route {
	out := make(map[string]*Route)
	for _, route := range c.GetRoutes() {
		if name := route.GetName(); name != "" {
			if _, ok := out[name]; !ok {
				out[name] = route
			}
		}
	}
	return out
}

// GetByName resolves a route by name: the lazy cached-name index first, then
// the dynamic routes.
func (c *CompiledRouteCollection) GetByName(name string) *Route {
	c.mu.Lock()
	defer c.mu.Unlock()
	if route, ok := c.nameCache[name]; ok {
		return route
	}
	for _, route := range c.cached {
		if route.GetName() == name {
			c.nameCache[name] = route
			return route
		}
	}
	return c.dynamic.GetByName(name)
}

// GetByAction resolves a route by its controller action string.
func (c *CompiledRouteCollection) GetByAction(action string) *Route {
	for _, route := range c.GetRoutes() {
		if route.ActionName() == action {
			return route
		}
	}
	return nil
}

// HasNamedRoute reports whether a route with the given name exists.
func (c *CompiledRouteCollection) HasNamedRoute(name string) bool {
	return c.GetByName(name) != nil
}

// RefreshNameLookups refreshes the name lookup table of the dynamic
// sub-collection, whose names may be set after Add.
func (c *CompiledRouteCollection) RefreshNameLookups() {
	c.dynamic.RefreshNameLookups()
}

// RefreshActionLookups refreshes the action lookup table of the dynamic
// sub-collection.
func (c *CompiledRouteCollection) RefreshActionLookups() {
	c.dynamic.RefreshActionLookups()
}

// Count returns the total number of routes (cached + dynamic).
func (c *CompiledRouteCollection) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cached) + c.dynamic.Count()
}

// cachedForMethod filters the cached routes by verb.
func cachedForMethod(cached []*Route, verb string) []*Route {
	var out []*Route
	for _, route := range cached {
		if matchMethods(verb, route.Methods()) {
			out = append(out, route)
		}
	}
	return out
}

// rawRequestPath returns the request path in its original escaped form, falling
// back to the decoded path.
func rawRequestPath(request *Request) string {
	if request.Request != nil && request.Request.URL != nil {
		if escaped := request.Request.URL.EscapedPath(); escaped != "" {
			return escaped
		}
	}
	return request.GetPath()
}
