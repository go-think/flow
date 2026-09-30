package flow

import (
	"strings"
	"sync"
)

// RouteCollectionInterface is the internal contract the router needs from a route
// store. Both RouteCollection (live routes) and CompiledRouteCollection
// (routes restored from the route cache plus dynamically added ones) satisfy
// it.
type RouteCollectionInterface interface {
	Add(route *Route) *Route
	Match(request *Request) (*Route, []*parameter, error)
	All() []*Route
	Get(method ...string) []*Route
	GetByMethod(method string) []*Route
	GetRoutes() []*Route
	GetRoutesByMethod() map[string][]*Route
	GetRoutesByName() map[string]*Route
	GetByName(name string) *Route
	GetByAction(action string) (*Route, bool)
	HasNamedRoute(name string) bool
	NamedRoutePattern(name string) (string, bool)
	NamedRouteDomain(name string) (string, bool)
	ReindexName(route *Route)
	Count() int
}

var _ RouteCollectionInterface = (*RouteCollection)(nil)
var _ RouteCollectionInterface = (*CompiledRouteCollection)(nil)

// CompiledRouteCollection mirrors the reference compiledRouteCollection: routes
// restored from the route cache are held apart from the routes registered
// AFTER the restore (the dynamic sub-collection), with the reference precedence
// rules:

// - matching consults the cached routes first, with the request path's
// trailing slashes trimmed (requestWithoutTrailingSlash — only cached
// matching trims);
//   - a cached miss or verb mismatch delegates to the dynamic routes;
//   - a cached FALLBACK match defers to a dynamic non-fallback match;
//   - dynamic routes take precedence over cached routes with the same
//     domain+uri;
//   - name lookups consult a lazy cache over the cached routes, then the
//
// dynamic routes.
type CompiledRouteCollection struct {
	mu        sync.RWMutex
	cached    []*Route
	dynamic   *RouteCollection
	nameCache map[string]*Route
}

// NewCompiledRouteCollection wraps the routes reconstructed from the route
// cache).
func NewCompiledRouteCollection(cached []*Route) *CompiledRouteCollection {
	return &CompiledRouteCollection{
		cached:    append([]*Route(nil), cached...),
		dynamic:   NewRouteCollection(),
		nameCache: make(map[string]*Route),
	}
}

// Add registers a post-restore route into the dynamic sub-collection
// (name/action lookups refresh lazily).
func (c *CompiledRouteCollection) Add(route *Route) *Route {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dynamic.Add(route)
}

// Match finds the first route matching the request, cached routes first
// .
func (c *CompiledRouteCollection) Match(request *Request) (*Route, []*parameter, error) {
	route, params := c.matchCached(request)
	if route == nil {
		// ResourceNotFoundException|MethodNotAllowedException from
		// the compiled matcher delegates to the dynamic routes; a dynamic
		// 404 surfaces as the final not-found error.
		return c.dynamic.Match(request)
	}
	if route.IsFallback() {
		// A cached fallback never wins over a dynamic non-fallback match.
		dynRoute, dynParams, err := c.dynamic.Match(request)
		if err == nil && dynRoute != nil && !dynRoute.IsFallback() {
			return dynRoute, dynParams, err
		}
	}
	return route, params, nil
}

// matchCached matches the cached routes with the trailing slashes trimmed off
// the request path.
// A verb mismatch among cached routes defers to the dynamic routes, like the
// MethodNotAllowedException branch.
func (c *CompiledRouteCollection) matchCached(request *Request) (*Route, []*parameter) {
	c.mu.RLock()
	cached := c.cached
	c.mu.RUnlock()

	trimmed := strings.TrimRight(rawRequestPath(request), "/")
	if trimmed == "" {
		trimmed = "/"
	}
	// Rebuild a lightweight copy of the request (never copy the struct: it
	// embeds a mutex) carrying the trailing-slash-trimmed path — the reference implementation
	// requestWithoutTrailingSlash duplicates the request.
	dup := NewRequest(request.Request)
	dup.method = request.method
	dup.path = trimmed
	dup.ctx = request.ctx

	routes := cachedForMethod(cached, dup.GetMethod())
	route := matchAgainstRoutes(routes, dup, true)
	if route == nil {
		return nil, nil
	}
	return route, route.Bind(dup, trimmed)
}

// Get returns the routes for a verb with dynamic routes taking precedence
// over cached routes with the same domain+uri (merged lookups).
func (c *CompiledRouteCollection) Get(method ...string) []*Route {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(method) == 0 || method[0] == "" {
		return c.All()
	}
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

// All returns the cached routes followed by the dynamic additions
// .
func (c *CompiledRouteCollection) All() []*Route {
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
	for _, route := range c.dynamic.All() {
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

// GetRoutes is an alias of All.
func (c *CompiledRouteCollection) GetRoutes() []*Route {
	return c.All()
}

// GetRoutesByMethod groups the routes by verb
// .
func (c *CompiledRouteCollection) GetRoutesByMethod() map[string][]*Route {
	out := make(map[string][]*Route)
	for _, route := range c.All() {
		for _, verb := range route.Methods() {
			out[verb] = append(out[verb], route)
		}
	}
	return out
}

// GetRoutesByName indexes the routes by name.
func (c *CompiledRouteCollection) GetRoutesByName() map[string]*Route {
	out := make(map[string]*Route)
	for _, route := range c.All() {
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

// GetByAction resolves a route by its controller action string
// .
func (c *CompiledRouteCollection) GetByAction(action string) (*Route, bool) {
	for _, route := range c.All() {
		if route.ActionName() == action {
			return route, true
		}
	}
	return nil, false
}

// HasNamedRoute reports whether a route with the name exists
// || attributes[name] ||
// routes->hasNamedRoute).
func (c *CompiledRouteCollection) HasNamedRoute(name string) bool {
	return c.GetByName(name) != nil
}

// NamedRoutePattern returns the raw pattern of a named route.
func (c *CompiledRouteCollection) NamedRoutePattern(name string) (string, bool) {
	route := c.GetByName(name)
	if route == nil {
		return "", false
	}
	return route.URI(), true
}

// NamedRouteDomain returns the domain template of a named route when set.
func (c *CompiledRouteCollection) NamedRouteDomain(name string) (string, bool) {
	route := c.GetByName(name)
	if route == nil {
		return "", false
	}
	return route.GetDomain(), route.GetDomain() != ""
}

// ReindexName refreshes the name/action indexes of the DYNAMIC sub-collection.
// the reference compiledRouteCollection makes this a no-op (routes never change
// after the cache is written), but flow's fluent registration sets names
// after Add, so post-restore routes need their dynamic index refreshed.
func (c *CompiledRouteCollection) ReindexName(route *Route) {
	c.dynamic.ReindexName(route)
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

// rawRequestPath returns the request path with its original (undecoded)
// trailing form, matching what the reference implementation trims from REQUEST_URI.
func rawRequestPath(request *Request) string {
	if request.Request != nil && request.Request.URL != nil {
		if escaped := request.Request.URL.EscapedPath(); escaped != "" {
			return escaped
		}
	}
	return request.GetPath()
}

// GetByMethod returns the routes for one verb (alias of Get with a single,
// mandatory verb argument).
func (c *CompiledRouteCollection) GetByMethod(method string) []*Route {
	return c.Get(method)
}
