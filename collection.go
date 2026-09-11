package flow

import (
	"errors"
	"sort"
	"strings"
)

// ErrRouteNotFound is returned when no route matches a request.
var ErrRouteNotFound = errors.New("flow: route not found")

// MethodNotAllowedError is returned when the request path matches routes that
// exist for other HTTP verbs only. Allowed carries the verbs that would match.
type MethodNotAllowedError struct {
	Allowed []string
}

func (e *MethodNotAllowedError) Error() string {
	return "flow: method not allowed (allowed: " + strings.Join(e.Allowed, ", ") + ")"
}

// RouteCollection stores the registered routes with their lookup indexes:
// a per-verb radix tree for fast matching, a per-verb regex fallback for
// patterns the tree cannot represent, and a name index.
type RouteCollection struct {
	routes  []*Route
	byName  map[string]*Route
	tries   map[string]*node
	regexes map[string][]*Route
}

// NewRouteCollection creates an empty route collection.
func NewRouteCollection() *RouteCollection {
	return &RouteCollection{
		tries:   make(map[string]*node),
		regexes: make(map[string][]*Route),
	}
}

// Add indexes a route into the collection. Routes with optional parameters
// are expanded into one matchable variant per combination. Each variant is
// added to the per-verb radix tree; when a variant conflicts with the tree's
// static/wildcard layout it falls back to regex-only matching, so resource
// routes like "/photos/create" and "/photos/{photo}" coexist.
func (c *RouteCollection) Add(route *Route) {
	c.routes = append(c.routes, route)

	if route.name != "" {
		if c.byName == nil {
			c.byName = make(map[string]*Route)
		}
		c.byName[route.name] = route
	}

	route.compile()

	for _, variant := range route.expanded {
		for _, method := range route.methods {
			c.regexes[method] = append(c.regexes[method], route)

			if existing, ok := c.tries[method]; ok {
				clone := existing.clone()
				inserted := func() (ok bool) {
					defer func() {
						if recover() != nil {
							ok = false
						}
					}()
					clone.addRoute(variant.pattern, route)
					return true
				}()
				if inserted {
					c.tries[method] = clone
				}
				continue
			}

			rootNode := &node{}
			rootNode.addRoute(variant.pattern, route)
			c.tries[method] = rootNode
		}
	}
}

// Match resolves a request to a route: the per-verb radix tree first, then the
// regex fallback of the same verb. When the path exists for other verbs only,
// a MethodNotAllowedError carrying the allowed verbs is returned.
func (c *RouteCollection) Match(request *Request) (*Route, []*parameter, error) {
	method := request.GetMethod()
	path := request.GetPath()

	if tree, ok := c.tries[method]; ok {
		if handle, ps, _ := tree.getValue(path); handle != nil {
			if route, ok := handle.(*Route); ok {
				params := paramsFromTree(ps)
				if route.ValidateParams(params) && routeMatchesScheme(route, request) {
					if hostMatched, hostParams := routeMatchesDomain(route, request); hostMatched {
						allParams := append(hostParams, params...)
						return route, allParams, nil
					}
				}
			}
		}
	}

	for _, route := range c.regexes[method] {
		if !matchMethods(method, route.methods) {
			continue
		}
		route.compile()
		if params, ok := route.matchRegex(path); ok {
			if route.ValidateParams(params) && routeMatchesScheme(route, request) {
				if hostMatched, hostParams := routeMatchesDomain(route, request); hostMatched {
					allParams := append(hostParams, params...)
					return route, allParams, nil
				}
			}
		}
	}

	// The path may exist for other verbs only: collect them for a 405.
	// HEAD is an automatic alias of GET and never triggers a 405 by itself.
	var allowed []string
	for m, tree := range c.tries {
		if m == method || (m == "HEAD" && method == "GET") || (m == "GET" && method == "HEAD") {
			continue
		}
		if handle, _, _ := tree.getValue(path); handle != nil {
			if route, ok := handle.(*Route); ok {
				if hostMatched, _ := routeMatchesDomain(route, request); hostMatched && routeMatchesScheme(route, request) {
					allowed = append(allowed, m)
				}
			} else {
				allowed = append(allowed, m)
			}
			continue
		}
		for _, route := range c.regexes[m] {
			if route.matchesPath(path) {
				if hostMatched, _ := routeMatchesDomain(route, request); hostMatched && routeMatchesScheme(route, request) {
					allowed = append(allowed, m)
					break
				}
			}
		}
	}
	if len(allowed) > 0 {
		sort.Strings(allowed)
		return nil, nil, &MethodNotAllowedError{Allowed: allowed}
	}

	return nil, nil, ErrRouteNotFound
}

// GetByName returns the route registered under the given name, or nil.
func (c *RouteCollection) GetByName(name string) *Route {
	return c.byName[name]
}

// GetByAction returns the route registered with the given action string (e.g. "UserController@index").
func (c *RouteCollection) GetByAction(action string) (*Route, bool) {
	for _, route := range c.routes {
		if route.ActionName() == action {
			return route, true
		}
	}
	return nil, false
}

// ReindexName updates the by-name index after a route's name was changed
// post-registration (immediate-registration mode).
func (c *RouteCollection) ReindexName(route *Route) {
	if c.byName == nil {
		c.byName = make(map[string]*Route)
	}
	c.byName[route.GetName()] = route
}

// HasNamedRoute reports whether a route with the given name exists.
func (c *RouteCollection) HasNamedRoute(name string) bool {
	_, ok := c.byName[name]
	return ok
}

// All returns every registered route in registration order.
func (c *RouteCollection) All() []*Route {
	return c.routes
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

// matchRegex extracts parameters from the path using the compiled variants.
func (r *Route) matchRegex(path string) ([]*parameter, bool) {
	r.compile()
	for _, variant := range r.expanded {
		if variant.regex == nil {
			continue
		}
		rawMatches := variant.regex.FindStringSubmatch(path)
		if len(rawMatches) <= 1 {
			continue
		}
		matches := rawMatches[1:]
		var parameters []*parameter
		for k, name := range variant.parameterNames {
			val := ""
			if k < len(matches) {
				val = matches[k]
			}
			parameters = append(parameters, &parameter{name: name, value: val})
		}
		return parameters, true
	}
	return nil, false
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

// routeMatchesDomain checks the host restriction of a route against the request host
// and extracts dynamic subdomain parameters if declared (e.g. "{account}.example.com").
func routeMatchesDomain(route *Route, request *Request) (bool, []*parameter) {
	domain := route.GetDomain()
	if domain == "" {
		return true, nil
	}
	httpReq := request.GetHttpRequest()
	if httpReq == nil {
		return true, nil
	}
	host := httpReq.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	route.compile()

	// 1. Dynamic regex host
	if route.compiledHostRegex != nil {
		matches := route.compiledHostRegex.FindStringSubmatch(host)
		if len(matches) <= 1 {
			return false, nil
		}
		var hostParams []*parameter
		for idx, name := range route.hostParameterNames {
			if idx+1 < len(matches) {
				hostParams = append(hostParams, &parameter{name: name, value: matches[idx+1]})
			}
		}
		return true, hostParams
	}

	// 2. Exact static host match
	return strings.EqualFold(host, domain), nil
}

func paramsFromTree(ps Params) []*parameter {
	routeParams := make([]*parameter, 0, len(ps))
	for _, p := range ps {
		routeParams = append(routeParams, &parameter{name: p.Key, value: p.Value})
	}
	return routeParams
}
