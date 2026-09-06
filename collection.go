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
				if route.ValidateParams(params) && routeMatchesScheme(route, request) && routeMatchesDomain(route, request) {
					return route, params, nil
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
			if route.ValidateParams(params) {
				return route, params, nil
			}
		}
	}

	// The path may exist for other verbs only: collect them for a 405.
	var allowed []string
	for m, tree := range c.tries {
		if m == method {
			continue
		}
		if handle, _, _ := tree.getValue(path); handle != nil {
			allowed = append(allowed, m)
			continue
		}
		for _, route := range c.regexes[m] {
			if route.matchesPath(path) {
				allowed = append(allowed, m)
				break
			}
		}
	}
	if len(allowed) > 0 {
		sort.Strings(allowed)
		return nil, nil, &MethodNotAllowedError{Allowed: allowed}
	}

	return nil, nil, ErrRouteNotFound
}

// GetByName returns the route registered under the given name.
func (c *RouteCollection) GetByName(name string) (*Route, bool) {
	route, ok := c.byName[name]
	return route, ok
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

// routeMatchesScheme checks the HTTPS requirement of a route against the
// request (TLS connection or X-Forwarded-Proto header).
func routeMatchesScheme(route *Route, request *Request) bool {
	if !route.IsSecure() {
		return true
	}
	httpReq := request.GetHttpRequest()
	if httpReq == nil {
		return true
	}
	if httpReq.TLS != nil {
		return true
	}
	proto := httpReq.Header.Get("X-Forwarded-Proto")
	return strings.EqualFold(proto, "https")
}

// routeMatchesDomain checks the host restriction of a route against the
// request host.
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
	return strings.EqualFold(host, domain)
}

func paramsFromTree(ps Params) []*parameter {
	routeParams := make([]*parameter, 0, len(ps))
	for _, p := range ps {
		routeParams = append(routeParams, &parameter{name: p.Key, value: p.Value})
	}
	return routeParams
}
