package flow

import (
	"net/http"
	"reflect"
	"strings"
)

// NewRouter creates a router with immediate route registration (Laravel
// semantics): routes are materialized into the collection the moment they are
// declared, so dispatch and lookups work without an explicit Register call.
func NewRouter(opts ...Option) Router {
	rt := New(opts...).(*router)
	rt.autoRegister = true
	return rt
}

// routeChain adapts a registered Route for method chaining after immediate
// registration: constraint/name/middleware calls mutate the registered entity
// while every other Router call falls through to the owning router.
type routeChain struct {
	*router
	route      *Route
	namePrefix string
}

// buildRouteEntity materializes a Route entity for a pending node, merging
// the full ancestor chain: prefixes, name prefixes, middleware, without-lists,
// where constraints, domain and metadata.
func (r *router) buildRouteEntity(methods []string, pattern string, handler any) *Route {
	// Walk from the declaring node up to the root, collecting attributes.
	var prefixes []string
	var names []string
	var middlewares []any
	var without []any
	wheres := make(map[string]string)
	metadata := make(map[string]any)
	domain := ""
	controllerPrefix := ""

	for cur := r; cur != nil; cur = cur.group {
		if cur.prefix != "" {
			prefixes = append([]string{cur.prefix}, prefixes...)
		}
		if cur.name != "" {
			names = append([]string{cur.name}, names...)
		}
		if len(cur.middlewares) > 0 {
			middlewares = append(append([]any(nil), cur.middlewares...), middlewares...)
		}
		if len(cur.withoutMiddleware) > 0 {
			without = append(append([]any(nil), cur.withoutMiddleware...), without...)
		}
		if cur.domain != "" && domain == "" {
			domain = cur.domain
		}
		if cur.controllerPrefix != "" && controllerPrefix == "" {
			controllerPrefix = cur.controllerPrefix
		}
		for k, v := range cur.groupWheres {
			wheres[k] = v
		}
		for k, v := range cur.groupMetadata {
			metadata[k] = v
		}
	}

	prefix := pathJoinSlice(prefixes)
	if prefix == "/" {
		prefix = ""
	}
	uri := prefix + pattern
	if uri == "" || uri[0] != '/' {
		uri = "/" + strings.TrimLeft(uri, "/")
	}

	name := ""
	for _, n := range names {
		name += n
	}

	action := parseControllerAction(handler)
	if ca, ok := action.(ControllerAction); ok {
		if nameStr, isName := ca.Controller.(string); isName && controllerPrefix != "" {
			ca.Controller = controllerPrefix + "." + nameStr
			action = ca
		}
	}

	entity := &Route{
		methods:           methods,
		uri:               uri,
		name:              name,
		handler:           action,
		middlewares:       middlewares,
		withoutMiddleware: without,
		wheres:            wheres,
		metadata:          metadata,
		domain:            domain,
		router:            r.root(),
	}
	return entity
}

// pathJoinSlice joins path fragments with "/" and cleans the result.
func pathJoinSlice(parts []string) string {
	joined := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		joined = joinPaths(joined, p)
	}
	if joined == "" {
		joined = "/"
	}
	return joined
}

func joinPaths(a, b string) string {
	if a == "" {
		return "/" + strings.TrimLeft(b, "/")
	}
	return a + "/" + strings.TrimLeft(b, "/")
}

// routeChainFor returns the chaining adapter for a freshly registered route.
func (r *router) routeChainFor(route *Route) Router {
	chain := &routeChain{router: r, route: route}
	// The chain name prefix is the accumulated group name at registration
	// time; recompute it by diffing the entity name against the raw name is
	// unnecessary — route names are fully built during entity construction.
	_ = chain.namePrefix
	return chain
}

// Name renames the registered route (chain override).
func (c *routeChain) Name(name string) Router {
	c.route.SetName(name)
	c.router.collection.ReindexName(c.route)
	return c
}

// Where adds a constraint to the registered route (chain override).
func (c *routeChain) Where(name string, expression string) Router {
	c.route.SetWhere(name, expression)
	return c
}

// WhereNumber adds a numeric constraint to the registered route.
func (c *routeChain) WhereNumber(names ...string) Router {
	for _, name := range names {
		c.route.SetWhere(name, "^[0-9]+$")
	}
	return c
}

// WhereAlpha adds an alphabetic constraint to the registered route.
func (c *routeChain) WhereAlpha(names ...string) Router {
	for _, name := range names {
		c.route.SetWhere(name, "^[a-zA-Z]+$")
	}
	return c
}

// WhereAlphaNumeric adds an alphanumeric constraint to the registered route.
func (c *routeChain) WhereAlphaNumeric(names ...string) Router {
	for _, name := range names {
		c.route.SetWhere(name, "^[a-zA-Z0-9]+$")
	}
	return c
}

// WhereUuid adds a UUID constraint to the registered route.
func (c *routeChain) WhereUuid(names ...string) Router {
	for _, name := range names {
		c.route.SetWhere(name, "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
	}
	return c
}

// WhereUlid adds a ULID constraint to the registered route.
func (c *routeChain) WhereUlid(names ...string) Router {
	for _, name := range names {
		c.route.SetWhere(name, "^[0-9A-HJKMNP-TV-Z]{26}$")
	}
	return c
}

// WhereIn adds an allowed-values constraint to the registered route.
func (c *routeChain) WhereIn(name string, allowed []string) Router {
	var escaped []string
	for _, val := range allowed {
		escaped = append(escaped, regexpQuote(val))
	}
	return c.Where(name, "^("+joinStrings(escaped, "|")+")$")
}

// Middleware attaches middleware to the registered route (chain override).
func (c *routeChain) Middleware(middlewares ...interface{}) Router {
	c.route.middlewares = append(c.route.middlewares, middlewares...)
	return c
}

// WithoutMiddleware excludes middleware from the registered route.
func (c *routeChain) WithoutMiddleware(middlewares ...interface{}) Router {
	c.route.WithoutMiddleware(middlewares...)
	return c
}

// Missing registers the missing-parameter fallback of the registered route.
func (c *routeChain) Missing(callback any) Router {
	c.route.Missing(normalizeMissingCallback(callback))
	return c
}

// SetSecure marks the registered route as HTTPS-only.
func (c *routeChain) SetSecure() Router {
	c.route.Secure()
	return c
}

// ScopeBindings marks the registered route as enforcing scoped bindings.
func (c *routeChain) ScopeBindings() Router {
	c.route.ScopeBindings()
	return c
}

// WithTrashed marks the registered route as allowing trashed bindings.
func (c *routeChain) WithTrashed() Router {
	c.route.WithTrashed()
	return c
}

func joinStrings(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}

var _ = http.StatusOK
var _ = reflect.TypeOf
