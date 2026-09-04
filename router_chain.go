package flow

import "strings"

// NewRouter creates a Router matching the reference constructor pattern:
// NewRouter(events, container). When called with no arguments it uses
// immediate route registration: routes are materialized
// the moment they are declared.

//	NewRouter() → immediate registration, no container
//	NewRouter(nil, myContainer) → immediate registration + container
//	NewRouter(eventsFn, nil) → immediate registration + events
//	NewRouter(eventsFn, myContainer) → both
func NewRouter(events EventDispatcher, container Container) Router {
	rt := &router{
		collection:        NewRouteCollection(),
		patterns:          make(map[string]string),
		wheres:            make(map[string]string),
		middlewareAliases: make(map[string]interface{}),
		middlewareGroups:  make(map[string][]interface{}),
		controllers:       make(map[string]any),
		autoRegister:      true,
		container:         container,
		resourceSingular:  true,
	}
	// the reference framework maps the "can" middleware alias; the default gate
	// denies every ability unless the application overrides the alias.
	rt.middlewareAliases["can"] = ParameterizedMiddleware(canMiddlewareFactory)
	rt.events = events
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
	routeWheres := make(map[string]string)
	metadata := make(map[string]any)
	domain := ""
	controllerPrefix := ""
	root := r.root()

	// Chain from outermost group to the declaring node: inner groups merge
	// OVER outer ones.
	var chain []*router
	for cur := r; cur != nil; cur = cur.group {
		chain = append([]*router{cur}, chain...)
	}
	for _, cur := range chain {
		if cur.prefix != "" {
			prefixes = append(prefixes, cur.prefix)
		}
		if cur.name != "" {
			names = append(names, cur.name)
		}
		if len(cur.middlewares) > 0 {
			middlewares = append(middlewares, cur.middlewares...)
		}
		if len(cur.withoutMiddleware) > 0 {
			without = append(without, cur.withoutMiddleware...)
		}
		if cur.domain != "" {
			domain = cur.domain
		}
		if cur.controllerPrefix != "" {
			controllerPrefix = cur.controllerPrefix
		}
		for k, v := range cur.groupWheres {
			wheres[k] = v
		}
		// In immediate-registration mode the declaring node holds route-local
		// wheres set via Where/whereNumber before the verb call (the reference implementation:
		// addWhereClausesToRoute merges the route's own where clause last).
		if cur == r {
			for k, v := range cur.wheres {
				routeWheres[k] = v
			}
		}
		// Deep merge: associated map values merge recursively so a nested
		// group's map keys do not clobber the outer group's (the reference implementation:
		//).
		metadata = mergeMetadataDeep(metadata, cur.groupMetadata)
	}
	// the reference implementation applies to every route created after the
	// pattern is registered. Immediate-registration mode uses this builder,
	// so merge the root patterns before route compilation. Route-local and
	// group constraints are already collected above and take precedence.
	for k, v := range root.patterns {
		if _, exists := wheres[k]; !exists {
			wheres[k] = v
		}
	}
	for k, v := range routeWheres {
		wheres[k] = v
	}

	prefix := pathJoinSlice(prefixes)
	if prefix == "/" {
		prefix = ""
	}
	uri := prefix + pattern
	if uri == "" || uri[0] != '/' {
		uri = "/" + strings.TrimLeft(uri, "/")
	}
	// semantics: "{user:id}" placeholders are rewritten to
	// "{user}" and their binding fields recorded.
	parsedURI := ParseRouteUri(uri)
	uri = parsedURI.URI

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

	scoped := r.scopedBindings
	bindingFields := make(map[string]string)
	for k, v := range r.bindingFields {
		bindingFields[k] = v
	}
	for k, v := range parsedURI.BindingFields {
		bindingFields[k] = v
	}

	var canEntries []canEntry
	for cur := r; cur != nil; cur = cur.group {
		canEntries = append(canEntries, cur.canEntries...)
	}

	entity := &Route{
		methods:           ensureHead(methods),
		uri:               uri,
		name:              name,
		handler:           action,
		middlewares:       middlewares,
		withoutMiddleware: without,
		wheres:            wheres,
		metadata:          metadata,
		domain:            domain,
		scopedBindings:    scoped,
		bindingFields:     bindingFields,
		withTrashed:       r.withTrashed,
		router:            r.root(),
	}
	for _, ce := range canEntries {
		entity.Can(ce.ability, ce.models...)
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

// Name adds to the registered route name (chain override) — the reference name()
// concatenates onto the existing name prefix. The lookup indexes are refreshed
// afterwards.
func (c *routeChain) Name(name string) Router {
	c.route.Name(name)
	c.router.collection.ReindexName(c.route)
	return c
}

// Where adds a constraint to the registered route (chain override).
func (c *routeChain) Where(name string, expression string) Router {
	c.route.SetWhere(name, expression)
	return c
}

// WhereNumber adds a numeric constraint to the registered route
//.
func (c *routeChain) WhereNumber(names ...string) Router {
	for _, name := range names {
		c.route.SetWhere(name, "[0-9]+")
	}
	return c
}

// WhereAlpha adds an alphabetic constraint to the registered route
//.
func (c *routeChain) WhereAlpha(names ...string) Router {
	for _, name := range names {
		c.route.SetWhere(name, "[a-zA-Z]+")
	}
	return c
}

// WhereAlphaNumeric adds an alphanumeric constraint to the registered route
//.
func (c *routeChain) WhereAlphaNumeric(names ...string) Router {
	for _, name := range names {
		c.route.SetWhere(name, "[a-zA-Z0-9]+")
	}
	return c
}

// WhereUuid adds a UUID constraint to the registered route
//.
func (c *routeChain) WhereUuid(names ...string) Router {
	for _, name := range names {
		c.route.SetWhere(name, `[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}`)
	}
	return c
}

// WhereUlid adds a ULID constraint to the registered route
//.
func (c *routeChain) WhereUlid(names ...string) Router {
	for _, name := range names {
		c.route.SetWhere(name, `[0-7][0-9a-hjkmnp-tv-zA-HJKMNP-TV-Z]{25}`)
	}
	return c
}

// WhereIn adds an allowed-values constraint to the registered route
//.
func (c *routeChain) WhereIn(name string, allowed []string) Router {
	return c.Where(name, strings.Join(allowed, "|"))
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

// Can applies the "can" authorization middleware to the registered route
//.
func (c *routeChain) Can(ability string, models ...any) Router {
	c.route.Can(ability, models...)
	return c
}
