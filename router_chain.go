package flow

import "strings"

// NewRouter creates a Router. It accepts an optional event dispatcher and
// container; nil may be passed for either. Routes are registered immediately:
// they are materialized the moment they are declared.
//
// NewRouter() → immediate registration, no container
// NewRouter(nil, myContainer) → immediate registration + container
// NewRouter(eventsFn, nil) → immediate registration + events
// NewRouter(eventsFn, myContainer) → both
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
	// Map the "can" middleware alias; the default gate denies every ability
	// unless the application overrides the alias.
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
	defaults := make(map[string]any)
	routeDefaults := make(map[string]any)
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
		for k, v := range cur.groupDefaults {
			defaults[k] = v
		}
		// In immediate-registration mode the declaring node holds route-local
		// wheres set via Where/WhereNumber before the verb call; the route's own
		// where clause is merged last.
		if cur == r {
			for k, v := range cur.wheres {
				routeWheres[k] = v
			}
			for k, v := range cur.defaults {
				routeDefaults[k] = v
			}
		}
		// Deep merge: associated map values merge recursively so a nested
		// group's map keys do not clobber the outer group's.
		metadata = mergeMetadataDeep(metadata, cur.groupMetadata)
	}
	for k, v := range routeDefaults {
		defaults[k] = v
	}
	// Root patterns apply to every route created after the pattern is
	// registered. Merge them before route compilation; route-local and group
	// constraints are already collected above and take precedence.
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
	// "{user:id}" placeholders are rewritten to "{user}" and their binding
	// fields recorded.
	parsedURI := ParseRouteUri(uri)
	uri = parsedURI.URI

	name := ""
	for _, n := range names {
		name += n
	}

	action := parseControllerAction(handler)
	if ca, ok := action.(ControllerAction); ok {
		if nameStr, isName := ca.Controller.(string); isName && controllerPrefix != "" {
			if ca.Method == "Invoke" {
				ca.Controller = controllerPrefix
				ca.Method = nameStr
			} else if nameStr != controllerPrefix {
				ca.Controller = controllerPrefix + "." + nameStr
			}
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
		defaults:          defaults,
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

// Name adds to the registered route name (chain override), concatenating onto
// the existing name prefix. The lookup indexes are refreshed afterwards.
func (c *routeChain) Name(name string) Router {
	c.route.Name(name)
	c.router.collection.RefreshNameLookups()
	c.router.collection.RefreshActionLookups()
	return c
}

// Where adds a constraint to the registered route (chain override).
func (c *routeChain) Where(name string, expression string) Router {
	c.route.SetWhere(name, expression)
	return c
}

// WhereMap adds multiple regex constraints to the registered route (chain override).
func (c *routeChain) WhereMap(wheres map[string]string) Router {
	c.route.WhereMap(wheres)
	return c
}

// WhereNumber adds a numeric constraint to the registered route.
func (c *routeChain) WhereNumber(names ...string) Router {
	for _, name := range names {
		c.route.SetWhere(name, "[0-9]+")
	}
	return c
}

// WhereAlpha adds an alphabetic constraint to the registered route.
func (c *routeChain) WhereAlpha(names ...string) Router {
	for _, name := range names {
		c.route.SetWhere(name, "[a-zA-Z]+")
	}
	return c
}

// WhereAlphaNumeric adds an alphanumeric constraint to the registered route.
func (c *routeChain) WhereAlphaNumeric(names ...string) Router {
	for _, name := range names {
		c.route.SetWhere(name, "[a-zA-Z0-9]+")
	}
	return c
}

// WhereUuid adds a UUID constraint to the registered route.
func (c *routeChain) WhereUuid(names ...string) Router {
	for _, name := range names {
		c.route.SetWhere(name, `[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}`)
	}
	return c
}

// WhereUlid adds a ULID constraint to the registered route.
func (c *routeChain) WhereUlid(names ...string) Router {
	for _, name := range names {
		c.route.SetWhere(name, `[0-7][0-9a-hjkmnp-tv-zA-HJKMNP-TV-Z]{25}`)
	}
	return c
}

// WhereIn adds an allowed-values constraint to the registered route.
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

// WithoutScopedBindings disables scoped bindings on the registered route.
func (c *routeChain) WithoutScopedBindings() Router {
	if c.route != nil {
		c.route.WithoutScopedBindings()
		return c
	}
	return c.router.WithoutScopedBindings()
}

// Controller sets the controller on the router.
func (c *routeChain) Controller(controller any) Router {
	return c.router.Controller(controller)
}

// Metadata sets metadata on the registered route.
func (c *routeChain) Metadata(key string, value any) Router {
	if c.route != nil {
		c.route.SetMetadata(key, value)
		return c
	}
	return c.router.Metadata(key, value)
}

// WithTrashed marks the registered route as allowing trashed bindings.
func (c *routeChain) WithTrashed() Router {
	c.route.WithTrashed()
	return c
}

// Can applies the "can" authorization middleware to the registered route.
func (c *routeChain) Can(ability string, models ...any) Router {
	c.route.Can(ability, models...)
	return c
}

// As is an alias for Name.
func (c *routeChain) As(name string) Router {
	return c.Name(name)
}

// Default sets a default parameter value on the route.
func (c *routeChain) Default(key string, value any) Router {
	c.route.Default(key, value)
	return c
}

// Defaults sets multiple default parameter values on the route.
func (c *routeChain) Defaults(defaults map[string]any) Router {
	c.route.SetDefaults(defaults)
	return c
}

// HasGroupStack reports whether the router is currently within a route group.
func (c *routeChain) HasGroupStack() bool {
	return c.router.HasGroupStack()
}

// GetGroupStack returns the group attributes stack from outer to inner.
func (c *routeChain) GetGroupStack() []GroupAttributes {
	return c.router.GetGroupStack()
}

// SetCallableDispatcher replaces the callable dispatcher.
func (c *routeChain) SetCallableDispatcher(dispatcher CallableDispatcher) {
	c.router.SetCallableDispatcher(dispatcher)
}

// GetCallableDispatcher returns the callable dispatcher.
func (c *routeChain) GetCallableDispatcher() CallableDispatcher {
	return c.router.GetCallableDispatcher()
}

// SingularResourceParameters sets the global singular parameter flag.
func (c *routeChain) SingularResourceParameters(singular ...bool) {
	c.router.SingularResourceParameters(singular...)
}

// SetResourceParameters sets the global resource parameter mapping.
func (c *routeChain) SetResourceParameters(params map[string]string) {
	c.router.SetResourceParameters(params)
}

// SetResourceVerbs sets the global resource verb overrides.
func (c *routeChain) SetResourceVerbs(verbs map[string]string) {
	c.router.SetResourceVerbs(verbs)
}

// RespondWithRoute dispatches the request to a route resolved by its name.
func (c *routeChain) RespondWithRoute(name string, request *Request) *Response {
	return c.router.RespondWithRoute(name, request)
}

// SubstituteImplicitBindingsUsing replaces the implicit binding resolution logic.
func (c *routeChain) SubstituteImplicitBindingsUsing(fn func(route *Route, key, value string) any) {
	c.router.SubstituteImplicitBindingsUsing(fn)
}

// Terminate calls Terminate on all terminable middlewares for the request.
func (c *routeChain) Terminate(request *Request, response any) {
	c.router.Terminate(request, response)
}
