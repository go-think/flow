package flow

import "strings"

// RouteRegistrar allows registering groups of routes with shared attributes.
type RouteRegistrar struct {
	router     Router
	attributes GroupAttributes
}

// NewRouteRegistrar creates a new RouteRegistrar bound to the router.
func NewRouteRegistrar(router Router) *RouteRegistrar {
	return &RouteRegistrar{
		router: router,
		attributes: GroupAttributes{
			Wheres:   make(map[string]string),
			Metadata: make(map[string]any),
		},
	}
}

// Router returns the underlying Router instance.
func (rr *RouteRegistrar) Router() Router {
	return rr.router
}

// Attributes returns a copy of the current group attributes.
func (rr *RouteRegistrar) Attributes() GroupAttributes {
	return rr.attributes
}

// Prefix sets the path prefix for the registrar.
func (rr *RouteRegistrar) Prefix(prefix string) *RouteRegistrar {
	if rr.attributes.Prefix != "" {
		rr.attributes.Prefix = joinPaths(rr.attributes.Prefix, prefix)
	} else {
		rr.attributes.Prefix = prefix
	}
	return rr
}

// Name sets the name prefix for routes registered through this registrar.
func (rr *RouteRegistrar) Name(name string) *RouteRegistrar {
	rr.attributes.Name += name
	return rr
}

// As is an alias for Name.
func (rr *RouteRegistrar) As(name string) *RouteRegistrar {
	return rr.Name(name)
}

// Domain sets the domain constraint for routes registered through this registrar.
func (rr *RouteRegistrar) Domain(domain string) *RouteRegistrar {
	rr.attributes.Domain = domain
	return rr
}

// Controller sets the controller prefix for routes registered through this registrar.
func (rr *RouteRegistrar) Controller(controller string) *RouteRegistrar {
	rr.attributes.Controller = controller
	return rr
}

// Middleware appends middleware to this registrar.
func (rr *RouteRegistrar) Middleware(middlewares ...any) *RouteRegistrar {
	rr.attributes.Middleware = append(rr.attributes.Middleware, middlewares...)
	return rr
}

// WithoutMiddleware excludes middleware from routes registered through this registrar.
func (rr *RouteRegistrar) WithoutMiddleware(middlewares ...any) *RouteRegistrar {
	rr.attributes.WithoutMiddleware = append(rr.attributes.WithoutMiddleware, middlewares...)
	return rr
}

// ScopeBindings enforces scoped bindings on routes registered through this registrar.
func (rr *RouteRegistrar) ScopeBindings() *RouteRegistrar {
	rr.attributes.ScopeBindings = true
	return rr
}

// WithoutScopedBindings disables scoped bindings on routes registered through this registrar.
func (rr *RouteRegistrar) WithoutScopedBindings() *RouteRegistrar {
	rr.attributes.ScopeBindings = false
	return rr
}

// WithTrashed allows soft-deleted entities on routes registered through this registrar.
func (rr *RouteRegistrar) WithTrashed() *RouteRegistrar {
	rr.attributes.WithTrashed = true
	return rr
}

// Default sets a default parameter value on routes registered through this registrar.
func (rr *RouteRegistrar) Default(key string, value any) *RouteRegistrar {
	if rr.attributes.Defaults == nil {
		rr.attributes.Defaults = make(map[string]any)
	}
	rr.attributes.Defaults[key] = value
	return rr
}

// Defaults sets multiple default parameter values on routes registered through this registrar.
func (rr *RouteRegistrar) Defaults(defaults map[string]any) *RouteRegistrar {
	if rr.attributes.Defaults == nil {
		rr.attributes.Defaults = make(map[string]any)
	}
	for k, v := range defaults {
		rr.attributes.Defaults[k] = v
	}
	return rr
}

// Metadata sets metadata attributes on routes registered through this registrar.
func (rr *RouteRegistrar) Metadata(metadata map[string]any) *RouteRegistrar {
	if rr.attributes.Metadata == nil {
		rr.attributes.Metadata = make(map[string]any)
	}
	for k, v := range metadata {
		rr.attributes.Metadata[k] = v
	}
	return rr
}

// Where adds a regex constraint to a route parameter.
func (rr *RouteRegistrar) Where(name, expression string) *RouteRegistrar {
	if rr.attributes.Wheres == nil {
		rr.attributes.Wheres = make(map[string]string)
	}
	rr.attributes.Wheres[name] = expression
	return rr
}

// WhereMap adds multiple regex constraints to route parameters.
func (rr *RouteRegistrar) WhereMap(wheres map[string]string) *RouteRegistrar {
	if rr.attributes.Wheres == nil {
		rr.attributes.Wheres = make(map[string]string)
	}
	for k, v := range wheres {
		rr.attributes.Wheres[k] = v
	}
	return rr
}

// WhereNumber adds a numeric regex constraint to parameters.
func (rr *RouteRegistrar) WhereNumber(names ...string) *RouteRegistrar {
	for _, name := range names {
		rr.Where(name, "[0-9]+")
	}
	return rr
}

// WhereAlpha adds an alphabetic regex constraint to parameters.
func (rr *RouteRegistrar) WhereAlpha(names ...string) *RouteRegistrar {
	for _, name := range names {
		rr.Where(name, "[a-zA-Z]+")
	}
	return rr
}

// WhereAlphaNumeric adds an alphanumeric regex constraint to parameters.
func (rr *RouteRegistrar) WhereAlphaNumeric(names ...string) *RouteRegistrar {
	for _, name := range names {
		rr.Where(name, "[a-zA-Z0-9]+")
	}
	return rr
}

// WhereUuid adds a UUID regex constraint to parameters.
func (rr *RouteRegistrar) WhereUuid(names ...string) *RouteRegistrar {
	for _, name := range names {
		rr.Where(name, `[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}`)
	}
	return rr
}

// WhereUlid adds a ULID regex constraint to parameters.
func (rr *RouteRegistrar) WhereUlid(names ...string) *RouteRegistrar {
	for _, name := range names {
		rr.Where(name, `[0-7][0-9a-hjkmnp-tv-zA-HJKMNP-TV-Z]{25}`)
	}
	return rr
}

// WhereIn adds an allowed values constraint to a parameter.
func (rr *RouteRegistrar) WhereIn(name string, allowed []string) *RouteRegistrar {
	return rr.Where(name, strings.Join(allowed, "|"))
}

// Group registers a group of routes sharing this registrar's attributes.
// The callback can be func(router Router) or func().
func (rr *RouteRegistrar) Group(callback any) {
	switch cb := callback.(type) {
	case func(group Router):
		rr.router.Group(rr.attributes, cb)
	case func():
		rr.router.Group(rr.attributes, func(group Router) {
			cb()
		})
	default:
		rr.router.Group(rr.attributes, callback)
	}
}

// Get registers a GET route within this registrar's attribute context.
func (rr *RouteRegistrar) Get(pattern string, handler any) Router {
	var route Router
	rr.router.Group(rr.attributes, func(group Router) {
		route = group.Get(pattern, handler)
	})
	return route
}

// Post registers a POST route within this registrar's attribute context.
func (rr *RouteRegistrar) Post(pattern string, handler any) Router {
	var route Router
	rr.router.Group(rr.attributes, func(group Router) {
		route = group.Post(pattern, handler)
	})
	return route
}

// Put registers a PUT route within this registrar's attribute context.
func (rr *RouteRegistrar) Put(pattern string, handler any) Router {
	var route Router
	rr.router.Group(rr.attributes, func(group Router) {
		route = group.Put(pattern, handler)
	})
	return route
}

// Patch registers a PATCH route within this registrar's attribute context.
func (rr *RouteRegistrar) Patch(pattern string, handler any) Router {
	var route Router
	rr.router.Group(rr.attributes, func(group Router) {
		route = group.Patch(pattern, handler)
	})
	return route
}

// Delete registers a DELETE route within this registrar's attribute context.
func (rr *RouteRegistrar) Delete(pattern string, handler any) Router {
	var route Router
	rr.router.Group(rr.attributes, func(group Router) {
		route = group.Delete(pattern, handler)
	})
	return route
}

// Options registers an OPTIONS route within this registrar's attribute context.
func (rr *RouteRegistrar) Options(pattern string, handler any) Router {
	var route Router
	rr.router.Group(rr.attributes, func(group Router) {
		route = group.Options(pattern, handler)
	})
	return route
}

// Any registers a route responding to all standard verbs within this registrar's context.
func (rr *RouteRegistrar) Any(pattern string, handler any) Router {
	var route Router
	rr.router.Group(rr.attributes, func(group Router) {
		route = group.Any(pattern, handler)
	})
	return route
}

// Match registers a route responding to the specified verbs within this registrar's context.
func (rr *RouteRegistrar) Match(methods []string, pattern string, handler any) Router {
	var route Router
	rr.router.Group(rr.attributes, func(group Router) {
		route = group.Match(methods, pattern, handler)
	})
	return route
}

// Resource registers a resource controller within this registrar's attribute context.
func (rr *RouteRegistrar) Resource(name string, controller any, options ...ResourceOption) *PendingResourceRegistration {
	var pr *PendingResourceRegistration
	rr.router.Group(rr.attributes, func(group Router) {
		pr = group.Resource(name, controller, options...)
	})
	return pr
}

// APIResource registers an API resource controller within this registrar's attribute context.
func (rr *RouteRegistrar) APIResource(name string, controller any, options ...ResourceOption) *PendingResourceRegistration {
	var pr *PendingResourceRegistration
	rr.router.Group(rr.attributes, func(group Router) {
		pr = group.APIResource(name, controller, options...)
	})
	return pr
}

// Singleton registers a singleton resource controller within this registrar's attribute context.
func (rr *RouteRegistrar) Singleton(name string, controller any, options ...ResourceOption) *PendingResourceRegistration {
	var pr *PendingResourceRegistration
	rr.router.Group(rr.attributes, func(group Router) {
		pr = group.Singleton(name, controller, options...)
	})
	return pr
}

// APISingleton registers an API singleton resource controller within this registrar's attribute context.
func (rr *RouteRegistrar) APISingleton(name string, controller any, options ...ResourceOption) *PendingResourceRegistration {
	var pr *PendingResourceRegistration
	rr.router.Group(rr.attributes, func(group Router) {
		pr = group.APISingleton(name, controller, options...)
	})
	return pr
}
