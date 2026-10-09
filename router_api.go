package flow

// GetMiddleware returns the full middleware alias table
// .
func (r *router) GetMiddleware() map[string]any {
	out := make(map[string]any, len(r.middlewareAliases))
	for k, v := range r.middlewareAliases {
		out[k] = v
	}
	return out
}

// Input retrieves a route parameter from the current route
// (route parameter with default).
func (r *router) Input(key string, defaultValue ...any) any {
	route := r.CurrentRoute()
	req := r.CurrentRequest()
	var fallback any
	if len(defaultValue) > 0 {
		fallback = defaultValue[0]
	}
	if route == nil {
		return fallback
	}
	var strFallback string
	if s, ok := fallback.(string); ok {
		strFallback = s
	}
	value := route.Parameter(req, key, strFallback)
	if value == "" && fallback != nil {
		return fallback
	}
	return value
}

// SingularResourceParameters sets the global singular parameter flag
// .
func (r *router) SingularResourceParameters(singular ...bool) {
	s := true
	if len(singular) > 0 {
		s = singular[0]
	}
	r.resourceSingular = s
}

// SetResourceParameters sets the global resource parameter mapping
// .
func (r *router) SetResourceParameters(params map[string]string) {
	r.resourceParams = params
}

// SetResourceVerbs sets the global resource verb overrides
// .
func (r *router) SetResourceVerbs(verbs map[string]string) {
	r.resourceVerbsMap = verbs
}

// GetResourceParameters returns the global resource parameter mapping
// .
func (r *router) GetResourceParameters() map[string]string {
	return r.resourceParams
}

// GetResourceVerbs returns the global resource verb overrides
// .
func (r *router) GetResourceVerbs() map[string]string {
	return r.resourceVerbsMap
}

// SetContainer replaces the router's IoC container
// . When the container also implements
// ParameterResolver it doubles as the dependency resolver.
func (r *router) SetContainer(container any) {
	root := r.root()
	if c, ok := container.(Container); ok {
		root.container = c
	}
	if pr, ok := container.(ParameterResolver); ok {
		root.parameterResolver = pr
	}
}

// SetImplicitBindingResolver replaces the implicit binding resolution logic.
func (r *router) SetImplicitBindingResolver(fn func(route *Route, key, value string) any) {
	r.implicitBindingResolver = fn
}

// SubstituteImplicitBindingsUsing replaces the implicit binding resolution logic.
func (r *router) SubstituteImplicitBindingsUsing(fn func(route *Route, key, value string) any) {
	r.SetImplicitBindingResolver(fn)
}
