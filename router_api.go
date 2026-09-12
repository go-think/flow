package flow

import (
	"strings"
)

// GetMiddleware returns the full middleware alias table
// (Laravel: getMiddleware).
func (r *router) GetMiddleware() map[string]any {
	out := make(map[string]any, len(r.middlewareAliases))
	for k, v := range r.middlewareAliases {
		out[k] = v
	}
	return out
}

// Input retrieves an input value from the current request
// (Laravel: Router::input).
func (r *router) Input(key string, defaultValue ...any) any {
	req := r.currentRequest
	if req == nil {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return nil
	}
	val, ok := req.Get(key)
	if !ok && len(defaultValue) > 0 {
		return defaultValue[0]
	}
	if !ok {
		return nil
	}
	return val
}

// SingularResourceParameters sets the global singular parameter flag
// (Laravel: singularResourceParameters).
func (r *router) SingularResourceParameters(singular bool) {
	r.resourceSingular = singular
}

// SetResourceParameters sets the global resource parameter mapping
// (Laravel: resourceParameters).
func (r *router) SetResourceParameters(params map[string]string) {
	r.resourceParams = params
}

// SetResourceVerbs sets the global resource verb overrides
// (Laravel: resourceVerbs).
func (r *router) SetResourceVerbs(verbs map[string]string) {
	r.resourceVerbsMap = verbs
}

// SetContainer sets the router's dependency resolver
// (Laravel: setContainer).
func (r *router) SetContainer(container any) {
	if pr, ok := container.(ParameterResolver); ok {
		r.parameterResolver = pr
	}
}

// SetImplicitBindingResolver replaces the implicit binding resolution logic
// (Laravel: substituteImplicitBindingsUsing).
func (r *router) SetImplicitBindingResolver(fn func(route *Route, key, value string) any) {
	r.implicitBindingResolver = fn
}

var _ = strings.Contains
