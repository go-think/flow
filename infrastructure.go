package flow

import (
	"context"
	"reflect"
	"strings"
)

// SortedMiddleware stably orders middleware entries by a priority list
// (Laravel: SortedMiddleware). Entries not in the priority list retain their
// relative order after the ranked ones.
func SortMiddleware(priority []any, middlewares []any) []any {
	if len(priority) == 0 || len(middlewares) < 2 {
		return middlewares
	}

	rank := func(m any) int {
		for i, p := range priority {
			if m == p || reflect.DeepEqual(m, p) {
				return i
			}
		}
		return len(priority)
	}

	ordered := make([]any, len(middlewares))
	copy(ordered, middlewares)
	for i := 1; i < len(ordered); i++ {
		for j := i; j > 0 && rank(ordered[j]) < rank(ordered[j-1]); j-- {
			ordered[j], ordered[j-1] = ordered[j-1], ordered[j]
		}
	}
	return ordered
}

// RouteAction parses and normalizes route actions
// (Laravel: RouteAction).
type RouteAction struct{}

// Parse normalizes an action value: strings become ControllerAction, other
// values pass through unchanged.
func (RouteAction) Parse(action any) any {
	return parseControllerAction(action)
}

// IsSerializedClosure always returns false in Go (closures cannot be
// serialized across a cache boundary).
func (RouteAction) IsSerializedClosure(action any) bool {
	return false
}

// MakeInvokable returns the action for a single-invocation controller.
func (RouteAction) MakeInvokable(action string) string {
	return action + "@Invoke"
}

// RouteUri represents a parsed route URI with its parameter and binding-field
// declarations (Laravel: RouteUri).
type RouteUri struct {
	URI           string
	BindingFields map[string]string
}

// ParseRouteUri parses a route URI into its segments and binding fields
// (Laravel: RouteUri::parse).
func ParseRouteUri(uri string) RouteUri {
	route := Route{uri: uri}
	route.compile()
	return RouteUri{
		URI:           uri,
		BindingFields: route.bindingFields,
	}
}

// RouteParameterBinder binds route parameters from a request path
// (Laravel: RouteParameterBinder).
type RouteParameterBinder struct {
	route *Route
}

// NewRouteParameterBinder creates a binder for the given route.
func NewRouteParameterBinder(route *Route) *RouteParameterBinder {
	return &RouteParameterBinder{route: route}
}

// Parameters extracts and returns the route parameters from the request path
// (Laravel: RouteParameterBinder::parameters).
func (b *RouteParameterBinder) Parameters(req *Request) []*parameter {
	b.route.compile()
	path := "/" + strings.TrimLeft(req.GetPath(), "/")
	var out []*parameter
	for _, variant := range b.route.expanded {
		if variant.regex == nil {
			continue
		}
		matches := variant.regex.FindStringSubmatch(path)
		if len(matches) <= 1 {
			continue
		}
		for i, name := range variant.parameterNames {
			val := ""
			if i < len(matches)-1 {
				val = matches[i+1]
			}
			out = append(out, &parameter{name: name, value: val})
		}
		break
	}
	return out
}

// RouteBinding provides explicit binding registration helpers
// (Laravel: RouteBinding).
type RouteBinding struct{}

// ForCallback returns a Binder that invokes the given callback.
func ForCallback(fn func(value string, route *Route) (any, error)) Binder {
	return Binder(fn)
}

// ForModel returns a Binder that resolves a model instance via Routable.
func ForModel(model Routable) Binder {
	return func(value string, route *Route) (any, error) {
		return model.ResolveRouteBinding(context.Background(), value, "")
	}
}

// ControllerMiddlewareOptions provides fluent only/except filters
// (Laravel: ControllerMiddlewareOptions).
type ControllerMiddlewareOptions struct {
	OnlyMethods   []string
	ExceptMethods []string
}

// Only limits the middleware to the given methods.
func (o *ControllerMiddlewareOptions) Only(methods ...string) *ControllerMiddlewareOptions {
	o.OnlyMethods = methods
	o.ExceptMethods = nil
	return o
}

// Except excludes the given methods from the middleware.
func (o *ControllerMiddlewareOptions) Except(methods ...string) *ControllerMiddlewareOptions {
	o.ExceptMethods = methods
	o.OnlyMethods = nil
	return o
}
