package flow

import (
	"fmt"
	"reflect"
	"strings"
)

// Binder resolves a route parameter value into an object that is injected
// into the route action (explicit binding).
type Binder func(value string, route *Route) (any, error)

// Routable is implemented by entities that can be resolved from a route
// parameter value (implicit binding). The parameter name of the route maps to
// the argument type implementing this interface.
type Routable interface {
	// ResolveRouteBinding retrieves the entity for the given parameter value;
	// field is the binding field when the route declared "{user:id}" syntax,
	// or "" when the default key applies. Return an error when the entity is
	// not found — the request then fails with a not-found response.
	ResolveRouteBinding(value string, field string) (any, error)
}

// Bind registers an explicit binder for a route parameter name.
func (r *router) Bind(key string, binder Binder) {
	root := r.root()
	if root.binders == nil {
		root.binders = make(map[string]Binder)
	}
	root.binders[key] = binder
}

// getBinder returns the explicit binder registered for a parameter name.
func (r *router) getBinder(key string) Binder {
	root := r.root()
	if root.binders == nil {
		return nil
	}
	return root.binders[key]
}

// resolveBindingParameters resolves bound values for the route parameters:
// explicit binders first, then implicit bindings through the Routable
// contract. Returns a map of parameter name to resolved object.
func (r *Route) resolveBindingParameters(request *Request, parameters []*parameter) map[string]any {
	resolved := make(map[string]any)
	for _, p := range parameters {
		name, field := splitBindingFieldName(p.name)

		if r.router != nil {
			if binder := r.router.getBinder(name); binder != nil {
				val, err := binder(p.value, r)
				if err != nil {
					panic(fmt.Sprintf("flow: binding for parameter [%s] failed: %v", name, err))
				}
				if val != nil {
					resolved[name] = val
					continue
				}
			}
		}

		// Implicit binding happens lazily during argument matching, when the
		// target argument type is known.
		_ = field
		_ = request
	}
	return resolved
}

// splitBindingFieldName splits a "{user:id}" style parameter into its name
// and binding field.
func splitBindingFieldName(raw string) (string, string) {
	if idx := strings.Index(raw, ":"); idx != -1 {
		return raw[:idx], raw[idx+1:]
	}
	return raw, ""
}

// bindingFieldFor returns the binding field declared for a parameter.
func (r *Route) bindingFieldFor(name string) string {
	if r.bindingFields == nil {
		return ""
	}
	return r.bindingFields[name]
}

// implicitBindingArgument builds the argument value for an implicit binding:
// a zero instance of the target type resolves itself through Routable.
func implicitBindingArgument(targetType reflect.Type, paramValue, field string, route *Route) (reflect.Value, bool) {
	if targetType.Kind() != reflect.Ptr {
		return reflect.Value{}, false
	}
	probe, ok := reflect.New(targetType.Elem()).Interface().(Routable)
	if !ok {
		return reflect.Value{}, false
	}
	bound, err := probe.ResolveRouteBinding(paramValue, field)
	if err != nil {
		panic(fmt.Sprintf("flow: implicit binding for [%s] failed: %v", targetType, err))
	}
	if bound == nil {
		return reflect.Value{}, false
	}
	val := reflect.ValueOf(bound)
	if !val.Type().AssignableTo(targetType) {
		return reflect.Value{}, false
	}
	return val, true
}
