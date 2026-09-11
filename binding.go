package flow

import (
	"context"
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
	ResolveRouteBinding(ctx context.Context, value string, field string) (any, error)
}

// ScopedRoutable is implemented by entities that can resolve a child entity (scoped binding).
type ScopedRoutable interface {
	ResolveChildRouteBinding(ctx context.Context, childType string, value string, field string) (any, error)
}

// SoftDeletableRoutable is implemented by entities that support resolving soft-deleted records.
type SoftDeletableRoutable interface {
	ResolveSoftDeletableRouteBinding(ctx context.Context, value string, field string) (any, error)
}

// ModelNotFoundError indicates that a bound model could not be found for a route parameter.
type ModelNotFoundError struct {
	Param string
	Value string
	Type  reflect.Type
	Err   error
}

func (e *ModelNotFoundError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("flow: model not found for parameter [%s] with value [%s]: %v", e.Param, e.Value, e.Err)
	}
	return fmt.Sprintf("flow: model not found for parameter [%s] with value [%s]", e.Param, e.Value)
}

func (e *ModelNotFoundError) Unwrap() error {
	return e.Err
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
		name, _ := splitBindingFieldName(p.name)

		if r.router != nil {
			if binder := r.router.getBinder(name); binder != nil {
				val, err := binder(p.value, r)
				if err != nil {
					panic(&ModelNotFoundError{Param: name, Value: p.value, Err: err})
				}
				if val != nil {
					resolved[name] = val
					continue
				}
			}
		}
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
// a zero instance of the target type resolves itself through Routable or ScopedRoutable.
func implicitBindingArgument(targetType reflect.Type, paramName, paramValue, field string, route *Route, parent any, ctx context.Context) (reflect.Value, error) {
	if targetType.Kind() != reflect.Ptr {
		return reflect.Value{}, nil
	}

	// 1. When a parent model was bound, attempt child resolution through it
	// (implicit scoped chaining for nested resources).
	if parent != nil {
		if scopedParent, ok := parent.(ScopedRoutable); ok {
			bound, err := scopedParent.ResolveChildRouteBinding(ctx, paramName, paramValue, field)
			if err != nil {
				return reflect.Value{}, &ModelNotFoundError{Value: paramValue, Type: targetType, Err: err}
			}
			if bound == nil {
				return reflect.Value{}, &ModelNotFoundError{Value: paramValue, Type: targetType}
			}
			val := reflect.ValueOf(bound)
			if val.Type().AssignableTo(targetType) {
				return val, nil
			}
		}
	}

	// 2. Normal Routable or SoftDeletableRoutable resolution
	probe := reflect.New(targetType.Elem()).Interface()

	if route != nil && route.AllowsTrashedBindings() {
		if soft, ok := probe.(SoftDeletableRoutable); ok {
			bound, err := soft.ResolveSoftDeletableRouteBinding(ctx, paramValue, field)
			if err != nil {
				return reflect.Value{}, &ModelNotFoundError{Value: paramValue, Type: targetType, Err: err}
			}
			if bound == nil {
				return reflect.Value{}, &ModelNotFoundError{Value: paramValue, Type: targetType}
			}
			val := reflect.ValueOf(bound)
			if val.Type().AssignableTo(targetType) {
				return val, nil
			}
		}
	}

	if routable, ok := probe.(Routable); ok {
		bound, err := routable.ResolveRouteBinding(ctx, paramValue, field)
		if err != nil {
			return reflect.Value{}, &ModelNotFoundError{Value: paramValue, Type: targetType, Err: err}
		}
		if bound == nil {
			return reflect.Value{}, &ModelNotFoundError{Value: paramValue, Type: targetType}
		}
		val := reflect.ValueOf(bound)
		if val.Type().AssignableTo(targetType) {
			return val, nil
		}
	}

	return reflect.Value{}, nil
}
