package flow

import (
	"reflect"
)

// CallableDispatcher defines the contract for dispatching callable route actions.
type CallableDispatcher interface {
	Dispatch(route *Route, callable any, request *Request, params []*parameter) (any, error)
}

// defaultCallableDispatcher provides standard reflection and parameter injection for callables.
type defaultCallableDispatcher struct{}

var defaultCallableDispatcherInstance CallableDispatcher = &defaultCallableDispatcher{}

// Dispatch executes the callable handler for the given route and request.
func (d *defaultCallableDispatcher) Dispatch(route *Route, callable any, request *Request, params []*parameter) (any, error) {
	if callable == nil {
		return nil, nil
	}

	v := reflect.ValueOf(callable)
	if v.Kind() == reflect.Func {
		in := route.parseParams(v, request, params)
		out := v.Call(in)
		if len(out) > 0 {
			return out[0].Interface(), nil
		}
		return nil, nil
	}

	return callable, nil
}
