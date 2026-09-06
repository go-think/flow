package flow

import (
	"fmt"
	"reflect"
	"strings"
)

// ControllerAction references a method on a controller. The controller may be
// a literal instance or the name it was registered under
// (Router.RegisterController).
type ControllerAction struct {
	Controller any    // instance or registered name (string)
	Method     string
}

// String renders the action as "Name@Method" when a name is used.
func (a ControllerAction) String() string {
	if name, ok := a.Controller.(string); ok {
		return name + "@" + a.Method
	}
	return fmt.Sprintf("%T@%s", a.Controller, a.Method)
}

// Controller is implemented by controllers that declare route middleware.
type Controller interface {
	// Middleware declares controller middleware with optional method filters.
	Middleware() []ControllerMiddleware
}

// ControllerMiddleware is a middleware entry declared by a controller. When
// Only is set the middleware applies to those methods; when Except is set it
// applies to every method except the listed ones.
type ControllerMiddleware struct {
	Handler any
	Only    []string
	Except  []string
}

// ControllerDispatcher dispatches a controller method with dependency
// injection (route parameters first, container dependencies by type).
type ControllerDispatcher interface {
	// Dispatch resolves the controller (a registered name is looked up in the
	// router registry), binds the method arguments and calls it.
	Dispatch(route *Route, request *Request, action ControllerAction, params []*parameter) (any, error)
	// ResolveController turns a registered controller name into its instance;
	// literal instances pass through.
	ResolveController(action ControllerAction) (any, error)
	// GetMiddleware returns the middleware declared by the controller for the
	// given method.
	GetMiddleware(controller any, method string) []any
}

// controllerDispatcher is the default ControllerDispatcher implementation.
type controllerDispatcher struct {
	router *router
}

// Dispatch resolves and invokes the controller method.
func (d *controllerDispatcher) Dispatch(route *Route, request *Request, action ControllerAction, params []*parameter) (any, error) {
	controller, err := d.resolveController(action)
	if err != nil {
		return nil, err
	}

	method := reflect.ValueOf(controller).MethodByName(action.Method)
	if !method.IsValid() {
		return nil, fmt.Errorf("flow: controller [%s] has no method [%s]", action.String(), action.Method)
	}

	in := route.parseParams(method, request, params)
	out := method.Call(in)
	if len(out) > 0 {
		return out[0].Interface(), nil
	}
	return nil, nil
}

// ResolveController turns a registered controller name into its instance.
func (d *controllerDispatcher) ResolveController(action ControllerAction) (any, error) {
	return d.resolveController(action)
}

// resolveController turns a name into the registered controller instance.
func (d *controllerDispatcher) resolveController(action ControllerAction) (any, error) {
	if name, ok := action.Controller.(string); ok {
		if d.router == nil {
			return nil, fmt.Errorf("flow: controller [%s] cannot be resolved without a router", name)
		}
		controller, ok := d.router.controllers[name]
		if !ok {
			return nil, fmt.Errorf("flow: controller [%s] is not registered", name)
		}
		return controller, nil
	}
	return action.Controller, nil
}

// GetMiddleware returns the middleware the controller declares for a method.
func (d *controllerDispatcher) GetMiddleware(controller any, method string) []any {
	cm, ok := controller.(Controller)
	if !ok {
		return nil
	}
	var out []any
	for _, m := range cm.Middleware() {
		if controllerMiddlewareApplies(m, method) {
			out = append(out, m.Handler)
		}
	}
	return out
}

// controllerMiddlewareApplies checks the Only/Except filters of a controller
// middleware declaration against the action method.
func controllerMiddlewareApplies(m ControllerMiddleware, method string) bool {
	if len(m.Only) > 0 {
		return containsString(m.Only, method)
	}
	if len(m.Except) > 0 {
		return !containsString(m.Except, method)
	}
	return true
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// parseControllerAction normalizes an action: a "Name@Method" or "Name"
// string becomes a ControllerAction (a missing method defaults to Invoke for
// single-invocation controllers); any other value is returned unchanged.
func parseControllerAction(handler any) any {
	if s, ok := handler.(string); ok {
		name, method := s, "Invoke"
		if idx := strings.Index(s, "@"); idx != -1 {
			name, method = s[:idx], s[idx+1:]
		}
		return ControllerAction{Controller: name, Method: method}
	}
	return handler
}
