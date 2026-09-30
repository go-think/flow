package flow

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
)

// ControllerAction references a method on a controller. The controller may be
// a literal instance or the name it was registered under
// (Router.RegisterController).
type ControllerAction struct {
	Controller any // instance or registered name (string)
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

// MiddlewareDefinition defines a controller middleware with optional method filters.
type MiddlewareDefinition struct {
	Handler       any
	OnlyMethods   []string
	ExceptMethods []string
}

// NewMiddlewareDefinition creates a new MiddlewareDefinition for controller middleware.
func NewMiddlewareDefinition(middleware any) *MiddlewareDefinition {
	return &MiddlewareDefinition{Handler: middleware}
}

// Only specifies the only controller methods the middleware should apply to.
func (m *MiddlewareDefinition) Only(methods ...string) *MiddlewareDefinition {
	m.OnlyMethods = append(m.OnlyMethods, methods...)
	return m
}

// Except specifies the controller methods the middleware should not apply to.
func (m *MiddlewareDefinition) Except(methods ...string) *MiddlewareDefinition {
	m.ExceptMethods = append(m.ExceptMethods, methods...)
	return m
}

// HasMiddleware is the interface for controller middleware configuration.
type HasMiddleware interface {
	Middleware() []*MiddlewareDefinition
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

// CallActionController is the optional dispatch hook mirroring the
// framework-agnostic callAction convention: when a controller implements it,
// Dispatch resolves the method arguments first and hands them to CallAction
// instead of invoking the method directly. Subclasses may override the hook
// to intercept every action call.
type CallActionController interface {
	// CallAction receives the action method name and the arguments resolved
	// for that method's signature).
	CallAction(method string, parameters []any) (any, error)
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

	// Controllers defining callAction intercept the dispatch
	//.
	if ca, ok := controller.(CallActionController); ok {
		parameters := make([]any, len(in))
		for i, v := range in {
			parameters[i] = v.Interface()
		}
		return ca.CallAction(action.Method, parameters)
	}

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
// It supports both HasMiddleware and the legacy Controller interface.
func (d *controllerDispatcher) GetMiddleware(controller any, method string) []any {
	if hm, ok := controller.(HasMiddleware); ok {
		var out []any
		for _, m := range hm.Middleware() {
			if m == nil {
				continue
			}
			if middlewareDefinitionApplies(m, method) {
				out = append(out, m.Handler)
			}
		}
		return out
	}
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

func middlewareDefinitionApplies(m *MiddlewareDefinition, method string) bool {
	if len(m.OnlyMethods) > 0 && !containsString(m.OnlyMethods, method) {
		return false
	}
	if len(m.ExceptMethods) > 0 && containsString(m.ExceptMethods, method) {
		return false
	}
	return true
}

// controllerMiddlewareApplies checks the Only/Except filters of a controller
// middleware declaration against the action method. The filters combine as OR,
// like the reference:
// excluded when the method misses a non-empty Only list OR when it is listed
// in a non-empty Except list — both options may be present at once.
func controllerMiddlewareApplies(m ControllerMiddleware, method string) bool {
	if len(m.Only) > 0 && !containsString(m.Only, method) {
		return false
	}
	if len(m.Except) > 0 && containsString(m.Except, method) {
		return false
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
// single-invocation controllers, mirroring); any
// other value is returned unchanged. Literal controller instances are checked
// for the default method at registration time, like the reference implementation validates
// an invoke-method existence check at registration time.
func parseControllerAction(handler any) any {
	if ca, ok := handler.(*ControllerAction); ok && ca != nil {
		return *ca
	}
	if s, ok := handler.(string); ok {
		name, method := s, "Invoke"
		if idx := strings.Index(s, "@"); idx != -1 {
			name, method = s[:idx], s[idx+1:]
		}
		return ControllerAction{Controller: name, Method: method}
	}
	return handler
}

// canMiddlewareFactory builds the middleware executing "can:ability,models"
// entries (the "can" alias resolves to this factory). Without an
// authorization backend the default is to deny,
// matching the reference returning false for undefined abilities;
// applications override it by aliasing "can" to their own factory.
func canMiddlewareFactory(params ...string) Middleware {
	ability := ""
	var models []string
	if len(params) > 0 {
		ability = params[0]
		models = append(models, params[1:]...)
	}
	// The default gate denies every ability; an application replaces the
	// "can" alias to plug in its own authorization backend.
	_, _ = ability, models
	return Middleware(func(req *Request, next Closure) any {
		return NewResponse().SetCode(http.StatusForbidden).SetContent("This action is unauthorized.")
	})
}
