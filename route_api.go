package flow

import (
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

// routeLock is the per-route atomic lock state (Laravel: block/withoutBlocking).
type routeLock struct {
	mu          sync.Mutex
	lockSeconds int
	waitSeconds int
}

// RouteCan stores the authorization ability and models declared via Can().
type RouteCan struct {
	Ability string
	Models  []any
}

// The following methods extend the Route entity with the Laravel-compatible
// parameter bag, action accessors, authorization and atomic-lock API.

// GetAction returns the route handler, or a specific field from a
// ControllerAction when key is "controller"/"method" (Laravel: getAction).
func (r *Route) GetAction(key ...string) any {
	if r.handler == nil {
		return nil
	}
	if len(key) > 0 && r.router != nil {
		if ca, ok := r.handler.(ControllerAction); ok {
			switch key[0] {
			case "controller":
				return ca.Controller
			case "method":
				return ca.Method
			}
		}
	}
	return r.handler
}

// SetAction replaces the route handler (Laravel: setAction).
func (r *Route) SetAction(handler any) *Route {
	r.handler = parseControllerAction(handler)
	return r
}

// GetActionName returns the canonical action identifier
// (Laravel: getActionName). Returns "" for closures.
func (r *Route) GetActionName() string {
	if ca, ok := r.handler.(ControllerAction); ok {
		if name, isName := ca.Controller.(string); isName {
			return name + "@" + ca.Method
		}
		return fmt.Sprintf("%T@%s", ca.Controller, ca.Method)
	}
	if reflect.ValueOf(r.handler).Kind() == reflect.Func {
		return normalizeActionName(runtime.FuncForPC(reflect.ValueOf(r.handler).Pointer()).Name())
	}
	return ""
}

// GetActionMethod returns the method name of the route action
// (Laravel: getActionMethod). Returns "Invoke" for invokable controllers.
func (r *Route) GetActionMethod() string {
	if ca, ok := r.handler.(ControllerAction); ok {
		return ca.Method
	}
	return ""
}

// Uses replaces the route action (Laravel: uses).
func (r *Route) Uses(action any) *Route {
	r.handler = parseControllerAction(action)
	return r
}

// Named reports whether the route name matches any of the given patterns
// (exact or wildcard "*", supporting "admin.*" style).
func (r *Route) Named(patterns ...string) bool {
	current := r.GetName()
	if current == "" {
		return false
	}
	for _, pattern := range patterns {
		if pattern == current {
			return true
		}
		if strings.Contains(pattern, "*") {
			pat := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$"
			if matched, _ := regexp.MatchString(pat, current); matched {
				return true
			}
		}
	}
	return false
}

// Can stores an authorization ability with optional model parameters
// (Laravel: Route::can). The router does not enforce this; it is an
// integration point for authorization middleware.
func (r *Route) Can(ability string, models ...any) *Route {
	if r.canList == nil {
		r.canList = make(map[string][]any)
	}
	r.canList[ability] = models
	return r
}

// GetCan returns the stored authorization abilities.
func (r *Route) GetCan() map[string][]any {
	return r.canList
}

// SignatureParameters extracts the struct fields of the handler's first
// bindable parameter via reflection (Laravel: RouteSignatureParameters).
func (r *Route) SignatureParameters(conditions ...string) []reflect.StructField {
	if r.handler == nil {
		return nil
	}
	v := reflect.ValueOf(r.handler)
	if v.Kind() != reflect.Func || v.Type().NumIn() == 0 {
		return nil
	}
	t := v.Type().In(0)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}

	var fields []reflect.StructField
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		include := true
		for _, cond := range conditions {
			switch cond {
			case "backed_enum":
				include = field.Type.Kind() == reflect.String || field.Type.Kind() == reflect.Int
			}
		}
		if include {
			fields = append(fields, field)
		}
	}
	return fields
}

// GetOptionalParameterNames returns the names of optional parameters
// (declared with "{name?}" in the pattern).
func (r *Route) GetOptionalParameterNames() []string {
	r.compile()
	var out []string
	for _, variant := range r.expanded {
		for _, name := range variant.parameterNames {
			if strings.Contains(r.uri, "{"+name+"?}") {
				out = append(out, name)
			}
		}
		break
	}
	return out
}

// WithoutScopedBindings marks the route as NOT enforcing scoped bindings
// (Laravel: withoutScopedBindings).
func (r *Route) WithoutScopedBindings() *Route {
	r.scopedBindings = false
	r.scopedDisabled = true
	return r
}

// PreventsScopedBindings reports whether scoped binding was explicitly disabled.
func (r *Route) PreventsScopedBindings() bool {
	return r.scopedDisabled
}

// HttpOnlyScheme marks the route as requiring a plain HTTP request.
func (r *Route) HttpOnlyScheme() *Route {
	r.httpOnly = true
	r.secure = false
	return r
}

// HttpsOnlyScheme marks the route as requiring an HTTPS request.
func (r *Route) HttpsOnlyScheme() *Route {
	r.secure = true
	r.httpOnly = false
	return r
}

// Block configures the route to hold an atomic lock for the given duration
// while handling the request (Laravel: block).
func (r *Route) Block(lockSeconds, waitSeconds int) *Route {
	r.lockSeconds = lockSeconds
	r.waitSeconds = waitSeconds
	return r
}

// WithoutBlocking marks the route as not holding an atomic lock.
func (r *Route) WithoutBlocking() *Route {
	r.lockSeconds = 0
	r.waitSeconds = 0
	return r
}

// LocksFor returns the configured lock duration in seconds.
func (r *Route) LocksFor() int {
	return r.lockSeconds
}

// WaitsFor returns the configured lock wait duration in seconds.
func (r *Route) WaitsFor() int {
	return r.waitSeconds
}

// FlushController clears the cached controller instance and computed middleware
// (Laravel: flushController).
func (r *Route) FlushController() {
	r.compileOnce = sync.Once{}
	r.expanded = nil
}

// GetControllerClass returns the controller class name for a controller action
// (Laravel: getControllerClass).
func (r *Route) GetControllerClass() string {
	if ca, ok := r.handler.(ControllerAction); ok {
		if name, isName := ca.Controller.(string); isName {
			return name
		}
		return reflect.TypeOf(ca.Controller).String()
	}
	return ""
}

// SetRouter sets the owning router back-reference.
func (r *Route) SetRouter(router *router) *Route {
	r.router = router
	return r
}

// SetContainer is the Laravel-compatible alias for SetRouter (the router
// serves as the IoC container in flow).
func (r *Route) SetContainer(container *router) *Route {
	r.router = container
	return r
}

// OriginalParameter returns the raw (pre-conversion) route parameter value
// for the given name (Laravel: originalParameter).
func (r *Route) OriginalParameter(request *Request, name string, defaultValue ...string) string {
	if request == nil {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return ""
	}
	return request.GetRouteParam(name, defaultValue...)
}

// OriginalParameters returns all raw route parameters for the request
// (Laravel: originalParameters).
func (r *Route) OriginalParameters(request *Request) map[string]string {
	return r.Parameters(request)
}

// ParametersWithoutNulls returns all route parameters, filtering out empty
// values (Laravel: parametersWithoutNulls).
func (r *Route) ParametersWithoutNulls(request *Request) map[string]string {
	all := r.Parameters(request)
	out := make(map[string]string, len(all))
	for k, v := range all {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

// SetParameter overrides a route parameter value at runtime
// (Laravel: setParameter).
func (r *Route) SetParameter(request *Request, name string, value string) *Route {
	if request != nil {
		request.SetRouteParam(name, value)
	}
	return r
}

// ForgetParameter removes a route parameter from the request
// (Laravel: forgetParameter).
func (r *Route) ForgetParameter(request *Request, name string) *Route {
	if request != nil {
		request.SetRouteParam(name, "")
	}
	return r
}

// ControllerDispatcher returns the dispatcher from the owning router
// (Laravel: controllerDispatcher).
func (r *Route) ControllerDispatcher() ControllerDispatcher {
	if r.router != nil {
		return r.router.getControllerDispatcher()
	}
	return &controllerDispatcher{}
}

// IsSerializedClosure reports whether the handler is a closure (always false
// in Go; Laravel checks for SerializableClosure).
func (r *Route) IsSerializedClosure() bool {
	return false
}

var _ = sync.Once{}
var _ = http.StatusOK
var _ = strings.Contains
