package flow

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

// The following methods extend the Route entity with the the reference implementation-compatible
// parameter bag, action accessors, authorization and atomic-lock API.

// getAction returns the route action as the reference-shaped attribute bag
// the look-ups consume: "uses" carries the action (the handler), and
// "controller" carries the "Controller@method" identifier for controller
// actions — mirroring the reference RouteAction::parse, which sets that key
// for every controller action and never for closures.
func (r *Route) getAction() map[string]any {
	action := map[string]any{"uses": nil}
	if r == nil {
		return action
	}
	action["uses"] = r.handler
	if isControllerActionHandler(r.handler) {
		action["controller"] = r.ActionName()
	}
	return action
}

// GetAction returns the route handler, or a specific field from a
// ControllerAction when key is "controller"/"method".
func (r *Route) GetAction(key ...string) any {
	if r == nil || r.handler == nil {
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

// SetAction replaces the route handler.
func (r *Route) SetAction(handler any) *Route {
	if r == nil {
		return r
	}
	r.handler = parseControllerAction(handler)
	return r
}

// GetActionName returns the canonical action identifier
// .
func (r *Route) GetActionName() string {
	if r == nil || r.handler == nil {
		return "Closure"
	}
	if ca, ok := r.handler.(ControllerAction); ok {
		if name, isName := ca.Controller.(string); isName {
			return name + "@" + ca.Method
		}
		return fmt.Sprintf("%T@%s", ca.Controller, ca.Method)
	}
	if reflect.ValueOf(r.handler).Kind() == reflect.Func {
		return "Closure"
	}
	return "Closure"
}

// GetActionMethod returns the method name of the route action
// .
func (r *Route) GetActionMethod() string {
	if r == nil || r.handler == nil {
		return "Closure"
	}
	if ca, ok := r.handler.(ControllerAction); ok {
		return ca.Method
	}
	return "Closure"
}

// Uses replaces the route action.
func (r *Route) Uses(action any) *Route {
	if r == nil {
		return r
	}
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

// Can applies the "Authorize" / "can" middleware to the route with the given
// models (the reference implementation: can — a "can:ability,models" entry is appended to the route
// middleware so it executes with the rest of the stack).
func (r *Route) Can(ability string, models ...any) *Route {
	entry := "can:" + ability
	if len(models) > 0 {
		parts := make([]string, 0, len(models))
		for _, model := range models {
			parts = append(parts, toStringValue(model))
		}
		entry += "," + strings.Join(parts, ",")
	}
	return r.Middleware(entry)
}

// SignatureParameters extracts the parameter types of the route handler via
// reflection. Supported
// conditions: "type=pkg.Type" filters to the exact type and
// "subClass=pkg.Interface" filters to types carrying that interface name in
// their method receivers, mirroring the reference type/sub-class filters.
func (r *Route) SignatureParameters(conditions ...string) []reflect.StructField {
	if r.handler == nil {
		return nil
	}
	v := reflect.ValueOf(r.handler)
	if v.Kind() != reflect.Func {
		return nil
	}
	var wantType string
	var wantSubClass string
	for _, condition := range conditions {
		if name, value, ok := strings.Cut(condition, "="); ok {
			switch strings.TrimSpace(name) {
			case "type":
				wantType = strings.TrimSpace(value)
			case "subClass":
				wantSubClass = strings.TrimSpace(value)
			}
		}
	}

	t := v.Type()
	var fields []reflect.StructField
	for i := 0; i < t.NumIn(); i++ {
		pt := t.In(i)
		// Skip *Request and Context (not bindable parameters).
		if pt == reflect.TypeOf((*Request)(nil)) || pt == reflect.TypeOf(Context{}) {
			continue
		}
		if wantType != "" && pt.String() != wantType && pt.Name() != wantType {
			continue
		}
		if wantSubClass != "" && !typeImplements(pt, wantSubClass) {
			continue
		}
		fields = append(fields, reflect.StructField{
			Name: fmt.Sprintf("Param%d", i),
			Type: pt,
		})
	}
	return fields
}

// typeImplements reports whether the type's method set suggests it satisfies
// the named interface (matched by interface method names appearing in the
// type's method set).
func typeImplements(t reflect.Type, interfaceName string) bool {
	// Go reflection cannot resolve an interface type from a name string, so
	// the check matches on the type declaring the interface's shape through
	// its method set: a type name match or an exact method-set prefix match.
	for i := 0; i < t.NumMethod(); i++ {
		if strings.Contains(t.Method(i).Type.String(), interfaceName) {
			return true
		}
	}
	return strings.Contains(t.String(), interfaceName)
}

// ParentOfParameter returns the route parameter that precedes the given
// parameter in the URI (nested resource parent), or "" when none
// .
func (r *Route) ParentOfParameter(name string) string {
	names := r.ParameterNames()
	for i, n := range names {
		if n == name && i > 0 {
			return names[i-1]
		}
	}
	return ""
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
// . The last scope decision wins.
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
// while handling the request (the reference implementation: block — defaults are 10 seconds for
// both the lock and the wait).
func (r *Route) Block(lockSeconds ...int) *Route {
	lock, wait := 10, 10
	if len(lockSeconds) > 0 {
		lock = lockSeconds[0]
	}
	if len(lockSeconds) > 1 {
		wait = lockSeconds[1]
	}
	r.lockSeconds = lock
	r.waitSeconds = wait
	return r
}

// WithoutBlocking marks the route as not holding an atomic lock.
func (r *Route) WithoutBlocking() *Route {
	r.lockSeconds = 0
	r.waitSeconds = 0
	return r
}

// WithoutOverlapping marks the route as not holding an atomic lock.
// Alias for WithoutBlocking.
func (r *Route) WithoutOverlapping() *Route {
	return r.WithoutBlocking()
}

// LocksFor returns the configured lock duration in seconds.
func (r *Route) LocksFor() int {
	return r.lockSeconds
}

// WaitsFor returns the configured lock wait duration in seconds.
func (r *Route) WaitsFor() int {
	return r.waitSeconds
}

// FlushController clears the computed middleware cache and the compiled
// matcher state (the reference implementation: flushController — resets computedMiddleware and the
// controller instance; flow resolves the controller on demand).
func (r *Route) FlushController() {
	r.computedMiddleware = nil
	r.invalidateCompile()
}

// GetControllerClass returns the controller class name for a controller action
// .
func (r *Route) GetControllerClass() string {
	if r == nil {
		return ""
	}
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

// Router returns the owning router instance.
func (r *Route) Router() Router {
	return r.router
}

// GetRouter returns the owning router instance.
func (r *Route) GetRouter() Router {
	return r.router
}

// SetContainer is the the reference implementation-compatible alias for SetRouter (the router
// serves as the IoC container in flow).
func (r *Route) SetContainer(container *router) *Route {
	r.router = container
	return r
}

// OriginalParameter returns the raw (pre-mutation) route parameter value for
// the given name (the reference implementation: originalParameter — the snapshot taken at bind
// time, before middleware or the dispatcher replaced values).
func (r *Route) OriginalParameter(request *Request, name string, defaultValue ...string) string {
	if request == nil {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return ""
	}
	return request.GetOriginalRouteParam(name, defaultValue...)
}

// OriginalParameters returns the raw route parameters snapshot
// .
func (r *Route) OriginalParameters(request *Request) map[string]string {
	if request == nil {
		return map[string]string{}
	}
	return request.OriginalParams()
}

// ParametersWithoutNulls returns all route parameters, filtering out empty
// values.
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
// .
func (r *Route) SetParameter(request *Request, name string, value string) *Route {
	if request != nil {
		request.SetRouteParam(name, value)
	}
	return r
}

// SetParameterValue stores an object value for a route parameter
// . The object is kept on the
// request and consumed by the dispatcher.
func (r *Route) SetParameterValue(request *Request, name string, value any) *Route {
	if request != nil {
		request.SetRouteParamObject(name, value)
	}
	return r
}

// ForgetParameter removes a route parameter.
func (r *Route) ForgetParameter(request *Request, name string) *Route {
	if request != nil {
		request.ForgetRouteParam(name)
	}
	return r
}

// ControllerDispatcher returns the dispatcher from the owning router
// .
func (r *Route) ControllerDispatcher() ControllerDispatcher {
	if r.router != nil {
		return r.router.getControllerDispatcher()
	}
	return &controllerDispatcher{}
}

// IsSerializedClosure reports whether the handler is a closure (always false
// in Go; the reference implementation checks for SerializableClosure).
func (r *Route) IsSerializedClosure() bool {
	return false
}
