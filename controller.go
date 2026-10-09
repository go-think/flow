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

// Controller is the embeddable base controller. Controllers embed it and
// register middleware imperatively in their constructor, with fluent
// only/except filters:
//
//	type UserController struct{ flow.Controller }
//
//	func NewUserController() *UserController {
//	    c := &UserController{}
//	    c.Middleware("auth").Only("Show")
//	    c.Middleware("throttle:60,1").Except("Index")
//	    return c
//	}
//
// The middleware field holds the registered entries; GetMiddleware is its
// accessor. A string middleware (alias, "alias:params" or group name) is kept
// raw and resolved through the router's alias/group tables at gather time,
// exactly like route-level middleware strings; any other value is used as the
// middleware itself.
type Controller struct {
	middleware []*ControllerMiddlewareEntry
}

// ControllerMiddlewareForm is the compile-time union of middleware forms a
// controller can declare through Controller.Middleware:
//
//   - string — a middleware alias ("auth"), a parameterized alias
//     ("role:admin") or a middleware group name, resolved through the
//     router's alias/group tables at gather time
//   - Middleware or func(*Request, Closure) any — a middleware function:
//     the named Middleware type, a bare closure literal, or a Handler's
//     Process method value (which carries the unnamed function type)
//   - a same-form slice of either — one entry per member
//   - []ControllerMiddleware — a heterogeneous list, e.g.
//     []ControllerMiddleware{Middleware(fn), MiddlewareString("auth")}
//
// The union enumerates the exact concrete types middlewareList handles, so the
// compile-time contract and the runtime normalization cannot diverge. A named
// function or string type (HandlerFunc, an application alias) requires an
// explicit conversion to Middleware or string at the call site. The constraint
// may appear only as a bare union term (ControllerMiddlewareItem below) or as a
// type-parameter constraint.
type ControllerMiddlewareForm interface {
	ControllerMiddlewareItem | []string | []Middleware | []func(*Request, Closure) any |
		[]ControllerMiddleware
}

// ControllerMiddlewareItem is the single-member form of the union: a string
// alias/group name, the named Middleware type, or a bare/unnamed function
// literal of the Middleware signature.
type ControllerMiddlewareItem interface {
	string | Middleware | func(*Request, Closure) any
}

// ControllerMiddleware is the sealed runtime storage box for one middleware
// declared through Controller.Middleware: a MiddlewareString (alias,
// parameterized alias or group name) or a Middleware function. Only those two
// types implement it — the unexported isControllerMiddleware method seals the
// set — so the middleware slice can never hold an arbitrary value. The
// compile-time union of accepted input forms is ControllerMiddlewareForm,
// enforced at the Middleware method signature; this interface is the runtime
// half of that contract.
type ControllerMiddleware interface {
	isControllerMiddleware()
}

// MiddlewareString wraps a string middleware (alias, "alias:params" or group
// name) so it satisfies the sealed ControllerMiddleware storage interface.
// It is unwrapped back to a plain string at the controller-route boundary
// (controllerMiddlewareToRaw), so router-side alias/group resolution is
// unchanged. It is exported so controllers outside the package can build the
// entries HasMiddleware returns.
type MiddlewareString string

// isControllerMiddleware seals MiddlewareString into the storage set.
func (MiddlewareString) isControllerMiddleware() {}

// String returns the wrapped alias/group name.
func (s MiddlewareString) String() string { return string(s) }

// isControllerMiddleware seals Middleware into the storage set, so a
// callable middleware is stored as itself, without wrapping.
func (Middleware) isControllerMiddleware() {}

// ControllerMiddlewareEntry is one middleware registered on a controller
// together with its only/except options. Entries of the same Middleware call
// share one options pointer.
type ControllerMiddlewareEntry struct {
	Middleware ControllerMiddleware
	Options    *ControllerMiddlewareOptions
}

// ControllerMiddlewareOptions provides fluent only/except filters for a
// controller middleware entry. The pointer returned by Controller.Middleware
// targets the stored entry, so chained calls mutate the registration in place.
type ControllerMiddlewareOptions struct {
	OnlyMethods   []string
	ExceptMethods []string
}

// ControllerMiddlewareMethodForm is the compile-time union of the method-list
// forms accepted by Only and Except: one string names a single method, a
// []string names several. A single call takes one form, not both.
type ControllerMiddlewareMethodForm interface {
	string | []string
}

// controllerMiddlewareMethodList flattens the forms of
// ControllerMiddlewareMethodForm into a []string.
func controllerMiddlewareMethodList[T ControllerMiddlewareMethodForm](methods []T) []string {
	var out []string
	for _, m := range methods {
		switch v := any(m).(type) {
		case string:
			out = append(out, v)
		case []string:
			out = append(out, v...)
		}
	}
	return out
}

// Only limits the middleware to the given methods, passed either as one name
// per argument or as a []string; the OR combination with Except is resolved in
// MethodExcludedByOptions.
func (o *ControllerMiddlewareOptions) Only[T ControllerMiddlewareMethodForm](methods ...T) *ControllerMiddlewareOptions {
	o.OnlyMethods = controllerMiddlewareMethodList(methods)
	return o
}

// Except excludes the given methods from the middleware, passed either as one
// name per argument or as a []string.
func (o *ControllerMiddlewareOptions) Except[T ControllerMiddlewareMethodForm](methods ...T) *ControllerMiddlewareOptions {
	o.ExceptMethods = controllerMiddlewareMethodList(methods)
	return o
}

// Middleware registers middleware on the controller. The ControllerMiddlewareForm
// type parameter accepts a single entry or a list (compile-time checked), the
// optional options value seeds the only/except filters, and the returned pointer
// is shared by every entry of this call, so chained Only/Except calls mutate them
// all.
//
// A string middleware (alias, "alias:params" or group name) is resolved
// through the router's alias/group tables at gather time; any other value is
// used as the middleware itself. A Handler is passed as its Process method
// value (see ControllerMiddlewareForm).
func (c *Controller) Middleware[T ControllerMiddlewareForm](middleware T, options ...ControllerMiddlewareOptions) *ControllerMiddlewareOptions {
	shared := &ControllerMiddlewareOptions{}
	if len(options) > 0 {
		*shared = options[0]
	}
	for _, m := range middlewareList(middleware) {
		c.middleware = append(c.middleware, &ControllerMiddlewareEntry{Middleware: m, Options: shared})
	}
	return shared
}

// middlewareList normalizes the middleware argument of Controller.Middleware
// (the ControllerMiddlewareForm union, compile-time checked through the type
// parameter) into sealed ControllerMiddleware values: a slice registers one
// entry per member, any other value registers a single entry. The switch
// enumerates exactly the union's concrete types, so every form the compiler
// admits has a case.
func middlewareList[T ControllerMiddlewareForm](middleware T) []ControllerMiddleware {
	switch v := any(middleware).(type) {
	case string:
		return []ControllerMiddleware{MiddlewareString(v)}
	case Middleware:
		return []ControllerMiddleware{v}
	case func(*Request, Closure) any:
		return []ControllerMiddleware{Middleware(v)}
	case []string:
		out := make([]ControllerMiddleware, len(v))
		for i, s := range v {
			out[i] = MiddlewareString(s)
		}
		return out
	case []Middleware:
		out := make([]ControllerMiddleware, len(v))
		for i, m := range v {
			out[i] = m
		}
		return out
	case []func(*Request, Closure) any:
		out := make([]ControllerMiddleware, len(v))
		for i, m := range v {
			out[i] = Middleware(m)
		}
		return out
	case []ControllerMiddleware:
		return v
	default:
		// Unreachable: ControllerMiddlewareForm admits exactly the cases above.
		panic(fmt.Sprintf("flow: unsupported controller middleware form %T", middleware))
	}
}

// GetMiddleware returns the middleware entries registered on the controller.
func (c *Controller) GetMiddleware() []*ControllerMiddlewareEntry {
	return c.middleware
}

// MethodExcludedByOptions reports whether the given only/except options exclude
// the action method: excluded when Only is set and the method is absent, or
// Except is set and the method is listed; both filters may be present at once.
// Callers that need the apply polarity negate the result.
func MethodExcludedByOptions(method string, options *ControllerMiddlewareOptions) bool {
	if len(options.OnlyMethods) > 0 && !containsString(options.OnlyMethods, method) {
		return true
	}
	if len(options.ExceptMethods) > 0 && containsString(options.ExceptMethods, method) {
		return true
	}
	return false
}

// ControllerDispatcher dispatches a controller method with dependency
// injection (route parameters first, container dependencies by type).
type ControllerDispatcher interface {
	// Dispatch resolves the controller (a registered name is looked up in the
	// router registry), binds the method arguments and calls it. request carries
	// the per-request state; the route parameters are recovered from it inside.
	Dispatch(route *Route, controller any, method string, request *Request) (any, error)
	// GetMiddleware returns the middleware declared by the controller for the
	// given method, in its sealed storage form.
	GetMiddleware(controller any, method string) []ControllerMiddleware
}

// controllerDispatcher is the default ControllerDispatcher implementation.
type controllerDispatcher struct {
	router *router
}

// CallActionController is the optional dispatch hook: when a controller
// implements it, Dispatch resolves the method arguments first and hands them to
// CallAction instead of invoking the method directly. Implementations may use
// the hook to intercept every action call.
type CallActionController interface {
	// CallAction receives the action method name and the arguments resolved
	// for that method's signature.
	CallAction(method string, parameters []reflect.Value) (any, error)
}

// HasMiddleware is the controller capability for declaring middleware without
// embedding the Controller base: a controller that implements this interface
// declares its middleware here, and the dispatcher prefers that declaration
// over the base GetMiddleware accessor.
//
// A controller embedding the Controller base already gets middleware support and
// should not implement this interface: a method named Middleware on the outer
// type would shadow the base's generic Middleware registration method.
type HasMiddleware interface {
	// Middleware returns the controller middleware entries, each optionally
	// carrying only/except options.
	Middleware() []*ControllerMiddlewareEntry
}

// Dispatch resolves and invokes the controller method. It resolves the
// controller instance, binds the method arguments, and either hands them to a
// CallActionController's CallAction or invokes the reflected method directly.
// The reflected method is validated up front; reflect's call would otherwise
// panic on a missing method.
func (d *controllerDispatcher) Dispatch(route *Route, controller any, method string, request *Request) (any, error) {
	instance, err := d.resolveController(controller)
	if err != nil {
		return nil, err
	}

	parameters, reflected, err := d.resolveParameters(route, instance, method, request)
	if err != nil {
		return nil, err
	}

	if ca, ok := instance.(CallActionController); ok {
		return ca.CallAction(method, parameters)
	}

	out := reflected.Call(parameters)
	if len(out) > 0 {
		return out[0].Interface(), nil
	}
	return nil, nil
}

// resolveParameters resolves the controller method's parameters (route
// parameters, the request value, model bindings and container dependencies)
// before the action is dispatched. request carries the per-request state; the
// route parameters are recovered from it. The reflected method value is
// returned alongside so Dispatch can invoke it.
func (d *controllerDispatcher) resolveParameters(route *Route, controller any, method string, request *Request) ([]reflect.Value, reflect.Value, error) {
	m := reflect.ValueOf(controller).MethodByName(method)
	if !m.IsValid() {
		return nil, reflect.Value{}, fmt.Errorf("flow: controller [%T] has no method [%s]", controller, method)
	}
	return route.parseParams(m, request, route.boundParameters(request)), m, nil
}

// resolveController turns a name into the registered controller instance;
// literal instances pass through. A dispatcher built without a router serves
// literal instances only.
func (d *controllerDispatcher) resolveController(controller any) (any, error) {
	if _, ok := controller.(string); !ok {
		return controller, nil
	}
	if d.router == nil {
		return nil, fmt.Errorf("flow: controller [%s] cannot be resolved without a router", controller)
	}
	return d.router.resolveController(controller)
}

// GetMiddleware returns the middleware the controller declares for a method, in
// its sealed storage form. A controller implementing HasMiddleware takes
// precedence over the embedded Controller base's GetMiddleware accessor. The
// only/except filters are applied.
func (d *controllerDispatcher) GetMiddleware(controller any, method string) []ControllerMiddleware {
	if hm, ok := controller.(HasMiddleware); ok {
		return controllerMiddlewareForMethod(hm.Middleware(), method)
	}
	c, ok := controller.(interface {
		GetMiddleware() []*ControllerMiddlewareEntry
	})
	if !ok {
		return nil
	}
	return controllerMiddlewareForMethod(c.GetMiddleware(), method)
}

// controllerMiddlewareForMethod applies the only/except filters of each entry to
// the action method and returns the surviving entries.
func controllerMiddlewareForMethod(entries []*ControllerMiddlewareEntry, method string) []ControllerMiddleware {
	var out []ControllerMiddleware
	for _, entry := range entries {
		if entry == nil || entry.Options == nil {
			out = append(out, entryMiddlewareValue(entry))
			continue
		}
		if !MethodExcludedByOptions(method, entry.Options) {
			out = append(out, entry.Middleware)
		}
	}
	return out
}

// controllerMiddlewareToRawList unwraps a sealed middleware list into the raw
// values the route middleware pipeline consumes.
func controllerMiddlewareToRawList(list []ControllerMiddleware) []any {
	if len(list) == 0 {
		return nil
	}
	out := make([]any, len(list))
	for i, m := range list {
		out[i] = controllerMiddlewareToRaw(m)
	}
	return out
}

// controllerMiddlewareToRaw unwraps a sealed ControllerMiddleware value back
// into the plain form the route pipeline consumes: MiddlewareString becomes
// a plain string (so the router's alias/group resolution is unchanged),
// Middleware passes through as itself. This is the single boundary where
// the sealed storage type meets the route middleware pipeline.
func controllerMiddlewareToRaw(m ControllerMiddleware) any {
	if s, ok := m.(MiddlewareString); ok {
		return string(s)
	}
	return m
}

// entryMiddlewareValue returns the middleware payload of a (possibly nil)
// entry without applying any filter.
func entryMiddlewareValue(entry *ControllerMiddlewareEntry) ControllerMiddleware {
	if entry == nil {
		return nil
	}
	return entry.Middleware
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
// Literal controller instances are checked for the default method at
// registration time.
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
// entries (the "can" alias resolves to this factory). Without an authorization
// backend the default is to deny; applications override it by aliasing "can" to
// their own factory.
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
