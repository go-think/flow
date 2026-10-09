package flow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Router defines the interface for the routing system.
type Router interface {
	// Get registers a GET route.
	Get(pattern string, handler interface{}) Router
	// Post registers a POST route.
	Post(pattern string, handler interface{}) Router
	// Put registers a PUT route.
	Put(pattern string, handler interface{}) Router
	// Patch registers a PATCH route.
	Patch(pattern string, handler interface{}) Router
	// Delete registers a DELETE route.
	Delete(pattern string, handler interface{}) Router
	// Options registers an OPTIONS route.
	Options(pattern string, handler interface{}) Router
	// Query registers a QUERY route (the reference implementation query).
	Query(pattern string, handler interface{}) Router
	// Any registers a route responding to all standard verbs.
	Any(pattern string, handler interface{}) Router
	// Fallback registers a fallback route: a real route on GET/HEAD that
	// only matches when nothing else does.
	Fallback(handler interface{}) Router
	// Redirect registers a redirect route to a destination on every verb.
	Redirect(uri, destination string, status ...int) Router
	// PermanentRedirect registers a 301 redirect route on every verb.
	PermanentRedirect(uri, destination string) Router
	// View registers a route that renders a view.
	View(pattern, viewName string, data ...any) Router
	// Match registers a route responding to the specified HTTP verbs.
	Match(methods []string, pattern string, handler interface{}) Router
	// Resources bulk registers resource controllers.
	Resources(resources map[string]any, options ...ResourceOption)
	// Resource registers a resource controller with the conventional seven
	// actions; the returned builder defers registration for customization.
	Resource(name string, controller any, options ...ResourceOption) *PendingResourceRegistration
	// APIResources bulk registers API resource controllers.
	APIResources(resources map[string]any, options ...ResourceOption)
	// APIResource registers a resource without Create/Edit actions.
	APIResource(name string, controller any, options ...ResourceOption) *PendingResourceRegistration
	// Singletons bulk registers singleton resource controllers.
	Singletons(singletons map[string]any, options ...ResourceOption)
	// Singleton registers a singleton resource (no id parameter).
	Singleton(name string, controller any, options ...ResourceOption) *PendingResourceRegistration
	// APISingletons bulk registers API singleton resource controllers.
	APISingletons(singletons map[string]any, options ...ResourceOption)
	// APISingleton registers an API singleton resource.
	APISingleton(name string, controller any, options ...ResourceOption) *PendingResourceRegistration
	// Group creates a route group; the first argument, when present, is a
	// GroupAttributes value whose prefix, name, controller namespace,
	// middleware, where constraints, domain and metadata are merged into
	// every route registered inside the callback.
	Group(args ...any)
	// Add registers a new route.
	Add(method []string, pattern string, handler interface{}) Router
	// Dispatch resolves the request (flow *Request or raw *http.Request) to a
	// handler and executes it, returning the response.
	Dispatch(request any) *Response
	// OnRouteMatched registers a callback fired after a route is matched.
	OnRouteMatched(callback func(route *Route, request *Request))
	// AliasMiddleware registers a route-specific middleware alias.
	AliasMiddleware(name string, middleware interface{}) Router
	// HasMiddlewareGroup determines if a middleware group with the name exists.
	HasMiddlewareGroup(name string) bool
	// GetMiddlewareGroup retrieves a registered middleware group.
	GetMiddlewareGroup(name string) []interface{}
	// GetMiddlewareGroups returns every registered middleware group
	//.
	GetMiddlewareGroups() map[string][]interface{}
	// MiddlewareGroup defines a named middleware group.
	MiddlewareGroup(name string, middlewares ...interface{}) Router
	// PrependMiddlewareToGroup prepends middleware to an existing group.
	PrependMiddlewareToGroup(name string, middleware interface{})
	// PushMiddlewareToGroup appends middleware to an existing group.
	PushMiddlewareToGroup(name string, middleware interface{})
	// RemoveMiddlewareFromGroup removes middleware from an existing group.
	RemoveMiddlewareFromGroup(name string, middleware interface{})
	// FlushMiddlewareGroups clears all middleware groups.
	FlushMiddlewareGroups()
	// Bind registers an explicit binder for a route parameter name.
	Bind(key string, binder Binder)
	// Pattern sets a global regex pattern for a parameter.
	Pattern(name string, expression string)
	// CurrentRequest returns the request of the most recent dispatch.
	CurrentRequest() *Request

	// CurrentRoute returns the route matched by the most recent dispatch.
	CurrentRoute() *Route
	// Has determines if the route collection contains a given named route.
	Has(name string) bool
	// HasAll determines if ALL the given named routes exist
	//).
	HasAll(names ...string) bool
	// NamedRouteDomain returns the domain template of a named route, enabling
	// UrlGenerator domain-route URL generation.
	NamedRouteDomain(name string) (domain string, ok bool)
	// CurrentRouteName returns the current route name for the request.
	CurrentRouteName(req *Request) string
	// CurrentRouteNamed determines if the current route matches the name
	// patterns.
	CurrentRouteNamed(req *Request, patterns ...string) bool
	// CurrentRouteAction returns the action identifier of the current route
	//.
	CurrentRouteAction(req *Request) string
	// CurrentRouteUses determines if the current route is served by the given
	// action.
	CurrentRouteUses(req *Request, action string) bool
	// Is determines if the current route's name matches given patterns.
	Is(req *Request, patterns ...string) bool
	// GetRoutes returns every registered route.
	GetRoutes() []*Route
	// Routes exposes the route collection. After RestoreCompiled the returned
	// RouteCollectionInterface is a *CompiledRouteCollection; otherwise it is
	// the live *RouteCollection.
	Routes() RouteCollectionInterface
	// RestoreCompiled replaces the route collection with routes deserialized
	// from a previous Compile.
	RestoreCompiled(data []byte) error
	// SetSignatureKey sets the secret HMAC key for signed URLs.
	SetSignatureKey(key string)
	// SetParameterResolver sets the dependency resolver for handler params.
	SetParameterResolver(resolver ParameterResolver)
	// SetEventDispatcher registers a dispatcher to receive routing lifecycle events
	//.
	SetEventDispatcher(dispatcher EventDispatcher) Router
	// GetEventDispatcher returns the registered event dispatcher.
	GetEventDispatcher() EventDispatcher
	// Compile serializes routes with string-serializable actions
	// (ControllerAction) for caching. Routes registered with closures cannot
	// be cached and make Compile return an error.
	Compile() ([]byte, error)
	// FlushPending materializes deferred resource registrations.
	FlushPending()
	// NamedRoutePattern returns the raw path pattern of a named route (e.g.
	// "/users/{id}"). ok is false when no route carries the name.
	NamedRoutePattern(name string) (pattern string, ok bool)

	// OnRouting registers a callback fired before a request is matched.
	OnRouting(callback func(request *Request))
	// OnPreparingResponse registers a callback fired before the response is built.
	OnPreparingResponse(callback func(request *Request, result any))
	// OnResponsePrepared registers a callback fired after the response is built.
	OnResponsePrepared(callback func(request *Request, response *Response))
	// DisableMiddleware disables (or re-enables) all route middleware.
	DisableMiddleware(disable bool)
	// RegisterController registers a controller instance under a name so
	// string actions ("Name@Method") can reference it.
	RegisterController(name string, controller any)
	// SetControllerDispatcher replaces the controller dispatcher.
	SetControllerDispatcher(dispatcher ControllerDispatcher)
	// MiddlewarePriority sets the middleware priority order.
	MiddlewarePriority(middlewares ...interface{})
	// Head registers a HEAD route.
	Head(pattern string, handler interface{}) Router
	// Static registers static file serving under the given path prefix.
	Static(path, root string)
	// Prefix adds a prefix to the current route group.
	Prefix(prefix string) Router
	// Domain restricts routes to a specific host pattern (supports dynamic {param} subdomains).
	Domain(domain string) Router
	// Middleware adds middleware to the current route or group.
	Middleware(middlewares ...interface{}) Router
	// WithoutMiddleware excludes middlewares from the current route or group.
	WithoutMiddleware(middlewares ...interface{}) Router
	// Controller sets the controller instance or name for subsequent route registrations or groups.
	Controller(controller any) Router
	// Metadata sets route or group metadata.
	Metadata(key string, value any) Router
	// ScopeBindings enforces scoped implicit bindings on the current route or
	// group.
	ScopeBindings() Router
	// WithoutScopedBindings disables scoped implicit bindings on the current route or group.
	WithoutScopedBindings() Router
	// WithTrashed allows soft-deleted entities in the route bindings
	//.
	WithTrashed() Router
	// Missing registers a fallback invoked when a bound parameter of the
	// route cannot be resolved (defaults to a 404 response). Accepts
	// func(Context) Response or func(*Request, error) any.
	Missing(callback any) Router
	// Name names the route.
	Name(name string) Router
	// Url generates a URL for a named route.
	Url(name string, params map[string]string) string
	// Where adds a regex constraint to a route parameter.
	Where(name string, expression string) Router
	// WhereMap adds multiple regex constraints to route parameters.
	WhereMap(wheres map[string]string) Router
	// Registrar returns a new RouteRegistrar bound to this router.
	Registrar() *RouteRegistrar
	// SetExceptionHandler registers a pipeline exception handler.
	SetExceptionHandler(handler ExceptionHandler) Router
	// GetExceptionHandler returns the pipeline exception handler.
	GetExceptionHandler() ExceptionHandler
	// Can applies the "can" authorization middleware with the given ability
	// and models.
	Can(ability string, models ...any) Router
	// WhereNumber adds a numeric regex constraint to parameters.
	WhereNumber(names ...string) Router
	// WhereAlpha adds an alphabetic regex constraint to parameters.
	WhereAlpha(names ...string) Router
	// WhereAlphaNumeric adds an alphanumeric regex constraint to parameters.
	WhereAlphaNumeric(names ...string) Router
	// WhereUuid adds a UUID regex constraint to parameters.
	WhereUuid(names ...string) Router
	// WhereUlid adds a ULID regex constraint to parameters.
	WhereUlid(names ...string) Router
	// WhereIn adds an allowed values constraint to a parameter.
	WhereIn(name string, allowed []string) Router
	// Register compiles and indexes the collected routes.
	Register()
	// Dump returns a byte slice dump of all registered routes.
	Dump() []byte

	// SignedUrl creates a signed URL for a named route.
	SignedUrl(name string, expiration time.Duration, params map[string]string) string
	// HasValidSignature determines if the request has a valid signature.
	HasValidSignature(req *Request) bool
	// GetRouteMiddleware retrieves a registered middleware alias.
	GetRouteMiddleware(name string) interface{}
	// DispatchToRoute dispatches a request to a matching route and runs it
	//)).
	DispatchToRoute(request *Request) *Response
	// SubstituteBindings resolves the explicit bindings of a route.
	SubstituteBindings(route *Route, request *Request, params []*parameter) map[string]any
	// SubstituteImplicitBindings resolves implicit model bindings.
	SubstituteImplicitBindings(route *Route, request *Request, params []*parameter) map[string]any
	// MatchRequest resolves a request to a route and binds its parameters.
	MatchRequest(request *Request) (*Route, error)
	// Model binds a route parameter to a model instance
	//.
	Model(key string, model any, callback ...func(val string) (any, error)) Router
	// SoftDeletableResources bulk-registers resources with WithTrashed enabled
	//.
	SoftDeletableResources(resources map[string]any, options ...ResourceOption)
	// GetResourceParameters returns the global resource parameter mapping
	//.
	GetResourceParameters() map[string]string
	// GetResourceVerbs returns the global resource verb overrides
	//.
	GetResourceVerbs() map[string]string
	// Patterns registers a batch of global regular expression patterns on route parameters
	//.
	Patterns(patterns map[string]string) Router
	// GetMiddlewarePriority returns the configured middleware priority list.
	GetMiddlewarePriority() []any
	// As is an alias for Name.
	As(name string) Router
	// Default sets a default parameter value on the current route or group.
	Default(key string, value any) Router
	// Defaults sets multiple default parameter values on the current route or group.
	Defaults(defaults map[string]any) Router
	// HasGroupStack reports whether the router is currently within a route group.
	HasGroupStack() bool
	// GetGroupStack returns the stack of group attributes from outer to inner.
	GetGroupStack() []GroupAttributes
	// SetCallableDispatcher replaces the callable/closure dispatcher.
	SetCallableDispatcher(dispatcher CallableDispatcher)
	// GetCallableDispatcher returns the callable/closure dispatcher.
	GetCallableDispatcher() CallableDispatcher
	// RouteList returns structured summaries for all registered routes.
	RouteList() []RouteSummary
	// FormatRouteList generates a clean human-readable table of all routes.
	FormatRouteList() string
	// SingularResourceParameters sets whether resource route parameters default to singular form.
	SingularResourceParameters(singular ...bool)
	// SetResourceParameters sets the global resource parameter mapping.
	SetResourceParameters(params map[string]string)
	// SetResourceVerbs sets the global resource verb overrides.
	SetResourceVerbs(verbs map[string]string)
	// RespondWithRoute dispatches the request to a route resolved by its name.
	RespondWithRoute(name string, request *Request) *Response
	// SubstituteImplicitBindingsUsing replaces the implicit binding resolution logic.
	SubstituteImplicitBindingsUsing(fn func(route *Route, key, value string) any)
	// Terminate calls Terminate on all terminable middlewares for the request.
	Terminate(request *Request, response any)
}

// GroupAttributes carries the attributes merged into every route registered
// inside a group.
type GroupAttributes struct {
	Prefix            string
	Name              string
	Domain            string
	Controller        string
	Middleware        []interface{}
	Wheres            map[string]string
	Defaults          map[string]any
	Metadata          map[string]any
	WithoutMiddleware []interface{}
	ScopeBindings     bool
	WithTrashed       bool
}

// verbs is the standard HTTP verb list (the reference Router::$verbs),
// including the QUERY verb; checkForAlternateVerbs probes it and Any
// registers against it.
var verbs = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "QUERY"}

type RouteRequest interface {
	GetMethod() string
	GetPath() string
}

// ParameterResolver defines the interface to resolve route handler parameters by type.
type ParameterResolver interface {
	ResolveParameter(paramType reflect.Type, request *Request) (reflect.Value, bool)
}

// ParameterResolverFunc is an adapter to allow the use of ordinary functions as ParameterResolver.
type ParameterResolverFunc func(paramType reflect.Type, request *Request) (reflect.Value, bool)

// ResolveParameter calls f(paramType, request).
func (f ParameterResolverFunc) ResolveParameter(paramType reflect.Type, request *Request) (reflect.Value, bool) {
	return f(paramType, request)
}

// router is the built-in Router implementation. The same type serves as the
// root router and as the group/pending registration nodes; at Register time
// the pending nodes are expanded into Route entities inside the collection.
type router struct {
	inited bool

	method                  []string
	prefix                  string
	pattern                 string
	handler                 interface{}
	middlewares             []interface{}
	withoutMiddleware       []interface{}
	group                   *router
	controllerPrefix        string
	name                    string
	wheres                  map[string]string
	groupWheres             map[string]string
	defaults                map[string]any
	groupDefaults           map[string]any
	groupMetadata           map[string]any
	domain                  string
	patterns                map[string]string
	signatureKey            string
	middlewareAliases       map[string]interface{}
	middlewareGroups        map[string][]interface{}
	middlewarePriority      []interface{}
	parameterResolver       ParameterResolver
	binders                 map[string]Binder
	pending                 []*PendingResourceRegistration
	registered              bool
	autoRegister            bool
	resourceSingular        bool
	resourceParams          map[string]string
	resourceVerbsMap        map[string]string
	implicitBindingResolver func(route *Route, key, value string) any
	scopedBindings          bool
	scopedDisabled          bool
	withTrashed             bool
	missing                 func(request *Request, err error) any
	bindingFields           map[string]string
	isFallback              bool
	canEntries              []canEntry

	collects []*router

	collection           RouteCollectionInterface
	currentRoute         *Route
	currentRequest       *Request
	currentMu            sync.RWMutex
	disableMiddleware    bool
	controllers          map[string]any
	controllerDispatcher ControllerDispatcher
	callableDispatcher   CallableDispatcher
	container            Container
	events               EventDispatcher
	exceptionHandler     ExceptionHandler
	groupStack           []GroupAttributes
	groupStackMu         sync.RWMutex

	onRouting           []func(request *Request)
	onRouteMatched      []func(route *Route, request *Request)
	onPreparingResponse []func(request *Request, result any)
	onResponsePrepared  []func(request *Request, response *Response)
}

// Container is the IoC container contract used by the Router
// .
type Container interface {
	Make(key string) any
	Bound(key string) bool
	Instance(key string, instance any)
}

// New creates a new Router. Matches the reference constructor:

//	NewRouter(events, container)

// Events is the request-scoped event dispatcher (may be nil).
// Container is the IoC container (may be nil).
func New(events EventDispatcher, container Container) Router {
	rt := &router{
		collection:        NewRouteCollection(),
		patterns:          make(map[string]string),
		wheres:            make(map[string]string),
		middlewareAliases: make(map[string]interface{}),
		middlewareGroups:  make(map[string][]interface{}),
		controllers:       make(map[string]any),
		container:         container,
		resourceSingular:  true,
	}
	// the reference framework maps the "can" middleware alias; the default gate
	// denies every ability unless the application overrides the alias.
	rt.middlewareAliases["can"] = ParameterizedMiddleware(canMiddlewareFactory)
	rt.events = events
	return rt
}

// Dispatch resolves the request to a route and executes it. The dispatch chain
// mirrors the reference implementation: dispatch → (Routing event) → findRoute → runRoute →
// runRouteWithinStack → Pipeline. A miss produces the the reference implementation 404 response; a
// verb mismatch produces the MethodNotAllowed response with an Allow header;
// OPTIONS requests get the automatic 200 + Allow route.
func (r *router) Dispatch(request any) *Response {
	root := r.root()
	root.flushPending()
	// Materialize deferred verb routes so dispatch works without an explicit
	// Register call.
	if !root.registered {
		root.register(root)
		root.registered = true
	}
	var req *Request
	switch v := request.(type) {
	case *Request:
		req = v
	case *http.Request:
		req = NewRequest(v)
	default:
		return NotFoundResponse()
	}
	root.currentMu.Lock()
	root.currentRequest = req
	root.currentMu.Unlock()

	route, err := root.findRoute(req)
	if err != nil {
		var notAllowed *MethodNotAllowedError
		if errors.As(err, &notAllowed) {
			res := NewResponse().SetCode(http.StatusMethodNotAllowed)
			res.Header("Allow", strings.Join(notAllowed.Allowed, ", "))
			res.SetContent(notAllowed.Message)
			return res
		}
		var notFound *NotFoundError
		if errors.As(err, &notFound) {
			res := NotFoundResponse()
			res.SetContent(notFound.Message)
			return res
		}
		return NotFoundResponse()
	}

	return root.runRoute(req, route)
}

// findRoute resolves the request to a Route entity, records it as the current
// route and binds its parameters onto the request (the reference implementation: findRoute — fires the Routing event
// and binds the route into the container).
func (r *router) findRoute(request *Request) (*Route, error) {
	// the reference implementation fires the Routing event before matching.
	for _, callback := range r.onRouting {
		callback(request)
	}
	if r.events != nil {
		r.events.Dispatch("flow.routing", request)
	}

	route, err := r.collection.Match(request)
	if err != nil {
		return nil, err
	}

	request.SetRoute(route)
	if route.name != "" {
		request.Set("_route_name", route.name)
	}
	r.currentMu.Lock()
	r.currentRoute = route
	r.currentMu.Unlock()

	// Bind the matched route into the container).
	if r.container != nil {
		r.container.Instance("route", route)
	}
	return route, nil
}

// runRoute fires the matched callbacks and runs the route within its
// middleware stack (the reference implementation: runRoute — setRouteResolver, RouteMatched event,
// prepareResponse of runRouteWithinStack).
func (r *router) runRoute(request *Request, route *Route) (result *Response) {
	for _, callback := range r.onRouteMatched {
		callback(route, request)
	}
	if r.events != nil {
		r.events.Dispatch("flow.route.matched", &RouteMatchedEvent{Route: route, Request: request})
	}

	defer func() {
		if rec := recover(); rec != nil {
			if modelErr, ok := rec.(*ModelNotFoundError); ok {
				if route != nil && route.GetMissing() != nil {
					result = r.prepareResponse(request, route.GetMissing()(request, modelErr))
					return
				}
				result = NotFoundResponse()
				return
			}
			panic(rec)
		}
	}()

	// Check middleware.disable in container.
	if r.container != nil && r.container.Bound("middleware.disable") {
		if v := r.container.Make("middleware.disable"); v != nil {
			if disabled, ok := v.(bool); ok && disabled {
				return r.prepareResponse(request, route.Run(request))
			}
		}
	}

	if r.disableMiddleware {
		return r.prepareResponse(request, route.Run(request))
	}

	out := r.runRouteWithinStack(route, request)
	// The pipeline destination already prepared the response (middlewares
	// observe a *Response on the way out); avoid re-preparing and firing the
	// response events twice.
	if res, ok := out.(*Response); ok {
		return res
	}
	return r.prepareResponse(request, out)
}

// runRouteWithinStack gathers the route middleware (resolved, sorted,
// excluding route-level exclusions) and runs the action inside the onion. The
// response is prepared inside the pipeline destination so that middlewares
// always observe a *Response on the way out.
func (r *router) runRouteWithinStack(route *Route, request *Request) any {
	pipeline := NewPipeline()
	root := r.root()
	if root.exceptionHandler != nil {
		pipeline.WithExceptionHandler(root.exceptionHandler)
	} else if root.container != nil && root.container.Bound("ExceptionHandler") {
		if eh, ok := root.container.Make("ExceptionHandler").(ExceptionHandler); ok {
			pipeline.WithExceptionHandler(eh)
		}
	}

	rawMiddlewares, resolved := r.gatherRouteMiddlewareWithRaw(route)
	for _, md := range resolved {
		pipeline.Pipe(HandlerFunc(md))
	}
	request.SetRouteMiddlewares(rawMiddlewares)

	return pipeline.Send(request).Then(func(req *Request) (res any) {
		defer func() {
			if rec := recover(); rec != nil {
				if modelErr, ok := rec.(*ModelNotFoundError); ok {
					if route != nil && route.GetMissing() != nil {
						res = r.prepareResponse(req, route.GetMissing()(req, modelErr))
						return
					}
					res = NotFoundResponse()
					return
				}
				panic(rec)
			}
		}()
		return r.prepareResponse(req, route.Run(req))
	})
}

// gatherRouteMiddleware collects the middleware of the route following
// the reference order: resolve the raw entries (aliases and groups expand) first,
// then remove the excluded ones — the excluded list itself is expanded through
// the alias/group tables first — and finally
// order the result by the priority list.
func (r *router) gatherRouteMiddleware(route *Route) []Middleware {
	_, out := r.gatherRouteMiddlewareWithRaw(route)
	return out
}

func (r *router) gatherRouteMiddlewareWithRaw(route *Route) ([]any, []Middleware) {
	// the reference implementation maps the excluded entries through MiddlewareNameResolver so a
	// group name excludes its concrete members.
	var excluded []any
	for _, e := range route.ExcludedMiddleware() {
		excluded = append(excluded, expandRawMiddlewareEntry(e, r)...)
	}

	var kept []any
	for _, m := range route.GatherMiddleware() {
		if isExcludedExpanded(m, excluded, r) {
			continue
		}
		kept = append(kept, m)
	}

	// the reference implementation resolves (expands groups and aliases) BEFORE priority sorting
	// (), so each concrete member is ranked individually
	// rather than the raw entry as a whole.
	resolvedRaw := make([]any, 0, len(kept))
	for _, m := range kept {
		resolvedRaw = append(resolvedRaw, resolveRawMiddlewareEntries(m, r)...)
	}

	// Sort by priority.
	sorted := sortMiddlewareRanked(r.middlewarePriority, resolvedRaw, nil)

	var out []Middleware
	for _, m := range sorted {
		out = append(out, resolveMiddleware(m, r)...)
	}
	return sorted, out
}

// resolveRawMiddlewareEntries expands one raw entry into its concrete raw
// entries: groups flatten into members, aliases are replaced by their target
// (with ":params" re-appended for string targets). Unlike
// expandRawMiddlewareEntry — which keeps the alias name for exclusion matching
// — this returns only what the reference would
// put into the pipeline.
func resolveRawMiddlewareEntries(m any, r *router) []any {
	name, isStr := m.(string)
	if !isStr {
		return []any{m}
	}
	if group := r.GetMiddlewareGroup(name); group != nil {
		var out []any
		for _, gm := range group {
			if entry, isEntryStr := gm.(string); isEntryStr && entry == name {
				panic(fmt.Sprintf("flow: [%s] middleware group is referencing itself", name))
			}
			out = append(out, resolveRawMiddlewareEntries(gm, r)...)
		}
		return out
	}
	aliasName, params := splitAliasParams(name)
	if alias := r.GetRouteMiddleware(aliasName); alias != nil {
		if params != "" {
			if target, isTargetStr := alias.(string); isTargetStr {
				return []any{target + ":" + params}
			}
		} else {
			return []any{alias}
		}
	}
	return []any{name}
}

// expandRawMiddlewareEntry expands group references into their member entries
// and aliases into their targets, keeping parameterized entries intact for
// later resolution.
func expandRawMiddlewareEntry(m any, r *router) []any {
	name, isStr := m.(string)
	if !isStr {
		return []any{m}
	}
	if group := r.GetMiddlewareGroup(name); group != nil {
		var out []any
		for _, gm := range group {
			if entry, isEntryStr := gm.(string); isEntryStr && entry == name {
				panic(fmt.Sprintf("flow: [%s] middleware group is referencing itself", name))
			}
			out = append(out, expandRawMiddlewareEntry(gm, r)...)
		}
		return out
	}
	aliasName, _ := splitAliasParams(name)
	if alias := r.GetRouteMiddleware(aliasName); alias != nil {
		return []any{name, alias}
	}
	return []any{name}
}

// isExcludedExpanded reports whether the entry, once expanded, matches one of
// the expanded exclusions.
func isExcludedExpanded(m any, excluded []any, r *router) bool {
	for _, entry := range expandRawMiddlewareEntry(m, r) {
		for _, e := range excluded {
			if middlewareEqual(entry, e) {
				return true
			}
		}
	}
	return false
}

// Add registers a new route. The pattern is stored raw; group prefixes are
// merged at registration time (Register in deferred mode, immediately in
// immediate mode). Verbs are normalized to upper case: the reference implementation compares the
// always-upper-case request method against upper-case route methods.
func (r *router) Add(method []string, pattern string, handler interface{}) Router {
	for i, m := range method {
		method[i] = strings.ToUpper(m)
	}
	if r.autoRegister {
		entity := r.buildRouteEntity(method, pattern, handler)
		r.collection.Add(entity)
		return r.routeChainFor(entity)
	}
	route := r.initRoute()
	route.method = method
	route.pattern = pattern
	route.handler = parseControllerAction(handler)
	return route
}

// Get registers a GET route.
func (r *router) Get(pattern string, handler interface{}) Router {
	return r.Add(Method("GET", "HEAD"), pattern, handler)
}

// Head registers a HEAD route.
func (r *router) Head(pattern string, handler interface{}) Router {
	return r.Add(Method("HEAD"), pattern, handler)
}

// Post registers a POST route.
func (r *router) Post(pattern string, handler interface{}) Router {
	return r.Add(Method("POST"), pattern, handler)
}

// Put registers a PUT route.
func (r *router) Put(pattern string, handler interface{}) Router {
	return r.Add(Method("PUT"), pattern, handler)
}

// Patch registers a PATCH route.
func (r *router) Patch(pattern string, handler interface{}) Router {
	return r.Add(Method("PATCH"), pattern, handler)
}

// Delete registers a DELETE route.
func (r *router) Delete(pattern string, handler interface{}) Router {
	return r.Add(Method("DELETE"), pattern, handler)
}

// Options registers an OPTIONS route.
func (r *router) Options(pattern string, handler interface{}) Router {
	return r.Add(Method("OPTIONS"), pattern, handler)
}

// Query registers a QUERY route (the reference implementation query).
func (r *router) Query(pattern string, handler interface{}) Router {
	return r.Add(Method("QUERY"), pattern, handler)
}

// Any registers a route responding to all standard verbs.
func (r *router) Any(pattern string, handler interface{}) Router {
	return r.Add(verbs, pattern, handler)
}

// Static registers static file serving under the given path prefix.
func (r *router) Static(path, root string) {
	cleanPrefix := "/" + strings.Trim(path, "/")
	wildcardPath := cleanPrefix + "/*"

	h := NewStaticHandle(cleanPrefix, root)

	r.Get(wildcardPath, h)
	r.Head(wildcardPath, h)
}

// Statics bulk registers static file serving.
func (r *router) Statics(statics map[string]string) {
	for path, root := range statics {
		r.Static(path, root)
	}
}

// Match registers a route responding to the specified HTTP verbs.
func (r *router) Match(methods []string, pattern string, handler interface{}) Router {
	return r.Add(Method(methods...), pattern, handler)
}

// View registers a route that renders a view (the reference implementation: view —
// match(['GET','HEAD'], ViewController) with view/data/status/headers
// defaults).
func (r *router) View(pattern, viewName string, data ...any) Router {
	vc := &viewController{view: viewName, status: 200}
	if len(data) > 0 {
		vc.data = data[0]
	}
	return r.Match(Method("GET", "HEAD"), pattern, vc)
}

// Prefix adds a prefix to the current route group.
func (r *router) Prefix(prefix string) Router {
	route := r.initRoute()
	route.prefix = route.getPrefix(prefix)
	return route
}

// Domain restricts routes to a specific host pattern (supports dynamic {param} subdomains).
func (r *router) Domain(domain string) Router {
	route := r.initRoute()
	route.domain = domain
	return route
}

// Group creates a route group whose attributes are merged into the routes
// registered inside the callback: prefixes concatenate (outer first), the
// group name prefixes route names, middleware entries are appended and where
// constraints are merged.
func (r *router) Group(args ...any) {
	var attrs GroupAttributes
	var callback func(group Router)
	for _, arg := range args {
		switch v := arg.(type) {
		case GroupAttributes:
			attrs = v
		case func(group Router):
			callback = v
		case func():
			callback = func(Router) { v() }
		}
	}
	if callback == nil {
		panic("flow: Group requires a callback func(group Router)")
	}
	node := r.cloneRoute()
	if attrs.Prefix != "" {
		node.prefix = node.getPrefix(attrs.Prefix)
	}
	if attrs.Controller != "" {
		node.controllerPrefix = attrs.Controller
	}
	node.name = node.name + attrs.Name
	if attrs.Domain != "" {
		node.domain = attrs.Domain
	}
	if len(attrs.WithoutMiddleware) > 0 {
		node.withoutMiddleware = append(node.withoutMiddleware, attrs.WithoutMiddleware...)
	}
	if attrs.ScopeBindings {
		node.scopedBindings = true
	}
	if attrs.WithTrashed {
		node.withTrashed = true
	}
	// the reference → mergeMetadata merges associated
	// map values recursively instead of replacing them wholesale.
	node.groupMetadata = mergeMetadataDeep(node.groupMetadata, attrs.Metadata)
	for k, v := range attrs.Wheres {
		if node.groupWheres == nil {
			node.groupWheres = make(map[string]string)
		}
		node.groupWheres[k] = v
	}
	for k, v := range attrs.Defaults {
		if node.groupDefaults == nil {
			node.groupDefaults = make(map[string]any)
		}
		node.groupDefaults[k] = v
	}
	if len(attrs.Middleware) > 0 {
		md := make([]interface{}, 0, len(node.middlewares)+len(attrs.Middleware))
		md = append(md, node.middlewares...)
		md = append(md, attrs.Middleware...)
		node.middlewares = md
	}

	root := r.root()

	currentPrefix := r.prefix
	if attrs.Prefix != "" {
		if currentPrefix == "" {
			currentPrefix = attrs.Prefix
		} else {
			currentPrefix = path.Join("/", currentPrefix, attrs.Prefix)
		}
	}
	currentName := r.name + attrs.Name
	currentDomain := r.domain
	if attrs.Domain != "" {
		currentDomain = attrs.Domain
	}
	currentController := r.controllerPrefix
	if attrs.Controller != "" {
		currentController = attrs.Controller
	}

	var currentMiddleware []any
	currentMiddleware = append(currentMiddleware, r.middlewares...)
	currentMiddleware = append(currentMiddleware, attrs.Middleware...)

	var currentWithoutMiddleware []any
	currentWithoutMiddleware = append(currentWithoutMiddleware, r.withoutMiddleware...)
	currentWithoutMiddleware = append(currentWithoutMiddleware, attrs.WithoutMiddleware...)

	currentWheres := make(map[string]string)
	for k, v := range r.groupWheres {
		currentWheres[k] = v
	}
	for k, v := range attrs.Wheres {
		currentWheres[k] = v
	}

	currentDefaults := make(map[string]any)
	for k, v := range r.groupDefaults {
		currentDefaults[k] = v
	}
	for k, v := range attrs.Defaults {
		currentDefaults[k] = v
	}

	currentMetadata := mergeMetadataDeep(r.groupMetadata, attrs.Metadata)

	root.groupStackMu.Lock()
	if len(root.groupStack) > 0 {
		last := root.groupStack[len(root.groupStack)-1]
		if last.Prefix != "" && !strings.HasPrefix(currentPrefix, last.Prefix) {
			currentPrefix = path.Join("/", last.Prefix, currentPrefix)
		}
		if last.Name != "" && !strings.HasPrefix(currentName, last.Name) {
			currentName = last.Name + currentName
		}
		if currentDomain == "" {
			currentDomain = last.Domain
		}
		if currentController == "" {
			currentController = last.Controller
		}
	}

	groupAttr := GroupAttributes{
		Prefix:            currentPrefix,
		Name:              currentName,
		Domain:            currentDomain,
		Controller:        currentController,
		Middleware:        currentMiddleware,
		WithoutMiddleware: currentWithoutMiddleware,
		Wheres:            currentWheres,
		Defaults:          currentDefaults,
		Metadata:          currentMetadata,
		ScopeBindings:     r.scopedBindings || attrs.ScopeBindings,
		WithTrashed:       r.withTrashed || attrs.WithTrashed,
	}

	root.groupStack = append(root.groupStack, groupAttr)
	root.groupStackMu.Unlock()

	defer func() {
		root.groupStackMu.Lock()
		if len(root.groupStack) > 0 {
			root.groupStack = root.groupStack[:len(root.groupStack)-1]
		}
		root.groupStackMu.Unlock()
	}()

	callback(node)
}

// Middleware adds middleware to the current route or group.
func (r *router) Middleware(middlewares ...interface{}) Router {
	route := r.initRoute()
	route.middlewares = append(route.middlewares, middlewares...)
	return route
}

// WithoutMiddleware excludes middleware from the current route or group.
func (r *router) WithoutMiddleware(middlewares ...interface{}) Router {
	route := r.initRoute()
	route.withoutMiddleware = append(route.withoutMiddleware, middlewares...)
	return route
}

// Controller sets the controller instance or name for subsequent route registrations or groups.
func (r *router) Controller(controller any) Router {
	route := r.initRoute()
	if name, ok := controller.(string); ok {
		route.controllerPrefix = name
		return route
	}
	if controller != nil {
		val := reflect.ValueOf(controller)
		typ := val.Type()
		if typ.Kind() == reflect.Ptr {
			typ = typ.Elem()
		}
		name := typ.Name()
		r.RegisterController(name, controller)
		route.controllerPrefix = name
	}
	return route
}

// Metadata sets route or group metadata.
func (r *router) Metadata(key string, value any) Router {
	route := r.initRoute()
	if route.groupMetadata == nil {
		route.groupMetadata = make(map[string]any)
	}
	route.groupMetadata[key] = value
	return route
}

// ScopeBindings enforces scoped implicit bindings on the current route or
// group.
func (r *router) ScopeBindings() Router {
	route := r.initRoute()
	route.scopedBindings = true
	return route
}

// WithoutScopedBindings disables scoped implicit bindings on the current route or group.
func (r *router) WithoutScopedBindings() Router {
	route := r.initRoute()
	route.scopedBindings = false
	return route
}

// WithTrashed allows soft-deleted entities in the route bindings
// .
func (r *router) WithTrashed() Router {
	route := r.initRoute()
	route.withTrashed = true
	return route
}

// canEntry records a pending declaration on a registration node.
type canEntry struct {
	ability string
	models  []any
}

// Can applies the "can" authorization middleware to the current route or group
// .
func (r *router) Can(ability string, models ...any) Router {
	route := r.initRoute()
	route.canEntries = append(route.canEntries, canEntry{ability: ability, models: models})
	return route
}

// Missing registers a fallback invoked when a bound parameter of the route
// cannot be resolved.
func (r *router) Missing(callback any) Router {
	route := r.initRoute()
	route.Missing(normalizeMissingCallback(callback))
	return route
}

// normalizeMissingCallback adapts the supported missing-handler signatures.
func normalizeMissingCallback(callback any) func(request *Request, err error) any {
	if callback == nil {
		return nil
	}
	switch v := callback.(type) {
	case func(*Request, error) any:
		return v
	case func(Context) Response:
		return func(request *Request, err error) any {
			return v(newContext(request))
		}
	}
	val := reflect.ValueOf(callback)
	t := val.Type()
	if val.Kind() == reflect.Func && t.NumIn() == 1 && t.In(0) == reflect.TypeOf(Context{}) && t.NumOut() >= 1 {
		return func(request *Request, err error) any {
			out := val.Call([]reflect.Value{reflect.ValueOf(newContext(request))})
			if len(out) > 0 {
				return out[0].Interface()
			}
			return nil
		}
	}
	return nil
}

// Name names the route (prefixed by the enclosing group name, if any).
func (r *router) Name(name string) Router {
	route := r.initRoute()
	route.name = r.name + name
	return route
}

// Url generates a URL for a named route.

// Deprecated: use UrlGenerator (see NewUrlGenerator) which escapes parameters
// and moves leftover parameters into the query string.
func (r *router) Url(name string, params map[string]string) string {
	pattern, ok := r.NamedRoutePattern(name)
	if !ok {
		return ""
	}
	urlPath := pattern
	for k, v := range params {
		urlPath = strings.ReplaceAll(urlPath, "{"+k+"}", v)
		urlPath = strings.ReplaceAll(urlPath, "{"+k+"?}", v)
	}
	urlPath = optionalParamRegex.ReplaceAllString(urlPath, "")
	if urlPath == "" {
		urlPath = "/"
	}
	return urlPath
}

// Fallback registers a fallback route: a real route on GET matching
// "{fallbackPlaceholder}" with a ".*" constraint, marked as fallback so it
// only matches when nothing else does.
func (r *router) Fallback(handler interface{}) Router {
	if r.autoRegister {
		entity := r.buildRouteEntity([]string{"GET"}, "/{fallbackPlaceholder}", handler)
		entity.Where("fallbackPlaceholder", ".*")
		entity.fallback = true
		r.collection.Add(entity)
		return r.routeChainFor(entity)
	}
	node := r.initRoute()
	node.method = []string{"GET"}
	node.pattern = "/{fallbackPlaceholder}"
	node.handler = parseControllerAction(handler)
	if node.wheres == nil {
		node.wheres = make(map[string]string)
	}
	node.wheres["fallbackPlaceholder"] = ".*"
	node.isFallback = true
	return node
}

// Redirect registers a redirect route to a destination on every verb
// + RedirectController with destination/status
// defaults). Parameterized destinations ("/users/{user}") are substituted
// with the matched route parameters.
func (r *router) Redirect(uri, destination string, status ...int) Router {
	code := 302
	if len(status) > 0 {
		code = status[0]
	}
	return r.Any(uri, &redirectController{destination: destination, status: code})
}

// PermanentRedirect registers a 301 redirect route.
func (r *router) PermanentRedirect(uri, destination string) Router {
	return r.Redirect(uri, destination, 301)
}

// Where adds a regex constraint to a route parameter.
func (r *router) Where(name string, expression string) Router {
	route := r.initRoute()
	if route.wheres == nil {
		route.wheres = make(map[string]string)
	}
	route.wheres[name] = expression
	return route
}

// WhereMap adds multiple regex constraints to route parameters.
func (r *router) WhereMap(wheres map[string]string) Router {
	route := r.initRoute()
	if route.wheres == nil {
		route.wheres = make(map[string]string)
	}
	for k, v := range wheres {
		route.wheres[k] = v
	}
	return route
}

// As is an alias for Name.
func (r *router) As(name string) Router {
	return r.Name(name)
}

// Default sets a default parameter value on the current route or group.
func (r *router) Default(key string, value any) Router {
	route := r.initRoute()
	if route.defaults == nil {
		route.defaults = make(map[string]any)
	}
	route.defaults[key] = value
	if route.groupDefaults == nil {
		route.groupDefaults = make(map[string]any)
	}
	route.groupDefaults[key] = value
	return route
}

// Defaults sets multiple default parameter values on the current route or group.
func (r *router) Defaults(defaults map[string]any) Router {
	route := r.initRoute()
	if route.defaults == nil {
		route.defaults = make(map[string]any)
	}
	if route.groupDefaults == nil {
		route.groupDefaults = make(map[string]any)
	}
	for k, v := range defaults {
		route.defaults[k] = v
		route.groupDefaults[k] = v
	}
	return route
}

// Registrar returns a new RouteRegistrar bound to this router.
func (r *router) Registrar() *RouteRegistrar {
	return NewRouteRegistrar(r)
}

// SetExceptionHandler registers a pipeline exception handler.
func (r *router) SetExceptionHandler(handler ExceptionHandler) Router {
	root := r.root()
	root.exceptionHandler = handler
	return r
}

// GetExceptionHandler returns the pipeline exception handler.
func (r *router) GetExceptionHandler() ExceptionHandler {
	root := r.root()
	return root.exceptionHandler
}

// WhereNumber adds a numeric regex constraint to parameters
// .
func (r *router) WhereNumber(names ...string) Router {
	for _, name := range names {
		r.Where(name, "[0-9]+")
	}
	return r
}

// WhereAlpha adds an alphabetic regex constraint to parameters
// .
func (r *router) WhereAlpha(names ...string) Router {
	for _, name := range names {
		r.Where(name, "[a-zA-Z]+")
	}
	return r
}

// WhereAlphaNumeric adds an alphanumeric regex constraint to parameters
// .
func (r *router) WhereAlphaNumeric(names ...string) Router {
	for _, name := range names {
		r.Where(name, "[a-zA-Z0-9]+")
	}
	return r
}

// WhereUuid adds a UUID regex constraint to parameters
// .
func (r *router) WhereUuid(names ...string) Router {
	for _, name := range names {
		r.Where(name, `[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}`)
	}
	return r
}

// WhereUlid adds a ULID regex constraint to parameters
// .
func (r *router) WhereUlid(names ...string) Router {
	for _, name := range names {
		r.Where(name, `[0-7][0-9a-hjkmnp-tv-zA-HJKMNP-TV-Z]{25}`)
	}
	return r
}

// WhereIn adds an allowed values constraint to a parameter
// .
func (r *router) WhereIn(name string, allowed []string) Router {
	return r.Where(name, strings.Join(allowed, "|"))
}

// Pattern sets a global regex pattern for a parameter.
func (r *router) Pattern(name string, expression string) {
	if r.patterns == nil {
		r.patterns = make(map[string]string)
	}
	r.patterns[name] = expression
}

func regexpQuote(s string) string {
	var b strings.Builder
	for _, ch := range s {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, ch) {
			b.WriteRune('\\')
		}
		b.WriteRune(ch)
	}
	return b.String()
}

// Register expands the collected pending routes into Route entities inside
// the route collection, after flushing any deferred resource registrations.
func (r *router) Register() {
	r.flushPending()
	r.registered = true
	for _, p := range r.pending {
		p.register()
	}
	r.pending = nil
	r.register(r)
}

// Dump returns a debug dump of all registered routes.
func (r *router) Dump() []byte {
	var b bytes.Buffer
	for _, route := range r.collection.GetRoutes() {
		fmt.Fprintf(&b, "%s %s %T \r\n", strings.Join(route.Methods(), "|"), route.URI(), route.Handler())
	}
	return b.Bytes()
}

// register walks the pending nodes: parent prefix/middleware/name are merged
// into children, nodes carrying a handler become Route entities.
func (r *router) register(root *router) {
	for _, node := range r.collects {
		node.prefix = r.getPrefix(node.prefix)

		var middlewares []interface{}
		for _, m := range r.middlewares {
			middlewares = append(middlewares, m)
		}
		for _, m := range node.middlewares {
			middlewares = append(middlewares, m)
		}
		node.middlewares = middlewares

		var without []interface{}
		without = append(without, r.withoutMiddleware...)
		without = append(without, node.withoutMiddleware...)
		node.withoutMiddleware = without

		var groupWheres map[string]string
		for k, v := range r.groupWheres {
			if groupWheres == nil {
				groupWheres = make(map[string]string)
			}
			groupWheres[k] = v
		}
		for k, v := range node.groupWheres {
			if groupWheres == nil {
				groupWheres = make(map[string]string)
			}
			groupWheres[k] = v
		}
		node.groupWheres = groupWheres

		node.register(root)

		if node.handler == nil {
			continue
		}

		routePattern := node.getPrefix(node.pattern)
		// semantics for deferred registration too: rewrite
		// "{user:id}" placeholders and record their binding fields.
		parsedPattern := ParseRouteUri(routePattern)
		routePattern = parsedPattern.URI
		if node.bindingFields == nil {
			node.bindingFields = parsedPattern.BindingFields
		} else {
			for k, v := range parsedPattern.BindingFields {
				node.bindingFields[k] = v
			}
		}

		combinedWheres := make(map[string]string)
		for k, v := range root.patterns {
			combinedWheres[k] = v
		}
		for k, v := range node.groupWheres {
			combinedWheres[k] = v
		}
		for k, v := range node.wheres {
			combinedWheres[k] = v
		}

		actionHandler := node.handler
		if action, ok := actionHandler.(ControllerAction); ok {
			if name, isName := action.Controller.(string); isName && node.controllerPrefix != "" {
				if action.Method == "Invoke" {
					action.Controller = node.controllerPrefix
					action.Method = name
				} else if name != node.controllerPrefix {
					action.Controller = node.controllerPrefix + "." + name
				}
				actionHandler = action
			}
		}
		// Group metadata is merged down the chain like groupWheres: nested
		// groups contribute their metadata to every route they contain, with
		// inner groups merged over outer ones.
		var chain []*router
		for cur := node; cur != nil; cur = cur.group {
			chain = append([]*router{cur}, chain...)
		}
		combinedMetadata := make(map[string]any)
		combinedDefaults := make(map[string]any)
		for _, cur := range chain {
			combinedMetadata = mergeMetadataDeep(combinedMetadata, cur.groupMetadata)
			for k, v := range cur.groupDefaults {
				combinedDefaults[k] = v
			}
		}
		for k, v := range node.defaults {
			combinedDefaults[k] = v
		}
		entity := &Route{
			methods:           ensureHead(node.method),
			uri:               routePattern,
			prefix:            node.prefix,
			name:              node.name,
			handler:           actionHandler,
			middlewares:       node.middlewares,
			withoutMiddleware: node.withoutMiddleware,
			wheres:            combinedWheres,
			defaults:          combinedDefaults,
			metadata:          combinedMetadata,
			domain:            node.domain,
			scopedBindings:    node.scopedBindings,
			withTrashed:       node.withTrashed,
			missing:           node.missing,
			fallback:          node.isFallback,
			bindingFields:     node.bindingFields,
			router:            root,
		}
		for _, ce := range node.collectCanEntries() {
			entity.Can(ce.ability, ce.models...)
		}

		root.collection.Add(entity)
	}
	r.collects = r.collects[0:0]
}

// collectCanEntries gathers the Can declarations of the node chain
// (outermost first).
func (r *router) collectCanEntries() []canEntry {
	var out []canEntry
	for cur := r; cur != nil; cur = cur.group {
		out = append(out, cur.canEntries...)
	}
	return out
}

// initRoute returns the node itself when already initialized as a pending
// route, otherwise creates a child node attached to this one.
func (r *router) initRoute() *router {
	// In immediate mode the node is initialized in place: attribute calls
	// (Prefix/Middleware/...) and the following verb registration share the
	// same node, like a scoped registrar.
	if r.autoRegister {
		r.inited = true
		return r
	}
	route := r
	if !r.inited {
		route = &router{
			inited:             true,
			autoRegister:       r.autoRegister,
			name:               r.name,
			domain:             r.domain,
			controllerPrefix:   r.controllerPrefix,
			group:              r,
			parameterResolver:  r.parameterResolver,
			signatureKey:       r.signatureKey,
			middlewareAliases:  r.middlewareAliases,
			middlewareGroups:   r.middlewareGroups,
			middlewarePriority: r.middlewarePriority,
			scopedBindings:     r.scopedBindings,
			scopedDisabled:     r.scopedDisabled,
			withTrashed:        r.withTrashed,
			missing:            r.missing,
		}
		if r.groupMetadata != nil {
			route.groupMetadata = make(map[string]any, len(r.groupMetadata))
			for k, v := range r.groupMetadata {
				route.groupMetadata[k] = v
			}
		}
		if r.collection != nil {
			route.collection = r.collection
		}
		r.collects = append(r.collects, route)
	}
	return route
}

// cloneRoute creates a group node attached to this node.
func (r *router) cloneRoute() *router {
	route := &router{
		inited:             false,
		autoRegister:       r.autoRegister,
		name:               r.name,
		domain:             r.domain,
		controllerPrefix:   r.controllerPrefix,
		group:              r,
		parameterResolver:  r.parameterResolver,
		signatureKey:       r.signatureKey,
		middlewareAliases:  r.middlewareAliases,
		middlewareGroups:   r.middlewareGroups,
		middlewarePriority: r.middlewarePriority,
		scopedBindings:     r.scopedBindings,
		scopedDisabled:     r.scopedDisabled,
		withTrashed:        r.withTrashed,
		missing:            r.missing,
	}
	if r.groupMetadata != nil {
		route.groupMetadata = make(map[string]any, len(r.groupMetadata))
		for k, v := range r.groupMetadata {
			route.groupMetadata[k] = v
		}
	}
	if r.collection != nil {
		route.collection = r.collection
	}
	r.collects = append(r.collects, route)

	return route
}

// AliasMiddleware registers a route-specific middleware alias.
func (r *router) AliasMiddleware(name string, middleware interface{}) Router {
	if r.middlewareAliases == nil {
		r.middlewareAliases = make(map[string]interface{})
	}
	r.middlewareAliases[name] = middleware
	return r
}

// MiddlewareGroup defines a named middleware group.
func (r *router) MiddlewareGroup(name string, middlewares ...interface{}) Router {
	if r.middlewareGroups == nil {
		r.middlewareGroups = make(map[string][]interface{})
	}
	r.middlewareGroups[name] = middlewares
	return r
}

// GetRouteMiddleware retrieves a registered middleware alias.
func (r *router) GetRouteMiddleware(name string) interface{} {
	if r.middlewareAliases != nil {
		if m, ok := r.middlewareAliases[name]; ok {
			return m
		}
	}
	if r.group != nil {
		return r.group.GetRouteMiddleware(name)
	}
	return nil
}

// GetMiddlewareGroup retrieves a registered middleware group.
func (r *router) GetMiddlewareGroup(name string) []interface{} {
	if r.middlewareGroups != nil {
		if g, ok := r.middlewareGroups[name]; ok {
			return g
		}
	}
	if r.group != nil {
		return r.group.GetMiddlewareGroup(name)
	}
	return nil
}

// GetMiddlewareGroups returns every registered middleware group
// .
func (r *router) GetMiddlewareGroups() map[string][]interface{} {
	root := r.root()
	out := make(map[string][]interface{}, len(root.middlewareGroups))
	for name, group := range root.middlewareGroups {
		out[name] = group
	}
	return out
}

// HasMiddlewareGroup determines if a middleware group with the name exists.
func (r *router) HasMiddlewareGroup(name string) bool {
	if _, ok := r.middlewareGroups[name]; ok {
		return true
	}
	if r.group != nil {
		return r.group.HasMiddlewareGroup(name)
	}
	return false
}

// PrependMiddlewareToGroup prepends middleware to a group, skipping entries
// already present. A group that does not exist is left alone
// .
func (r *router) PrependMiddlewareToGroup(name string, middleware interface{}) {
	root := r.root()
	group, exists := root.middlewareGroups[name]
	if !exists {
		return
	}
	for _, m := range group {
		if middlewareEqual(m, middleware) {
			return
		}
	}
	if root.middlewareGroups == nil {
		root.middlewareGroups = make(map[string][]interface{})
	}
	root.middlewareGroups[name] = append([]interface{}{middleware}, group...)
}

// PushMiddlewareToGroup appends middleware to a group, creating the group when
// it does not exist and skipping entries already present
// .
func (r *router) PushMiddlewareToGroup(name string, middleware interface{}) {
	root := r.root()
	group := root.middlewareGroups[name]
	for _, m := range group {
		if middlewareEqual(m, middleware) {
			return
		}
	}
	if root.middlewareGroups == nil {
		root.middlewareGroups = make(map[string][]interface{})
	}
	root.middlewareGroups[name] = append(group, middleware)
}

// RemoveMiddlewareFromGroup removes middleware from an existing group. Like
// the reference implementation (array_flip keeps the last occurrence's key), only the LAST
// occurrence is removed.
func (r *router) RemoveMiddlewareFromGroup(name string, middleware interface{}) {
	if group, ok := r.middlewareGroups[name]; ok {
		last := -1
		for i, m := range group {
			if middlewareEqual(m, middleware) {
				last = i
			}
		}
		if last != -1 {
			group = append(group[:last], group[last+1:]...)
			r.middlewareGroups[name] = group
		}
	}
}

// FlushMiddlewareGroups clears all middleware groups.
func (r *router) FlushMiddlewareGroups() {
	r.middlewareGroups = make(map[string][]interface{})
}

// MiddlewarePriority sets the middleware priority order used when sorting the
// resolved middleware of a route.
func (r *router) MiddlewarePriority(middlewares ...interface{}) {
	r.middlewarePriority = middlewares
}

func (r *router) getParameterResolver() ParameterResolver {
	if r.parameterResolver != nil {
		return r.parameterResolver
	}
	if r.group != nil {
		return r.group.getParameterResolver()
	}
	return nil
}

func (r *router) getSignatureKey() string {
	if r != nil && r.signatureKey != "" {
		return r.signatureKey
	}
	if r != nil && r.group != nil {
		if k := r.group.getSignatureKey(); k != "" {
			return k
		}
	}
	return getSignatureKey()
}

func (r *router) getPrefix(pattern string) string {
	return path.Join("/", r.prefix, pattern)
}

// NamedRouteDomain returns the host/domain template of a named route when the
// route is restricted to a (possibly dynamic) domain. Implementing
// DomainNamedRouteSource lets UrlGenerator.Route() take the formatDomain path
// for domain routes — scheme, subdomain placeholders and the request port are
// resolved exactly like the reference.
func (r *router) NamedRouteDomain(name string) (string, bool) {
	r.flushPending()
	if r.collection == nil {
		return "", false
	}
	route := r.collection.GetByName(name)
	if route == nil {
		return "", false
	}
	return route.GetDomain(), route.GetDomain() != ""
}

// SignedUrl creates a signed URL for a named route.

// Deprecated: use UrlGenerator (see NewUrlGenerator) for URL signing; it adds
// lazy key resolution and key rotation support. This delegate keeps working
// with the key set via WithSignatureKey/ResolveSignatureKey.
func (r *router) SignedUrl(name string, expiration time.Duration, params map[string]string) string {
	return r.legacyUrlGenerator().SignedRoute(name, params, expiration)
}

// HasValidSignature checks if the given request has a valid signature.

// Deprecated: use UrlGenerator (see NewUrlGenerator) instead.
func (r *router) HasValidSignature(req *Request) bool {
	return r.legacyUrlGenerator().HasValidSignature(req)
}

// legacyUrlGenerator builds a single-key UrlGenerator view over the router,
// preserving the pre-UrlGenerator key resolution chain.
func (r *router) legacyUrlGenerator() *UrlGenerator {
	return &UrlGenerator{
		routes:      r,
		keyResolver: func() []string { return []string{r.getSignatureKey()} },
	}
}

// Has determines if the route collection contains a given named route.
func (r *router) Has(name string) bool {
	r.flushPending()
	return r.collection.HasNamedRoute(name)
}

// HasAll determines if ALL the given named routes exist
// with array_all semantics). Router.Has covers the
// single-name form.
func (r *router) HasAll(names ...string) bool {
	r.flushPending()
	for _, name := range names {
		if !r.collection.HasNamedRoute(name) {
			return false
		}
	}
	return len(names) > 0
}

// CurrentRouteName returns the current route name for the request. When the
// request carries no name marker the current route entity is consulted
// .
func (r *router) CurrentRouteName(req *Request) string {
	if req != nil {
		if nameVal, ok := req.Get("_route_name"); ok {
			if name, ok := nameVal.(string); ok {
				return name
			}
		}
	}
	if route := r.CurrentRoute(); route != nil {
		return route.GetName()
	}
	return ""
}

// CurrentRouteNamed determines whether the current route name matches any of
// the given patterns.
func (r *router) CurrentRouteNamed(req *Request, patterns ...string) bool {
	return r.Is(req, patterns...)
}

// CurrentRouteAction returns the action identifier of the current route
// , which is null for
// closure routes, so closures report "" here).
func (r *router) CurrentRouteAction(req *Request) string {
	if route := r.CurrentRoute(); route != nil {
		if ca, ok := route.handler.(ControllerAction); ok {
			if name, isName := ca.Controller.(string); isName {
				return name + "@" + ca.Method
			}
			return fmt.Sprintf("%T@%s", ca.Controller, ca.Method)
		}
		return ""
	}
	return ""
}

// CurrentRouteUses determines whether the current route is served by the
// given action.
func (r *router) CurrentRouteUses(req *Request, action string) bool {
	return r.CurrentRouteAction(req) == action
}

// Uses determines if the current route action matches any of the given
// patterns with semantics (wildcard "*", case-sensitive)
// .
func (r *router) Uses(req *Request, patterns ...string) bool {
	current := r.CurrentRouteAction(req)
	for _, pattern := range patterns {
		if strIs(pattern, current) {
			return true
		}
	}
	return false
}

// Is determines if the current route's name matches given patterns.
func (r *router) Is(req *Request, patterns ...string) bool {
	currentName := r.CurrentRouteName(req)
	if currentName == "" {
		return false
	}
	for _, pattern := range patterns {
		if pattern == currentName {
			return true
		}
		if strings.Contains(pattern, "*") {
			pat := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$"
			if matched, _ := regexp.MatchString(pat, currentName); matched {
				return true
			}
		}
	}
	return false
}

var ResolveSignatureKey func() string

// Deprecated: superseded by UrlGenerator.SetKeyResolver; kept for
// compatibility with code written against v1.0.0.
func getSignatureKey() string {
	if ResolveSignatureKey != nil {
		if k := ResolveSignatureKey(); k != "" {
			return k
		}
	}
	// No hardcoded fallback: an unconfigured key disables URL signing entirely
	// (SignedRoute returns "" and HasValidSignature returns false).
	return ""
}

// NamedRoutePattern returns the raw pattern of a named route.
func (r *router) NamedRoutePattern(name string) (string, bool) {
	r.flushPending()
	if r.collection == nil {
		return "", false
	}
	route := r.collection.GetByName(name)
	if route == nil {
		return "", false
	}
	return route.URI(), true
}

// ActionRoutePattern returns the raw pattern of a route matching the action string.
func (r *router) ActionRoutePattern(action string) (string, bool) {
	if r.collection == nil {
		return "", false
	}
	route := r.collection.GetByAction(action)
	if route == nil {
		return "", false
	}
	return route.URI(), true
}

// CurrentRoute returns the route matched by the most recent dispatch.
func (r *router) CurrentRoute() *Route {
	r.currentMu.RLock()
	defer r.currentMu.RUnlock()
	return r.currentRoute
}

// CurrentRequest returns the request of the most recent dispatch.
func (r *router) CurrentRequest() *Request {
	r.currentMu.RLock()
	defer r.currentMu.RUnlock()
	return r.currentRequest
}

// MatchRequest resolves a request to a Route entity and binds its parameters.
func (r *router) MatchRequest(request *Request) (*Route, error) {
	r.flushPending()
	route, err := r.findRoute(request)
	return route, err
}

// FlushPending materializes deferred resource registrations.
func (r *router) FlushPending() { r.flushPending() }

// MergeWithLastGroup merges group attributes into the current group stack
// .
func (r *router) MergeWithLastGroup(attrs GroupAttributes) GroupAttributes {
	merged := GroupAttributes{
		Prefix:     r.getPrefix(attrs.Prefix),
		Name:       r.name + attrs.Name,
		Domain:     attrs.Domain,
		Controller: r.controllerPrefix + attrs.Controller,
	}
	for k, v := range r.groupWheres {
		if merged.Wheres == nil {
			merged.Wheres = make(map[string]string)
		}
		merged.Wheres[k] = v
	}
	for k, v := range attrs.Wheres {
		if merged.Wheres == nil {
			merged.Wheres = make(map[string]string)
		}
		merged.Wheres[k] = v
	}
	return merged
}

// GetLastGroupPrefix returns the innermost group prefix on the chain
// .
func (r *router) GetLastGroupPrefix() string {
	node := r
	for node != nil {
		if node.prefix != "" {
			return node.prefix
		}
		node = node.group
	}
	return ""
}

// SoftDeletableResources bulk-registers resources with WithTrashed enabled
// .
func (r *router) SoftDeletableResources(resources map[string]any, options ...ResourceOption) {
	for name, controller := range resources {
		p := r.Resource(name, controller, options...)
		p.WithTrashed()
	}
}

// GetRoutes returns every registered route.
func (r *router) GetRoutes() []*Route {
	r.flushPending()
	return r.collection.GetRoutes()
}

// flushPending materializes deferred resource registrations.
func (r *router) flushPending() {
	root := r.root()
	if len(root.pending) == 0 {
		return
	}
	pending := root.pending
	root.pending = nil
	for _, p := range pending {
		p.register()
	}
}

// Routes exposes the route collection. After RestoreCompiled the returned
// RouteCollectionInterface is a *CompiledRouteCollection; otherwise it is the
// live *RouteCollection.
func (r *router) Routes() RouteCollectionInterface {
	r.flushPending()
	return r.collection
}

// OnRouting registers a callback fired before a request is matched.
func (r *router) OnRouting(callback func(request *Request)) {
	r.onRouting = append(r.onRouting, callback)
}

// OnRouteMatched registers a callback fired after a route is matched.
func (r *router) OnRouteMatched(callback func(route *Route, request *Request)) {
	r.onRouteMatched = append(r.onRouteMatched, callback)
}

// OnPreparingResponse registers a callback fired before the response is built.
func (r *router) OnPreparingResponse(callback func(request *Request, result any)) {
	r.onPreparingResponse = append(r.onPreparingResponse, callback)
}

// OnResponsePrepared registers a callback fired after the response is built.
func (r *router) OnResponsePrepared(callback func(request *Request, response *Response)) {
	r.onResponsePrepared = append(r.onResponsePrepared, callback)
}

// DisableMiddleware disables (or re-enables) all route middleware.
func (r *router) DisableMiddleware(disable bool) {
	r.disableMiddleware = disable
}

// RegisterController registers a controller instance under a name. The
// registry lives on the root router, like the named-route index.
func (r *router) RegisterController(name string, controller any) {
	root := r.root()
	if root.controllers == nil {
		root.controllers = make(map[string]any)
	}
	root.controllers[name] = controller
}

// Resource registers a resource controller with the conventional seven
// actions; the returned builder defers registration for customization. When
// the router already booted the resource registers immediately
// .
func (r *router) Resource(name string, controller any, options ...ResourceOption) *PendingResourceRegistration {
	p := &PendingResourceRegistration{router: r, name: name, controller: controller}
	applyResourceOptions(&p.options, options)
	root := r.root()
	if root.registered {
		p.register()
		return p
	}
	root.pending = append(root.pending, p)
	return p
}

// Resources bulk registers resource controllers.
func (r *router) Resources(resources map[string]any, options ...ResourceOption) {
	for name, controller := range resources {
		r.Resource(name, controller, options...)
	}
}

// APIResource registers a resource without Create/Edit actions
// (the reference implementation: apiResource — only = ['index','show','store','update','destroy'];
// the user's options are applied after the default, so a user-supplied Only
// wins like merging the default only-list under user options).
func (r *router) APIResource(name string, controller any, options ...ResourceOption) *PendingResourceRegistration {
	p := r.Resource(name, controller)
	p.options.APIOnly = []string{"Index", "Show", "Store", "Update", "Destroy"}
	applyResourceOptions(&p.options, options)
	return p
}

// APIResources bulk registers API resource controllers.
func (r *router) APIResources(resources map[string]any, options ...ResourceOption) {
	for name, controller := range resources {
		r.APIResource(name, controller, options...)
	}
}

// Singleton registers a singleton resource (no id parameter)
// (the reference implementation: singleton returns PendingSingletonResourceRegistration; flow keeps
// one pending type).
func (r *router) Singleton(name string, controller any, options ...ResourceOption) *PendingResourceRegistration {
	p := r.Resource(name, controller, options...)
	p.singleton = true
	return p
}

// Singletons bulk registers singleton resource controllers.
func (r *router) Singletons(singletons map[string]any, options ...ResourceOption) {
	for name, controller := range singletons {
		r.Singleton(name, controller, options...)
	}
}

// APISingleton registers an API singleton resource
// .
func (r *router) APISingleton(name string, controller any, options ...ResourceOption) *PendingResourceRegistration {
	p := r.Singleton(name, controller)
	p.options.APIOnly = []string{"Store", "Show", "Update", "Destroy"}
	applyResourceOptions(&p.options, options)
	return p
}

// APISingletons bulk registers API singleton resource controllers.
func (r *router) APISingletons(singletons map[string]any, options ...ResourceOption) {
	for name, controller := range singletons {
		r.APISingleton(name, controller, options...)
	}
}

// root walks up the group chain to the owning router.
func (r *router) root() *router {
	node := r
	for node != nil && node.group != nil {
		node = node.group
	}
	return node
}

// SetControllerDispatcher replaces the controller dispatcher.
func (r *router) SetControllerDispatcher(dispatcher ControllerDispatcher) {
	r.controllerDispatcher = dispatcher
}

// SetCallableDispatcher replaces the callable/closure dispatcher.
func (r *router) SetCallableDispatcher(dispatcher CallableDispatcher) {
	root := r.root()
	root.callableDispatcher = dispatcher
}

// GetCallableDispatcher returns the callable/closure dispatcher.
func (r *router) GetCallableDispatcher() CallableDispatcher {
	root := r.root()
	if root.callableDispatcher != nil {
		return root.callableDispatcher
	}
	return defaultCallableDispatcherInstance
}

// HasGroupStack reports whether the router is currently within a route group.
func (r *router) HasGroupStack() bool {
	root := r.root()
	root.groupStackMu.RLock()
	defer root.groupStackMu.RUnlock()
	return len(root.groupStack) > 0
}

// GetGroupStack returns the stack of group attributes from outer to inner.
func (r *router) GetGroupStack() []GroupAttributes {
	root := r.root()
	root.groupStackMu.RLock()
	defer root.groupStackMu.RUnlock()
	out := make([]GroupAttributes, len(root.groupStack))
	copy(out, root.groupStack)
	return out
}

// compiledRouteData is the JSON-serializable form of a cacheable route.
type compiledRouteData struct {
	Methods           []string          `json:"methods"`
	URI               string            `json:"uri"`
	Name              string            `json:"name,omitempty"`
	Action            string            `json:"action"`
	Wheres            map[string]string `json:"wheres,omitempty"`
	Defaults          map[string]any    `json:"defaults,omitempty"`
	Metadata          map[string]any    `json:"metadata,omitempty"`
	Middleware        []any             `json:"middleware,omitempty"`
	WithoutMiddleware []any             `json:"without_middleware,omitempty"`
	Domain            string            `json:"domain,omitempty"`
	BindingFields     map[string]string `json:"binding_fields,omitempty"`
	Fallback          bool              `json:"fallback,omitempty"`
	Secure            bool              `json:"secure,omitempty"`
	ScopeBindings     bool              `json:"scope_bindings,omitempty"`
	WithTrashed       bool              `json:"with_trashed,omitempty"`
	LockSeconds       int               `json:"lock_seconds,omitempty"`
	WaitSeconds       int               `json:"wait_seconds,omitempty"`
}

// Compile serializes routes whose actions are controller actions; closures
// cannot cross a cache boundary and make Compile return an error.
func (r *router) Compile() ([]byte, error) {
	var out []compiledRouteData
	assignedNames := make(map[string]bool)
	for _, route := range r.collection.GetRoutes() {
		action, ok := route.Handler().(ControllerAction)
		if !ok {
			return nil, fmt.Errorf("flow: route [%s] has a non-serializable action and cannot be cached", route.URI())
		}
		name, ok := action.Controller.(string)
		if !ok {
			return nil, fmt.Errorf("flow: route [%s] has a non-serializable action and cannot be cached", route.URI())
		}
		// the cache-preparation pass guards the name lookup tables before
		// serialization: a duplicate name is an error unless the name is a bare
		// prefix ("."), which is silently dropped from the later route.
		routeName := route.GetName()
		if routeName != "" {
			if assignedNames[routeName] {
				if strings.HasSuffix(routeName, ".") {
					routeName = ""
				} else {
					return nil, fmt.Errorf(
						"Unable to prepare route [%s] for serialization. Another route has already been assigned name [%s].",
						route.URI(), routeName)
				}
			} else {
				assignedNames[routeName] = true
			}
		}
		entry := compiledRouteData{
			Methods:           route.Methods(),
			URI:               route.URI(),
			Name:              routeName,
			Action:            name + "@" + action.Method,
			Wheres:            route.Wheres(),
			Defaults:          route.Defaults(),
			Metadata:          route.metadata,
			Middleware:        route.GetMiddleware(),
			WithoutMiddleware: route.ExcludedMiddleware(),
			Domain:            route.GetDomain(),
			BindingFields:     route.bindingFields,
			Fallback:          route.IsFallback(),
			Secure:            route.IsSecure(),
			ScopeBindings:     route.EnforcesScopedBindings(),
			WithTrashed:       route.AllowsTrashedBindings(),
			LockSeconds:       route.LocksFor(),
			WaitSeconds:       route.WaitsFor(),
		}
		out = append(out, entry)
	}
	return json.Marshal(out)
}

// RestoreCompiled replaces the route collection with routes deserialized from
// a previous Compile. Controllers must be registered before restoring.
func (r *router) RestoreCompiled(data []byte) error {
	var out []compiledRouteData
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}

	var cached []*Route
	r.currentMu.Lock()
	r.currentRoute = nil
	r.currentMu.Unlock()

	for _, cr := range out {
		if _, ok := r.controllers[cr.Action[:strings.Index(cr.Action, "@")]]; !ok {
			return fmt.Errorf("flow: controller [%s] is not registered", cr.Action[:strings.Index(cr.Action, "@")])
		}
		handler := parseControllerAction(cr.Action)
		if ca, ok := handler.(ControllerAction); ok {
			ca.Controller = cr.Action[:strings.Index(cr.Action, "@")]
			handler = ca
		}
		entity := &Route{
			methods:           cr.Methods,
			uri:               cr.URI,
			name:              cr.Name,
			handler:           handler,
			wheres:            cr.Wheres,
			defaults:          cr.Defaults,
			metadata:          cr.Metadata,
			middlewares:       cr.Middleware,
			withoutMiddleware: cr.WithoutMiddleware,
			domain:            cr.Domain,
			bindingFields:     cr.BindingFields,
			fallback:          cr.Fallback,
			secure:            cr.Secure,
			scopedBindings:    cr.ScopeBindings,
			withTrashed:       cr.WithTrashed,
			lockSeconds:       cr.LockSeconds,
			waitSeconds:       cr.WaitSeconds,
			router:            r,
		}
		cached = append(cached, entity)
	}
	// setCompiledRoutes wraps the restored routes in a
	// CompiledRouteCollection so post-restore registrations land in the
	// dynamic sub-collection with the reference precedence rules.
	r.collection = NewCompiledRouteCollection(cached)
	return nil
}

// SetEventDispatcher registers a dispatcher to receive routing lifecycle events.
func (r *router) SetEventDispatcher(dispatcher EventDispatcher) Router {
	r.events = dispatcher
	return r
}

// GetEventDispatcher returns the registered event dispatcher.
func (r *router) GetEventDispatcher() EventDispatcher {
	return r.events
}

// Model binds a route parameter to a model instance
// .
func (r *router) Model(key string, model any, callback ...func(val string) (any, error)) Router {
	if len(callback) > 0 && callback[0] != nil {
		r.Bind(key, func(value string, route *Route) (any, error) {
			return callback[0](value)
		})
		return r
	}
	if routable, ok := model.(Routable); ok {
		r.Bind(key, ForModel(routable))
	}
	return r
}

// Patterns registers a batch of global regular expression patterns on route parameters
// .
func (r *router) Patterns(patterns map[string]string) Router {
	for k, v := range patterns {
		r.Pattern(k, v)
	}
	return r
}

// GetMiddlewarePriority returns the configured middleware priority list
// .
func (r *router) GetMiddlewarePriority() []any {
	out := make([]any, len(r.middlewarePriority))
	copy(out, r.middlewarePriority)
	return out
}

// getControllerDispatcher returns the configured dispatcher or the default one.
func (r *router) getControllerDispatcher() ControllerDispatcher {
	if r.controllerDispatcher != nil {
		return r.controllerDispatcher
	}
	return &controllerDispatcher{router: r}
}

// prepareResponse converts the action result into a response, firing the
// pre/post response events.
func (r *router) prepareResponse(request *Request, result any) *Response {
	for _, callback := range r.onPreparingResponse {
		callback(request, result)
	}
	if r.events != nil {
		r.events.Dispatch("flow.preparing_response", &PreparingResponseEvent{Request: request, Result: result})
	}
	response := r.toResponse(request, result)
	for _, callback := range r.onResponsePrepared {
		callback(request, response)
	}
	if r.events != nil {
		r.events.Dispatch("flow.response_prepared", &ResponsePreparedEvent{Request: request, Response: response})
	}
	return response
}

// toResponse converts an action result into a *Response following the reference implementation
// type branches: Responsable values produce their own response, responses pass
// through, recently-created models become 201 JSON, Stringer values render as
// text/html, other values are formatted (JSON for composite types via
// FormatContent), and a 304 status gets setNotModified applied
// .
func (r *router) toResponse(request *Request, result any) *Response {
	response := r.toResponseType(request, result)
	// HTTP_NOT_MODIFIED → setNotModified (strip content & type).
	if response.GetCode() == http.StatusNotModified {
		response.SetContent("")
		response.Headers().Del("Content-Type")
	}
	// HEAD requests strip response content while preserving or setting Content-Length.
	if request != nil && request.GetMethod() == "HEAD" {
		if response.Headers().Get("Content-Length") == "" && len(response.GetContent()) > 0 {
			response.Headers().Set("Content-Length", strconv.Itoa(len(response.GetContent())))
		}
		response.SetContent("")
	}
	return response
}

// Responsable is the Go equivalent of:
// an action result that produces its own response.
type Responsable interface {
	ToResponse(request *Request) *Response
}

// RecentlyCreated mirrors the reference branch: values
// reporting a recent creation are serialized with a 201 status.
type RecentlyCreated interface {
	WasRecentlyCreated() bool
}

// toResponseType implements the result-type branches of.
func (r *router) toResponseType(request *Request, result any) *Response {
	switch res := result.(type) {
	case Responsable:
		return res.ToResponse(request)
	case *Response:
		return res
	case Response:
		// A Context-built response value: its header map is shared with the
		// request's canonical response.
		return &res
	case RecentlyCreated:
		// Model && wasRecentlyCreated → JsonResponse(..., 201);
		// otherwise it serializes like any other composite value.
		if res.WasRecentlyCreated() {
			return NewResponse().SetCode(201).SetContent(FormatContent(res))
		}
		return NewResponse().SetCode(200).SetContent(FormatContent(res))
	case fmt.Stringer:
		// Stringable → text response with 200 and text/html.
		return NewResponse().SetCode(200).SetContent(res.String()).Header("Content-Type", "text/html")
	case string:
		return NewResponse().SetCode(200).SetContent(res).Header("Content-Type", "text/html")
	default:
		response := request.CanonicalResponse()
		response.SetContent(FormatContent(result))
		return response
	}
}

// resolveMiddleware resolves a single middleware entry into Middleware(s).
func resolveMiddleware(m interface{}, r *router) []Middleware {
	var resolved []Middleware
	if md, ok := m.(Middleware); ok {
		resolved = append(resolved, md)
	} else if handler, ok := m.(interface {
		Process(req *Request, next Closure) interface{}
	}); ok {
		resolved = append(resolved, handler.Process)
	} else if items, ok := m.([]any); ok {
		for _, item := range items {
			resolved = append(resolved, resolveMiddleware(item, r)...)
		}
	} else if name, ok := m.(string); ok && r != nil {
		var params []string
		if idx := strings.Index(name, ":"); idx != -1 {
			paramsStr := name[idx+1:]
			name = name[:idx]
			params = strings.Split(paramsStr, ",")
		}

		if group := r.GetMiddlewareGroup(name); group != nil {
			for _, gm := range group {
				if entry, isStr := gm.(string); isStr && entry == name {
					panic(fmt.Sprintf("flow: [%s] middleware group is referencing itself", name))
				}
				resolved = append(resolved, resolveMiddleware(gm, r)...)
			}
		} else if alias := r.GetRouteMiddleware(name); alias != nil {
			if len(params) > 0 {
				if factory, ok := alias.(ParameterizedMiddleware); ok {
					resolved = append(resolved, factory(params...))
				} else if factory, ok := alias.(func(...string) Middleware); ok {
					resolved = append(resolved, factory(params...))
				} else {
					val := reflect.ValueOf(alias)
					if val.Kind() == reflect.Func {
						var inArgs []reflect.Value
						if val.Type().IsVariadic() {
							for _, p := range params {
								inArgs = append(inArgs, reflect.ValueOf(p))
							}
						} else {
							numIn := val.Type().NumIn()
							for i := 0; i < numIn && i < len(params); i++ {
								inArgs = append(inArgs, reflect.ValueOf(params[i]))
							}
						}
						out := val.Call(inArgs)
						if len(out) > 0 {
							resolved = append(resolved, resolveMiddleware(out[0].Interface(), r)...)
						}
					} else {
						resolved = append(resolved, resolveMiddleware(alias, r)...)
					}
				}
			} else {
				resolved = append(resolved, resolveMiddleware(alias, r)...)
			}
		}
	} else if m != nil {
		val := reflect.ValueOf(m)
		method := val.MethodByName("Process")
		if method.IsValid() && method.Type().NumIn() == 2 {
			resolved = append(resolved, func(req *Request, next Closure) interface{} {
				nextVal := reflect.ValueOf(next)
				targetType := method.Type().In(1)
				if nextVal.Type().ConvertibleTo(targetType) {
					nextVal = nextVal.Convert(targetType)
				}
				res := method.Call([]reflect.Value{reflect.ValueOf(req), nextVal})
				if len(res) > 0 {
					return res[0].Interface()
				}
				return nil
			})
		} else if val.Kind() == reflect.Func && val.Type().NumIn() == 2 && val.Type().NumOut() >= 1 {
			// A raw closure with a middleware signature. Arguments are built
			// dynamically: *Request, Context, and a next() function whose
			// return type matches the declaration.
			resolved = append(resolved, Middleware(func(req *Request, next Closure) interface{} {
				t := val.Type()
				args := make([]reflect.Value, t.NumIn())
				for i := 0; i < t.NumIn(); i++ {
					pt := t.In(i)
					switch {
					case pt == reflect.TypeOf(req):
						args[i] = reflect.ValueOf(req)
					case pt == contextType:
						args[i] = reflect.ValueOf(newContext(req))
					case pt.Kind() == reflect.Func:
						outType := pt.Out(0)
						args[i] = reflect.MakeFunc(pt, func(in []reflect.Value) []reflect.Value {
							result := next(req)
							res := r.prepareResponse(req, result)
							switch {
							case outType == reflect.TypeOf(res):
								return []reflect.Value{reflect.ValueOf(res)}
							case outType == reflect.TypeOf(Response{}):
								return []reflect.Value{reflect.ValueOf(*res)}
							case outType.Kind() == reflect.Interface:
								if res != nil {
									if v := reflect.ValueOf(res); v.Type().Implements(outType) {
										return []reflect.Value{v}
									}
								}
								if result != nil {
									if v := reflect.ValueOf(result); v.Type().Implements(outType) {
										return []reflect.Value{v}
									}
								}
							}
							if result != nil {
								if v := reflect.ValueOf(result); v.Type().AssignableTo(outType) {
									return []reflect.Value{v}
								}
							}
							return []reflect.Value{reflect.Zero(outType)}
						})
					default:
						args[i] = reflect.Zero(pt)
					}
				}
				out := val.Call(args)
				if len(out) > 0 {
					return out[0].Interface()
				}
				return nil
			}))
		}
	}
	return resolved
}

// --- Begin controllers.go ---
// viewController backs.
type viewController struct {
	view    string
	data    any
	status  int
	headers map[string]string
}

// Render produces the response for a view route. Like the reference implementation
// , the route parameters (excluding view/data/status/
// headers keys) are merged into the data bag. flow has no bundled view engine:
// the view name and merged data are formatted into the response body,
// honoring the configured status/headers.
func (c *viewController) Render(request *Request) any {
	data := c.data
	if request != nil {
		merged := make(map[string]any)
		if m, ok := data.(map[string]any); ok {
			for k, v := range m {
				merged[k] = v
			}
		} else if data != nil {
			merged["data"] = data
		}
		for name, value := range request.routeParamsSnapshot() {
			switch name {
			case "view", "data", "status", "headers":
				continue
			}
			merged[name] = value
		}
		data = merged
	}
	res := NewResponse().SetCode(c.status).SetContent(FormatContent(map[string]any{
		"view": c.view,
		"data": data,
	}))
	for name, value := range c.headers {
		res.Header(name, value)
	}
	return res
}

// redirectController backs.
type redirectController struct {
	destination string
	status      int
}

// Render produces the redirect response, substituting parameterized
// destination segments ("/users/{user}") with the matched route parameters and
// moving leftover parameters into the query string (the reference implementation: RedirectController
// +).
func (c *redirectController) Render(request *Request) any {
	destination := c.destination
	query := url.Values{}
	for name, value := range request.routeParamsSnapshot() {
		placeholder := "{" + name + "}"
		if strings.Contains(destination, placeholder) || strings.Contains(destination, placeholder+"?") {
			destination = strings.ReplaceAll(destination, placeholder, value)
			destination = strings.ReplaceAll(destination, placeholder+"?", value)
		} else {
			query.Set(name, value)
		}
	}
	destination = optionalParamRegex.ReplaceAllString(destination, "")
	if query.Encode() != "" {
		destination = destination + "?" + query.Encode()
	}
	if destination == "" {
		destination = "/"
	}
	// The reference implementation strips the extra leading slash when the
	// destination itself is relative but the generated URL starts with one.
	if !strings.HasPrefix(c.destination, "/") && strings.HasPrefix(destination, "/") {
		destination = strings.TrimPrefix(destination, "/")
	}
	return Redirect(destination, c.status)
}

// --- End controllers.go ---

// --- Begin parameter.go ---
type parameter struct {
	name  string
	value string
}

// --- End parameter.go ---

// --- Begin utils.go ---
// Method converts multiple method strings to an upper-cased slice.
func Method(method ...string) []string {
	var methods []string
	if len(method) == 0 {
		return methods
	}
	for _, m := range method {
		methods = append(methods, strings.ToUpper(m))
	}
	return methods
}

// --- End utils.go ---

// --- Begin static.go ---
type staticHandle struct {
	fileServer http.Handler
	fs         http.FileSystem
}

// NewStaticHandle A Handler responds to a Static HTTP request.
func NewStaticHandle(prefixAndRoot ...string) http.Handler {
	prefix := ""
	root := "."
	if len(prefixAndRoot) == 1 {
		root = prefixAndRoot[0]
	} else if len(prefixAndRoot) >= 2 {
		prefix = "/" + strings.Trim(prefixAndRoot[0], "/")
		root = prefixAndRoot[1]
	}

	fs := http.Dir(root)
	var srv http.Handler = http.FileServer(fs)
	if prefix != "" && prefix != "/" {
		srv = http.StripPrefix(prefix, srv)
	}

	return &staticHandle{
		fileServer: srv,
		fs:         fs,
	}
}

// ServeHTTP responds to a Static HTTP request.
func (s *staticHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.fileServer.ServeHTTP(w, r)
}

// --- End static.go ---

// DispatchToRoute dispatches the request to a matching route and runs it
// )).
func (r *router) DispatchToRoute(request *Request) *Response {
	root := r.root()
	root.flushPending()
	if !root.registered {
		root.register(root)
		root.registered = true
	}
	route, err := root.findRoute(request)
	if err != nil {
		var notFound *NotFoundError
		if errors.As(err, &notFound) {
			return NotFoundResponse().SetContent(notFound.Message)
		}
		var notAllowed *MethodNotAllowedError
		if errors.As(err, &notAllowed) {
			res := NewResponse().SetCode(http.StatusMethodNotAllowed)
			res.Header("Allow", strings.Join(notAllowed.Allowed, ", "))
			res.SetContent(notAllowed.Message)
			return res
		}
		return NotFoundResponse()
	}
	return root.runRoute(request, route)
}

// SubstituteBindings resolves the explicit bindings of the route: every
// parameter with a registered binder is resolved, a failure surfaces as
// *ModelNotFoundError (the reference implementation: substituteBindings + performBinding, which
// rethrows), and resolved values are stored on the route as objects.
// Parameters absent from the request (padded with "" — see Route.Bind) never
// reach a binder, like the reference implementation where substituteBindings only iterates the
// parameters that matched ( + matchToKeys).
func (r *router) SubstituteBindings(route *Route, request *Request, params []*parameter) map[string]any {
	resolved := make(map[string]any)
	for _, p := range params {
		if p.value == "" {
			continue
		}
		name, _ := splitBindingFieldName(p.name)
		if binder := r.getBinder(name); binder != nil {
			val, err := binder(p.value, route)
			if err != nil {
				panic(&ModelNotFoundError{Param: name, Value: p.value, Err: err})
			}
			if val != nil {
				resolved[name] = val
				route.SetParameterValue(request, name, val)
			}
		}
	}
	return resolved
}

// SubstituteImplicitBindings resolves implicit model bindings
// .
// The type-driven resolution runs inside the dispatcher; this method resolves
// the custom implicit binding resolver when one is configured.
func (r *router) SubstituteImplicitBindings(route *Route, request *Request, params []*parameter) map[string]any {
	resolved := make(map[string]any)
	if r.implicitBindingResolver == nil {
		return resolved
	}
	for _, p := range params {
		name, _ := splitBindingFieldName(p.name)
		if val := r.implicitBindingResolver(route, name, p.value); val != nil {
			resolved[name] = val
			route.SetParameterValue(request, name, val)
		}
	}
	return resolved
}

// ToResponse converts a handler result into a *Response.
func ToResponse(request *Request, result any) *Response {
	switch res := result.(type) {
	case *Response:
		return res
	case Response:
		return &res
	case fmt.Stringer:
		return NewResponse().SetCode(200).SetContent(res.String()).Header("Content-Type", "text/html")
	case string:
		return NewResponse().SetCode(200).SetContent(res).Header("Content-Type", "text/html")
	default:
		return NewResponse().SetContent(FormatContent(result))
	}
}

// UniqueMiddleware removes duplicate entries from a middleware list
// . Comparison is reflect-based so
// uncomparable entries (functions, slices, maps) do not panic.
func UniqueMiddleware(middlewares []any) []any {
	var out []any
	for i, m := range middlewares {
		duplicate := false
		for j := 0; j < i; j++ {
			if middlewareEqual(m, middlewares[j]) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			out = append(out, m)
		}
	}
	return out
}

// middlewareEqual compares two middleware entries without panicking on
// uncomparable dynamic types.
func middlewareEqual(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ta := reflect.TypeOf(a)
	if ta.Comparable() && reflect.TypeOf(b).Comparable() {
		if a == b {
			return true
		}
	}
	return reflect.DeepEqual(a, b)
}

// ensureHead appends HEAD when the method list carries GET, mirroring
// the reference route constructor.
func ensureHead(methods []string) []string {
	hasGet, hasHead := false, false
	for _, m := range methods {
		if m == "GET" {
			hasGet = true
		}
		if m == "HEAD" {
			hasHead = true
		}
	}
	if hasGet && !hasHead {
		return append(append([]string(nil), methods...), "HEAD")
	}
	return methods
}

// Terminate calls Terminate on all terminable middlewares for the request.
func (r *router) Terminate(request *Request, response any) {
	if request == nil {
		return
	}
	for _, m := range request.RouteMiddlewares() {
		if terminable, ok := m.(Terminable); ok {
			terminable.Terminate(request, response)
		}
	}
}
