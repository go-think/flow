package flow

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"path"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// Router defines the interface for the routing system.
type Router interface {
	// Add registers a new route.
	Add(method []string, pattern string, handler interface{}) Router
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
	// Any registers a route responding to all standard verbs.
	Any(pattern string, handler interface{}) Router
	// Head registers a HEAD route.
	Head(pattern string, handler interface{}) Router
	// Static registers static file serving under the given path prefix.
	Static(path, root string)
	// Group creates a route group whose attributes (prefix, name, middleware,
	// where) are merged into every route registered inside the callback.
	Group(attrs GroupAttributes, callback func(group Router))
	// Prefix adds a prefix to the current route group.
	Prefix(prefix string) Router
	// Middleware adds middleware to the current route or group.
	Middleware(middlewares ...interface{}) Router
	// WithoutMiddleware excludes middlewares from the current route or group.
	WithoutMiddleware(middlewares ...interface{}) Router
	// Dispatch resolves the request to a handler and executes it.
	Dispatch(request *Request) interface{}
	// Name names the route.
	Name(name string) Router
	// Url generates a URL for a named route.
	Url(name string, params map[string]string) string
	// Fallback registers a fallback route.
	Fallback(handler interface{})
	// Where adds a regex constraint to a route parameter.
	Where(name string, expression string) Router
	// WhereNumber adds a numeric regex constraint to parameters.
	WhereNumber(names ...string) Router
	// WhereAlpha adds an alphabetic regex constraint to parameters.
	WhereAlpha(names ...string) Router
	// WhereIn adds an allowed values constraint to a parameter.
	WhereIn(name string, allowed []string) Router
	// Has determines if the route collection contains a given named route.
	Has(name string) bool
	// Bind registers an explicit binder for a route parameter name.
	Bind(key string, binder Binder)
	// CurrentRouteName returns the current route name for the request.
	CurrentRouteName(req *Request) string
	// Is determines if the current route's name matches given patterns.
	Is(req *Request, patterns ...string) bool
	// Register compiles and indexes the collected routes.
	Register()
	// Dump returns a byte slice dump of all registered routes.
	Dump() []byte
	// RegisterController registers a controller instance under a name so
	// string actions ("Name@Method") can reference it.
	RegisterController(name string, controller any)
	// SetControllerDispatcher replaces the controller dispatcher.
	SetControllerDispatcher(dispatcher ControllerDispatcher)

	// SignedUrl creates a signed URL for a named route.
	SignedUrl(name string, expiration time.Duration, params map[string]string) string
	// HasValidSignature determines if the request has a valid signature.
	HasValidSignature(req *Request) bool
	// NamedRoutePattern returns the raw path pattern of a named route (e.g.
	// "/users/{id}"). ok is false when no route carries the name.
	NamedRoutePattern(name string) (pattern string, ok bool)
	// AliasMiddleware registers a route-specific middleware alias.
	AliasMiddleware(name string, middleware interface{}) Router
	// MiddlewareGroup defines a named middleware group.
	MiddlewareGroup(name string, middlewares ...interface{}) Router
	// GetRouteMiddleware retrieves a registered middleware alias.
	GetRouteMiddleware(name string) interface{}
	// GetMiddlewareGroup retrieves a registered middleware group.
	GetMiddlewareGroup(name string) []interface{}
	// HasMiddlewareGroup determines if a middleware group with the name exists.
	HasMiddlewareGroup(name string) bool
	// PrependMiddlewareToGroup prepends middleware to an existing group.
	PrependMiddlewareToGroup(name string, middleware interface{})
	// PushMiddlewareToGroup appends middleware to an existing group.
	PushMiddlewareToGroup(name string, middleware interface{})
	// RemoveMiddlewareFromGroup removes middleware from an existing group.
	RemoveMiddlewareFromGroup(name string, middleware interface{})
	// FlushMiddlewareGroups clears all middleware groups.
	FlushMiddlewareGroups()
	// MiddlewarePriority sets the middleware priority order.
	MiddlewarePriority(middlewares ...interface{})

	// CurrentRoute returns the route matched by the most recent dispatch.
	CurrentRoute() *Route
	// CurrentRequest returns the request of the most recent dispatch.
	CurrentRequest() *Request
	// MatchRequest resolves a request to a route and binds its parameters.
	MatchRequest(request *Request) (*Route, error)
	// GetRoutes returns every registered route.
	GetRoutes() []*Route

	// OnRouting registers a callback fired before a request is matched.
	OnRouting(callback func(request *Request))
	// OnRouteMatched registers a callback fired after a route is matched.
	OnRouteMatched(callback func(route *Route, request *Request))
	// OnPreparingResponse registers a callback fired before the response is built.
	OnPreparingResponse(callback func(request *Request, result any))
	// OnResponsePrepared registers a callback fired after the response is built.
	OnResponsePrepared(callback func(request *Request, response *Response))
	// DisableMiddleware disables (or re-enables) all route middleware.
	DisableMiddleware(disable bool)
}

// --- End router.go ---

// GroupAttributes carries the attributes merged into every route registered
// inside a group: the prefix is concatenated (outer first), the name is used
// as a name prefix, middleware entries are appended, and where constraints
// are merged.
type GroupAttributes struct {
	Prefix     string
	Name       string
	Controller string // namespace prefix applied to string controller actions
	Middleware []interface{}
	Wheres     map[string]string
}

var verbs = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

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

	method             []string
	prefix             string
	pattern            string
	handler            interface{}
	middlewares        []interface{}
	withoutMiddleware  []interface{}
	group              *router
	controllerPrefix   string
	name               string
	wheres             map[string]string
	groupWheres        map[string]string
	patterns           map[string]string
	signatureKey       string
	middlewareAliases  map[string]interface{}
	middlewareGroups   map[string][]interface{}
	middlewarePriority []interface{}
	parameterResolver  ParameterResolver
	binders            map[string]Binder

	collects []*router

	collection           *RouteCollection
	fallback             interface{}
	currentRoute         *Route
	currentRequest       *Request
	disableMiddleware    bool
	controllers          map[string]any
	controllerDispatcher ControllerDispatcher

	onRouting           []func(request *Request)
	onRouteMatched      []func(route *Route, request *Request)
	onPreparingResponse []func(request *Request, result any)
	onResponsePrepared  []func(request *Request, response *Response)
}

// New creates a new Router with optional configuration options.
func New(opts ...Option) Router {
	rt := &router{
		collection:        NewRouteCollection(),
		patterns:          make(map[string]string),
		wheres:            make(map[string]string),
		middlewareAliases: make(map[string]interface{}),
		middlewareGroups:  make(map[string][]interface{}),
		controllers:       make(map[string]any),
	}

	for _, opt := range opts {
		opt(rt)
	}

	return rt
}

// Dispatch resolves the request to a route and executes it. A miss falls back
// to the fallback route (when registered) or a 404 response; a verb mismatch
// produces a 405 response with an Allow header.
func (r *router) Dispatch(request *Request) interface{} {
	r.currentRequest = request
	for _, fn := range r.onRouting {
		fn(request)
	}

	route, params, err := r.findRoute(request)
	if err != nil {
		// The fallback route matches any path and verb, so it takes
		// priority over a 405.
		if r.fallback != nil {
			fallbackRoute := &Route{
				methods:  verbs,
				uri:      "/fallback",
				name:     "fallback",
				handler:  r.fallback,
				fallback: true,
				router:   r,
			}
			return r.runRoute(request, fallbackRoute, nil)
		}
		var notAllowed *MethodNotAllowedError
		if errors.As(err, &notAllowed) {
			res := NewResponse().SetCode(http.StatusMethodNotAllowed)
			res.Header.Set("Allow", strings.Join(notAllowed.Allowed, ", "))
			return res
		}
		return NotFoundResponse()
	}

	return r.runRoute(request, route, params)
}

// findRoute resolves the request to a Route entity, records it as the
// current route and binds its parameters.
func (r *router) findRoute(request *Request) (*Route, []*parameter, error) {
	route, params, err := r.collection.Match(request)
	if err != nil {
		return nil, nil, err
	}

	params = route.Bind(request, request.GetPath(), params)

	if route.name != "" {
		request.Set("_route_name", route.name)
	}
	r.currentRoute = route
	return route, params, nil
}

// runRoute fires the matched callbacks and runs the route within its
// middleware stack.
func (r *router) runRoute(request *Request, route *Route, params []*parameter) interface{} {
	for _, fn := range r.onRouteMatched {
		fn(route, request)
	}

	var result any
	if r.disableMiddleware {
		result = route.Run(request, params)
	} else {
		result = r.runRouteWithinStack(route, request, params)
	}
	return r.prepareResponse(request, result)
}

// runRouteWithinStack gathers the route middleware (resolved, sorted,
// excluding route-level exclusions) and runs the action inside the onion. The
// response is prepared inside the pipeline destination so that middlewares
// always observe a *Response on the way out.
func (r *router) runRouteWithinStack(route *Route, request *Request, params []*parameter) any {
	pipeline := NewPipeline()

	resolved := r.gatherRouteMiddleware(route)
	var applied []any
	for _, md := range resolved {
		pipeline.Pipe(HandlerFunc(md))
		applied = append(applied, md)
	}
	request.SetRouteMiddlewares(applied)

	return pipeline.Send(request).Then(func(req *Request) any {
		return r.prepareResponse(req, route.Run(req, params))
	})
}

// gatherRouteMiddleware collects the raw middleware entries of the route
// (skipping route-level exclusions), orders them by the priority list, and
// then resolves them into Middleware instances.
func (r *router) gatherRouteMiddleware(route *Route) []Middleware {
	var raw []any
	for _, m := range route.GatherMiddleware() {
		if isExcludedMiddleware(m, route.ExcludedMiddleware()) {
			continue
		}
		raw = append(raw, m)
	}
	raw = sortMiddlewareRaw(raw, r.middlewarePriority)

	var resolved []Middleware
	for _, m := range raw {
		resolved = append(resolved, resolveMiddleware(m, r)...)
	}
	return resolved
}

// isExcludedMiddleware reports whether the raw entry matches one of the
// exclusions (by value equality or deep equality).
func isExcludedMiddleware(m interface{}, excluded []interface{}) bool {
	for _, e := range excluded {
		if m == e {
			return true
		}
		if reflect.DeepEqual(m, e) {
			return true
		}
	}
	return false
}

// sortMiddlewareRaw orders raw middleware entries by the priority list;
// entries not in the list keep their relative order after the ranked ones.
func sortMiddlewareRaw(raw []any, priority []any) []any {
	if len(priority) == 0 || len(raw) < 2 {
		return raw
	}

	rank := func(m any) int {
		for i, p := range priority {
			if m == p || reflect.DeepEqual(m, p) {
				return i
			}
		}
		return len(priority)
	}

	ordered := make([]any, len(raw))
	copy(ordered, raw)
	// Stable insertion sort by rank keeps the relative order of equal ranks.
	for i := 1; i < len(ordered); i++ {
		for j := i; j > 0 && rank(ordered[j]) < rank(ordered[j-1]); j-- {
			ordered[j], ordered[j-1] = ordered[j-1], ordered[j]
		}
	}
	return ordered
}

// Add registers a new route. The pattern is stored raw; group prefixes are
// applied once at Register time.
func (r *router) Add(method []string, pattern string, handler interface{}) Router {
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

// Prefix adds a prefix to the current route group.
func (r *router) Prefix(prefix string) Router {
	route := r.initRoute()
	route.prefix = route.getPrefix(prefix)
	return route
}

// Group creates a route group whose attributes are merged into the routes
// registered inside the callback: prefixes concatenate (outer first), the
// group name prefixes route names, middleware entries are appended and where
// constraints are merged.
func (r *router) Group(attrs GroupAttributes, callback func(group Router)) {
	node := r.cloneRoute()
	node.prefix = attrs.Prefix
	node.controllerPrefix = attrs.Controller
	node.name = node.name + attrs.Name
	for k, v := range attrs.Wheres {
		if node.groupWheres == nil {
			node.groupWheres = make(map[string]string)
		}
		node.groupWheres[k] = v
	}
	if len(attrs.Middleware) > 0 {
		md := make([]interface{}, 0, len(node.middlewares)+len(attrs.Middleware))
		md = append(md, node.middlewares...)
		md = append(md, attrs.Middleware...)
		node.middlewares = md
	}

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

// Name names the route (prefixed by the enclosing group name, if any).
func (r *router) Name(name string) Router {
	route := r.initRoute()
	route.name = r.name + name
	return route
}

// Url generates a URL for a named route.
//
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

// Fallback registers a fallback route.
func (r *router) Fallback(handler interface{}) {
	r.fallback = handler
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

// WhereNumber adds a numeric regex constraint to parameters.
func (r *router) WhereNumber(names ...string) Router {
	for _, name := range names {
		r.Where(name, "^[0-9]+$")
	}
	return r
}

// WhereAlpha adds an alphabetic regex constraint to parameters.
func (r *router) WhereAlpha(names ...string) Router {
	for _, name := range names {
		r.Where(name, "^[a-zA-Z]+$")
	}
	return r
}

// WhereIn adds an allowed values constraint to a parameter.
func (r *router) WhereIn(name string, allowed []string) Router {
	escaped := make([]string, len(allowed))
	for i, val := range allowed {
		escaped[i] = regexpQuote(val)
	}
	return r.Where(name, "^("+strings.Join(escaped, "|")+")$")
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
// the route collection.
func (r *router) Register() {
	r.register(r)
}

// Dump returns a debug dump of all registered routes.
func (r *router) Dump() []byte {
	var b bytes.Buffer
	for _, route := range r.collection.All() {
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
				action.Controller = node.controllerPrefix + "." + name
				actionHandler = action
			}
		}
		entity := &Route{
			methods:           node.method,
			uri:               routePattern,
			name:              node.name,
			handler:           actionHandler,
			middlewares:       node.middlewares,
			withoutMiddleware: node.withoutMiddleware,
			wheres:            combinedWheres,
			router:            root,
		}

		root.collection.Add(entity)
	}
	r.collects = r.collects[0:0]
}

// initRoute returns the node itself when already initialized as a pending
// route, otherwise creates a child node attached to this one.
func (r *router) initRoute() *router {
	route := r
	if !r.inited {
		route = &router{
			inited:             true,
			name:               r.name,
			controllerPrefix:   r.controllerPrefix,
			group:              r,
			parameterResolver:  r.parameterResolver,
			signatureKey:       r.signatureKey,
			middlewareAliases:  r.middlewareAliases,
			middlewareGroups:   r.middlewareGroups,
			middlewarePriority: r.middlewarePriority,
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
		name:               r.name,
		controllerPrefix:   r.controllerPrefix,
		group:              r,
		parameterResolver:  r.parameterResolver,
		signatureKey:       r.signatureKey,
		middlewareAliases:  r.middlewareAliases,
		middlewareGroups:   r.middlewareGroups,
		middlewarePriority: r.middlewarePriority,
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

// PrependMiddlewareToGroup prepends middleware to an existing group.
func (r *router) PrependMiddlewareToGroup(name string, middleware interface{}) {
	if group, ok := r.middlewareGroups[name]; ok {
		r.middlewareGroups[name] = append([]interface{}{middleware}, group...)
	}
}

// PushMiddlewareToGroup appends middleware to an existing group.
func (r *router) PushMiddlewareToGroup(name string, middleware interface{}) {
	if group, ok := r.middlewareGroups[name]; ok {
		r.middlewareGroups[name] = append(group, middleware)
	}
}

// RemoveMiddlewareFromGroup removes middleware from an existing group.
func (r *router) RemoveMiddlewareFromGroup(name string, middleware interface{}) {
	if group, ok := r.middlewareGroups[name]; ok {
		var kept []interface{}
		for _, m := range group {
			if m == middleware || reflect.DeepEqual(m, middleware) {
				continue
			}
			kept = append(kept, m)
		}
		r.middlewareGroups[name] = kept
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

// SignedUrl creates a signed URL for a named route.
//
// Deprecated: use UrlGenerator (see NewUrlGenerator) for URL signing; it adds
// lazy key resolution and key rotation support. This delegate keeps working
// with the key set via WithSignatureKey/ResolveSignatureKey.
func (r *router) SignedUrl(name string, expiration time.Duration, params map[string]string) string {
	return r.legacyUrlGenerator().SignedRoute(name, params, expiration)
}

// HasValidSignature checks if the given request has a valid signature.
//
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
	return r.collection.HasNamedRoute(name)
}

// CurrentRouteName returns the current route name for the request.
func (r *router) CurrentRouteName(req *Request) string {
	if req == nil {
		return ""
	}
	if nameVal, ok := req.Get("_route_name"); ok {
		if name, ok := nameVal.(string); ok {
			return name
		}
	}
	return ""
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
	if r.collection == nil {
		return "", false
	}
	route, ok := r.collection.GetByName(name)
	if !ok {
		return "", false
	}
	return route.URI(), true
}

// CurrentRoute returns the route matched by the most recent dispatch.
func (r *router) CurrentRoute() *Route {
	return r.currentRoute
}

// CurrentRequest returns the request of the most recent dispatch.
func (r *router) CurrentRequest() *Request {
	return r.currentRequest
}

// MatchRequest resolves a request to a Route entity and binds its parameters.
func (r *router) MatchRequest(request *Request) (*Route, error) {
	route, _, err := r.findRoute(request)
	return route, err
}

// GetRoutes returns every registered route.
func (r *router) GetRoutes() []*Route {
	return r.collection.All()
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
	for _, fn := range r.onPreparingResponse {
		fn(request, result)
	}
	var response *Response
	if res, ok := result.(*Response); ok {
		response = res
	} else {
		response = NewResponse().SetContent(FormatContent(result))
	}
	for _, fn := range r.onResponsePrepared {
		fn(request, response)
	}
	return response
}

// RunRoute returns the response for the given route.
//
// Deprecated: the dispatch chain lives on Router (findRoute/runRoute).
func RunRoute(request *Request, route *Route, params ...[]*parameter) interface{} {
	return PrepareResponse(
		request,
		route,
		runMiddlewares(request, route, params...),
	)
}

// PrepareResponse creates a response instance from the given value.
func PrepareResponse(request *Request, route *Route, result interface{}) interface{} {
	if res, ok := result.(*Response); ok {
		return res
	}
	return NewResponse().SetContent(FormatContent(result))
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
	} else if name, ok := m.(string); ok && r != nil {
		var params []string
		if idx := strings.Index(name, ":"); idx != -1 {
			paramsStr := name[idx+1:]
			name = name[:idx]
			params = strings.Split(paramsStr, ",")
		}

		if group := r.GetMiddlewareGroup(name); group != nil {
			for _, gm := range group {
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
			// A raw closure with the middleware signature.
			resolved = append(resolved, func(req *Request, next Closure) interface{} {
				res := val.Call([]reflect.Value{reflect.ValueOf(req), reflect.ValueOf(next)})
				if len(res) > 0 {
					return res[0].Interface()
				}
				return nil
			})
		}
	}
	return resolved
}

// runMiddlewares runs the route within its middleware stack.
//
// Deprecated: the dispatch chain lives on Router (runRouteWithinStack).
func runMiddlewares(request *Request, route *Route, params ...[]*parameter) interface{} {
	pipeline := NewPipeline()

	if route == nil {
		return nil
	}

	var routeMiddlewares []interface{}
	for _, md := range route.GatherMiddleware() {
		for _, resolved := range resolveMiddleware(md, route.router) {
			pipeline.Pipe(HandlerFunc(resolved))
			routeMiddlewares = append(routeMiddlewares, resolved)
		}
	}

	request.SetRouteMiddlewares(routeMiddlewares)

	return pipeline.Send(request).Then(func(req *Request) any {
		return PrepareResponse(
			req,
			route,
			route.Run(req, params...),
		)
	})
}

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
