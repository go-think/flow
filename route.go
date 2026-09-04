package flow

import (
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// routeLocks provides per-URI atomic locks for Block-enabled routes.
type LockProvider interface {
	Acquire(key string, lockSeconds, waitSeconds int) (release func(), ok bool)
}

var routeLocks sync.Map

// matchMethod reports whether a request verb matches a target verb
// (the reference implementation: MethodValidator compares with in_array — both sides are upper
// case by construction, so the comparison is case-insensitive in effect).
func matchMethod(method, target string) bool {
	return strings.EqualFold(target, method)
}

// matchMethods reports whether a request verb matches any of the targets.
func matchMethods(method string, target []string) bool {
	for _, v := range target {
		if matchMethod(method, v) {
			return true
		}
	}
	return false
}

// optionalParamRegex strips unprovided optional parameters, e.g. /{param?}.
var optionalParamRegex = regexp.MustCompile(`(/)?\{[a-zA-Z0-9_]+\?\}`)

// Route is a single registered route: its verb list, URI pattern, constraints,
// defaults, middleware and action, plus the compiled matching artifacts.
// syncOnceAlias is an alias for sync.Once used in recompilation.
type syncOnceAlias = sync.Once

type Route struct {
	methods           []string
	uri               string
	prefix            string
	name              string
	handler           any
	middlewares       []any
	withoutMiddleware []any
	wheres            map[string]string
	bindingFields     map[string]string
	defaults          map[string]any
	metadata          map[string]any
	fallback          bool
	secure            bool
	httpOnly          bool
	domain            string
	scopedBindings    bool
	scopedDisabled    bool
	withTrashed       bool
	missing           func(request *Request, err error) any
	lockSeconds       int
	waitSeconds       int
	validators        []RouteValidator

	router *router // back reference for resolver/registry lookups

	// Bind-time parameter snapshot lives on the request so concurrent
	// dispatches sharing one Route never race (the reference implementation stores the state on
	// the route itself, which is safe under PHP's per-worker model).

	expanded           []*compiledPattern
	compiledHostRegex  *regexp.Regexp
	hostParameterNames []string
	compileOnce        sync.Once

	// computedMiddleware caches the gathered middleware list
	//.
	middlewareMu       sync.Mutex
	computedMiddleware []any
}

// compiledPattern is one matchable variant of the route URI. Routes with
// optional parameters ("{name?}") expand into several variants.
type compiledPattern struct {
	pattern        string
	regex          *regexp.Regexp
	parameterNames []string
}

// Methods returns the HTTP verbs this route responds to.
func (r *Route) Methods() []string {
	return r.methods
}

// URI returns the raw path pattern of the route (e.g. "/users/{id}").
func (r *Route) URI() string {
	return r.uri
}

// Uri is the the reference implementation-style spelling of URI.
func (r *Route) Uri() string {
	return r.uri
}

// GetUri returns the URI pattern of the route.
func (r *Route) GetUri() string {
	return r.uri
}

// SetUri updates the route URI pattern (the reference implementation: setUri + parseUri — the URI
// is passed through, extracting binding fields and rewriting
// "{user:id}" placeholders to "{user}").
func (r *Route) SetUri(uri string) *Route {
	parsed := ParseRouteUri(uri)
	r.uri = "/" + strings.TrimLeft(parsed.URI, "/")
	r.bindingFields = parsed.BindingFields
	r.invalidateCompile()
	return r
}

// SetPrefix overwrites the route URI prefix.
func (r *Route) SetPrefix(prefix string) *Route {
	cleanPrefix := "/" + strings.Trim(prefix, "/")
	if cleanPrefix == "/" {
		cleanPrefix = ""
	}
	r.prefix = cleanPrefix
	if !strings.HasPrefix(r.uri, cleanPrefix) {
		r.uri = cleanPrefix + r.uri
	}
	r.invalidateCompile()
	return r
}

// GetPrefix returns the route URI prefix.
func (r *Route) GetPrefix() string {
	return r.prefix
}

// ExcludedControllerMiddleware returns controller middleware excluded via PHP
// attributes (the reference implementation: collects the
// WithoutMiddleware attribute only). Go has no attribute mechanism: controller
// middleware filtered by an entry's Except list is already removed in
// GetMiddleware (methodExcludedByOptions), and per the reference implementation such entries never
// join the route's excluded-middleware list, so this returns nil.
func (r *Route) ExcludedControllerMiddleware() []any {
	return nil
}

// ActionName returns the canonical action identifier used by the action
// lookup: "Name@Method" for controller actions, the normalized runtime name
// ("Type.Method") for method-value handlers.
func (r *Route) ActionName() string {
	if r == nil || r.handler == nil {
		return ""
	}
	if ca, ok := r.handler.(ControllerAction); ok {
		if name, isName := ca.Controller.(string); isName {
			return name + "@" + ca.Method
		}
		return fmt.Sprintf("%T@%s", ca.Controller, ca.Method)
	}
	if reflect.ValueOf(r.handler).Kind() == reflect.Func {
		return normalizeRuntimeActionName(runtime.FuncForPC(reflect.ValueOf(r.handler).Pointer()).Name())
	}
	return ""
}

// normalizeRuntimeActionName converts a runtime function name into the public action
// form: "pkg.(*Type).Method-fm" -> "Type.Method".
func normalizeRuntimeActionName(name string) string {
	name = strings.TrimSuffix(name, "-fm")
	if idx := strings.Index(name, ")."); idx != -1 {
		left := name[:idx]
		if dot := strings.LastIndex(left, "."); dot != -1 {
			left = left[dot+1:]
		}
		left = strings.TrimPrefix(left, "(*")
		return left + "." + name[idx+2:]
	}
	parts := strings.Split(name, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return name
}

// Name returns the route name.
func (r *Route) GetName() string {
	return r.name
}

// Name adds or changes the route name. Like the reference name(), the given name
// is concatenated onto any name prefix the route already carries (group "as"
// prefixes), so name("admin.") + name("users") yields "admin.users".
func (r *Route) Name(name string) *Route {
	r.name += name
	return r
}

// SetName sets the route name.
func (r *Route) SetName(name string) *Route {
	r.name = name
	return r
}

// Handler returns the route action.
func (r *Route) Handler() any {
	return r.handler
}

// Wheres returns the parameter constraints of the route.
func (r *Route) Wheres() map[string]string {
	return r.wheres
}

// Where adds a regex constraint.
func (r *Route) Where(name, expression string) *Route {
	return r.SetWhere(name, expression)
}

// SetWhere adds a regex constraint for a route parameter.
func (r *Route) SetWhere(name, expression string) *Route {
	if r.wheres == nil {
		r.wheres = make(map[string]string)
	}
	r.wheres[name] = expression
	r.invalidateCompile()
	return r
}

// WhereNumber adds a numeric regex constraint to parameters
//.
func (r *Route) WhereNumber(names ...string) *Route {
	for _, name := range names {
		r.SetWhere(name, "[0-9]+")
	}
	return r
}

// WhereAlpha adds an alphabetic regex constraint to parameters
//.
func (r *Route) WhereAlpha(names ...string) *Route {
	for _, name := range names {
		r.SetWhere(name, "[a-zA-Z]+")
	}
	return r
}

// WhereAlphaNumeric adds an alphanumeric regex constraint to parameters
//.
func (r *Route) WhereAlphaNumeric(names ...string) *Route {
	for _, name := range names {
		r.SetWhere(name, "[a-zA-Z0-9]+")
	}
	return r
}

// WhereUuid adds a UUID regex constraint to parameters
//.
func (r *Route) WhereUuid(names ...string) *Route {
	for _, name := range names {
		r.SetWhere(name, `[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}`)
	}
	return r
}

// WhereUlid adds a ULID regex constraint to parameters
//.
func (r *Route) WhereUlid(names ...string) *Route {
	for _, name := range names {
		r.SetWhere(name, `[0-7][0-9a-hjkmnp-tv-zA-HJKMNP-TV-Z]{25}`)
	}
	return r
}

// WhereIn adds an allowed values constraint to a parameter
// (the reference implementation: — values are
// joined without escaping).
func (r *Route) WhereIn(name string, allowed []string) *Route {
	return r.SetWhere(name, strings.Join(allowed, "|"))
}

// Defaults returns the route parameter defaults.
func (r *Route) Defaults() map[string]any {
	return r.defaults
}

// SetDefault sets a default value for a route parameter.
func (r *Route) SetDefault(key string, value any) *Route {
	if r.defaults == nil {
		r.defaults = make(map[string]any)
	}
	r.defaults[key] = value
	return r
}

// Metadata returns route metadata, or the default when the key is absent.
func (r *Route) Metadata(key string, defaultValue ...any) any {
	if v, ok := r.metadata[key]; ok {
		return v
	}
	if len(defaultValue) > 0 {
		return defaultValue[0]
	}
	return nil
}

// MetadataAll returns the whole metadata map — the nil-key form of the reference implementation
// getMetadata with a null key).
func (r *Route) MetadataAll() map[string]any {
	return r.metadata
}

// MergeMetadata recursively merges the given metadata into the route's
// metadata: map values are merged key-wise, other values replace
//.
func (r *Route) MergeMetadata(metadata map[string]any) *Route {
	r.metadata = mergeMetadataDeep(r.metadata, metadata)
	return r
}

// ReplaceMetadata replaces the whole metadata map.
func (r *Route) ReplaceMetadata(metadata map[string]any) *Route {
	r.metadata = metadata
	return r
}

// mergeMetadataDeep implements: associated map
// values merge recursively, list/scalar values replace wholesale.
func mergeMetadataDeep(old, new map[string]any) map[string]any {
	out := make(map[string]any, len(old)+len(new))
	for k, v := range old {
		out[k] = v
	}
	for k, v := range new {
		if oldMap, okOld := out[k].(map[string]any); okOld {
			if newMap, okNew := v.(map[string]any); okNew {
				out[k] = mergeMetadataDeep(oldMap, newMap)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// strIs replicates: the "*" wildcard becomes ".*",
// the rest is quoted, the match is anchored and case-sensitive.
func strIs(pattern, value string) bool {
	if pattern == value {
		return true
	}
	pat := regexp.QuoteMeta(pattern)
	pat = strings.ReplaceAll(pat, `\*`, ".*")
	matched, err := regexp.MatchString("^"+pat+"$", value)
	return err == nil && matched
}

// SetMetadata stores route metadata.
func (r *Route) SetMetadata(key string, value any) *Route {
	if r.metadata == nil {
		r.metadata = make(map[string]any)
	}
	r.metadata[key] = value
	return r
}

// SetFallback marks this route as a fallback route.
func (r *Route) SetFallback(isFallback bool) *Route {
	r.fallback = isFallback
	return r
}

// IsFallback reports whether this route is the router fallback.
func (r *Route) IsFallback() bool {
	return r.fallback
}

// Validators returns the route validators to run for this route
//.
func (r *Route) Validators() []RouteValidator {
	if r.validators != nil {
		return r.validators
	}
	return defaultValidators()
}

// SetValidators sets custom route validators for this route
//.
func (r *Route) SetValidators(validators []RouteValidator) *Route {
	r.validators = validators
	return r
}

// Matches reports whether the candidate route satisfies all validators for the request
//.
func (r *Route) Matches(request *Request, includingMethod ...bool) bool {
	checkMethod := true
	if len(includingMethod) > 0 {
		checkMethod = includingMethod[0]
	}
	for _, v := range r.Validators() {
		if !checkMethod {
			if _, isMethod := v.(MethodValidator); isMethod {
				continue
			}
		}
		if !v.Matches(r, request) {
			return false
		}
	}
	return true
}

// Prefix adds a URI prefix to the route.
// The new prefix is recorded on the route and prepended to any prefix it
// already carries; the URI gets the prefix prepended as well.
func (r *Route) Prefix(prefix string) *Route {
	if r == nil {
		return r
	}
	// updatePrefixOnAction — new prefix comes before the old one.
	if newPrefix := strings.Trim(strings.TrimRight(prefix, "/")+"/"+strings.TrimLeft(r.prefix, "/"), "/"); newPrefix != "" {
		r.prefix = newPrefix
	}
	uri := strings.Trim(strings.TrimRight(prefix, "/")+"/"+strings.TrimLeft(r.uri, "/"), "/")
	if uri == "" {
		r.uri = "/"
	} else {
		r.uri = "/" + uri
	}
	r.invalidateCompile()
	return r
}

// Secure marks the route as requiring an HTTPS request.
func (r *Route) Secure() *Route {
	r.secure = true
	r.httpOnly = false
	return r
}

// IsSecure reports whether the route requires HTTPS.
func (r *Route) IsSecure() bool {
	return r.secure
}

// HttpOnly marks the route as requiring an HTTP (non-secure) request.
func (r *Route) HttpOnly() *Route {
	r.httpOnly = true
	r.secure = false
	return r
}

// IsHttpOnly reports whether the route requires standard HTTP.
func (r *Route) IsHttpOnly() bool {
	return r.httpOnly
}

// Missing sets the callback to run when a route binding cannot be resolved.
func (r *Route) Missing(callback func(request *Request, err error) any) *Route {
	r.missing = callback
	return r
}

// GetMissing returns the missing binding callback, if configured.
func (r *Route) GetMissing() func(request *Request, err error) any {
	return r.missing
}

// SetDomain restricts the route to a request host (e.g. "api.example.com" or "{account}.example.com").
func (r *Route) SetDomain(domain string) *Route {
	r.domain = domain
	r.invalidateCompile()
	return r
}

// Domain sets the route host restriction (the reference implementation: domain — the domain is
// parsed with, merging any "{account:id}" binding fields).
func (r *Route) Domain(domain string) *Route {
	parsed := ParseRouteUri(domain)
	r.domain = parsed.URI
	if len(parsed.BindingFields) > 0 {
		merged := make(map[string]string, len(r.bindingFields)+len(parsed.BindingFields))
		for k, v := range r.bindingFields {
			merged[k] = v
		}
		for k, v := range parsed.BindingFields {
			merged[k] = v
		}
		r.bindingFields = merged
	}
	r.invalidateCompile()
	return r
}

// GetDomain returns the route host restriction, or "" when unrestricted. Any
// scheme prefix is stripped.
func (r *Route) GetDomain() string {
	domain := r.domain
	domain = strings.ReplaceAll(domain, "http://", "")
	domain = strings.ReplaceAll(domain, "https://", "")
	return domain
}

// ScopeBindings marks nested resource parameters as bound in a scoped chain.
// The last scope decision wins (the reference implementation: scopeBindings overrides a previous
// withoutScopedBindings call).
func (r *Route) ScopeBindings() *Route {
	r.scopedBindings = true
	r.scopedDisabled = false
	return r
}

// EnforcesScopedBindings reports whether scoped binding is enforced.
func (r *Route) EnforcesScopedBindings() bool {
	return r.scopedBindings
}

// BindingFields returns the binding fields declared for parameters
//.
func (r *Route) BindingFields() map[string]string {
	return r.bindingFields
}

// SetBindingFieldFor sets the custom binding field for a route parameter
//.
func (r *Route) SetBindingFieldFor(parameter, field string) *Route {
	if r.bindingFields == nil {
		r.bindingFields = make(map[string]string)
	}
	r.bindingFields[parameter] = field
	r.invalidateCompile()
	return r
}

// SetBindingFields replaces the map of parameter binding fields
//.
func (r *Route) SetBindingFields(fields map[string]string) *Route {
	r.bindingFields = fields
	r.invalidateCompile()
	return r
}

// BindingFieldFor returns the binding field declared for a parameter
//.
func (r *Route) BindingFieldFor(name string) string {
	return r.bindingFieldFor(name)
}

// WithTrashed marks the route as allowing soft-deleted entities in bindings
//.
func (r *Route) WithTrashed(withTrashed ...bool) *Route {
	value := true
	if len(withTrashed) > 0 {
		value = withTrashed[0]
	}
	r.withTrashed = value
	return r
}

// AllowsTrashedBindings reports whether trashed entities may be bound.
func (r *Route) AllowsTrashedBindings() bool {
	return r.withTrashed
}

// SetWheres replaces all parameter constraints.
func (r *Route) SetWheres(wheres map[string]string) *Route {
	if r.wheres == nil {
		r.wheres = make(map[string]string)
	}
	// the reference setWheres merges into the existing constraints (it calls
	// where() per entry) rather than replacing them.
	for k, v := range wheres {
		r.wheres[k] = v
	}
	r.invalidateCompile()
	return r
}

// SetDefaults replaces all parameter defaults.
func (r *Route) SetDefaults(defaults map[string]any) *Route {
	r.defaults = defaults
	return r
}

// HasParameters reports whether the route declares parameters. the reference implementation checks
// the bound-parameter state on the route; flow keeps binding state per request
// for concurrency safety, so the declaration is reported here.
func (r *Route) HasParameters() bool {
	return len(r.ParameterNames()) > 0
}

// HasParameter reports whether the named parameter is declared on the route.
func (r *Route) HasParameter(name string) bool {
	for _, n := range r.ParameterNames() {
		if n == name {
			return true
		}
	}
	return false
}

// WithoutMiddleware excludes middlewares (matched by value equality on the
// raw registration entry) from this route.
func (r *Route) WithoutMiddleware(middlewares ...any) *Route {
	r.withoutMiddleware = append(r.withoutMiddleware, middlewares...)
	r.computedMiddleware = nil
	return r
}

// ExcludedMiddleware returns the middleware that should be removed from the
// route: the route-level exclusions merged with the controller-level ones
//.
func (r *Route) ExcludedMiddleware() []any {
	out := append([]any(nil), r.withoutMiddleware...)
	return append(out, r.ExcludedControllerMiddleware()...)
}

// Middleware returns the raw middleware entries, or appends when args provided
//.
func (r *Route) Middleware(middleware ...any) *Route {
	if len(middleware) == 0 {
		return r
	}
	r.middlewares = append(r.middlewares, middleware...)
	r.computedMiddleware = nil
	return r
}

// GetMiddleware returns the raw middleware entries (read-only).
func (r *Route) GetMiddleware() []any {
	return r.middlewares
}

// ControllerMiddleware returns only the middleware declared by the route's
// controller.
func (r *Route) ControllerMiddleware() []any {
	if action, ok := r.handler.(ControllerAction); ok {
		dispatcher := r.router.getControllerDispatcher()
		if controller, err := dispatcher.ResolveController(action); err == nil {
			return dispatcher.GetMiddleware(controller, action.Method)
		}
	}
	return nil
}

// GatherMiddleware returns all middleware for the route: the entries attached
// at registration plus the middleware the controller declares for its method
// (with only/except filters applied), deduplicated and cached
//.
func (r *Route) GatherMiddleware() []any {
	r.middlewareMu.Lock()
	defer r.middlewareMu.Unlock()
	if r.computedMiddleware != nil {
		return r.computedMiddleware
	}
	out := append([]any(nil), r.middlewares...)
	if action, ok := r.handler.(ControllerAction); ok {
		dispatcher := r.router.getControllerDispatcher()
		if controller, err := dispatcher.ResolveController(action); err == nil {
			out = append(out, dispatcher.GetMiddleware(controller, action.Method)...)
		}
	}
	r.computedMiddleware = UniqueMiddleware(out)
	return r.computedMiddleware
}

// FlushComputedMiddleware clears the gathered middleware cache
//.
func (r *Route) FlushComputedMiddleware() *Route {
	r.computedMiddleware = nil
	return r
}

// HandleMatchedRoute binds the request parameters and returns the bound route
//.
func (r *Route) HandleMatchedRoute(request *Request) *Route {
	r.Bind(request, request.GetPath())
	return r
}

// MatchesMethodAndPath determines whether the route matches the given method and path.
func (r *Route) MatchesMethodAndPath(method, path string) bool {
	r.compile()
	if !matchMethods(method, r.methods) {
		return false
	}
	for _, variant := range r.expanded {
		if variant.regex != nil && variant.regex.MatchString(path) {
			return true
		}
	}
	return false
}

// Bind extracts the route parameters for a request, stores them on the route
// (the reference implementation: bind — + originalParameters
// snapshot) and mirrors them onto the request for Context access. Host
// parameters extracted from a dynamic domain come first, path parameters
// follow in declaration order, and defaults fill anything missing.
func (r *Route) Bind(req *Request, path string, treeParams ...[]*parameter) []*parameter {
	r.compile()

	binder := NewRouteParameterBinder(r)
	parameters := binder.Parameters(req)

	// A declared parameter that produced no match is padded with "" — Go
	// cannot pass nil to a string parameter, so this is the zero-value
	// coercion of the reference null at the call boundary. Model/pointer binding
	// skips empty values (parseParams), mirroring the reference implementation where the parameter
	// is absent and the binding is skipped.
	for _, name := range r.ParameterNames() {
		found := false
		for _, p := range parameters {
			if p.name == name {
				found = true
				break
			}
		}
		if !found {
			value := ""
			if r.defaults != nil {
				if d, ok := r.defaults[name]; ok {
					value = fmt.Sprintf("%v", d)
				}
			}
			parameters = append(parameters, &parameter{name: name, value: value})
		}
	}

	// Mirror the parameters onto the request and snapshot the original values
	// there too (the reference implementation: parameters + originalParameters; flow keeps the
	// state per-request so shared routes stay concurrency-safe).
	if req != nil {
		for _, p := range parameters {
			req.SetRouteParam(p.name, p.value)
		}
		req.SetOriginalParams(parameters)
	}

	return parameters
}

// Run executes the route action and returns its raw result. When no explicit
// parameters are passed, they are recovered from the request by the parameter
// names declared in the pattern. A route without an action fails like
// the reference ("Route [uri] has no action.")
// instead of silently returning nil.
func (r *Route) Run(request *Request, params ...[]*parameter) (result any) {
	if r == nil {
		return nil
	}
	if r.handler == nil {
		panic(fmt.Sprintf("Route for [%s] has no action.", r.uri))
	}

	// Atomic lock acquisition for Block-enabled routes.
	if r.lockSeconds > 0 {
		lockKey := r.methods[0] + ":" + r.domain + ":" + r.uri
		lockKey = strings.ReplaceAll(lockKey, "{", "_")
		lockKey = strings.ReplaceAll(lockKey, "}", "_")
		release := func() { routeLocks.Delete(lockKey) }
		if _, loaded := routeLocks.LoadOrStore(lockKey, time.Now()); loaded {
			deadline := time.Now().Add(time.Duration(r.waitSeconds) * time.Second)
			for time.Now().Before(deadline) {
				time.Sleep(50 * time.Millisecond)
				if _, loaded := routeLocks.LoadOrStore(lockKey, time.Now()); !loaded {
					defer release()
					break
				}
			}
			if _, stillLocked := routeLocks.Load(lockKey); stillLocked {
				return NewResponse().SetCode(http.StatusTooManyRequests).
					SetContent("Too Many Attempts.")
			}
		} else {
			defer release()
		}
	}

	var parsedParams []*parameter
	if len(params) > 0 {
		parsedParams = params[0]
	} else if request != nil {
		r.compile()
		for _, variant := range r.expanded {
			for _, name := range variant.parameterNames {
				parsedParams = append(parsedParams, &parameter{
					name:  name,
					value: request.GetRouteParam(name),
				})
			}
			break // all variants declare the same parameter set
		}
	}

	// Dedicated route controllers (view/redirect) render directly.
	if action, ok := r.handler.(interface{ Render(*Request) any }); ok {
		return action.Render(request)
	}

	// Direct execution for http.Handler (e.g. static files via http.FileServer).
	if httpHandler, ok := r.handler.(http.Handler); ok {
		if request != nil && request.ResponseWriter() != nil && request.Request != nil {
			httpHandler.ServeHTTP(request.ResponseWriter(), request.Request)
			return HandledResponse()
		}
	}

	// Controller actions are dispatched through the ControllerDispatcher.
	if action, ok := r.handler.(ControllerAction); ok {
		result, err := r.router.getControllerDispatcher().Dispatch(r, request, action, parsedParams)
		if err != nil {
			// Controller resolution failures are programming errors; they are
			// reported through the exception pipeline like any other panic.
			panic(err)
		}
		return result
	}

	v := reflect.ValueOf(r.handler)
	switch v.Type().Kind() {
	case reflect.Func:
		in := r.parseParams(v, request, parsedParams)
		out := v.Call(in)
		if len(out) > 0 {
			result = out[0].Interface()
		}
	default:
		result = r.handler
	}

	return result
}

// ValidateParams checks whether the given parameters satisfy the where
// constraints of the route.
func (r *Route) ValidateParams(params []*parameter) bool {
	if len(r.wheres) == 0 {
		return true
	}
	for _, p := range params {
		if constraint, ok := r.wheres[p.name]; ok {
			clean := strings.TrimPrefix(strings.TrimSuffix(constraint, "$"), "^")
			reg, err := regexp.Compile("^(" + clean + ")$")
			if err == nil && !reg.MatchString(p.value) {
				return false
			}
		}
	}
	return true
}

// Parameter returns the route parameter value for the request
// — the state is stored per request).
func (r *Route) Parameter(request *Request, name string, defaultValue ...string) string {
	if request == nil {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return ""
	}
	return request.GetRouteParam(name, defaultValue...)
}

// Parameters returns the route parameters of the request
//).
func (r *Route) Parameters(request *Request) map[string]string {
	out := make(map[string]string)
	if request == nil {
		return out
	}
	r.compile()
	for _, name := range r.ParameterNames() {
		out[name] = request.GetRouteParam(name)
	}
	return out
}

// ParameterNames returns all parameter names declared on the route. Domain
// parameters come first, then the path parameters in declaration order.
func (r *Route) ParameterNames() []string {
	r.compile()
	names := make([]string, 0, len(r.hostParameterNames)+2)
	names = append(names, r.hostParameterNames...)
	for _, variant := range r.expanded {
		names = append(names, variant.parameterNames...)
		break // all variants declare the same parameter set
	}
	return names
}

// compile expands the URI into its matchable variants and builds their regexes.
func (r *Route) compile() {
	r.compileOnce.Do(func() {
		// 1. Compile host regex if domain contains parameters (e.g. "{account}.myapp.com")
		if r.domain != "" && strings.Contains(r.domain, "{") {
			domainPat := regexp.QuoteMeta(r.domain)
			regParam := regexp.MustCompile(`\\\{(\w+)(?::(\w+))?\\\}`)
			r.hostParameterNames = nil
			hostRegexStr := regParam.ReplaceAllStringFunc(domainPat, func(m string) string {
				groups := regParam.FindStringSubmatch(m)
				paramName := groups[1]
				r.hostParameterNames = append(r.hostParameterNames, paramName)
				// Record "{account:id}" binding fields declared in the domain
				// merges binding fields).
				if groups[2] != "" {
					if r.bindingFields == nil {
						r.bindingFields = map[string]string{}
					}
					r.bindingFields[paramName] = groups[2]
				}
				if r.wheres != nil {
					if constraint, ok := r.wheres[paramName]; ok {
						clean := strings.TrimPrefix(strings.TrimSuffix(constraint, "$"), "^")
						return "(" + clean + ")"
					}
				}
				return `([^.]+)`
			})
			r.compiledHostRegex = regexp.MustCompile("(?i)^" + hostRegexStr + "$")
		}

		for _, pattern := range expandOptionalPatterns(r.uri) {
			variant := &compiledPattern{pattern: pattern}
			variant.parameterNames = compileParameterNames(pattern)

			pat := strings.ReplaceAll(pattern, "/*", "/.*")
			reg := regexp.MustCompile(`\{(\w+)(?::(\w+))?\??\}`)
			regexStr := reg.ReplaceAllStringFunc(pat, func(m string) string {
				groups := reg.FindStringSubmatch(m)
				paramName := groups[1]
				if groups[2] != "" && r.bindingFields == nil {
					r.bindingFields = map[string]string{}
				}
				if groups[2] != "" {
					r.bindingFields[paramName] = groups[2]
				}
				if r.wheres != nil {
					if constraint, ok := r.wheres[paramName]; ok {
						clean := strings.TrimPrefix(strings.TrimSuffix(constraint, "$"), "^")
						return "(" + clean + ")"
					}
				}
				return "([^/]+)"
			})
			variant.regex = regexp.MustCompile("^" + regexStr + "$")

			r.expanded = append(r.expanded, variant)
		}
	})
}

// invalidateCompile clears derived regex state after a route mutator changes
// the URI, domain, constraints, or binding fields. the reference implementation builds its route
// matcher after these fluent calls; immediate-registration mode must therefore
// rebuild rather than retain the regex compiled during Add.
func (r *Route) invalidateCompile() {
	r.compileOnce = sync.Once{}
	r.expanded = nil
	r.compiledHostRegex = nil
	r.hostParameterNames = nil
}

func (r *Route) getParameterResolver() ParameterResolver {
	if r.router != nil {
		return r.router.getParameterResolver()
	}
	return nil
}

// parseParams builds the argument list for the action: *Request first, then
// route parameters (explicit binders, implicit bindings, positional scalars),
// and container-provided dependencies (ParameterResolver) only when the
// argument is class-typed and no route parameter supplies it — mirroring
// the reference resolveMethodDependencies, where bound model instances take
// priority over container resolution (alreadyInParameters).
func (r *Route) parseParams(value reflect.Value, request *Request, parameters []*parameter) []reflect.Value {
	valueType := value.Type()
	needNum := valueType.NumIn()
	if needNum < 1 {
		return nil
	}

	in := make([]reflect.Value, 0, needNum)
	paramIdx := 0
	resolver := r.getParameterResolver()
	var lastBoundModel any

	// Phase 1 — explicit bindings (the reference implementation: SubstituteBindings middleware →
	// → performBinding). All binders run up front
	// and a failure propagates before the action executes.
	var resolved map[string]any
	if r.router != nil {
		resolved = r.router.SubstituteBindings(r, request, parameters)
	}

	for i := 0; i < needNum; i++ {
		t := valueType.In(i)

		var reqType reflect.Type
		if request != nil {
			reqType = reflect.TypeOf(request)
		}

		if reqType != nil && t == reqType {
			in = append(in, reflect.ValueOf(request))
			continue
		} else if reqType != nil && t == reqType.Elem() {
			in = append(in, reflect.ValueOf(request).Elem())
			continue
		}

		// Context injection for the Context-based handler signature.
		if t == contextType {
			in = append(in, reflect.ValueOf(newContext(request)))
			continue
		}

		if paramIdx < len(parameters) {
			p := parameters[paramIdx]
			if cleanName, _ := splitBindingFieldName(p.name); cleanName != p.name {
				p.name = cleanName
			}

			// An absent optional parameter (padded with "" — see Bind) must
			// not trigger model binding: the reference implementation never sees the parameter, so
			// the argument falls through to the zero value (the reference implementation:
			// getParameterName returns null → continue).
			if p.value == "" {
				if _, isBound := resolved[p.name]; !isBound {
					paramIdx++
					in = append(in, reflect.Zero(t))
					continue
				}
			}

			// 1. Explicitly bound value for this parameter.
			if val, ok := resolved[p.name]; ok && val != nil {
				if v := reflect.ValueOf(val); v.Type().AssignableTo(t) {
					paramIdx++
					lastBoundModel = val
					in = append(in, v)
					continue
				}
			}

			// 2a. Custom implicit binding resolver.
			if r.router != nil && r.router.implicitBindingResolver != nil {
				if val := r.router.implicitBindingResolver(r, p.name, p.value); val != nil {
					if v := reflect.ValueOf(val); v.Type().AssignableTo(t) {
						paramIdx++
						lastBoundModel = val
						in = append(in, v)
						continue
					}
				}
			}

			// 2b. Implicit binding through the Routable contract (supports scoped parent chaining).
			if v, err := implicitBindingArgument(t, p.name, p.value, r.bindingFieldFor(p.name), r, lastBoundModel, request.Context()); err != nil {
				if modelErr, ok := err.(*ModelNotFoundError); ok && modelErr.Param == "" {
					modelErr.Param = p.name
				}
				panic(err)
			} else if v.IsValid() {
				paramIdx++
				lastBoundModel = v.Interface()
				in = append(in, v)
				continue
			}

			// 3. Scalar route parameters fill positional scalar arguments.
			if isScalarParamTarget(t) {
				paramIdx++
				in = append(in, convertParamValue(p.value, t))
				continue
			}

			// 4. Class-typed argument with a remaining route parameter: resolve
			// from the container without consuming the parameter
			// (the reference implementation: alreadyInParameters — the route parameter stays
			// available for the scalar arguments that follow).
			if resolver != nil {
				if val, ok := resolver.ResolveParameter(t, request); ok {
					in = append(in, val)
					continue
				}
			}
			in = append(in, reflect.Zero(t))
			continue
		}

		// No route parameter left: container dependency, then zero value
		//.
		if resolver != nil {
			if val, ok := resolver.ResolveParameter(t, request); ok {
				in = append(in, val)
				continue
			}
		}
		in = append(in, reflect.Zero(t))
	}

	return in
}

// isScalarParamTarget reports whether the argument type can hold a converted
// route parameter value.
func isScalarParamTarget(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64, reflect.Bool:
		return true
	case reflect.Ptr:
		return isScalarParamTarget(t.Elem())
	}
	return false
}

// compileParameterNames extracts the parameter names of a pattern, stripping
// the binding field suffix of "{user:id}" syntax.
func compileParameterNames(pattern string) []string {
	reg := regexp.MustCompile(`\{(\w+)(?::(\w+))?\??\}`)
	matches := reg.FindAllStringSubmatch(pattern, -1)

	var result []string
	for _, v := range matches {
		result = append(result, v[1])
	}

	return result
}

// expandOptionalPatterns enumerates the matchable variants of a pattern that
// contains optional parameters ("{name?}").
func expandOptionalPatterns(pattern string) []string {
	if !strings.Contains(pattern, "?}") {
		return []string{pattern}
	}

	var results []string
	curr := pattern

	for {
		standardPat := regexp.MustCompile(`\{(\w+)\?\}`).ReplaceAllString(curr, "{$1}")
		results = append(results, standardPat)

		reLastOptional := regexp.MustCompile(`/[^/]*\{(\w+)\?\}[^/]*$`)
		loc := reLastOptional.FindStringIndex(curr)
		if loc == nil {
			break
		}

		curr = curr[:loc[0]]
		if curr == "" {
			curr = "/"
		}
		if curr == "/" {
			results = append(results, "/")
			break
		}
	}

	return results
}

func convertParamValue(str string, targetType reflect.Type) reflect.Value {
	kind := targetType.Kind()
	if kind == reflect.Ptr {
		elemVal := convertParamValue(str, targetType.Elem())
		ptr := reflect.New(targetType.Elem())
		ptr.Elem().Set(elemVal)
		return ptr
	}

	switch kind {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		intVal, _ := strconv.ParseInt(str, 10, 64)
		return reflect.ValueOf(intVal).Convert(targetType)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		uintVal, _ := strconv.ParseUint(str, 10, 64)
		return reflect.ValueOf(uintVal).Convert(targetType)
	case reflect.Bool:
		boolVal, _ := strconv.ParseBool(str)
		return reflect.ValueOf(boolVal)
	case reflect.Float32, reflect.Float64:
		floatVal, _ := strconv.ParseFloat(str, 64)
		return reflect.ValueOf(floatVal).Convert(targetType)
	default:
		return reflect.ValueOf(str).Convert(targetType)
	}
}
