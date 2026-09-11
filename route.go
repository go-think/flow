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
)

// matchMethod reports whether a request verb matches a target verb.
func matchMethod(method, target string) bool {
	if target == "*" {
		return true
	}
	return target == method
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
type Route struct {
	methods           []string
	uri               string
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
	withTrashed       bool
	missing           func(request *Request, err error) any

	router *router // back reference for resolver/registry lookups

	expanded           []*compiledPattern
	compiledHostRegex  *regexp.Regexp
	hostParameterNames []string
	compileOnce        sync.Once
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

// Uri is the Laravel-style spelling of URI.
func (r *Route) Uri() string {
	return r.uri
}

// ActionName returns the canonical action identifier of the route: dot form
// for controller actions ("Name.Method") and the cleaned runtime name for
// bound method values ("Type.Method").
func (r *Route) ActionName() string {
	if ca, ok := r.handler.(ControllerAction); ok {
		if name, isName := ca.Controller.(string); isName {
			return name + "." + ca.Method
		}
		return fmt.Sprintf("%T.%s", ca.Controller, ca.Method)
	}
	if reflect.ValueOf(r.handler).Kind() == reflect.Func {
		return normalizeActionName(runtime.FuncForPC(reflect.ValueOf(r.handler).Pointer()).Name())
	}
	return ""
}

// normalizeActionName converts a runtime function name into the public action
// form: "pkg.(*Type).Method-fm" -> "Type.Method".
func normalizeActionName(name string) string {
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

// SetWhere adds a regex constraint for a route parameter.
func (r *Route) SetWhere(name, expression string) *Route {
	if r.wheres == nil {
		r.wheres = make(map[string]string)
	}
	r.wheres[name] = expression
	return r
}

// WhereNumber adds a numeric regex constraint to parameters.
func (r *Route) WhereNumber(names ...string) *Route {
	for _, name := range names {
		r.SetWhere(name, "^[0-9]+$")
	}
	return r
}

// WhereAlpha adds an alphabetic regex constraint to parameters.
func (r *Route) WhereAlpha(names ...string) *Route {
	for _, name := range names {
		r.SetWhere(name, "^[a-zA-Z]+$")
	}
	return r
}

// WhereAlphaNumeric adds an alphanumeric regex constraint to parameters.
func (r *Route) WhereAlphaNumeric(names ...string) *Route {
	for _, name := range names {
		r.SetWhere(name, "^[a-zA-Z0-9]+$")
	}
	return r
}

// WhereUuid adds a UUID regex constraint to parameters.
func (r *Route) WhereUuid(names ...string) *Route {
	for _, name := range names {
		r.SetWhere(name, `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	}
	return r
}

// WhereUlid adds a ULID regex constraint to parameters.
func (r *Route) WhereUlid(names ...string) *Route {
	for _, name := range names {
		r.SetWhere(name, `^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	}
	return r
}

// WhereIn adds an allowed values constraint to a parameter.
func (r *Route) WhereIn(name string, allowed []string) *Route {
	escaped := make([]string, len(allowed))
	for i, val := range allowed {
		escaped[i] = regexpQuote(val)
	}
	return r.SetWhere(name, "^("+strings.Join(escaped, "|")+")$")
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

// SetMetadata stores route metadata.
func (r *Route) SetMetadata(key string, value any) *Route {
	if r.metadata == nil {
		r.metadata = make(map[string]any)
	}
	r.metadata[key] = value
	return r
}

// IsFallback reports whether this route is the router fallback.
func (r *Route) IsFallback() bool {
	return r.fallback
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
	return r
}

// GetDomain returns the route host restriction, or "" when unrestricted.
func (r *Route) GetDomain() string {
	return r.domain
}

// ScopeBindings marks nested resource parameters as bound in a scoped chain.
func (r *Route) ScopeBindings() *Route {
	r.scopedBindings = true
	return r
}

// EnforcesScopedBindings reports whether scoped binding is enforced.
func (r *Route) EnforcesScopedBindings() bool {
	return r.scopedBindings
}

// WithTrashed marks the route as allowing soft-deleted entities in bindings.
func (r *Route) WithTrashed() *Route {
	r.withTrashed = true
	return r
}

// AllowsTrashedBindings reports whether trashed entities may be bound.
func (r *Route) AllowsTrashedBindings() bool {
	return r.withTrashed
}

// WithoutMiddleware excludes middlewares (matched by value equality on the
// raw registration entry) from this route.
func (r *Route) WithoutMiddleware(middlewares ...any) *Route {
	r.withoutMiddleware = append(r.withoutMiddleware, middlewares...)
	return r
}

// ExcludedMiddleware returns the excluded raw middleware entries.
func (r *Route) ExcludedMiddleware() []any {
	return r.withoutMiddleware
}

// Middleware returns the raw middleware entries attached to the route.
func (r *Route) Middleware() []any {
	return r.middlewares
}

// GatherMiddleware returns all middleware for the route: the entries attached
// at registration plus the middleware the controller declares for its method
// (with only/except filters applied).
func (r *Route) GatherMiddleware() []any {
	out := append([]any(nil), r.middlewares...)
	if action, ok := r.handler.(ControllerAction); ok {
		dispatcher := r.router.getControllerDispatcher()
		if controller, err := dispatcher.ResolveController(action); err == nil {
			out = append(out, dispatcher.GetMiddleware(controller, action.Method)...)
		}
	}
	return out
}

// Matches determines whether the route matches the given method and path.
func (r *Route) Matches(method, path string) bool {
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

// Bind extracts the route parameters for a request and stores them on it.
// Parameters extracted by the matcher (treeParams) take precedence; the rest
// are recovered from the compiled patterns. Every declared parameter —
// including optional ones — is guaranteed to be present.
func (r *Route) Bind(req *Request, path string, treeParams ...[]*parameter) []*parameter {
	r.compile()

	path = "/" + strings.TrimLeft(path, "/")
	parameters := make([]*parameter, 0)

	if len(treeParams) > 0 && len(treeParams[0]) > 0 {
		for _, p := range treeParams[0] {
			parameters = append(parameters, p)
			if req != nil {
				req.SetRouteParam(p.name, p.value)
			}
		}
	} else {
		for _, variant := range r.expanded {
			if variant.regex == nil {
				continue
			}
			rawMatches := variant.regex.FindStringSubmatch(path)
			if len(rawMatches) <= 1 {
				continue
			}
			matches := rawMatches[1:]
			for k, name := range variant.parameterNames {
				val := ""
				if k < len(matches) {
					val = matches[k]
				}
				p := &parameter{name: name, value: val}
				parameters = append(parameters, p)
				if req != nil {
					req.SetRouteParam(name, val)
				}
			}
			break
		}
	}

	for _, variant := range r.expanded {
		for _, name := range variant.parameterNames {
			found := false
			for _, p := range parameters {
				if p.name == name {
					found = true
					break
				}
			}
			if !found {
				value := ""
				// 默认值填充（对齐 Laravel replaceDefaults）。
				if r.defaults != nil {
					if d, ok := r.defaults[name]; ok {
						value = fmt.Sprintf("%v", d)
					}
				}
				p := &parameter{name: name, value: value}
				parameters = append(parameters, p)
				if req != nil {
					req.SetRouteParam(name, value)
				}
			}
		}
	}

	return parameters
}

// Run executes the route action and returns its raw result. When no explicit
// parameters are passed, they are recovered from the request by the parameter
// names declared in the pattern.
func (r *Route) Run(request *Request, params ...[]*parameter) (result any) {
	if r == nil || r.handler == nil {
		return nil
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
			reg, err := regexp.Compile("^" + constraint + "$")
			if err == nil && !reg.MatchString(p.value) {
				return false
			}
		}
	}
	return true
}

// Parameter returns a decoded route parameter value for the request
// (Laravel: Route::parameter($name)).
func (r *Route) Parameter(request *Request, name string, defaultValue ...string) string {
	if request == nil {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return ""
	}
	return request.GetRouteParam(name, defaultValue...)
}

// Parameters returns all decoded route parameters of the request
// (Laravel: Route::parameters()).
func (r *Route) Parameters(request *Request) map[string]string {
	out := make(map[string]string)
	r.compile()
	for _, variant := range r.expanded {
		for _, name := range variant.parameterNames {
			out[name] = request.GetRouteParam(name)
		}
		break
	}
	return out
}

// ParameterNames returns all parameter names declared in the route pattern.
func (r *Route) ParameterNames() []string {
	r.compile()
	var names []string
	for _, variant := range r.expanded {
		names = variant.parameterNames
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
			regParam := regexp.MustCompile(`\\\{(\w+)\\\}`)
			r.hostParameterNames = nil
			hostRegexStr := regParam.ReplaceAllStringFunc(domainPat, func(m string) string {
				paramName := m[2 : len(m)-2]
				r.hostParameterNames = append(r.hostParameterNames, paramName)
				if r.wheres != nil {
					if constraint, ok := r.wheres[paramName]; ok {
						return "(" + constraint + ")"
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
						return "(" + constraint + ")"
					}
				}
				return "([^/]+)"
			})
			variant.regex = regexp.MustCompile("^" + regexStr + "$")

			r.expanded = append(r.expanded, variant)
		}
	})
}

func (r *Route) getParameterResolver() ParameterResolver {
	if r.router != nil {
		return r.router.getParameterResolver()
	}
	return nil
}

// parseParams builds the argument list for the action: *Request first, then
// container-provided dependencies (ParameterResolver), then route parameters
// in order of appearance.
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

		if resolver != nil {
			if val, ok := resolver.ResolveParameter(t, request); ok {
				in = append(in, val)
				continue
			}
		}

		if paramIdx < len(parameters) {
			p := parameters[paramIdx]
			if cleanName, _ := splitBindingFieldName(p.name); cleanName != p.name {
				p.name = cleanName
			}

			// 1. Explicit binder registered for the parameter name.
			if r.router != nil {
				if binder := r.router.getBinder(p.name); binder != nil {
					val, err := binder(p.value, r)
					if err != nil {
						panic(&ModelNotFoundError{Param: p.name, Value: p.value, Err: err})
					}
					if val != nil {
						if v := reflect.ValueOf(val); v.Type().AssignableTo(t) {
							paramIdx++
							lastBoundModel = val
							in = append(in, v)
							continue
						}
					}
				}
			}

			// 2. Implicit binding through the Routable contract (supports scoped parent chaining).
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

			// 3. Positional conversion.
			paramIdx++
			in = append(in, convertParamValue(p.value, t))
			continue
		}

		in = append(in, reflect.Zero(t))
	}

	return in
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
