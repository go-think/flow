package flow

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- Begin router.go ---
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
	// Group creates a route group.
	Group(callback func(group Router))
	// Prefix adds a prefix to the current route group.
	Prefix(prefix string) Router
	// Middleware adds middleware to the current route or group.
	Middleware(middlewares ...interface{}) Router
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
	// CurrentRouteName returns the current route name for the request.
	CurrentRouteName(req *Request) string
	// Is determines if the current route's name matches given patterns.
	Is(req *Request, patterns ...string) bool
	// Register compiles and indexes the collected route rules into the Radix Tree.
	Register()
	// Dump returns a byte slice dump of all registered route rules.
	Dump() []byte

	// SignedUrl creates a signed URL for a named route.
	SignedUrl(name string, expiration time.Duration, params map[string]string) string
	// HasValidSignature determines if the request has a valid signature.
	HasValidSignature(req *Request) bool
	// AliasMiddleware registers a route-specific middleware alias.
	AliasMiddleware(name string, middleware interface{}) Router
	// MiddlewareGroup defines a named middleware group.
	MiddlewareGroup(name string, middlewares ...interface{}) Router
	// GetRouteMiddleware retrieves a registered middleware alias.
	GetRouteMiddleware(name string) interface{}
	// GetMiddlewareGroup retrieves a registered middleware group.
	GetMiddlewareGroup(name string) []interface{}
}

// --- End router.go ---

// --- Begin router_route.go ---
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

type Route struct {
	inited bool

	method            []string
	prefix            string
	pattern           string
	handler           interface{}
	middlewares       []interface{}
	group             *Route
	name              string
	wheres            map[string]string
	patterns          map[string]string
	signatureKey      string
	middlewareAliases map[string]interface{}
	middlewareGroups  map[string][]interface{}
	parameterResolver ParameterResolver

	collects []*Route

	trees       map[string]*node
	rules       map[string]map[string]*Rule
	allRules    map[string]*Rule
	namedRoutes map[string]*Rule
	fallback    interface{}
}

// New Create a new Route instance with optional configuration options.
func New(opts ...Option) *Route {
	route := &Route{
		trees:             make(map[string]*node),
		rules:             make(map[string]map[string]*Rule),
		patterns:          make(map[string]string),
		wheres:            make(map[string]string),
		middlewareAliases: make(map[string]interface{}),
		middlewareGroups:  make(map[string][]interface{}),
	}

	for _, opt := range opts {
		opt(route)
	}

	return route
}

// Dispatch executes the request and returns the response.
func (r *Route) Dispatch(request *Request) interface{} {
	rule, params, err := r.MatchRequest(request)
	if err != nil {
		if r.fallback != nil {
			fallbackRule := &Rule{
				route:   r,
				handler: r.fallback,
			}
			return RunRoute(request, fallbackRule, nil)
		}
		return NotFoundResponse()
	}

	if rule.name != "" {
		request.Set("_route_name", rule.name)
	}

	for _, p := range params {
		request.SetRouteParam(p.name, p.value)
	}

	return RunRoute(request, rule, params)
}

// MatchRequest Dispatch the request to find a matching rule
func (r *Route) MatchRequest(request *Request) (*Rule, []*parameter, error) {
	rule, treeParams, err := r.Match(request)
	if err != nil {
		return nil, nil, err
	}

	params := rule.Bind(request, request.GetPath(), treeParams)

	return rule, params, nil
}

// Match Find the first rule matching a given request using Radix Tree with fallback.
func (r *Route) Match(request *Request) (*Rule, []*parameter, error) {
	method := request.GetMethod()
	path := request.GetPath()

	// Prioritize Radix Tree index
	if tree, ok := r.trees[method]; ok {
		if handle, ps, _ := tree.getValue(path); handle != nil {
			if rule, ok := handle.(*Rule); ok {
				// Sync dynamically parsed parameters from tree to local slice
				ruleParams := make([]*parameter, 0, len(ps))
				for _, p := range ps {
					ruleParams = append(ruleParams, &parameter{
						name:  p.Key,
						value: p.Value,
					})
				}
				if rule.ValidateParams(ruleParams) {
					return rule, ruleParams, nil
				}
			}
		}
	}

	// Fallback to regex rules library
	for _, rule := range r.rules[method] {
		if true == rule.Matches(method, path) {
			return rule, nil, nil
		}
	}
	return nil, nil, errors.New("Not Found")
}

// AddRule Add a Rule to the Router.Rules and Radix Tree
func (r *Route) AddRule(rule *Rule) *Rule {
	if strings.Contains(rule.pattern, "?}") {
		patterns := expandOptionalPatterns(rule.pattern)
		cleanNames := extractParameterNames(rule.pattern)
		var firstRule *Rule
		for _, pat := range patterns {
			subRule := &Rule{
				route:          r,
				name:           rule.name,
				method:         rule.method,
				pattern:        pat,
				handler:        rule.handler,
				middlewares:    rule.middlewares,
				wheres:         rule.wheres,
				parameterNames: cleanNames,
			}
			res := r.addSingleRule(subRule)
			if firstRule == nil {
				firstRule = res
			}
		}
		return firstRule
	}
	return r.addSingleRule(rule)
}

func (r *Route) addSingleRule(rule *Rule) *Rule {
	rule.route = r
	domainAndUri := rule.pattern
	for _, method := range rule.method {
		// Add to regex list as fallback
		if _, ok := r.rules[method]; !ok {
			r.rules[method] = map[string]*Rule{
				domainAndUri: rule,
			}
		} else {
			r.rules[method][domainAndUri] = rule
		}

		// Build/Get Radix Tree for Method
		rootNode, ok := r.trees[method]
		if !ok {
			rootNode = &node{}
			r.trees[method] = rootNode
		}
		rootNode.addRoute(domainAndUri, rule)
	}

	if r.allRules == nil {
		r.allRules = map[string]*Rule{}
	}
	r.allRules[strings.Join(rule.method, "|")+domainAndUri] = rule

	return rule
}

// Add Add a router
func (r *Route) Add(method []string, pattern string, handler interface{}) Router {
	route := r.initRoute()
	route.method = method
	route.pattern = r.getPrefix(pattern)
	route.handler = handler
	return route
}

// Get Register a new GET rule with the router.
func (r *Route) Get(pattern string, handler interface{}) Router {
	return r.Add(Method("GET", "HEAD"), pattern, handler)
}

// Head Register a new Head rule with the router.
func (r *Route) Head(pattern string, handler interface{}) Router {
	return r.Add(Method("HEAD"), pattern, handler)
}

// Post Register a new POST rule with the router.
func (r *Route) Post(pattern string, handler interface{}) Router {
	return r.Add(Method("POST"), pattern, handler)
}

// Put Register a new PUT rule with the router.
func (r *Route) Put(pattern string, handler interface{}) Router {
	return r.Add(Method("PUT"), pattern, handler)
}

// Patch Register a new PATCH rule with the router.
func (r *Route) Patch(pattern string, handler interface{}) Router {
	return r.Add(Method("PATCH"), pattern, handler)
}

// Delete Register a new DELETE rule with the router.
func (r *Route) Delete(pattern string, handler interface{}) Router {
	return r.Add(Method("DELETE"), pattern, handler)
}

// Options Register a new OPTIONS rule with the router.
func (r *Route) Options(pattern string, handler interface{}) Router {
	return r.Add(Method("OPTIONS"), pattern, handler)
}

// Any Register a new rule responding to all verbs.
func (r *Route) Any(pattern string, handler interface{}) Router {
	return r.Add(verbs, pattern, handler)
}

// Static Register a new Static rule.
func (r *Route) Static(path, root string) {
	cleanPrefix := "/" + strings.Trim(path, "/")
	wildcardPath := cleanPrefix + "/*"

	h := NewStaticHandle(cleanPrefix, root)

	r.Get(wildcardPath, h)
	r.Head(wildcardPath, h)
}

// Statics Bulk register Static rule.
func (r *Route) Statics(statics map[string]string) {
	for path, root := range statics {
		r.Static(path, root)
	}
}

// Prefix Add a prefix to the route URI.
func (r *Route) Prefix(prefix string) Router {
	route := r.initRoute()
	route.prefix = route.getPrefix(prefix)
	return route
}

// Group Create a route group
func (r *Route) Group(callback func(group Router)) {
	route := r.initRoute()
	group := route.cloneRoute()

	var md []interface{}
	for _, m := range route.middlewares {
		md = append(md, m)
	}
	group.Middleware(md...)

	callback(group)
}

// Middleware Set the middleware attached to the route.
func (r *Route) Middleware(middlewares ...interface{}) Router {
	route := r.initRoute()
	route.middlewares = append(route.middlewares, middlewares...)
	return route
}

// Name Set the name attached to the route.
func (r *Route) Name(name string) Router {
	route := r.initRoute()
	route.name = r.name + name
	return route
}

// Url generates a URL for a named route.
func (r *Route) Url(name string, params map[string]string) string {
	if r.namedRoutes == nil {
		return ""
	}
	rule, ok := r.namedRoutes[name]
	if !ok {
		return ""
	}
	urlPath := rule.pattern
	for k, v := range params {
		urlPath = strings.Replace(urlPath, "{"+k+"}", v, -1)
		urlPath = strings.Replace(urlPath, "{"+k+"?}", v, -1)
	}
	// Clean up any remaining unprovided optional parameters e.g., /{param?}
	urlPath = regexp.MustCompile(`(/)?\{[a-zA-Z0-9_]+\?\}`).ReplaceAllString(urlPath, "")
	if urlPath == "" {
		urlPath = "/"
	}
	return urlPath
}

// Fallback registers a fallback route.
func (r *Route) Fallback(handler interface{}) {
	r.fallback = handler
}

// Where adds a regex constraint to a route parameter.
func (r *Route) Where(name string, expression string) Router {
	route := r.initRoute()
	if route.wheres == nil {
		route.wheres = make(map[string]string)
	}
	route.wheres[name] = expression
	return route
}

// WhereNumber adds a numeric regex constraint to parameters.
func (r *Route) WhereNumber(names ...string) Router {
	for _, name := range names {
		r.Where(name, "^[0-9]+$")
	}
	return r
}

// WhereAlpha adds an alphabetic regex constraint to parameters.
func (r *Route) WhereAlpha(names ...string) Router {
	for _, name := range names {
		r.Where(name, "^[a-zA-Z]+$")
	}
	return r
}

// WhereIn adds an allowed values constraint to a parameter.
func (r *Route) WhereIn(name string, allowed []string) Router {
	escaped := make([]string, len(allowed))
	for i, val := range allowed {
		escaped[i] = regexpQuote(val)
	}
	return r.Where(name, "^("+strings.Join(escaped, "|")+")$")
}

// Pattern sets a global regex pattern for a parameter.
func (r *Route) Pattern(name string, expression string) {
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

func extractParameterNames(pattern string) []string {
	reg := regexp.MustCompile(`\{(.*?)\}`)
	matches := reg.FindAllStringSubmatch(pattern, -1)

	var result []string
	for _, v := range matches {
		name := strings.TrimSuffix(v[1], "?")
		result = append(result, name)
	}

	return result
}

// Register Register route from the collect.
func (r *Route) Register() {
	r.register(r)
}

func (r *Route) Dump() []byte {
	var b bytes.Buffer
	for _, rule := range r.allRules {
		fmt.Fprintf(&b, "%s %s %T \r\n", strings.Join(rule.method, "|"), rule.pattern, rule.handler)
	}

	return b.Bytes()
}

func (r *Route) register(root *Route) {
	for _, route := range r.collects {
		route.prefix = r.getPrefix(route.prefix)

		var middlewares []interface{}
		for _, m := range r.middlewares {
			middlewares = append(middlewares, m)
		}
		for _, m := range route.middlewares {
			middlewares = append(middlewares, m)
		}
		route.middlewares = middlewares

		route.register(root)

		if route.handler == nil {
			continue
		}

		routePattern := route.getPrefix(route.pattern)

		combinedWheres := make(map[string]string)
		if root.patterns != nil {
			for k, v := range root.patterns {
				combinedWheres[k] = v
			}
		}
		if route.wheres != nil {
			for k, v := range route.wheres {
				combinedWheres[k] = v
			}
		}

		rule := &Rule{
			route:       root,
			name:        route.name,
			method:      route.method,
			pattern:     routePattern,
			handler:     route.handler,
			middlewares: route.middlewares,
			wheres:      combinedWheres,
		}

		root.AddRule(rule)
		if route.name != "" {
			if root.namedRoutes == nil {
				root.namedRoutes = make(map[string]*Rule)
			}
			root.namedRoutes[route.name] = &Rule{
				route:          root,
				name:           rule.name,
				method:         rule.method,
				pattern:        routePattern,
				handler:        rule.handler,
				middlewares:    rule.middlewares,
				wheres:         rule.wheres,
				parameterNames: rule.parameterNames,
			}
		}
	}
	r.collects = r.collects[0:0]
}

// initRoute Initialize a new Route if not initialized
func (r *Route) initRoute() *Route {
	route := r
	if !r.inited {
		route = &Route{
			inited:            true,
			rules:             make(map[string]map[string]*Rule),
			name:              r.name,
			group:             r,
			parameterResolver: r.parameterResolver,
			signatureKey:      r.signatureKey,
			middlewareAliases: r.middlewareAliases,
			middlewareGroups:  r.middlewareGroups,
			// prefix:      r.prefix,
			// middlewares: r.middlewares,
		}
		r.collects = append(r.collects, route)
	}
	return route
}

func (r *Route) cloneRoute() *Route {
	route := &Route{
		inited:            false,
		rules:             make(map[string]map[string]*Rule),
		name:              r.name,
		group:             r,
		parameterResolver: r.parameterResolver,
		signatureKey:      r.signatureKey,
		middlewareAliases: r.middlewareAliases,
		middlewareGroups:  r.middlewareGroups,
		// prefix:      r.prefix,
		// middlewares: r.middlewares,
	}
	r.collects = append(r.collects, route)

	return route
}

// AliasMiddleware registers a route-specific middleware alias.
func (r *Route) AliasMiddleware(name string, middleware interface{}) Router {
	if r.middlewareAliases == nil {
		r.middlewareAliases = make(map[string]interface{})
	}
	r.middlewareAliases[name] = middleware
	return r
}

// MiddlewareGroup defines a named middleware group.
func (r *Route) MiddlewareGroup(name string, middlewares ...interface{}) Router {
	if r.middlewareGroups == nil {
		r.middlewareGroups = make(map[string][]interface{})
	}
	r.middlewareGroups[name] = middlewares
	return r
}

// GetRouteMiddleware retrieves a registered middleware alias.
func (r *Route) GetRouteMiddleware(name string) interface{} {
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
func (r *Route) GetMiddlewareGroup(name string) []interface{} {
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

func (r *Route) getParameterResolver() ParameterResolver {
	if r.parameterResolver != nil {
		return r.parameterResolver
	}
	if r.group != nil {
		return r.group.getParameterResolver()
	}
	return nil
}

func (r *Route) getSignatureKey() string {
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

func (r *Route) getPrefix(pattern string) string {
	return path.Join("/", r.prefix, pattern)
}

// SignedUrl creates a signed URL for a named route.
func (r *Route) SignedUrl(name string, expiration time.Duration, params map[string]string) string {
	urlPath := r.Url(name, params)
	if urlPath == "" {
		return ""
	}

	key := r.getSignatureKey()
	expires := time.Now().Add(expiration).Unix()

	queryVals := url.Values{}
	queryVals.Set("expires", strconv.FormatInt(expires, 10))

	// Build query string sorted
	queryString := queryVals.Encode()
	fullUrl := urlPath + "?" + queryString

	// Calculate HMAC signature
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(fullUrl))
	sig := hex.EncodeToString(mac.Sum(nil))

	return fullUrl + "&signature=" + sig
}

// HasValidSignature checks if the given request has a valid signature.
func (r *Route) HasValidSignature(req *Request) bool {
	if req == nil || req.Request == nil || req.Request.URL == nil {
		return false
	}

	sig, err := req.Query("signature")
	if err != nil || sig == "" {
		return false
	}

	expiresStr, err := req.Query("expires")
	if err != nil || expiresStr == "" {
		return false
	}

	expires, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil || time.Now().Unix() > expires {
		return false
	}

	// Recreate query string without signature
	u := req.Request.URL
	rawQuery := u.Query()
	rawQuery.Del("signature")

	keys := make([]string, 0, len(rawQuery))
	for k := range rawQuery {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var pairs []string
	for _, k := range keys {
		for _, v := range rawQuery[k] {
			pairs = append(pairs, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}

	target := u.Path + "?" + strings.Join(pairs, "&")
	key := r.getSignatureKey()

	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(target))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(sig), []byte(expectedSig))
}

// Has determines if the route collection contains a given named route.
func (r *Route) Has(name string) bool {
	if r.namedRoutes == nil {
		return false
	}
	_, ok := r.namedRoutes[name]
	return ok
}

// CurrentRouteName returns the current route name for the request.
func (r *Route) CurrentRouteName(req *Request) string {
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
func (r *Route) Is(req *Request, patterns ...string) bool {
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

func getSignatureKey() string {
	if ResolveSignatureKey != nil {
		if k := ResolveSignatureKey(); k != "" {
			return k
		}
	}
	return "thinkgo-default-secret-signature-key"
}

// --- End router_route.go ---

// --- Begin router_router.go ---
// RunRoute Return the response for the given rule.
func RunRoute(request *Request, rule *Rule, params ...[]*parameter) interface{} {
	return PrepareResponse(
		request,
		rule,
		runMiddlewares(request, rule, params...),
	)
}

// PrepareResponse Create a response instance from the given value.
func PrepareResponse(request *Request, rule *Rule, result interface{}) interface{} {
	if res, ok := result.(*Response); ok {
		return res
	}
	return NewResponse().SetContent(FormatContent(result))
}

// resolveMiddleware resolves a single middleware interface{} into Middleware(s)
func resolveMiddleware(m interface{}, r *Route) []Middleware {
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
		}
	}
	return resolved
}

// runMiddlewares Run the given route within Middlewares instance.
func runMiddlewares(request *Request, rule *Rule, params ...[]*parameter) interface{} {
	pipeline := NewPipeline()

	var route *Route
	if rule != nil {
		route = rule.route
	}

	var routeMiddlewares []interface{}
	for _, m := range rule.GatherRouteMiddleware() {
		for _, md := range resolveMiddleware(m, route) {
			pipeline.Pipe(HandlerFunc(md))
			routeMiddlewares = append(routeMiddlewares, md)
		}
	}

	request.SetRouteMiddlewares(routeMiddlewares)

	return pipeline.Send(request).Then(func(req *Request) any {
		return PrepareResponse(
			req,
			rule,
			rule.Run(req, params...),
		)
	})
}

// --- End router_router.go ---

// --- Begin rule.go ---
// Rule Route rule
type Rule struct {
	route          *Route
	name           string
	middlewares    []interface{}
	method         []string
	pattern        string
	handler        interface{}
	parameterNames []string
	wheres         map[string]string
	Compiled       *Compiled
	compileOnce    sync.Once
}

func (r *Rule) getParameterResolver() ParameterResolver {
	if r != nil && r.route != nil {
		return r.route.getParameterResolver()
	}
	return nil
}

type Compiled struct {
	Regex  string
	Regexp *regexp.Regexp
}

// Matches Determine if the rule matches given request.
func (r *Rule) Matches(method, path string) bool {
	r.compile()

	if false == matchMethods(method, r.method) {
		return false
	}

	if r.Compiled != nil && r.Compiled.Regexp != nil {
		return r.Compiled.Regexp.MatchString(path)
	}

	return matchPath(path, r.Compiled.Regex)
}

// Bind Bind the router parameters to a given request and return parsed parameters.
func (r *Rule) Bind(req *Request, path string, treeParams ...[]*parameter) []*parameter {
	r.compile()

	path = "/" + strings.TrimLeft(path, "/")
	parameters := make([]*parameter, 0)

	// If parameters were already extracted from the Radix Tree
	if len(treeParams) > 0 && len(treeParams[0]) > 0 {
		for _, p := range treeParams[0] {
			parameters = append(parameters, p)
			if req != nil {
				req.SetRouteParam(p.name, p.value)
			}
		}
	} else if r.Compiled != nil && r.Compiled.Regexp != nil {
		// Extract parameters using pre-compiled regex
		rawMatches := r.Compiled.Regexp.FindStringSubmatch(path)
		if len(rawMatches) > 1 {
			matches := rawMatches[1:]
			parameterNames := r.getParameterNames()
			for k, v := range parameterNames {
				val := ""
				if k < len(matches) {
					val = matches[k]
				}
				p := &parameter{
					name:  v,
					value: val,
				}
				parameters = append(parameters, p)
				if req != nil {
					req.SetRouteParam(v, val)
				}
			}
		}
	}

	// Ensure all declared parameters (including optional parameters) are present
	for _, name := range r.getParameterNames() {
		found := false
		for _, p := range parameters {
			if p.name == name {
				found = true
				break
			}
		}
		if !found {
			p := &parameter{
				name:  name,
				value: "",
			}
			parameters = append(parameters, p)
			if req != nil {
				req.SetRouteParam(name, "")
			}
		}
	}

	return parameters
}

// Middleware Set the middleware attached to the rule.
func (r *Rule) Middleware(middlewares ...interface{}) *Rule {
	for _, m := range middlewares {
		r.middlewares = append(r.middlewares, m)
	}
	return r
}

// GatherRouteMiddleware Get all middleware, including the ones from the controller.
func (r *Rule) GatherRouteMiddleware() []interface{} {
	return r.middlewares
}

// Run Run the route action and return the response.
func (r *Rule) Run(request *Request, params ...[]*parameter) (result interface{}) {
	if r == nil || r.handler == nil {
		return nil
	}

	var parsedParams []*parameter
	if len(params) > 0 {
		parsedParams = params[0]
	}

	// Direct execution for http.Handler (e.g. Static files via http.FileServer)
	if httpHandler, ok := r.handler.(http.Handler); ok {
		if request != nil && request.ResponseWriter() != nil && request.Request != nil {
			httpHandler.ServeHTTP(request.ResponseWriter(), request.Request)
			return HandledResponse()
		}
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

	return
}

// getParameterNames Get all of the parameter names for the rule.
func (r *Rule) getParameterNames() []string {
	r.compile()
	return r.parameterNames
}

func (r *Rule) compile() {
	r.compileOnce.Do(func() {
		if r.parameterNames == nil {
			r.parameterNames = r.compileParameterNames()
		}
		pat := strings.Replace(r.pattern, "/*", "/.*", -1)

		reg := regexp.MustCompile(`\{(\w+)\??\}`)
		regex := reg.ReplaceAllStringFunc(pat, func(m string) string {
			paramName := strings.TrimSuffix(strings.Trim(m, "{}"), "?")
			if r.wheres != nil {
				if constraint, ok := r.wheres[paramName]; ok {
					return "(" + constraint + ")"
				}
			}
			return "([^/]+)"
		})
		fullRegex := "^" + regex + "$"

		compiledReg, _ := regexp.Compile(fullRegex)

		r.Compiled = &Compiled{
			Regex:  fullRegex,
			Regexp: compiledReg,
		}
	})
}

// ValidateParams checks if given parameters satisfy where constraints
func (r *Rule) ValidateParams(params []*parameter) bool {
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

func (r *Rule) compileParameterNames() []string {
	reg := regexp.MustCompile(`\{(.*?)\}`)
	matches := reg.FindAllStringSubmatch(r.pattern, -1)

	var result []string
	for _, v := range matches {
		name := strings.TrimSuffix(v[1], "?")
		result = append(result, name)
	}

	return result
}

func parseParams(value reflect.Value, request *Request, parameters []*parameter) []reflect.Value {
	var r *Rule
	return r.parseParams(value, request, parameters)
}

func (r *Rule) parseParams(value reflect.Value, request *Request, parameters []*parameter) []reflect.Value {
	valueType := value.Type()
	needNum := valueType.NumIn()
	if needNum < 1 {
		return nil
	}

	in := make([]reflect.Value, 0, needNum)
	paramIdx := 0
	resolver := r.getParameterResolver()

	for i := 0; i < needNum; i++ {
		t := valueType.In(i)

		var reqType reflect.Type
		if request != nil {
			reqType = reflect.TypeOf(request)
		}

		// Check if it is *Request or Request
		if reqType != nil && t == reqType {
			in = append(in, reflect.ValueOf(request))
			continue
		} else if reqType != nil && t == reqType.Elem() {
			in = append(in, reflect.ValueOf(request).Elem())
			continue
		}

		// Try to resolve parameter via ParameterResolver interface
		if resolver != nil {
			if val, ok := resolver.ResolveParameter(t, request); ok {
				in = append(in, val)
				continue
			}
		}

		// Fetch from route params
		if paramIdx < len(parameters) {
			strVal := parameters[paramIdx].value
			paramIdx++
			in = append(in, convertParamValue(strVal, t))
			continue
		}

		in = append(in, reflect.Zero(t))
	}

	return in
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

// Private helper functions for route matching
func matchMethod(method, target string) bool {
	if "*" == target {
		return true
	}
	if target == method {
		return true
	}
	return false
}

func matchMethods(method string, target []string) bool {
	for _, v := range target {
		if matchMethod(method, v) {
			return true
		}
	}
	return false
}

func matchPath(path, target string) bool {
	res, err := regexp.MatchString(target, path)
	if err != nil {
		return false
	}
	return res
}

// --- End rule.go ---

// --- Begin parameter.go ---
type parameter struct {
	name  string
	value string
}

// --- End parameter.go ---

// --- Begin utils.go ---
// Method Convert multiple method strings to an slice
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

// ServeHTTP responds to an Static HTTP request.
func (s *staticHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.fileServer.ServeHTTP(w, r)
}

// --- End static.go ---
