package flow

import (
	"context"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// SortMiddleware stably orders middleware entries by a priority list
// . The algorithm replicates the reference implementation: only string
// entries participate, the ":params" suffix is stripped before lookup, entries
// missing from the priority list keep their original position, and an
// out-of-order entry is moved above the previously ranked one. The result is
// deduplicated like the reference implementation ().
func SortMiddleware(priority []any, middlewares []any) []any {
	return sortMiddlewareRanked(priority, middlewares, nil)
}

// sortMiddlewareRanked is SortMiddleware with an optional per-entry namer
// override (used by the router so an alias entry is also ranked by the concrete
// middleware it resolves to — the reference implementation sorts the resolved entries).
func sortMiddlewareRanked(priority []any, middlewares []any, namer func(any) []string) []any {
	if len(priority) == 0 || len(middlewares) < 2 {
		return UniqueMiddleware(middlewares)
	}

	lastIndex := 0
	lastPriorityIndex := -1

	for index, middleware := range middlewares {
		var names []string
		var ok bool
		if namer != nil {
			names, ok = namer(middleware), true
		} else {
			names, ok = middlewareNames(middleware)
		}
		if !ok {
			continue
		}

		priorityIndex, found := priorityMapIndex(priority, names)
		if found {
			if lastPriorityIndex >= 0 && priorityIndex < lastPriorityIndex {
				return sortMiddlewareRanked(priority, moveMiddleware(middlewares, index, lastIndex), namer)
			}
			lastIndex = index
			lastPriorityIndex = priorityIndex
		}
	}

	return UniqueMiddleware(middlewares)
}

// middlewareNames resolves the names a middleware entry is ranked by
// (the reference implementation: middlewareNames — the stripped head plus implemented
// interfaces/parents; Go has no inheritance, so string entries are stripped of
// their ":params" suffix and object entries are matched by type name).
func middlewareNames(middleware any) ([]string, bool) {
	switch m := middleware.(type) {
	case string:
		if idx := strings.Index(m, ":"); idx != -1 {
			return []string{m[:idx], m}, true
		}
		return []string{m}, true
	default:
		t := reflect.TypeOf(middleware)
		if t == nil {
			return nil, false
		}
		return []string{t.String()}, true
	}
}

// priorityMapIndex returns the priority position of the first name found in
// the priority list. the reference implementation iterates the entry's names first
// (): the FIRST name that appears in the map
// determines the rank, not the smallest map index across all names.
func priorityMapIndex(priority []any, names []string) (int, bool) {
	for _, name := range names {
		for i, p := range priority {
			if ps, ok := p.(string); ok {
				if name == ps {
					return i, true
				}
				continue
			}
			if reflect.DeepEqual(p, name) {
				return i, true
			}
		}
	}
	return 0, false
}

// moveMiddleware splices a middleware into a new position and removes the old
// entry.
func moveMiddleware(middlewares []any, from, to int) []any {
	m := append([]any(nil), middlewares...)
	value := m[from]
	m = append(m[:from], m[from+1:]...)
	rest := append([]any{value}, m[to:]...)
	m = append(m[:to], rest...)
	return m
}

// RouteAction parses and normalizes route actions
// .
type RouteAction struct{}

// Parse normalizes an action value: strings become ControllerAction, other
// values pass through unchanged.
func (RouteAction) Parse(action any) any {
	return parseControllerAction(action)
}

// IsSerializedClosure always returns false in Go (closures cannot be
// serialized across a cache boundary).
func (RouteAction) IsSerializedClosure(action any) bool {
	return false
}

// MakeInvokable returns the action for a single-invocation controller.
func (RouteAction) MakeInvokable(action string) string {
	return action + "@Invoke"
}

// routeUriParamRegex mirrors the reference pattern
// "/\{([\w\:]+?)\??\}/".
var routeUriParamRegex = regexp.MustCompile(`\{([\w:]+?)\??\}`)

// RouteUri represents a parsed route URI with its parameter and binding-field
// declarations.
type RouteUri struct {
	URI           string
	BindingFields map[string]string
}

// ParseRouteUri parses a route URI: placeholders carrying a binding field are
// extracted into BindingFields and the URI is rewritten from "{user:id}" to
// "{user}".
func ParseRouteUri(uri string) RouteUri {
	bindingFields := make(map[string]string)
	for _, match := range routeUriParamRegex.FindAllString(uri, -1) {
		if !strings.Contains(match, ":") {
			continue
		}
		segments := strings.Split(strings.Trim(match, "{}?"), ":")
		bindingFields[segments[0]] = segments[1]
		if strings.Contains(match, "?") {
			uri = strings.ReplaceAll(uri, match, "{"+segments[0]+"?}")
		} else {
			uri = strings.ReplaceAll(uri, match, "{"+segments[0]+"}")
		}
	}
	return RouteUri{URI: uri, BindingFields: bindingFields}
}

// RouteParameterBinder binds route parameters from a request path
// .
type RouteParameterBinder struct {
	route *Route
}

// NewRouteParameterBinder creates a binder for the given route.
func NewRouteParameterBinder(route *Route) *RouteParameterBinder {
	return &RouteParameterBinder{route: route}
}

// Parameters extracts the route parameters: path parameters first, then host
// parameters when the route has a dynamic domain (host entries precede path
// entries, the reference implementation: bindHostParameters), then defaults fill anything missing
// . Empty matches are dropped like matchToKeys.
func (b *RouteParameterBinder) Parameters(req *Request) []*parameter {
	b.route.compile()

	var pathParams []*parameter
	if req != nil {
		path := "/" + strings.TrimLeft(req.GetPath(), "/")
		for _, variant := range b.route.expanded {
			if variant.regex == nil {
				continue
			}
			matches := variant.regex.FindStringSubmatch(path)
			if len(matches) <= 1 {
				continue
			}
			for i, name := range variant.parameterNames {
				if i+1 >= len(matches) {
					continue
				}
				val := matches[i+1]
				if val == "" {
					continue
				}
				pathParams = append(pathParams, &parameter{name: name, value: val})
			}
			break
		}
	}

	var hostParams []*parameter
	if b.route.compiledHostRegex != nil && req != nil {
		host := requestHost(req)
		matches := b.route.compiledHostRegex.FindStringSubmatch(host)
		for i, name := range b.route.hostParameterNames {
			if i+1 < len(matches) && matches[i+1] != "" {
				hostParams = append(hostParams, &parameter{name: name, value: matches[i+1]})
			}
		}
	}

	out := append(hostParams, pathParams...)
	// the reference implementation merges host then path arrays, so a path parameter with the same
	// name overrides the host entry (RouteParameterBinder: array_merge).
	for i, hp := range hostParams {
		for _, pp := range pathParams {
			if pp.name == hp.name {
				out[i] = nil
				break
			}
		}
	}
	merged := out[:0]
	for _, p := range out {
		if p != nil {
			merged = append(merged, p)
		}
	}
	out = merged
	for _, name := range b.route.ParameterNames() {
		found := false
		for _, p := range out {
			if p.name == name {
				found = true
				break
			}
		}
		if found {
			continue
		}
		if value, ok := b.route.defaults[name]; ok && value != nil {
			out = append(out, &parameter{name: name, value: toStringValue(value)})
		}
	}
	// the reference replaceDefaults also merges default entries that are not
	// route parameters (). Keys are sorted to
	// keep the result deterministic (PHP foreach iterates in insertion order).
	if len(b.route.defaults) > 0 {
		keys := make([]string, 0, len(b.route.defaults))
		for key := range b.route.defaults {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			exists := false
			for _, p := range out {
				if p.name == key {
					exists = true
					break
				}
			}
			if !exists {
				if value := b.route.defaults[key]; value != nil {
					out = append(out, &parameter{name: key, value: toStringValue(value)})
				}
			}
		}
	}
	return out
}

// ImplicitRouteBinding resolves implicit model bindings for a route
// .
type ImplicitRouteBinding struct {
	route *Route
}

// NewImplicitRouteBinding creates a resolver for the given route.
func NewImplicitRouteBinding(route *Route) *ImplicitRouteBinding {
	return &ImplicitRouteBinding{route: route}
}

// ResolveForRoute resolves the explicitly bound parameters of the route.
// Implicit bindings are type-driven in Go and therefore run inside the
// dispatcher.
func (ib *ImplicitRouteBinding) ResolveForRoute(request *Request, params []*parameter) map[string]any {
	return ib.route.resolveBindingParameters(request, params)
}

// RouteBinding provides explicit binding registration helpers
// .
type RouteBinding struct{}

// ForCallback returns a Binder that invokes the given callback
// .
func ForCallback(fn func(value string, route *Route) (any, error)) Binder {
	return Binder(fn)
}

// ForModelOfClass returns a Binder that resolves a named model class via a
// custom resolver function.
func ForModelOfClass(className string, resolver func(ctx context.Context, value string) (any, error)) Binder {
	return func(value string, route *Route) (any, error) {
		ctx := context.Background()
		if route != nil && route.router != nil {
			if req := route.router.CurrentRequest(); req != nil {
				ctx = req.Context()
			}
		}
		return resolver(ctx, value)
	}
}

// ForModel returns a Binder that resolves a model instance via Routable
// . Soft-deleted records are resolved through
// SoftDeletableRoutable when the route allows trashed bindings, and a missing
// entity surfaces as *ModelNotFoundError like the reference modelNotFoundException.
func ForModel(model Routable) Binder {
	return func(value string, route *Route) (any, error) {
		ctx := context.Background()
		if route != nil && route.router != nil {
			if req := route.router.CurrentRequest(); req != nil {
				ctx = req.Context()
			}
		}
		if route != nil && route.AllowsTrashedBindings() {
			if soft, ok := model.(SoftDeletableRoutable); ok {
				return soft.ResolveSoftDeletableRouteBinding(ctx, value, "")
			}
		}
		return model.ResolveRouteBinding(ctx, value, "")
	}
}

// ControllerMiddlewareOptions provides fluent only/except filters
// .
type ControllerMiddlewareOptions struct {
	OnlyMethods   []string
	ExceptMethods []string
}

// Only limits the middleware to the given methods. Both keys coexist like
// the reference controllerMiddlewareOptions (only() writes only its own key; the
// OR combination is resolved in methodExcludedByOptions).
func (o *ControllerMiddlewareOptions) Only(methods ...string) *ControllerMiddlewareOptions {
	o.OnlyMethods = methods
	return o
}

// Except excludes the given methods from the middleware.
func (o *ControllerMiddlewareOptions) Except(methods ...string) *ControllerMiddlewareOptions {
	o.ExceptMethods = methods
	return o
}
