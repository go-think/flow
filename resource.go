package flow

import (
	"fmt"
	"strings"
)

// resourceVerb describes one action of a resource controller.
type resourceVerb struct {
	action   string // controller method name (Index, Store, ...)
	method   string // HTTP method
	uri      string // URI suffix; "%s" is replaced by the id parameter name
	hasParam bool   // whether the route carries the resource id parameter
}

// resourceVerbs lists the seven conventional resource actions in order.
var resourceVerbs = []resourceVerb{
	{action: "Index", method: "GET", uri: "", hasParam: false},
	{action: "Store", method: "POST", uri: "", hasParam: false},
	{action: "Create", method: "GET", uri: "/create", hasParam: false},
	{action: "Show", method: "GET", uri: "/%s", hasParam: true},
	{action: "Edit", method: "GET", uri: "/%s/edit", hasParam: true},
	{action: "Update", method: "PUT,PATCH", uri: "/%s", hasParam: true},
	{action: "Destroy", method: "DELETE", uri: "/%s", hasParam: true},
}

// singletonResourceVerbs lists the actions of a singleton resource (no id
// parameter; Store/Create are only added by creatable resources).
var singletonResourceVerbs = []resourceVerb{
	{action: "Show", method: "GET", uri: "", hasParam: false},
	{action: "Edit", method: "GET", uri: "/edit", hasParam: false},
	{action: "Update", method: "PUT,PATCH", uri: "", hasParam: false},
	{action: "Destroy", method: "DELETE", uri: "", hasParam: false},
}

// apiResourceActions are excluded from API resources.
var apiResourceExcluded = map[string]bool{"Create": true, "Edit": true}

// ResourceOptions restrict and customize a resource registration.
type ResourceOptions struct {
	Only                 []string
	Except               []string
	Middleware           []any
	MiddlewareFor        map[string][]any
	WithoutMiddleware    []any
	WithoutMiddlewareFor map[string][]any
	Wheres               map[string]string
	Names                map[string]string // action -> full route name override
	NamePrefix           string
	Parameters           map[string]string // segment -> parameter placeholder override
	Shallow              bool
	Creatable            bool
	Destroyable          bool
	Trashed              []string
	Missing              func(req *Request, err error) any
	Scoped               bool
}

func (o *ResourceOptions) applies(action string) bool {
	if len(o.Only) > 0 {
		return containsString(o.Only, action)
	}
	if len(o.Except) > 0 {
		return !containsString(o.Except, action)
	}
	return true
}

// PendingResourceRegistration defers the registration of a resource so it can
// be customized fluently before it lands in the router.
type PendingResourceRegistration struct {
	router     Router
	name       string
	controller any
	options    ResourceOptions
	singleton  bool
	registered bool
}

// Only limits the resource to the given actions (Index/Store/Create/Show/
// Edit/Update/Destroy).
func (p *PendingResourceRegistration) Only(actions ...string) *PendingResourceRegistration {
	p.options.Only = actions
	return p
}

// Except removes the given actions from the resource.
func (p *PendingResourceRegistration) Except(actions ...string) *PendingResourceRegistration {
	p.options.Except = actions
	return p
}

// Middleware attaches middleware to every resource route.
func (p *PendingResourceRegistration) Middleware(middleware ...any) *PendingResourceRegistration {
	p.options.Middleware = append(p.options.Middleware, middleware...)
	return p
}

// MiddlewareFor attaches middleware to specific actions of the resource.
func (p *PendingResourceRegistration) MiddlewareFor(actions []string, middleware ...any) *PendingResourceRegistration {
	if p.options.MiddlewareFor == nil {
		p.options.MiddlewareFor = make(map[string][]any)
	}
	for _, action := range actions {
		p.options.MiddlewareFor[action] = append(p.options.MiddlewareFor[action], middleware...)
	}
	return p
}

// WithoutMiddleware excludes middleware from every resource route.
func (p *PendingResourceRegistration) WithoutMiddleware(middleware ...any) *PendingResourceRegistration {
	p.options.WithoutMiddleware = append(p.options.WithoutMiddleware, middleware...)
	return p
}

// WithoutMiddlewareFor excludes middleware from specific actions of the resource.
func (p *PendingResourceRegistration) WithoutMiddlewareFor(actions []string, middleware ...any) *PendingResourceRegistration {
	if p.options.WithoutMiddlewareFor == nil {
		p.options.WithoutMiddlewareFor = make(map[string][]any)
	}
	for _, action := range actions {
		p.options.WithoutMiddlewareFor[action] = append(p.options.WithoutMiddlewareFor[action], middleware...)
	}
	return p
}

// Parameters sets explicit parameter names for segments.
func (p *PendingResourceRegistration) Parameters(parameters map[string]string) *PendingResourceRegistration {
	if p.options.Parameters == nil {
		p.options.Parameters = make(map[string]string)
	}
	for k, v := range parameters {
		p.options.Parameters[k] = v
	}
	return p
}

// Parameter sets an explicit parameter name for a segment.
func (p *PendingResourceRegistration) Parameter(previous, newParam string) *PendingResourceRegistration {
	if p.options.Parameters == nil {
		p.options.Parameters = make(map[string]string)
	}
	p.options.Parameters[previous] = newParam
	return p
}

// Creatable enables create and store actions on singleton resources.
func (p *PendingResourceRegistration) Creatable() *PendingResourceRegistration {
	p.options.Creatable = true
	return p
}

// Destroyable enables destroy action on singleton resources.
func (p *PendingResourceRegistration) Destroyable() *PendingResourceRegistration {
	p.options.Destroyable = true
	return p
}

// WithTrashed enables trashed entity binding on resource routes (or specific actions).
func (p *PendingResourceRegistration) WithTrashed(methods ...string) *PendingResourceRegistration {
	p.options.Trashed = append(p.options.Trashed, methods...)
	return p
}

// Missing sets the fallback callback when a bound resource parameter is missing.
func (p *PendingResourceRegistration) Missing(callback func(req *Request, err error) any) *PendingResourceRegistration {
	p.options.Missing = callback
	return p
}

// Scoped enables scoped child model bindings on nested resource routes.
func (p *PendingResourceRegistration) Scoped() *PendingResourceRegistration {
	p.options.Scoped = true
	return p
}

// Names sets explicit route names per action, overriding the default
// "name.action" convention.
func (p *PendingResourceRegistration) Names(names map[string]string) *PendingResourceRegistration {
	p.options.Names = names
	return p
}

// Name sets an explicit route name for a specific action.
func (p *PendingResourceRegistration) Name(action, name string) *PendingResourceRegistration {
	if p.options.Names == nil {
		p.options.Names = make(map[string]string)
	}
	p.options.Names[action] = name
	return p
}

// Where adds parameter constraints to every resource route.
func (p *PendingResourceRegistration) Where(wheres map[string]string) *PendingResourceRegistration {
	if p.options.Wheres == nil {
		p.options.Wheres = make(map[string]string)
	}
	for k, v := range wheres {
		p.options.Wheres[k] = v
	}
	return p
}

// Shallow registers a nested resource without the parent id on the parameter
// routes (show/edit/update/destroy live at the top level).
func (p *PendingResourceRegistration) Shallow() *PendingResourceRegistration {
	p.options.Shallow = true
	return p
}

// Register lands the resource routes into the router. Called automatically
// when the application boots; calling it explicitly is optional.
func (p *PendingResourceRegistration) Register() Router {
	if p.registered {
		return p.router
	}
	p.registered = true
	p.register()
	return p.router
}

// register builds the resource routes.
func (p *PendingResourceRegistration) register() {
	verbs := resourceVerbs
	if p.singleton {
		verbs = singletonResourceVerbs
		if p.options.Creatable {
			verbs = append([]resourceVerb{
				{action: "Create", method: "GET", uri: "/create", hasParam: false},
				{action: "Store", method: "POST", uri: "", hasParam: false},
			}, verbs...)
		}
		if p.options.Destroyable {
			verbs = append(verbs, resourceVerb{action: "Destroy", method: "DELETE", uri: "", hasParam: false})
		}
	}

	// Resolve parameter names for segments with overrides if present.
	resolveParam := func(seg string) string {
		if p.options.Parameters != nil {
			if override, ok := p.options.Parameters[seg]; ok {
				return override
			}
		}
		return singularize(seg)
	}

	// Global resource config from the router affects parameter naming,
	// verb overrides and singularization.
	effectiveParams := p.options.Parameters
	if len(globalResourceParams) > 0 {
		if effectiveParams == nil {
			effectiveParams = make(map[string]string)
		}
		for k, v := range globalResourceParams {
			if _, exists := effectiveParams[k]; !exists {
				effectiveParams[k] = v
			}
		}
	}

	// A nested name ("albums.photos") becomes
	// "/albums/{album}/photos/{photo}": every parent segment contributes its
	// singularized id parameter, the last segment stays literal.
	segments := strings.Split(p.name, ".")
	var pathBuilder strings.Builder
	for i, seg := range segments {
		pathBuilder.WriteString("/")
		pathBuilder.WriteString(seg)
		if i < len(segments)-1 {
			pathBuilder.WriteString("/{" + resolveParam(seg) + "}")
		}
	}
	path := pathBuilder.String()
	param := resolveParam(lastSegment(p.name))

	for _, rv := range verbs {
		if !p.options.applies(rv.action) {
			continue
		}

		routePath := path
		if rv.hasParam && !p.singleton {
			idSegment := fmt.Sprintf(rv.uri, "{"+param+"}")
			_ = effectiveParams
			if p.options.Shallow && isNestedResource(p.name) {
				routePath = "/" + lastSegment(p.name) + idSegment
			} else {
				routePath = path + idSegment
			}
		} else {
			routePath = path + rv.uri
		}

		routeName := p.routeName(rv.action)

		var action any
		if name, isName := p.controller.(string); isName {
			action = name + "@" + rv.action
		} else {
			action = ControllerAction{Controller: p.controller, Method: rv.action}
		}
		child := p.router.Add(Method(strings.Split(rv.method, ",")...), routePath, action)
		child.Name(routeName)
		child.Middleware(p.options.Middleware...)
		if forAction, ok := p.options.MiddlewareFor[rv.action]; ok {
			child.Middleware(forAction...)
		}
		if forAction, ok := p.options.MiddlewareFor[strings.ToLower(rv.action)]; ok {
			child.Middleware(forAction...)
		}
		if len(p.options.WithoutMiddleware) > 0 {
			child.WithoutMiddleware(p.options.WithoutMiddleware...)
		}
		if withoutAction, ok := p.options.WithoutMiddlewareFor[rv.action]; ok {
			child.WithoutMiddleware(withoutAction...)
		}
		if withoutAction, ok := p.options.WithoutMiddlewareFor[strings.ToLower(rv.action)]; ok {
			child.WithoutMiddleware(withoutAction...)
		}
		for k, v := range p.options.Wheres {
			child.Where(k, v)
		}
		if rChild, ok := child.(*router); ok {
			if p.options.Scoped {
				rChild.scopedBindings = true
			}
			if len(p.options.Trashed) > 0 {
				for _, m := range p.options.Trashed {
					if strings.EqualFold(m, rv.action) {
						rChild.withTrashed = true
						break
					}
				}
			}
			if p.options.Missing != nil {
				rChild.missing = p.options.Missing
			}
		}
	}
}

// routeName resolves the route name of an action: the explicit override when
// present, otherwise "namePrefix + resource.action".
func (p *PendingResourceRegistration) routeName(action string) string {
	if name, ok := p.options.Names[action]; ok {
		return name
	}
	if name, ok := p.options.Names[strings.ToLower(action)]; ok {
		return name
	}
	name := p.name
	if idx := strings.LastIndex(name, "."); idx != -1 {
		name = name[idx+1:]
	}
	return p.options.NamePrefix + name + "." + strings.ToLower(action)
}

// lastSegment returns the last dotted segment of a resource name.
func lastSegment(name string) string {
	if idx := strings.LastIndex(name, "."); idx != -1 {
		return name[idx+1:]
	}
	return name
}

// lastSegmentPath returns the top-level path of a nested resource path (used
// by shallow resources): "/albums/{album}/photos" -> "/photos".
func lastSegmentPath(path string) string {
	if idx := strings.LastIndex(path, "/{"); idx != -1 {
		if parentEnd := strings.LastIndex(path[:idx], "/"); parentEnd != -1 {
			return path[parentEnd:]
		}
	}
	return path
}

// isNestedResource reports whether the resource name is nested.
func isNestedResource(name string) bool {
	return strings.Contains(name, ".")
}

// singularize derives the parameter name from a resource name: the trailing
// "s" of the last segment is stripped (simplified singularization without a
// full irregular-word table).
var globalResourceSingular bool
var globalResourceParams map[string]string
var globalResourceVerbsMap map[string]string

func singularize(name string) string {
	if override, ok := globalResourceParams[name]; ok {
		return override
	}
	base := name
	if len(base) > 1 && strings.HasSuffix(base, "s") && !strings.HasSuffix(base, "ss") && !strings.HasSuffix(base, "us") {
		base = base[:len(base)-1]
	}
	return base
}
