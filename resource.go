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
	{action: "Update", method: "PUT", uri: "/%s", hasParam: true},
	{action: "Destroy", method: "DELETE", uri: "/%s", hasParam: true},
}

// singletonResourceVerbs lists the actions of a singleton resource (no id
// parameter; Store/Create are only added by creatable resources).
var singletonResourceVerbs = []resourceVerb{
	{action: "Show", method: "GET", uri: "", hasParam: false},
	{action: "Edit", method: "GET", uri: "/edit", hasParam: false},
	{action: "Update", method: "PUT", uri: "", hasParam: false},
	{action: "Destroy", method: "DELETE", uri: "", hasParam: false},
}

// apiResourceActions are excluded from API resources.
var apiResourceExcluded = map[string]bool{"Create": true, "Edit": true}

// ResourceOptions restrict and customize a resource registration.
type ResourceOptions struct {
	Only       []string
	Except     []string
	Middleware []any
	Wheres     map[string]string
	Names      map[string]string // action -> full route name override
	NamePrefix string
	Shallow    bool
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
	controller string
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

// Names sets explicit route names per action, overriding the default
// "name.action" convention.
func (p *PendingResourceRegistration) Names(names map[string]string) *PendingResourceRegistration {
	p.options.Names = names
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
			pathBuilder.WriteString("/{" + singularize(seg) + "}")
		}
	}
	path := pathBuilder.String()
	param := singularize(lastSegment(p.name))

	for _, rv := range verbs {
		if !p.options.applies(rv.action) {
			continue
		}
		if p.singleton && rv.action == "Store" {
			continue
		}

		routePath := path
		if rv.hasParam && !p.singleton {
			idSegment := fmt.Sprintf(rv.uri, "{"+param+"}")
			if p.options.Shallow && isNestedResource(p.name) {
				routePath = "/" + lastSegment(p.name) + idSegment
			} else {
				routePath = path + idSegment
			}
		} else {
			routePath = path + rv.uri
		}

		routeName := p.routeName(rv.action)

		child := p.router.Add(Method(rv.method), routePath, p.controller+"@"+rv.action)
		child.Name(routeName)
		child.Middleware(p.options.Middleware...)
		for k, v := range p.options.Wheres {
			child.Where(k, v)
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
func singularize(name string) string {
	base := lastSegment(name)
	if len(base) > 1 && strings.HasSuffix(base, "s") && !strings.HasSuffix(base, "ss") && !strings.HasSuffix(base, "us") {
		base = base[:len(base)-1]
	}
	return base
}
