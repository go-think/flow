package flow

import (
	"fmt"
	"strings"
	"unicode"
)

// resourceVerb describes one action of a resource controller.
type resourceVerb struct {
	action   string // controller method name (Index, Store,...)
	method   string // HTTP method
	uri      string // URI suffix; "%s" is replaced by the id parameter name
	hasParam bool   // whether the route carries the resource id parameter
}

// resourceVerbs lists the seven conventional resource actions in order
// (reference defaults — index, create, store, show, edit, update,
// destroy).
var resourceVerbs = []resourceVerb{
	{action: "Index", method: "GET", uri: "", hasParam: false},
	{action: "Create", method: "GET", uri: "/create", hasParam: false},
	{action: "Store", method: "POST", uri: "", hasParam: false},
	{action: "Show", method: "GET", uri: "/%s", hasParam: true},
	{action: "Edit", method: "GET", uri: "/%s/edit", hasParam: true},
	{action: "Update", method: "PUT,PATCH", uri: "/%s", hasParam: true},
	{action: "Destroy", method: "DELETE", uri: "/%s", hasParam: true},
}

// singletonResourceVerbs lists the actions of a singleton resource (no id
// parameter; singleton defaults — show, edit, update).
var singletonResourceVerbs = []resourceVerb{
	{action: "Show", method: "GET", uri: "", hasParam: false},
	{action: "Edit", method: "GET", uri: "/edit", hasParam: false},
	{action: "Update", method: "PUT,PATCH", uri: "", hasParam: false},
}

// singletonCreatableVerbs appends to the singleton defaults for creatable
// singletons).
var singletonCreatableVerbs = []resourceVerb{
	{action: "Create", method: "GET", uri: "/create", hasParam: false},
	{action: "Store", method: "POST", uri: "", hasParam: false},
	{action: "Destroy", method: "DELETE", uri: "", hasParam: false},
}

// singletonDestroyableVerb appends for destroyable-only singletons
// ).
var singletonDestroyableVerb = resourceVerb{action: "Destroy", method: "DELETE", uri: "", hasParam: false}

// ResourceOptions restrict and customize a resource registration.
type ResourceOptions struct {
	Only                 []string
	Except               []string
	APIOnly              []string // implied by APIResource; overridden by Only
	Middleware           []any
	MiddlewareFor        map[string][]any
	WithoutMiddleware    []any
	WithoutMiddlewareFor map[string][]any
	Wheres               map[string]string
	Names                map[string]string // action -> full route name override
	BaseName             string            // string form of names: used as the base name
	NamePrefix           string
	Parameters           map[string]string // segment -> parameter placeholder override
	Shallow              bool
	Creatable            bool
	Destroyable          bool
	Trashed              []string // empty means the member actions show/edit/update
	Missing              func(req *Request, err error) any
	Scoped               bool
	ScopedFields         map[string]string
	Metadata             map[string]any
}

// applies mirrors the reference getResourceMethods: the only list is intersected
// first (user Only overrides the API default), then the except list is
// subtracted. Action names are matched case-sensitively after the user-provided
// entries are normalized to the canonical capitalized action form (see
// normalizeResourceAction).
func (o *ResourceOptions) applies(action string) bool {
	only := o.Only
	if len(only) == 0 {
		only = o.APIOnly
	}
	if len(only) > 0 && !containsAction(only, action) {
		return false
	}
	if len(o.Except) > 0 && containsAction(o.Except, action) {
		return false
	}
	return true
}

// normalizeResourceAction maps a user-provided resource action name to the
// canonical capitalized form used by the verb tables ("index" → "Index",
// "show" → "Show"). the reference implementation compares action names case-sensitively
// ( — array_intersect/in_array), so
// beyond this single normalization the comparison is exact: "INDEX" does not
// match "Index".
func normalizeResourceAction(action string) string {
	if action == "" {
		return action
	}
	r := []rune(action)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// containsAction reports whether the list contains the action after each entry
// is normalized to the canonical capitalized action form and compared exactly
// (the reference implementation: array_intersect/in_array — case-sensitive beyond the normalization
// of the conventional lower-case action spellings).
func containsAction(list []string, action string) bool {
	for _, v := range list {
		if normalizeResourceAction(v) == action {
			return true
		}
	}
	return false
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
	// trashedRequested distinguishes an explicit WithTrashed() call from no
	// call at all — an empty list still
	// counts as requested, while no call never applies withTrashed).
	trashedRequested bool
}

// ResourceOption mutates the options of a resource registration. It is passed
// variadically to Resource/APIResource/Singleton/... like the reference implementation
// options argument.
type ResourceOption func(*ResourceOptions)

// WithBaseName sets the base route name of the resource, the string form of
// the reference names option: the final name becomes "prefix.base.action"
// ).
func WithBaseName(base string) ResourceOption {
	return func(o *ResourceOptions) {
		o.BaseName = base
	}
}

// applyResourceOptions applies the variadic options in order.
func applyResourceOptions(o *ResourceOptions, options []ResourceOption) {
	for _, opt := range options {
		if opt != nil {
			opt(o)
		}
	}
}

// uniqueMiddleware removes duplicate middleware entries, keeping the first
// occurrence. Only comparable scalar
// entries (e.g. strings) are deduplicated, mirroring the reference implementation where object
// instances are compared by identity.
func uniqueMiddleware(middleware []any) []any {
	result := make([]any, 0, len(middleware))
	for _, item := range middleware {
		if !middlewareContains(result, item) {
			result = append(result, item)
		}
	}
	return result
}

func middlewareContains(list []any, item any) bool {
	for _, existing := range list {
		if existing == nil || item == nil {
			if existing == nil && item == nil {
				return true
			}
			continue
		}
		if s, ok := item.(string); ok {
			if e, ok := existing.(string); ok && e == s {
				return true
			}
		}
	}
	return false
}

// Only limits the resource to the given actions (Index/Store/Create/Show/
// Edit/Update/Destroy).
func (p *PendingResourceRegistration) Only(actions ...string) *PendingResourceRegistration {
	p.options.Only = actions
	return p
}

// Except removes the given actions from the resource
// (the reference implementation: — array_diff after the only
// intersection, so it composes with the API default list).
func (p *PendingResourceRegistration) Except(actions ...string) *PendingResourceRegistration {
	p.options.Except = actions
	return p
}

// Middleware attaches middleware to every resource route, replacing any
// previous middleware.
// Per-action lists registered with MiddlewareFor are re-merged with the new
// base, the per-action entries first
// (the reference implementation:, options['middleware_for']
// = unique merge of the base list with the per-action list).
func (p *PendingResourceRegistration) Middleware(middleware ...any) *PendingResourceRegistration {
	p.options.Middleware = middleware
	for action, forMiddleware := range p.options.MiddlewareFor {
		merged := append(append([]any(nil), forMiddleware...), middleware...)
		p.options.MiddlewareFor[action] = uniqueMiddleware(merged)
	}
	return p
}

// MiddlewareFor attaches middleware to specific actions of the resource. The
// base middleware is merged in front of the action-specific one and the list
// is deduplicated, replacing any previous list for those actions
// (the reference implementation: —
// unique merge of the base middleware with the per-action middleware).
func (p *PendingResourceRegistration) MiddlewareFor(actions []string, middleware ...any) *PendingResourceRegistration {
	if len(p.options.Middleware) > 0 {
		middleware = uniqueMiddleware(append(append([]any(nil), p.options.Middleware...), middleware...))
	}
	if p.options.MiddlewareFor == nil {
		p.options.MiddlewareFor = make(map[string][]any)
	}
	for _, action := range actions {
		p.options.MiddlewareFor[action] = middleware
	}
	return p
}

// WithoutMiddleware excludes middleware from every resource route.
func (p *PendingResourceRegistration) WithoutMiddleware(middleware ...any) *PendingResourceRegistration {
	p.options.WithoutMiddleware = append(p.options.WithoutMiddleware, middleware...)
	return p
}

// WithoutMiddlewareFor excludes middleware from specific actions of the
// resource, replacing the previous list for those actions
// .
func (p *PendingResourceRegistration) WithoutMiddlewareFor(actions []string, middleware ...any) *PendingResourceRegistration {
	if p.options.WithoutMiddlewareFor == nil {
		p.options.WithoutMiddlewareFor = make(map[string][]any)
	}
	for _, action := range actions {
		p.options.WithoutMiddlewareFor[action] = middleware
	}
	return p
}

// Parameters sets explicit parameter names for segments, replacing any
// previous mapping.
func (p *PendingResourceRegistration) Parameters(parameters map[string]string) *PendingResourceRegistration {
	p.options.Parameters = parameters
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

// WithTrashed enables trashed entity binding on the resource routes. Without
// arguments the member actions (show/edit/update) are marked; with arguments
// only the listed actions are (the reference implementation: withTrashed — empty means
// an intersection of the method list with show/edit/update). The flag is
// only applied when WithTrashed was actually called
// ), and never
// on singleton resources.
func (p *PendingResourceRegistration) WithTrashed(methods ...string) *PendingResourceRegistration {
	p.options.Trashed = methods
	p.trashedRequested = true
	return p
}

// As prefixes every generated route name; the prefix is joined with a dot
// (the reference implementation: options['as'] injected via RouteRegistrar attributes —
// (the prefix is joined with a dot).
func (p *PendingResourceRegistration) As(prefix string) *PendingResourceRegistration {
	p.options.NamePrefix = prefix
	return p
}

// BaseName sets the base route name of the resource; the final name becomes
// "prefix.base.action".
func (p *PendingResourceRegistration) BaseName(base string) *PendingResourceRegistration {
	p.options.BaseName = base
	return p
}

// WhereNumber adds a numeric regex constraint to the given resource parameters
// .
func (p *PendingResourceRegistration) WhereNumber(names ...string) *PendingResourceRegistration {
	return p.assignWheres("[0-9]+", names)
}

// WhereAlpha adds an alphabetic regex constraint to the given resource
// parameters.
func (p *PendingResourceRegistration) WhereAlpha(names ...string) *PendingResourceRegistration {
	return p.assignWheres("[a-zA-Z]+", names)
}

// WhereAlphaNumeric adds an alphanumeric regex constraint to the given
// resource parameters.
func (p *PendingResourceRegistration) WhereAlphaNumeric(names ...string) *PendingResourceRegistration {
	return p.assignWheres("[a-zA-Z0-9]+", names)
}

// WhereUuid adds a UUID regex constraint to the given resource parameters
// .
func (p *PendingResourceRegistration) WhereUuid(names ...string) *PendingResourceRegistration {
	return p.assignWheres(`[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}`, names)
}

// WhereUlid adds a ULID regex constraint to the given resource parameters
// .
func (p *PendingResourceRegistration) WhereUlid(names ...string) *PendingResourceRegistration {
	return p.assignWheres(`[0-7][0-9a-hjkmnp-tv-zA-HJKMNP-TV-Z]{25}`, names)
}

// WhereIn adds an allowed values constraint to a resource parameter
// .
func (p *PendingResourceRegistration) WhereIn(name string, allowed []string) *PendingResourceRegistration {
	return p.Where(map[string]string{name: strings.Join(allowed, "|")})
}

// assignWheres builds the parameter -> expression map and routes it through
// Where.
func (p *PendingResourceRegistration) assignWheres(expression string, names []string) *PendingResourceRegistration {
	wheres := make(map[string]string, len(names))
	for _, name := range names {
		wheres[name] = expression
	}
	return p.Where(wheres)
}

// Missing sets the fallback callback when a bound resource parameter is missing.
func (p *PendingResourceRegistration) Missing(callback func(req *Request, err error) any) *PendingResourceRegistration {
	p.options.Missing = callback
	return p
}

// Scoped enables scoped child model bindings on nested resource routes
// . Optionally accepts field mappings.
func (p *PendingResourceRegistration) Scoped(fields ...map[string]string) *PendingResourceRegistration {
	p.options.Scoped = true
	if len(fields) > 0 && fields[0] != nil {
		if p.options.ScopedFields == nil {
			p.options.ScopedFields = make(map[string]string)
		}
		for k, v := range fields[0] {
			p.options.ScopedFields[k] = v
		}
	}
	return p
}

// Metadata associates metadata with each generated resource route
// .
func (p *PendingResourceRegistration) Metadata(metadata map[string]any) *PendingResourceRegistration {
	if p.options.Metadata == nil {
		p.options.Metadata = make(map[string]any)
	}
	for k, v := range metadata {
		p.options.Metadata[k] = v
	}
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

// Where adds parameter constraints to every resource route, replacing any
// previous constraints.
func (p *PendingResourceRegistration) Where(wheres map[string]string) *PendingResourceRegistration {
	p.options.Wheres = wheres
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

// register builds the resource routes. The registered guard prevents double
// registration.
func (p *PendingResourceRegistration) register() {
	if p.registered {
		return
	}
	p.registered = true

	verbs := resourceVerbs
	if p.singleton {
		verbs = singletonResourceVerbs
		if p.options.Creatable {
			verbs = append(append([]resourceVerb(nil), singletonResourceVerbs...), singletonCreatableVerbs...)
		} else if p.options.Destroyable {
			verbs = append(append([]resourceVerb(nil), singletonResourceVerbs...), singletonDestroyableVerb)
		}
	}

	// Merge per-resource and global parameter overrides.
	effectiveParams := p.options.Parameters
	if len(p.params()) > 0 {
		if effectiveParams == nil {
			effectiveParams = make(map[string]string)
		}
		for k, v := range p.params() {
			if _, exists := effectiveParams[k]; !exists {
				effectiveParams[k] = v
			}
		}
	}

	// Resolve parameter names for segments with overrides if present.
	resolveParam := func(seg string) string {
		if effectiveParams != nil {
			if override, ok := effectiveParams[seg]; ok {
				return override
			}
		}
		// the reference resourceRegistrar converts hyphens in wildcard names to
		// underscores after singularization (getResourceWildcard).
		return strings.ReplaceAll(singularize(strings.ReplaceAll(seg, "-", "_"), effectiveParams, p.singular()), "-", "_")
	}

	// A nested name ("albums.photos") becomes
	// "/albums/{album}/photos/{photo}": every parent segment contributes its
	// singularized id parameter, the last segment stays literal.
	// Supports prefixed resources like "admin/users".
	resourceName := p.name
	prefixPath := ""
	if strings.Contains(resourceName, "/") {
		slashIdx := strings.LastIndex(resourceName, "/")
		prefixPath = "/" + strings.Trim(resourceName[:slashIdx], "/")
		resourceName = resourceName[slashIdx+1:]
	}

	segments := strings.Split(resourceName, ".")
	var pathBuilder strings.Builder
	if prefixPath != "" {
		pathBuilder.WriteString(prefixPath)
	}
	for i, seg := range segments {
		pathBuilder.WriteString("/")
		pathBuilder.WriteString(seg)
		if i < len(segments)-1 {
			pathBuilder.WriteString("/{" + resolveParam(seg) + "}")
		}
	}
	path := pathBuilder.String()
	param := resolveParam(lastSegment(resourceName))

	for _, rv := range verbs {
		if !p.options.applies(rv.action) {
			continue
		}

		routePath := path
		if rv.hasParam && !p.singleton {
			idSegment := fmt.Sprintf(rv.uri, "{"+param+"}")
			if p.options.Shallow && isNestedResource(p.name) {
				// Shallow member routes keep the URI prefix of the resource
				// (the reference implementation registers shallow members inside the same prefixed
				// group, dropping only the parent id parameters).
				routePath = prefixPath + "/" + lastSegment(resourceName) + idSegment
			} else {
				routePath = path + idSegment
			}
		} else {
			routePath = path + rv.uri
		}

		// Verb overrides apply to the create/edit URI suffixes only
		//.
		if override, ok := p.verbsMap()[strings.ToLower(rv.action)]; ok && (rv.action == "Create" || rv.action == "Edit") {
			if rv.action == "Create" {
				routePath = path + "/" + override
			} else if p.options.Shallow && isNestedResource(p.name) {
				routePath = prefixPath + "/" + lastSegment(resourceName) + "/{" + param + "}/" + override
			} else {
				routePath = path + "/{" + param + "}/" + override
			}
		}

		routeName := p.routeName(rv.action)
		// the reference implementation ( setResourceBindingFields):
		// the binding fields are extracted per route from the parameters that
		// actually occur in its URI — collection routes (index/store/create)
		// carry no placeholder and receive none.
		uriParams := routeURIParameters(routePath)

		var action any
		if name, isName := p.controller.(string); isName {
			action = name + "@" + rv.action
		} else {
			action = ControllerAction{Controller: p.controller, Method: rv.action}
		}
		child := p.router.Add(Method(strings.Split(rv.method, ",")...), routePath, action)
		child.Name(routeName)

		// The action-specific middleware list replaces the base list, while
		// the excluded list is merged with the base and deduplicated. The
		// action key is looked up once — exact match first, then the
		// lower-cased form.
		middleware := p.options.Middleware
		if forAction, ok := middlewareForAction(p.options.MiddlewareFor, rv.action); ok {
			middleware = forAction
		}
		if len(middleware) > 0 {
			child.Middleware(middleware...)
		}
		excluded := p.options.WithoutMiddleware
		if forExcluded, ok := middlewareForAction(p.options.WithoutMiddlewareFor, rv.action); ok {
			excluded = uniqueMiddleware(append(append([]any(nil), excluded...), forExcluded...))
		}
		if len(excluded) > 0 {
			child.WithoutMiddleware(excluded...)
		}
		for k, v := range p.options.Wheres {
			child.Where(k, v)
		}
		if rc, ok := child.(*routeChain); ok && rc.route != nil {
			// Only the binding fields of the parameters actually present in
			// the route URI are applied (placeholder scan over the URI), so a
			// scoped field for a parameter the route does not carry is
			// skipped; the route-level scopeBindings flag is NOT set.
			if len(p.options.ScopedFields) > 0 {
				for k, v := range p.options.ScopedFields {
					if _, present := uriParams[k]; present {
						rc.route.SetBindingFieldFor(k, v)
					}
				}
			}
			if len(p.options.Metadata) > 0 {
				for k, v := range p.options.Metadata {
					rc.route.SetMetadata(k, v)
				}
			}
			// withTrashed applies only when WithTrashed was called,
			// to the listed actions or to the member actions
			// (show/edit/update) when the list is empty.
			if p.trashedApplies(rv.action) {
				rc.route.WithTrashed()
			}
			if p.options.Missing != nil && p.missingApplies(rv.action) {
				rc.route.Missing(p.options.Missing)
			}
		} else if rChild, ok := child.(*router); ok {
			if len(p.options.ScopedFields) > 0 {
				// Same URI-based filtering as the route branch above
				//.
				if rChild.bindingFields == nil {
					rChild.bindingFields = make(map[string]string)
				}
				for k, v := range p.options.ScopedFields {
					if _, present := uriParams[k]; present {
						rChild.bindingFields[k] = v
					}
				}
			}
			if len(p.options.Metadata) > 0 {
				if rChild.groupMetadata == nil {
					rChild.groupMetadata = make(map[string]any)
				}
				for k, v := range p.options.Metadata {
					rChild.groupMetadata[k] = v
				}
			}
			if p.trashedApplies(rv.action) {
				rChild.withTrashed = true
			}
			if p.options.Missing != nil && p.missingApplies(rv.action) {
				rChild.missing = p.options.Missing
			}
		}
	}
}

// routeURIParameters extracts the placeholder names occurring in a route URI,
// e.g. "/users/{user}/posts/{post}" → {"user", "post"} (the reference implementation:
// setResourceBindingFields —
// a placeholder scan over the route URI). Like the raw scan,
// an optional placeholder keeps its "?" suffix ("{post?}" → "post?").
func routeURIParameters(uri string) map[string]struct{} {
	params := make(map[string]struct{})
	for i := 0; i < len(uri); i++ {
		if uri[i] == '{' {
			end := strings.IndexByte(uri[i:], '}')
			if end == -1 {
				break
			}
			params[uri[i+1:i+end]] = struct{}{}
			i += end
		}
	}
	return params
}

// middlewareForAction looks up the action-specific list: the exact action key
// first, then the lower-cased form. Only one lookup wins, so a list is never
// applied twice.
func middlewareForAction(m map[string][]any, action string) ([]any, bool) {
	if v, ok := m[action]; ok {
		return v, true
	}
	v, ok := m[strings.ToLower(action)]
	return v, ok
}

// routeName resolves the route name of an action: the explicit override when
// present, otherwise "prefix.base.action" (the reference implementation: getResourceRouteName —
// the per-method names entry wins, then a string names value replaces the
// base, then the resource name; the "as" option becomes "as." prefix).
func (p *PendingResourceRegistration) routeName(action string) string {
	if name, ok := p.options.Names[action]; ok {
		return name
	}
	if name, ok := p.options.Names[strings.ToLower(action)]; ok {
		return name
	}
	name := p.name
	if slashIdx := strings.LastIndex(name, "/"); slashIdx != -1 {
		name = name[slashIdx+1:]
	}
	// the reference implementation keeps the complete dotted resource name for collection routes.
	// Only the member routes of a shallow nested resource use the final
	// resource segment as their route-name base. The singleton show route is
	// not shallow-named.
	if p.options.Shallow && isNestedResource(name) && isShallowMemberAction(action) &&
		!(p.singleton && action == "Show") {
		if idx := strings.LastIndex(name, "."); idx != -1 {
			name = name[idx+1:]
		}
	}
	// A string names value replaces the resource name entirely
	//.
	if p.options.BaseName != "" {
		name = p.options.BaseName
	}
	prefix := ""
	if p.options.NamePrefix != "" {
		prefix = p.options.NamePrefix + "."
	}
	return prefix + name + "." + strings.ToLower(action)
}

// trashedApplies reports whether the action receives the withTrashed flag.
// Like the reference implementation, the flag is only applied when
// WithTrashed was actually called, to the listed actions or — with an empty
// list — to the member actions (show/edit/update). Singleton registrations
// never apply it (they have no trashed handling).
func (p *PendingResourceRegistration) trashedApplies(action string) bool {
	if !p.trashedRequested || p.singleton {
		return false
	}
	if len(p.options.Trashed) == 0 {
		return containsAction([]string{"Show", "Edit", "Update"}, action)
	}
	return containsAction(p.options.Trashed, action)
}

// missingApplies reports whether the action receives the missing callback.
// the reference implementation unsets options['missing'] for the collection actions index/create/
// store of a resource (,318,338) and for the
// singleton create/store/show (,456,475).
func (p *PendingResourceRegistration) missingApplies(action string) bool {
	if p.singleton {
		return !containsAction([]string{"Create", "Store", "Show"}, action)
	}
	return !containsAction([]string{"Index", "Create", "Store"}, action)
}

func isShallowMemberAction(action string) bool {
	switch strings.ToLower(action) {
	case "show", "edit", "update", "destroy":
		return true
	default:
		return false
	}
}

// lastSegment returns the last dotted segment of a resource name.
func lastSegment(name string) string {
	if idx := strings.LastIndex(name, "."); idx != -1 {
		return name[idx+1:]
	}
	return name
}

// isNestedResource reports whether the resource name is nested.
func isNestedResource(name string) bool {
	return strings.Contains(name, ".")
}

// irregularPlurals maps common irregular English plurals to their singular form
// .
var irregularPlurals = map[string]string{
	"categories": "category",
	"queries":    "query",
	"companies":  "company",
	"cities":     "city",
	"parties":    "party",
	"people":     "person",
	"children":   "child",
	"men":        "man",
	"women":      "woman",
	"mice":       "mouse",
	"teeth":      "tooth",
	"feet":       "foot",
	"statuses":   "status",
	"buses":      "bus",
}

// GetResourceWildcard returns the singular form of a resource name
// .
func GetResourceWildcard(name string) string {
	return singularize(name, nil, true)
}

func (p *PendingResourceRegistration) params() map[string]string {
	return p.routerResourceParams()
}

func (p *PendingResourceRegistration) verbsMap() map[string]string {
	return p.routerResourceVerbsMap()
}

func (p *PendingResourceRegistration) singular() bool {
	return p.routerResourceSingular()
}

func (p *PendingResourceRegistration) routerResourceParams() map[string]string {
	if rt, ok := p.router.(*router); ok {
		return rt.resourceParams
	}
	return nil
}

func (p *PendingResourceRegistration) routerResourceVerbsMap() map[string]string {
	if rt, ok := p.router.(*router); ok {
		return rt.resourceVerbsMap
	}
	return nil
}

func (p *PendingResourceRegistration) routerResourceSingular() bool {
	if rt, ok := p.router.(*router); ok {
		return rt.resourceSingular
	}
	return true
}

func singularize(name string, overrides map[string]string, useSingular bool) string {
	if override, ok := overrides[name]; ok {
		return override
	}
	if !useSingular {
		return name
	}
	lower := strings.ToLower(name)
	if sing, found := irregularPlurals[lower]; found {
		return sing
	}
	base := name
	if strings.HasSuffix(lower, "ies") && len(base) > 3 {
		return base[:len(base)-3] + "y"
	}
	if len(base) > 1 && strings.HasSuffix(base, "s") && !strings.HasSuffix(base, "ss") && !strings.HasSuffix(base, "us") {
		base = base[:len(base)-1]
	}
	return base
}
