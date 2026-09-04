package flow

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Behavioral regression tests for router and route semantics.

// The fallback route registers GET only.
func TestFallbackRegistersGetOnly(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Fallback(func() string { return "fallback" })
	r.Register()

	routes := r.GetRoutes()
	for _, route := range routes {
		if route.IsFallback() {
			methods := route.Methods()
			assert.Equal(t, "GET", methods[0], "fallback registers GET only")
			assert.NotContains(t, methods, "POST", "fallback must not cover all verbs")
			assert.NotContains(t, methods, "PUT", "fallback must not cover all verbs")
			return
		}
	}
	t.Fatal("no fallback route registered")
}

// Binder keys normalize "-" to "_"; the same normalization applies on
// lookup.
func TestBinderKeyHyphenNormalization(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Bind("user-id", func(value string, route *Route) (any, error) {
		return value, nil
	})
	rt := r.(*router)
	assert.NotNil(t, rt.getBinder("user_id"), "hyphen key must resolve via underscore lookup")
	assert.NotNil(t, rt.getBinder("user-id"))
}

// Scope decisions are three-state with the last call winning:
// scopeBindings overrides a previous withoutScopedBindings and vice versa.
func TestScopeBindingsLastCallWins(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Get("/x/{a}/{b}", func() {})
	r.Register()
	var route *Route
	for _, candidate := range r.GetRoutes() {
		if candidate.GetUri() == "/x/{a}/{b}" {
			route = candidate
		}
	}
	if route == nil {
		t.Fatal("route not registered")
	}

	route.WithoutScopedBindings().ScopeBindings()
	assert.True(t, route.EnforcesScopedBindings())
	assert.False(t, route.PreventsScopedBindings())

	route.ScopeBindings().WithoutScopedBindings()
	assert.False(t, route.EnforcesScopedBindings())
	assert.True(t, route.PreventsScopedBindings())
}

// replaces ALL occurrences of a binding-field placeholder
// (string-replacement semantics).
func TestParseRouteUriReplacesAllOccurrences(t *testing.T) {
	parsed := ParseRouteUri("/x/{user:id}/y/{user:id}")
	assert.Equal(t, "/x/{user}/y/{user}", parsed.URI)
	assert.Equal(t, "id", parsed.BindingFields["user"])
}

// Route verbs are normalized to upper case (the reference implementation compares upper-case
// request methods with upper-case route methods).
func TestAddNormalizesVerbCase(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Add([]string{"get", "Post"}, "/mixed", func() string { return "ok" })
	r.Register()
	for _, route := range r.GetRoutes() {
		if route.GetUri() == "/mixed" {
			methods := route.Methods()
			assert.Equal(t, "GET", methods[0])
			assert.Equal(t, "POST", methods[1])
			for _, m := range methods {
				assert.Equal(t, strings.ToUpper(m), m, "verbs must be upper case")
			}
			return
		}
	}
	t.Fatal("route /mixed not registered")
}

// SetWheres merges into the existing constraints instead of replacing them.
func TestSetWheresMerges(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Get("/z/{a}/{b}", func() {})
	r.Register()
	var route *Route
	for _, candidate := range r.GetRoutes() {
		if candidate.GetUri() == "/z/{a}/{b}" {
			route = candidate
		}
	}
	if route == nil {
		t.Fatal("route not registered")
	}

	route.Where("a", "[0-9]+")
	route.SetWheres(map[string]string{"b": "[a-z]+"})
	wheres := route.Wheres()
	assert.Equal(t, "[0-9]+", wheres["a"], "existing where must survive SetWheres")
	assert.Equal(t, "[a-z]+", wheres["b"])
}

// Immediate-registration mode honors route-level Where set before the verb
// call.
func TestImmediateModeRouteWheresApplied(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Where("id", "[0-9]+").Get("/items/{id}", func(id string) string { return id })
	r.Register()

	// Non-numeric id must not match → 404.
	req := NewRequest(httptest.NewRequest("GET", "/items/abc", nil))
	res := r.Dispatch(req)
	assert.Equal(t, 404, res.GetCode())

	reqOK := NewRequest(httptest.NewRequest("GET", "/items/7", nil))
	resOK := r.Dispatch(reqOK)
	assert.Equal(t, 200, resOK.GetCode())
}

// The 404 message uses the request path: both-side trimmed, root "/".
func TestNotFoundMessagePathSemantics(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Get("/", func() string { return "home" })
	r.Register()

	req := NewRequest(httptest.NewRequest("GET", "/missing", nil))
	res := r.Dispatch(req)
	assert.Equal(t, 404, res.GetCode())
	assert.Equal(t, "The route missing could not be found.", res.GetContent())

	// PUT / hits 405 (the GET / route exists — the reference implementation behavior); the message
	// reports the trimmed root path "/".
	reqRoot := NewRequest(httptest.NewRequest("PUT", "/", nil))
	resRoot := r.Dispatch(reqRoot)
	assert.Equal(t, 405, resRoot.GetCode())
	assert.Contains(t, resRoot.GetContent(), "not supported for route /")
	assert.False(t, strings.Contains(resRoot.GetContent(), "  "), "no double spaces")
}

// Deferred-registration mode merges group metadata down the chain into every
// route.
func TestDeferredGroupMetadata(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Group(GroupAttributes{
		Metadata: map[string]any{"layer": "outer", "nested": map[string]any{"a": 1}},
	}, func(g Router) {
		g.Group(GroupAttributes{
			Metadata: map[string]any{"layer2": "inner", "nested": map[string]any{"b": 2}},
		}, func(gg Router) {
			gg.Get("/deep", func() string { return "deep" }).Name("deep.route")
		})
	})
	r.Register()

	var route *Route
	for _, candidate := range r.GetRoutes() {
		if candidate.GetUri() == "/deep" {
			route = candidate
		}
	}
	if route == nil {
		t.Fatal("route /deep not registered")
	}
	assert.Equal(t, "outer", route.Metadata("layer"), "outer group metadata must reach the route")
	assert.Equal(t, "inner", route.Metadata("layer2"), "inner group metadata must reach the route")
	nested := route.Metadata("nested")
	nestedMap, ok := nested.(map[string]any)
	assert.True(t, ok, "nested metadata map should survive deep merge")
	if ok {
		assert.Equal(t, 1, nestedMap["a"])
		assert.Equal(t, 2, nestedMap["b"])
	}
}

// Router.HasAll requires every name to exist.
func TestRouterHasAll(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Get("/a", func() string { return "a" }).Name("a.route")
	r.Get("/b", func() string { return "b" }).Name("b.route")
	r.Register()

	assert.True(t, r.HasAll("a.route", "b.route"))
	assert.False(t, r.HasAll("a.route", "missing.route"))
}
