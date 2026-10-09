package flow

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// domainTestController is a minimal registered controller used to exercise
// serializable (cacheable) routes and domain-restricted URL generation.
type domainTestController struct{}

func (c *domainTestController) Index() string { return "items" }

func TestRestoreCompiledDynamicPrecedence(t *testing.T) {
	r := NewRouter(nil, nil)
	r.RegisterController("domainTestController", &domainTestController{})
	r.Get("/v1/items", "domainTestController@Index").Name("items.index")
	data, err := r.Compile()
	assert.NoError(t, err)

	r2 := NewRouter(nil, nil)
	r2.RegisterController("domainTestController", &domainTestController{})
	assert.NoError(t, r2.RestoreCompiled(data))

	// Cached route still matches.
	res := r2.Dispatch(NewRequest(httptest.NewRequest("GET", "/v1/items", nil)))
	assert.Equal(t, 200, res.GetCode())

	// Match semantics: the compiled matcher's hit wins, so a same-URI
	// dynamic route is NOT consulted for matching (the dynamic-precedence
	// rule applies to the route LIST (get), not to matching).
	// Register a dynamic route on the same URI and assert the cached one
	// still serves it.
	r2.Get("/v1/items", func() string { return "dynamic" })
	res2 := r2.Dispatch(NewRequest(httptest.NewRequest("GET", "/v1/items", nil)))
	assert.Equal(t, "items", res2.GetContent())

	// The route LIST prefers the dynamic route on the same domain+uri.
	list := r2.Routes().Get("GET")
	var found string
	for _, rt := range list {
		if rt.GetUri() == "/v1/items" {
			found = rt.ActionName()
		}
	}
	assert.NotEmpty(t, found)

	// Cached routes with other URIs still match.
	r2.Get("/v1/other", "domainTestController@Index")
	res3 := r2.Dispatch(NewRequest(httptest.NewRequest("GET", "/v1/other", nil)))
	assert.Equal(t, 200, res3.GetCode())
}

func TestRestoreCompiledFallbackDeference(t *testing.T) {
	r := NewRouter(nil, nil)
	r.RegisterController("domainTestController", &domainTestController{})
	r.Fallback("domainTestController@Index")
	data, err := r.Compile()
	assert.NoError(t, err)

	r2 := NewRouter(nil, nil)
	r2.RegisterController("domainTestController", &domainTestController{})
	assert.NoError(t, r2.RestoreCompiled(data))

	// No dynamic match: the cached fallback serves the request.
	res := r2.Dispatch(NewRequest(httptest.NewRequest("GET", "/anything", nil)))
	assert.Equal(t, 200, res.GetCode())

	// A dynamic non-fallback route for the same URI takes precedence.
	r2.Get("/anything", func() string { return "dynamic" })
	res2 := r2.Dispatch(NewRequest(httptest.NewRequest("GET", "/anything", nil)))
	assert.Equal(t, "dynamic", res2.GetContent())
}

func TestRestoreCompiledLookups(t *testing.T) {
	r := NewRouter(nil, nil)
	r.RegisterController("domainTestController", &domainTestController{})
	r.Domain("{sub}.example.com").Get("/d/{user}", "domainTestController@Index").Name("dom.show")
	data, err := r.Compile()
	assert.NoError(t, err)

	r2 := NewRouter(nil, nil)
	r2.RegisterController("domainTestController", &domainTestController{})
	assert.NoError(t, r2.RestoreCompiled(data))

	// Cached route by name.
	assert.True(t, r2.Routes().HasNamedRoute("dom.show"))
	domain, ok := r2.NamedRouteDomain("dom.show")
	assert.True(t, ok)
	assert.Equal(t, "{sub}.example.com", domain)

	// Dynamic route by name.
	r2.Get("/fresh", func() string { return "fresh" }).Name("fresh.route")
	assert.True(t, r2.Routes().HasNamedRoute("fresh.route"))

	// Domain URL generation goes through formatDomain after restore.
	gen := NewUrlGenerator(r2, "")
	url, err := gen.Route("dom.show", map[string]string{"sub": "api", "user": "7"})
	assert.NoError(t, err)
	assert.Equal(t, "http://api.example.com/d/7", url)
}

func TestCompileDuplicateNameGuard(t *testing.T) {
	r := NewRouter(nil, nil)
	r.RegisterController("fragmentCtl", &domainTestController{})
	r.Get("/a", "fragmentCtl@Index").Name("dup.name")
	r.Get("/b", "fragmentCtl@Index").Name("dup.name")
	_, err := r.Compile()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Another route has already been assigned name [dup.name]")

	r2 := NewRouter(nil, nil)
	r2.RegisterController("fragmentCtl", &domainTestController{})
	r2.Get("/a", "fragmentCtl@Index").Name("prefix.")
	r2.Get("/b", "fragmentCtl@Index").Name("prefix.")
	data, err := r2.Compile()
	assert.NoError(t, err)
	r3 := NewRouter(nil, nil)
	r3.RegisterController("fragmentCtl", &domainTestController{})
	assert.NoError(t, r3.RestoreCompiled(data))
	assert.True(t, r3.Routes().HasNamedRoute("prefix."))
	// Exactly one route keeps the name (the later duplicate was dropped).
	assert.Equal(t, 1, len(r3.Routes().GetRoutesByName()))
}
