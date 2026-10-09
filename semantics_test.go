package flow

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The tests in this file cover router semantics: registration-order matching,
// fallback-last, trailing slash normalization, name concatenation, automatic
// HEAD, Allow ordering and the can middleware chain.

func TestSemantics_RegistrationOrderPriority(t *testing.T) {
	// Routes match in registration order: a dynamic route declared first beats
	// a static route declared later (no static-over-dynamic priority).
	r := NewRouter(nil, nil)
	r.Get("/users/{id}", func(ctx Context, id string) Response {
		return ctx.String(200, "dynamic:"+id)
	})
	r.Get("/users/create", func(ctx Context) Response {
		return ctx.String(200, "static")
	})

	resp := r.Dispatch(httptest.NewRequest(http.MethodGet, "/users/create", nil))
	assert.Equal(t, 200, resp.StatusCode())
	assert.Equal(t, "dynamic:create", resp.Body())
}

func TestSemantics_TrailingSlash(t *testing.T) {
	// The trailing slash of the request path is trimmed before matching.
	r := NewRouter(nil, nil)
	r.Get("/users", func(ctx Context) Response { return ctx.String(200, "users") })

	resp := r.Dispatch(httptest.NewRequest(http.MethodGet, "/users/", nil))
	assert.Equal(t, 200, resp.StatusCode())
	assert.Equal(t, "users", resp.Body())
}

func TestSemantics_FallbackRouteLast(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Get("/users/{id}", func(ctx Context, id string) Response {
		return ctx.String(200, "user:"+id)
	})
	r.Fallback(func(ctx Context) Response {
		return ctx.String(200, "fallback")
	})

	// The fallback is a real route registered on every verb.
	assert.True(t, r.Has("fallbackPlaceholder") == false) // no name by default
	found := false
	for _, route := range r.GetRoutes() {
		if route.IsFallback() {
			found = true
		}
	}
	assert.True(t, found, "fallback route should live in the collection")

	// A normal route wins over the fallback...
	resp := r.Dispatch(httptest.NewRequest(http.MethodGet, "/users/7", nil))
	assert.Equal(t, "user:7", resp.Body())

	//...and the fallback only matches when nothing else does.
	resp = r.Dispatch(httptest.NewRequest(http.MethodGet, "/anything/else", nil))
	assert.Equal(t, 200, resp.StatusCode())
	assert.Equal(t, "fallback", resp.Body())
}

func TestSemantics_NameConcatenation(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Group(func(sub Router) {
		sub.Prefix("admin").Name("admin.")
		sub.Get("/dashboard", func(ctx Context) Response {
			return ctx.String(200, "ok")
		}).Name("dashboard")
	})
	assert.True(t, r.Has("admin.dashboard"))
}

func TestSemantics_HeadAutoAppend(t *testing.T) {
	r := NewRouter(nil, nil)
	route := r.Match(Method("GET"), "/users", func(ctx Context) Response {
		return ctx.String(200, "ok")
	})
	_ = route
	// A GET route automatically also handles HEAD.
	var found *Route
	for _, rt := range r.GetRoutes() {
		found = rt
	}
	assert.NotNil(t, found)
	assert.Contains(t, found.Methods(), "HEAD")

	// A HEAD request hits a GET route and never produces a 405.
	resp := r.Dispatch(httptest.NewRequest(http.MethodHead, "/users", nil))
	assert.Equal(t, 200, resp.StatusCode())
	assert.Empty(t, resp.Body())
	assert.Equal(t, "2", resp.Headers().Get("Content-Length"))
}

func TestSemantics_405VerbsOrderAndMessage(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Post("/users", func(ctx Context) Response { return ctx.String(200, "created") })
	r.Delete("/users", func(ctx Context) Response { return ctx.String(200, "deleted") })

	resp := r.Dispatch(httptest.NewRequest(http.MethodGet, "/users", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode())
	// The Allow list follows the router's verb order (GET, HEAD, POST, ...).
	assert.Equal(t, "POST, DELETE", resp.Headers().Get("Allow"))
	assert.Contains(t, resp.Body(), "The GET method is not supported for route users. Supported methods: POST, DELETE.")
}

func TestSemantics_404Message(t *testing.T) {
	r := NewRouter(nil, nil)
	resp := r.Dispatch(httptest.NewRequest(http.MethodGet, "/missing", nil))
	assert.Equal(t, 404, resp.StatusCode())
	assert.Contains(t, resp.Body(), "The route missing could not be found.")
}

func TestSemantics_WhereUlidLowercase(t *testing.T) {
	// WhereUlid accepts both cases; lowercase ULIDs must match.
	r := NewRouter(nil, nil)
	r.Get("/ulid/{id}", func(ctx Context, id string) Response {
		return ctx.String(200, "ulid:"+id)
	}).WhereUlid("id")

	const ulid = "01arz3ndek5zvczakg6vq6v7ga"
	resp := r.Dispatch(httptest.NewRequest(http.MethodGet, "/ulid/"+ulid, nil))
	assert.Equal(t, 200, resp.StatusCode())
}

func TestSemantics_PushMiddlewareToGroupCreatesGroup(t *testing.T) {
	r := NewRouter(nil, nil)
	// The group is created when it does not exist, and duplicates are skipped.
	r.PushMiddlewareToGroup("web", "auth")
	r.PushMiddlewareToGroup("web", "auth")
	r.PushMiddlewareToGroup("web", "sessions")

	group := r.GetMiddlewareGroup("web")
	assert.Len(t, group, 2)
}

func TestSemantics_DuplicateRegistrationReplaces(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Get("/users", func(ctx Context) Response { return ctx.String(200, "first") })
	r.Get("/users", func(ctx Context) Response { return ctx.String(200, "second") })

	// Routes are keyed by methods+domain+uri: the later registration wins
	// everywhere (matching and listing).
	assert.Equal(t, 1, r.Routes().Count())
	resp := r.Dispatch(httptest.NewRequest(http.MethodGet, "/users", nil))
	assert.Equal(t, "second", resp.Body())
}

func TestSemantics_OnCallbacksFired(t *testing.T) {
	r := NewRouter(nil, nil)
	routing := false
	matched := false
	preparing := false
	prepared := false

	r.OnRouting(func(req *Request) { routing = true })
	r.OnRouteMatched(func(route *Route, req *Request) { matched = true })
	r.OnPreparingResponse(func(req *Request, result any) { preparing = true })
	r.OnResponsePrepared(func(req *Request, res *Response) { prepared = true })

	r.Get("/", func(ctx Context) Response { return ctx.String(200, "ok") })
	resp := r.Dispatch(httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, 200, resp.StatusCode())
	assert.True(t, routing, "OnRouting should fire before matching")
	assert.True(t, matched, "OnRouteMatched should fire after matching")
	assert.True(t, preparing, "OnPreparingResponse should fire before the response")
	assert.True(t, prepared, "OnResponsePrepared should fire after the response")
}

func TestSemantics_CanMiddlewareDeniesByDefault(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Get("/admin", func(ctx Context) Response { return ctx.String(200, "secret") }).Can("viewAdmin")

	// The can middleware denies abilities the gate does not grant.
	resp := r.Dispatch(httptest.NewRequest(http.MethodGet, "/admin", nil))
	assert.Equal(t, http.StatusForbidden, resp.StatusCode())
	assert.Equal(t, "This action is unauthorized.", resp.Body())
}

func TestSemantics_BindingFieldUriRewrite(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Get("/users/{user:uuid}", func(ctx Context, user string) Response {
		return ctx.String(200, "user:"+user)
	})

	// rewrites "{user:uuid}" to "{user}" in the stored URI and
	// records the binding field.
	route := r.GetRoutes()[0]
	assert.Equal(t, "/users/{user}", route.URI())
	assert.Equal(t, "uuid", route.BindingFieldFor("user"))
}
