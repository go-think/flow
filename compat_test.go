package flow

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock scoped model for testing
type mockUser struct {
	ID   string
	Name string
}

func (u *mockUser) ResolveRouteBinding(ctx context.Context, value string, field string) (any, error) {
	if value == "404" {
		return nil, errors.New("user not found")
	}
	return &mockUser{ID: value, Name: "User " + value}, nil
}

type mockPost struct {
	ID     string
	UserID string
	Title  string
}

func (p *mockPost) ResolveRouteBinding(ctx context.Context, value string, field string) (any, error) {
	if value == "not-found" {
		return nil, errors.New("post not found")
	}
	return &mockPost{ID: value, Title: "Post " + value}, nil
}

func (p *mockPost) ResolveChildRouteBinding(ctx context.Context, childType string, value string, field string) (any, error) {
	if childType == "comment" && value == "child-404" {
		return nil, errors.New("child comment not found")
	}
	return &mockComment{ID: value, PostID: p.ID}, nil
}

type mockComment struct {
	ID     string
	PostID string
}

func (c *mockComment) ResolveRouteBinding(ctx context.Context, value string, field string) (any, error) {
	return &mockComment{ID: value}, nil
}

func (c *mockComment) ResolveChildRouteBinding(ctx context.Context, childType string, value string, field string) (any, error) {
	return nil, nil
}

func TestCompat_MatchAndWhereConstraints(t *testing.T) {
	r := NewRouter(nil, nil)

	r.Match([]string{http.MethodGet, http.MethodPost}, "/match-test", func(ctx Context) Response {
		return ctx.String(http.StatusOK, "matched")
	})

	r.Get("/alpha-num/{code}", func(ctx Context) Response {
		return ctx.String(http.StatusOK, ctx.Param("code"))
	}).WhereAlphaNumeric("code")

	r.Get("/uuid/{id}", func(ctx Context) Response {
		return ctx.String(http.StatusOK, ctx.Param("id"))
	}).WhereUuid("id")

	r.Get("/ulid/{id}", func(ctx Context) Response {
		return ctx.String(http.StatusOK, ctx.Param("id"))
	}).WhereUlid("id")

	// Match test
	reqGet := httptest.NewRequest(http.MethodGet, "/match-test", nil)
	respGet := r.Dispatch(reqGet)
	assert.Equal(t, http.StatusOK, respGet.StatusCode())

	reqPost := httptest.NewRequest(http.MethodPost, "/match-test", nil)
	respPost := r.Dispatch(reqPost)
	assert.Equal(t, http.StatusOK, respPost.StatusCode())

	reqPut := httptest.NewRequest(http.MethodPut, "/match-test", nil)
	respPut := r.Dispatch(reqPut)
	assert.Equal(t, http.StatusMethodNotAllowed, respPut.StatusCode())
	assert.Contains(t, respPut.Headers().Get("Allow"), "GET")
	assert.Contains(t, respPut.Headers().Get("Allow"), "POST")

	// WhereAlphaNumeric
	respValidAlpha := r.Dispatch(httptest.NewRequest(http.MethodGet, "/alpha-num/abc123XYZ", nil))
	assert.Equal(t, http.StatusOK, respValidAlpha.StatusCode())
	respInvalidAlpha := r.Dispatch(httptest.NewRequest(http.MethodGet, "/alpha-num/abc-123", nil))
	assert.Equal(t, http.StatusNotFound, respInvalidAlpha.StatusCode())

	// WhereUuid
	respValidUuid := r.Dispatch(httptest.NewRequest(http.MethodGet, "/uuid/123e4567-e89b-12d3-a456-426614174000", nil))
	assert.Equal(t, http.StatusOK, respValidUuid.StatusCode())
	respInvalidUuid := r.Dispatch(httptest.NewRequest(http.MethodGet, "/uuid/not-a-uuid", nil))
	assert.Equal(t, http.StatusNotFound, respInvalidUuid.StatusCode())

	// WhereUlid
	respValidUlid := r.Dispatch(httptest.NewRequest(http.MethodGet, "/ulid/01ARZ3NDEKTSV4RRFFQ69G5FAV", nil))
	assert.Equal(t, http.StatusOK, respValidUlid.StatusCode())
	respInvalidUlid := r.Dispatch(httptest.NewRequest(http.MethodGet, "/ulid/short", nil))
	assert.Equal(t, http.StatusNotFound, respInvalidUlid.StatusCode())
}

func TestCompat_GlobalPatternsApplyToImmediateRoutes(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Pattern("id", "[0-9]+")
	r.Get("/global/{id}", func(ctx Context) Response {
		return ctx.String(http.StatusOK, ctx.Param("id"))
	})

	valid := r.Dispatch(httptest.NewRequest(http.MethodGet, "/global/42", nil))
	assert.Equal(t, http.StatusOK, valid.StatusCode())
	assert.Equal(t, "42", valid.Body())

	invalid := r.Dispatch(httptest.NewRequest(http.MethodGet, "/global/not-a-number", nil))
	assert.Equal(t, http.StatusNotFound, invalid.StatusCode())
}

func TestCompat_OptionalRoutesEnumerateOnce(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Get("/optional/{id?}", func(ctx Context) Response { return ctx.String(200, "ok") })

	routes := r.Routes().Get(http.MethodGet)
	assert.Len(t, routes, 1)
}

func TestCompat_TemporarySignedRedirectKeepsExpiration(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Get("/signed", func(ctx Context) Response { return ctx.String(200, "ok") }).Name("signed")

	generator := NewUrlGenerator(r, "http://example.test").SetKeyResolver(func() []string {
		return []string{"secret"}
	})
	redirector := NewRedirector(generator)
	response := redirector.TemporarySignedRoute("signed", 2*time.Minute, nil)

	location := response.Headers().Get("Location")
	assert.Contains(t, location, "expires=")
	assert.Contains(t, location, "signature=")
}

func TestCompat_DynamicSubdomainRoute(t *testing.T) {
	r := NewRouter(nil, nil)

	r.Domain("{account}.myapp.com").Group(func(sub Router) {
		sub.Get("/profile", func(ctx Context) Response {
			account := ctx.Param("account")
			return ctx.String(http.StatusOK, "account:"+account)
		})
	})

	req := httptest.NewRequest(http.MethodGet, "http://tenant1.myapp.com/profile", nil)
	resp := r.Dispatch(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode())
	assert.Equal(t, "account:tenant1", resp.Body())

	// Mismatched domain
	reqMismatch := httptest.NewRequest(http.MethodGet, "http://otherdomain.com/profile", nil)
	respMismatch := r.Dispatch(reqMismatch)
	assert.Equal(t, http.StatusNotFound, respMismatch.StatusCode())
}

// TestCompat_DynamicSubdomainRouteParameterOrder verifies that positional
// handler arguments on a dynamic-domain route receive host parameters first,
// then path parameters, as Bind and ParameterNames both declare.
func TestCompat_DynamicSubdomainRouteParameterOrder(t *testing.T) {
	r := NewRouter(nil, nil)

	r.Domain("{account}.myapp.com").Get("/users/{user}", func(account, user string) string {
		return account + "|" + user
	})

	resp := r.Dispatch(httptest.NewRequest(http.MethodGet, "http://tenant1.myapp.com/users/42", nil))
	assert.Equal(t, http.StatusOK, resp.StatusCode())
	assert.Equal(t, "tenant1|42", resp.Body())
}

func TestCompat_DynamicSubdomainWhereConstraint(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Domain("{account}.myapp.com").Group(func(sub Router) {
		sub.Get("/profile", func(ctx Context) Response {
			return ctx.String(http.StatusOK, ctx.Param("account"))
		}).WhereAlpha("account")
	})

	valid := httptest.NewRequest(http.MethodGet, "http://tenant.myapp.com/profile", nil)
	assert.Equal(t, http.StatusOK, r.Dispatch(valid).StatusCode())

	invalid := httptest.NewRequest(http.MethodGet, "http://tenant-1.myapp.com/profile", nil)
	assert.Equal(t, http.StatusNotFound, r.Dispatch(invalid).StatusCode())
}

func TestCompat_ModelBindingMissingAndScoped(t *testing.T) {
	r := NewRouter(nil, nil)

	// 1. Model binding failure -> 404
	r.Get("/users/{user}", func(ctx Context, user *mockUser) Response {
		return ctx.String(http.StatusOK, user.Name)
	})

	respOk := r.Dispatch(httptest.NewRequest(http.MethodGet, "/users/10", nil))
	assert.Equal(t, http.StatusOK, respOk.StatusCode())
	assert.Equal(t, "User 10", respOk.Body())

	respNotFound := r.Dispatch(httptest.NewRequest(http.MethodGet, "/users/404", nil))
	assert.Equal(t, http.StatusNotFound, respNotFound.StatusCode())

	// 2. Custom Missing handler
	r.Get("/custom-missing/{user}", func(ctx Context, user *mockUser) Response {
		return ctx.String(http.StatusOK, user.Name)
	}).Missing(func(ctx Context) Response {
		return ctx.String(http.StatusAccepted, "custom-missing-handled")
	})

	respMissing := r.Dispatch(httptest.NewRequest(http.MethodGet, "/custom-missing/404", nil))
	assert.Equal(t, http.StatusAccepted, respMissing.StatusCode())
	assert.Equal(t, "custom-missing-handled", respMissing.Body())

	// 3. Scoped binding (parent -> child): scoping only applies when the route
	// enforces it (ScopeBindings); otherwise the child resolves its own
	// binding.
	r.Get("/posts/{post}/comments/{comment}", func(ctx Context, post *mockPost, comment *mockComment) Response {
		return ctx.String(http.StatusOK, "post:"+post.ID+",comment:"+comment.ID)
	})

	respScopedOk := r.Dispatch(httptest.NewRequest(http.MethodGet, "/posts/100/comments/200", nil))
	assert.Equal(t, http.StatusOK, respScopedOk.StatusCode())
	assert.Equal(t, "post:100,comment:200", respScopedOk.Body())

	// Without enforced scoping the comment resolves independently, so the
	// parent's child-binding rejection does not apply.
	respUnscoped := r.Dispatch(httptest.NewRequest(http.MethodGet, "/posts/100/comments/child-404", nil))
	assert.Equal(t, http.StatusOK, respUnscoped.StatusCode())

	r.Get("/scoped-posts/{post}/comments/{comment}", func(ctx Context, post *mockPost, comment *mockComment) Response {
		return ctx.String(http.StatusOK, "post:"+post.ID+",comment:"+comment.ID)
	}).ScopeBindings()

	respScopedChildFail := r.Dispatch(httptest.NewRequest(http.MethodGet, "/scoped-posts/100/comments/child-404", nil))
	assert.Equal(t, http.StatusNotFound, respScopedChildFail.StatusCode())
}

type dummyController struct{}

func (d *dummyController) Index(ctx Context) Response   { return ctx.String(200, "index") }
func (d *dummyController) Show(ctx Context) Response    { return ctx.String(200, "show") }
func (d *dummyController) Create(ctx Context) Response  { return ctx.String(200, "create") }
func (d *dummyController) Store(ctx Context) Response   { return ctx.String(200, "store") }
func (d *dummyController) Edit(ctx Context) Response    { return ctx.String(200, "edit") }
func (d *dummyController) Update(ctx Context) Response  { return ctx.String(200, "update") }
func (d *dummyController) Destroy(ctx Context) Response { return ctx.String(200, "destroy") }

func TestCompat_ResourceAndSingletonEnhancements(t *testing.T) {
	r := NewRouter(nil, nil)

	// Parameters mapping
	r.Resource("users", &dummyController{}).Parameters(map[string]string{
		"users": "admin_user",
	})

	// Check that parameter name in show route is admin_user
	route := r.Routes().GetByName("users.show")
	require.NotNil(t, route)
	assert.Contains(t, route.Uri(), "{admin_user}")

	// Singleton with Creatable & Destroyable
	r.Singleton("profile", &dummyController{}).Creatable().Destroyable()

	assert.NotNil(t, r.Routes().GetByName("profile.show"))
	assert.NotNil(t, r.Routes().GetByName("profile.create"))
	assert.NotNil(t, r.Routes().GetByName("profile.store"))
	assert.NotNil(t, r.Routes().GetByName("profile.edit"))
	assert.NotNil(t, r.Routes().GetByName("profile.update"))
	assert.NotNil(t, r.Routes().GetByName("profile.destroy"))

	// Batch resources registration
	r.Resources(map[string]any{
		"photos": &dummyController{},
		"videos": &dummyController{},
	})
	assert.NotNil(t, r.Routes().GetByName("photos.index"))
	assert.NotNil(t, r.Routes().GetByName("videos.index"))
}

func TestCompat_WithoutMiddlewareGroup(t *testing.T) {
	r := NewRouter(nil, nil)

	// Register a middleware group
	r.MiddlewareGroup("web", []any{
		func(ctx Context, next func() Response) Response {
			ctx.Response().Header("X-Group-Web", "applied")
			return next()
		},
	})

	r.Group(func(sub Router) {
		sub.Middleware("web")
		sub.Get("/group-applied", func(ctx Context) Response {
			return ctx.String(http.StatusOK, "ok")
		})
		sub.Get("/group-excluded", func(ctx Context) Response {
			return ctx.String(http.StatusOK, "ok")
		}).WithoutMiddleware("web")
	})

	respApplied := r.Dispatch(httptest.NewRequest(http.MethodGet, "/group-applied", nil))
	assert.Equal(t, "applied", respApplied.Headers().Get("X-Group-Web"))

	respExcluded := r.Dispatch(httptest.NewRequest(http.MethodGet, "/group-excluded", nil))
	assert.Empty(t, respExcluded.Headers().Get("X-Group-Web"))
}

func TestCompat_UrlGeneratorAndRedirectorAction(t *testing.T) {
	r := NewRouter(nil, nil)

	r.Get("/user/details/{id}", (&dummyController{}).Show).Name("user.show")

	urlGen := NewUrlGenerator(r, "https://example.com")

	// Test Action URL lookup
	url, err := urlGen.Action("dummyController.Show", map[string]string{"id": "42"})
	assert.NoError(t, err)
	assert.Equal(t, "https://example.com/user/details/42", url)

	// Test Redirector Action
	red := NewRedirector(urlGen)
	resp := red.Action("dummyController.Show", map[string]string{"id": "42"})
	assert.Equal(t, http.StatusFound, resp.StatusCode())
	assert.Equal(t, "https://example.com/user/details/42", resp.Headers().Get("Location"))
}

func TestCompat_EventDispatcher(t *testing.T) {
	r := NewRouter(nil, nil)

	var eventsReceived []string
	dispatcher := NewEventDispatcher()
	dispatcher.Listen("flow.routing", func(payload any) {
		eventsReceived = append(eventsReceived, "Routing")
	})
	dispatcher.Listen("flow.route.matched", func(payload any) {
		eventsReceived = append(eventsReceived, "RouteMatched")
	})
	dispatcher.Listen("flow.preparing_response", func(payload any) {
		eventsReceived = append(eventsReceived, "PreparingResponse")
	})
	dispatcher.Listen("flow.response_prepared", func(payload any) {
		eventsReceived = append(eventsReceived, "ResponsePrepared")
	})

	r.SetEventDispatcher(dispatcher)
	assert.NotNil(t, r.GetEventDispatcher())

	r.Get("/hello", func(ctx Context) Response {
		return ctx.String(http.StatusOK, "world")
	})

	resp := r.Dispatch(httptest.NewRequest(http.MethodGet, "/hello", nil))
	assert.Equal(t, http.StatusOK, resp.StatusCode())
	assert.Equal(t, []string{"Routing", "RouteMatched", "PreparingResponse", "ResponsePrepared"}, eventsReceived)
}

type headerValidator struct {
	expectedHeader string
}

func (h headerValidator) Matches(route *Route, request *Request) bool {
	return request.Header(h.expectedHeader) != ""
}

func TestCompat_CustomRouteValidator(t *testing.T) {
	r := NewRouter(nil, nil)

	r.Get("/custom-val", func(ctx Context) Response {
		return ctx.String(http.StatusOK, "validated")
	})

	// Retrieve route from collection
	routes := r.GetRoutes()
	require.NotEmpty(t, routes)
	var targetRoute *Route
	for _, rt := range routes {
		if rt.URI() == "/custom-val" {
			targetRoute = rt
			break
		}
	}
	require.NotNil(t, targetRoute)

	// Append custom validator to default validators
	validators := append(targetRoute.Validators(), headerValidator{expectedHeader: "X-Custom-Auth"})
	targetRoute.SetValidators(validators)

	// Request without header -> 404
	reqWithout := httptest.NewRequest(http.MethodGet, "/custom-val", nil)
	resp1 := r.Dispatch(reqWithout)
	assert.Equal(t, http.StatusNotFound, resp1.StatusCode())

	// Request with header -> 200
	reqWith := httptest.NewRequest(http.MethodGet, "/custom-val", nil)
	reqWith.Header.Set("X-Custom-Auth", "true")
	resp2 := r.Dispatch(reqWith)
	assert.Equal(t, http.StatusOK, resp2.StatusCode())
}

func TestCompat_NamedRateLimiter(t *testing.T) {
	// Register named limiter "uploads"
	DefaultRateLimiterRegistry().For("uploads", func(request *Request) *Limit {
		return PerMinute(2).By("user-upload")
	})

	r := NewRouter(nil, nil)
	r.Get("/upload", func(ctx Context) Response {
		return ctx.String(http.StatusOK, "uploaded")
	}).Middleware(NewNamedThrottleMiddleware("uploads"))

	// 1st request -> ok
	res1 := r.Dispatch(httptest.NewRequest(http.MethodGet, "/upload", nil))
	assert.Equal(t, http.StatusOK, res1.StatusCode())

	// 2nd request -> ok
	res2 := r.Dispatch(httptest.NewRequest(http.MethodGet, "/upload", nil))
	assert.Equal(t, http.StatusOK, res2.StatusCode())

	// 3rd request -> 429 Too Many Requests
	res3 := r.Dispatch(httptest.NewRequest(http.MethodGet, "/upload", nil))
	assert.Equal(t, http.StatusTooManyRequests, res3.StatusCode())
	assert.Equal(t, "2", res3.Headers().Get("X-RateLimit-Limit"))
	assert.Equal(t, "0", res3.Headers().Get("X-RateLimit-Remaining"))

	// Unregistered limiter -> panics with MissingRateLimiterError
	r2 := NewRouter(nil, nil)
	r2.Get("/missing-limiter", func(ctx Context) Response {
		return ctx.String(http.StatusOK, "ok")
	}).Middleware(NewNamedThrottleMiddleware("unregistered-limiter"))

	assert.Panics(t, func() {
		r2.Dispatch(httptest.NewRequest(http.MethodGet, "/missing-limiter", nil))
	})
}

func TestCompat_UrlGeneratorDomainAndAbsolute(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Domain("{tenant}.example.com").Get("/posts/{id}", func(ctx Context) Response {
		return ctx.String(http.StatusOK, "post")
	}).Name("tenant.posts.show")

	ug := NewUrlGenerator(r, "https://app.com")

	// 1. Default absolute URL with domain parameter substitution
	urlAbs, err := ug.Route("tenant.posts.show", map[string]string{
		"tenant": "acme",
		"id":     "99",
	})
	assert.NoError(t, err)
	assert.Equal(t, "http://acme.example.com/posts/99", urlAbs)

	// 2. Relative URL option (absolute = false)
	urlRel, err := ug.Route("tenant.posts.show", map[string]string{
		"tenant": "acme",
		"id":     "99",
	}, false)
	assert.NoError(t, err)
	assert.Equal(t, "/posts/99", urlRel)
}

func TestCompat_ResourceScopedFieldsAndMetadata(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Resource("users.posts", &dummyController{}).
		Scoped(map[string]string{"post": "slug"}).
		Metadata(map[string]any{"scope": "admin", "audit": true})

	routes := r.GetRoutes()
	require.NotEmpty(t, routes)

	foundShow := false
	for _, rt := range routes {
		if rt.GetName() == "users.posts.show" {
			foundShow = true
			// Scoped() only records binding fields; the route-level
			// ScopeBindings flag stays unset.
			assert.False(t, rt.EnforcesScopedBindings())
			assert.Equal(t, "slug", rt.BindingFieldFor("post"))
			assert.Equal(t, "admin", rt.Metadata("scope"))
			assert.Equal(t, true, rt.Metadata("audit"))
		}
	}
	assert.True(t, foundShow)
}

func TestCompat_ModelPatternsAndPriority(t *testing.T) {
	r := NewRouter(nil, nil)

	// 1. Patterns registration
	r.Patterns(map[string]string{
		"id":   "[0-9]+",
		"code": "[A-Z]+",
	})
	rt := r.Get("/items/{id}/{code}", func(ctx Context) Response {
		return ctx.String(200, "item")
	})
	assert.NotNil(t, rt)

	// 2. Model binding with explicit callback
	r.Model("user", nil, func(val string) (any, error) {
		return "user-" + val, nil
	})

	// 3. Middleware priority
	r.MiddlewarePriority("auth", "throttle")
	prio := r.GetMiddlewarePriority()
	assert.Equal(t, []any{"auth", "throttle"}, prio)

	// 4. Route prefix & uri manipulation
	singleRoute := r.Get("/old-path", func(ctx Context) Response {
		return ctx.String(200, "ok")
	})
	if rc, ok := singleRoute.(*routeChain); ok && rc.route != nil {
		rc.route.SetPrefix("/api")
		assert.Equal(t, "/api", rc.route.GetPrefix())
		rc.route.SetUri("/new-path")
		assert.Equal(t, "/new-path", rc.route.GetUri())
	}
}

func TestCompat_PrefixedResource(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Resource("admin/users", &dummyController{})

	routes := r.GetRoutes()
	foundIndex := false
	for _, rt := range routes {
		if rt.GetName() == "admin.users.index" || rt.GetName() == "users.index" {
			assert.Contains(t, rt.GetUri(), "admin/users")
			foundIndex = true
		}
	}
	assert.True(t, foundIndex)
}

// TestCompat_QueryVerbRoute verifies the QUERY verb registration and dispatch.
func TestCompat_QueryVerbRoute(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Query("/search", func(ctx Context) string {
		return "query result"
	})

	resp := r.Dispatch(httptest.NewRequest("QUERY", "/search", nil))
	assert.Equal(t, http.StatusOK, resp.StatusCode())
	assert.Equal(t, "query result", resp.Body())
}

// TestCompat_AnyIncludesQueryVerb verifies Any() also registers the QUERY verb.
func TestCompat_AnyIncludesQueryVerb(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Any("/catch-all", func(ctx Context) string {
		return "any"
	})

	resp := r.Dispatch(httptest.NewRequest("QUERY", "/catch-all", nil))
	assert.Equal(t, http.StatusOK, resp.StatusCode())
	assert.Equal(t, "any", resp.Body())
}
