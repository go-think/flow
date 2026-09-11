package flow

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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

func TestLaravelCompat_MatchAndWhereConstraints(t *testing.T) {
	r := NewRouter()

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

func TestLaravelCompat_DynamicSubdomainRoute(t *testing.T) {
	r := NewRouter()

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

func TestLaravelCompat_ModelBindingMissingAndScoped(t *testing.T) {
	r := NewRouter()

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

	// 3. Scoped binding (parent -> child)
	r.Get("/posts/{post}/comments/{comment}", func(ctx Context, post *mockPost, comment *mockComment) Response {
		return ctx.String(http.StatusOK, "post:"+post.ID+",comment:"+comment.ID)
	})

	respScopedOk := r.Dispatch(httptest.NewRequest(http.MethodGet, "/posts/100/comments/200", nil))
	assert.Equal(t, http.StatusOK, respScopedOk.StatusCode())
	assert.Equal(t, "post:100,comment:200", respScopedOk.Body())

	respScopedChildFail := r.Dispatch(httptest.NewRequest(http.MethodGet, "/posts/100/comments/child-404", nil))
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

func TestLaravelCompat_ResourceAndSingletonEnhancements(t *testing.T) {
	r := NewRouter()

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

func TestLaravelCompat_WithoutMiddlewareGroup(t *testing.T) {
	r := NewRouter()

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

func TestLaravelCompat_UrlGeneratorAndRedirectorAction(t *testing.T) {
	r := NewRouter()

	r.Get("/user/details/{id}", (&dummyController{}).Show).Name("user.show")

	urlGen := NewUrlGenerator(r.Routes(), "https://example.com")

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
