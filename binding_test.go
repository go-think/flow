package flow

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// boundUser is resolved by an explicit binder.
type boundUser struct {
	Name string
}

// implicitUser resolves itself through the Routable contract.
type implicitUser struct {
	ID    string
	Field string
}

func (u *implicitUser) ResolveRouteBinding(ctx context.Context, value string, field string) (any, error) {
	if value == "missing" {
		return nil, fmt.Errorf("no implicit user for %s", value)
	}
	return &implicitUser{ID: value, Field: field}, nil
}

func TestExplicitBinder(t *testing.T) {
	r := New(nil, nil)
	r.Bind("user", func(value string, route *Route) (any, error) {
		return &boundUser{Name: "user:" + value}, nil
	})
	r.Get("/users/{user}", func(req *Request, u *boundUser) string {
		return "hello " + u.Name
	})
	r.Register()

	httpReq, _ := http.NewRequest("GET", "/users/alice", nil)
	req := NewRequest(httpReq)
	req.SetResponseWriter(httptest.NewRecorder())
	res := r.Dispatch(req)
	assert.Equal(t, "hello user:alice", res.GetContent())
}

func TestImplicitRouteBinding(t *testing.T) {
	r := New(nil, nil)
	r.Get("/posts/{post}", func(req *Request, p *implicitUser) string {
		return fmt.Sprintf("post:%s", p.ID)
	})
	r.Register()

	httpReq, _ := http.NewRequest("GET", "/posts/abc", nil)
	req := NewRequest(httpReq)
	req.SetResponseWriter(httptest.NewRecorder())
	res := r.Dispatch(req)
	assert.Equal(t, "post:abc", res.GetContent())
}

func TestBindingField(t *testing.T) {
	r := New(nil, nil)
	r.Get("/users/{user:id}", func(req *Request, u *implicitUser) string {
		return fmt.Sprintf("id=%s field=%s", u.ID, u.Field)
	})
	r.Register()

	httpReq, _ := http.NewRequest("GET", "/users/77", nil)
	req := NewRequest(httpReq)
	req.SetResponseWriter(httptest.NewRecorder())
	res := r.Dispatch(req)
	assert.Equal(t, "id=77 field=id", res.GetContent())
}

type zzMockUser struct{}

func (u *zzMockUser) ResolveRouteBinding(ctx context.Context, value string, field string) (any, error) {
	return &zzMockUser{}, nil
}

type zzMockPost struct{ ID string }

func (p *zzMockPost) ResolveRouteBinding(ctx context.Context, value string, field string) (any, error) {
	return &zzMockPost{}, nil
}

func (p *zzMockPost) ResolveChildRouteBinding(ctx context.Context, childType string, value string, field string) (any, error) {
	fmt.Printf("DBG child resolve: type=%s value=%s\n", childType, value)
	if value == "child-404" {
		return nil, fmt.Errorf("no child")
	}
	return &zzMockComment{ID: value}, nil
}

type zzMockComment struct{ ID string }

func (c *zzMockComment) ResolveRouteBinding(ctx context.Context, value string, field string) (any, error) {
	fmt.Printf("DBG comment plain resolve: %s\n", value)
	return &zzMockComment{ID: value}, nil
}

func TestZZScopedDebug(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Get("/users/{user}", func(ctx Context, user *zzMockUser) Response { return ctx.String(200, "u") })
	r.Get("/custom-missing/{user}", func(ctx Context, user *zzMockUser) Response { return ctx.String(200, "u") }).Missing(func(ctx Context) Response {
		return ctx.String(http.StatusAccepted, "custom")
	})
	r.Get("/posts/{post}/comments/{comment}", func(ctx Context, post *zzMockPost, comment *zzMockComment) Response {
		return ctx.String(200, "post:"+post.ID+",comment:"+comment.ID)
	})
	req := httptest.NewRequest(http.MethodGet, "/posts/100/comments/child-404", nil)
	res := r.Dispatch(req)
	fmt.Printf("DBG status=%d body=%q\n", res.StatusCode(), res.Body())
}

type genericUserEntity struct {
	ID   string
	Name string
}

func TestGenericBindModel(t *testing.T) {
	r := NewRouter(nil, nil)

	BindModel(r, "user", func(ctx context.Context, value string) (*genericUserEntity, error) {
		if value == "404" {
			return nil, fmt.Errorf("user not found")
		}
		return &genericUserEntity{ID: value, Name: "User_" + value}, nil
	})

	r.Get("/profile/{user}", func(u *genericUserEntity) string {
		if u == nil {
			return "nil"
		}
		return u.Name
	})

	// Valid user
	req := httptest.NewRequest("GET", "/profile/99", nil)
	resp := r.Dispatch(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode())
	assert.Equal(t, "User_99", resp.GetContent())

	// Missing user returns 404
	req404 := httptest.NewRequest("GET", "/profile/404", nil)
	resp404 := r.Dispatch(req404)
	assert.Equal(t, http.StatusNotFound, resp404.StatusCode())
}

func TestRouter_RespondWithRoute(t *testing.T) {
	var r Router = NewRouter(nil, nil)

	r.Get("/items/{id}", func(id string) string {
		return "item:" + id
	}).As("items.show")

	req := httptest.NewRequest("GET", "/items/123", nil)
	resp := r.RespondWithRoute("items.show", NewRequest(req))
	assert.Equal(t, http.StatusOK, resp.StatusCode())
	assert.Equal(t, "item:123", resp.GetContent())
}

func TestRouter_SubstituteImplicitBindingsUsing(t *testing.T) {
	var r Router = NewRouter(nil, nil)

	r.SubstituteImplicitBindingsUsing(func(route *Route, key, value string) any {
		if key == "account" {
			return "resolved-" + value
		}
		return nil
	})

	r.Get("/accounts/{account}", func(account string) string {
		return account
	})

	req := httptest.NewRequest("GET", "/accounts/acct100", nil)
	resp := r.Dispatch(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode())
	assert.Equal(t, "resolved-acct100", resp.GetContent())
}
