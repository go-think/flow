package flow

import (
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

func (u *implicitUser) ResolveRouteBinding(value string, field string) (any, error) {
	if value == "missing" {
		return nil, fmt.Errorf("no implicit user for %s", value)
	}
	return &implicitUser{ID: value, Field: field}, nil
}

func TestExplicitBinder(t *testing.T) {
	r := New()
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
	res := r.Dispatch(req).(*Response)
	assert.Equal(t, "hello user:alice", res.GetContent())
}

func TestImplicitRouteBinding(t *testing.T) {
	r := New()
	r.Get("/posts/{post}", func(req *Request, p *implicitUser) string {
		return fmt.Sprintf("post:%s", p.ID)
	})
	r.Register()

	httpReq, _ := http.NewRequest("GET", "/posts/abc", nil)
	req := NewRequest(httpReq)
	req.SetResponseWriter(httptest.NewRecorder())
	res := r.Dispatch(req).(*Response)
	assert.Equal(t, "post:abc", res.GetContent())
}

func TestBindingField(t *testing.T) {
	r := New()
	r.Get("/users/{user:id}", func(req *Request, u *implicitUser) string {
		return fmt.Sprintf("id=%s field=%s", u.ID, u.Field)
	})
	r.Register()

	httpReq, _ := http.NewRequest("GET", "/users/77", nil)
	req := NewRequest(httpReq)
	req.SetResponseWriter(httptest.NewRecorder())
	res := r.Dispatch(req).(*Response)
	assert.Equal(t, "id=77 field=id", res.GetContent())
}
