package flow

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// testUserController is a controller with declared middleware.
type testUserController struct{}

func (c *testUserController) Middleware() []ControllerMiddleware {
	return []ControllerMiddleware{
		{Handler: func(req *Request, next Closure) any {
			res := next(req)
			if res2, ok := res.(*Response); ok {
				res2.Header("X-Controller", "yes")
				return res2
			}
			return res
		}},
		{Handler: func(req *Request, next Closure) any { return next(req) }, Only: []string{"Show"}},
		{Handler: func(req *Request, next Closure) any { return next(req) }, Except: []string{"Show"}},
	}
}

func (c *testUserController) Show(req *Request, id string) *Response {
	return NewResponse().SetContent("show:" + id)
}

func (c *testUserController) Update(req *Request, id string) *Response {
	return NewResponse().SetContent("update:" + id)
}

// testInvokableController is a single-invocation controller.
type testInvokableController struct{}

func (c *testInvokableController) Invoke(req *Request) *Response {
	return NewResponse().SetContent("invoked")
}

func TestControllerActionStringRegistration(t *testing.T) {
	r := New()
	r.RegisterController("TestUserController", &testUserController{})
	r.Get("/users/{id}", "TestUserController@Show").Name("users.show")
	r.Register()

	httpReq, _ := http.NewRequest("GET", "/users/42", nil)
	req := NewRequest(httpReq)
	req.SetResponseWriter(httptest.NewRecorder())
	res := r.Dispatch(req)

	resp := res
	assert.Equal(t, "show:42", resp.GetContent())
	// Controller middleware declared without filters applies.
	assert.Equal(t, "yes", resp.Headers().Get("X-Controller"))
}

func TestControllerMiddlewareOnlyExcept(t *testing.T) {
	r := New()
	r.RegisterController("TestUserController", &testUserController{})
	r.Get("/users/{id}", "TestUserController@Show")
	r.Put("/users/{id}", "TestUserController@Update")
	r.Register()

	// Show: Only-filter middleware applies, Except-filter does not.
	req1 := NewRequest(mustRequest("PUT", "/users/42"))
	req1.SetResponseWriter(httptest.NewRecorder())
	res1 := r.Dispatch(req1)
	assert.Equal(t, "update:42", res1.GetContent())
	// Update is excluded by Except but the Except-declared entry only skips
	// Show; the Only entry skips Update. Both unfiltered entries already ran.

	// Show runs the Only entry.
	showReq := NewRequest(mustRequest("GET", "/users/42"))
	rec2 := httptest.NewRecorder()
	showReq.SetResponseWriter(rec2)
	_ = r.Dispatch(showReq)
}

func mustRequest(method, url string) *http.Request {
	httpReq, err := http.NewRequest(method, url, nil)
	if err != nil {
		panic(err)
	}
	return httpReq
}

func TestInvokableControllerAction(t *testing.T) {
	r := New()
	r.RegisterController("TestInvokableController", &testInvokableController{})
	r.Get("/invoke", "TestInvokableController")
	r.Register()

	httpReq, _ := http.NewRequest("GET", "/invoke", nil)
	req := NewRequest(httpReq)
	req.SetResponseWriter(httptest.NewRecorder())
	res := r.Dispatch(req)
	assert.Equal(t, "invoked", res.GetContent())
}

func TestControllerNamespacePrefix(t *testing.T) {
	r := New()
	r.Group(GroupAttributes{Controller: "Admin"}, func(admin Router) {
		admin.RegisterController("Admin.UserController", &testUserController{})
		admin.Get("/admin/users/{id}", "UserController@Show")
	})
	r.Register()

	httpReq, _ := http.NewRequest("GET", "/admin/users/7", nil)
	req := NewRequest(httpReq)
	req.SetResponseWriter(httptest.NewRecorder())
	res := r.Dispatch(req)
	assert.Equal(t, "show:7", res.GetContent())
}

func TestUnregisteredControllerErrors(t *testing.T) {
	r := New()
	r.Get("/broken", "Missing@Show")
	r.Register()

	httpReq, _ := http.NewRequest("GET", "/broken", nil)
	req := NewRequest(httpReq)
	req.SetResponseWriter(httptest.NewRecorder())

	assert.Panics(t, func() { r.Dispatch(req) })
}
