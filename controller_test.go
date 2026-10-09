package flow

import (
	"fmt"
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
	r := New(nil, nil)
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
	r := New(nil, nil)
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
	r := New(nil, nil)
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
	r := New(nil, nil)
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

func TestRouterControllerGroup(t *testing.T) {
	r := New(nil, nil)
	// Pointer instance
	r.Controller(&testUserController{}).Group(func(users Router) {
		users.Get("/orders/{id}", "Show")
	})
	// String name
	r.RegisterController("CustomUser", &testUserController{})
	r.Controller("CustomUser").Metadata("module", "orders").Group(func(users Router) {
		users.Get("/custom/{id}", "Show").WithoutScopedBindings()
	})
	r.Register()

	httpReq, _ := http.NewRequest("GET", "/orders/99", nil)
	req := NewRequest(httpReq)
	req.SetResponseWriter(httptest.NewRecorder())
	res := r.Dispatch(req)
	assert.Equal(t, "show:99", res.GetContent())

	httpReq2, _ := http.NewRequest("GET", "/custom/100", nil)
	req2 := NewRequest(httpReq2)
	req2.SetResponseWriter(httptest.NewRecorder())
	res2 := r.Dispatch(req2)
	assert.Equal(t, "show:100", res2.GetContent())
}

func TestUnregisteredControllerErrors(t *testing.T) {
	r := New(nil, nil)
	r.Get("/broken", "Missing@Show")
	r.Register()

	httpReq, _ := http.NewRequest("GET", "/broken", nil)
	req := NewRequest(httpReq)
	req.SetResponseWriter(httptest.NewRecorder())

	assert.Panics(t, func() { r.Dispatch(req) })
}

// --- Begin combined filter + callAction tests ---

// testCombinedFilterController declares ONE middleware with BOTH Only and
// Except; the reference
// combines the two with OR, so both must be honored at once.
type testCombinedFilterController struct{}

func (c *testCombinedFilterController) Middleware() []ControllerMiddleware {
	return []ControllerMiddleware{
		{Handler: func(req *Request, next Closure) any {
			res := next(req)
			if res2, ok := res.(*Response); ok {
				res2.Header("X-Combined", "applied")
				return res2
			}
			return res
		}, Only: []string{"Show", "Update"}, Except: []string{"Update"}},
	}
}

func (c *testCombinedFilterController) Show(req *Request, id string) *Response {
	return NewResponse().SetContent("show:" + id)
}

func (c *testCombinedFilterController) Update(req *Request, id string) *Response {
	return NewResponse().SetContent("update:" + id)
}

func TestControllerMiddlewareOnlyAndExceptCombine(t *testing.T) {
	r := New(nil, nil)
	r.RegisterController("TestCombinedFilterController", &testCombinedFilterController{})
	r.Get("/combined/{id}", "TestCombinedFilterController@Show")
	r.Put("/combined/{id}", "TestCombinedFilterController@Update")
	r.Register()

	// Show is in Only and not in Except: the middleware applies.
	showReq := NewRequest(mustRequest("GET", "/combined/1"))
	showReq.SetResponseWriter(httptest.NewRecorder())
	showRes := r.Dispatch(showReq)
	assert.Equal(t, "applied", showRes.Headers().Get("X-Combined"))

	// Update is in both Only and Except: Except excludes it even though it is
	// also listed in Only.
	updateReq := NewRequest(mustRequest("PUT", "/combined/1"))
	updateReq.SetResponseWriter(httptest.NewRecorder())
	updateRes := r.Dispatch(updateReq)
	assert.Empty(t, updateRes.Headers().Get("X-Combined"))
}

// testCallActionController intercepts dispatch through CallAction, mirroring
// the reference implementation controllers overriding callAction (the reference implementation: ControllerDispatcher
// prefers callAction; ViewController overrides it).
type testCallActionController struct {
	callActionUsed bool
}

func (c *testCallActionController) CallAction(method string, parameters []any) (any, error) {
	c.callActionUsed = true
	if method == "Show" {
		return NewResponse().SetContent("via-callAction:" + fmt.Sprint(parameters[1])), nil
	}
	return nil, fmt.Errorf("flow: method [%s] not handled by callAction", method)
}

func (c *testCallActionController) Show(req *Request, id string) *Response {
	return NewResponse().SetContent("direct:" + id)
}

func TestControllerCallActionHook(t *testing.T) {
	r := New(nil, nil)
	controller := &testCallActionController{}
	r.RegisterController("TestCallActionController", controller)
	r.Get("/call-action/{id}", "TestCallActionController@Show")
	r.Register()

	httpReq, _ := http.NewRequest("GET", "/call-action/9", nil)
	req := NewRequest(httpReq)
	req.SetResponseWriter(httptest.NewRecorder())
	res := r.Dispatch(req)

	assert.True(t, controller.callActionUsed, "CallAction must intercept the dispatch")
	assert.Equal(t, "via-callAction:9", res.GetContent())
	assert.NotEqual(t, "direct:9", res.GetContent(), "the plain method must not run when CallAction exists")
}

type testHasMiddlewareController struct{}

func (c *testHasMiddlewareController) Index() string {
	return "index"
}

func (c *testHasMiddlewareController) Show(id string) string {
	return "show:" + id
}

func (c *testHasMiddlewareController) Edit(id string) string {
	return "edit:" + id
}

func (c *testHasMiddlewareController) Middleware() []*MiddlewareDefinition {
	return []*MiddlewareDefinition{
		NewMiddlewareDefinition(func(req *Request, next Closure) any {
			res := next(req)
			if r, ok := res.(*Response); ok {
				r.Header("X-Index-Only", "true")
			}
			return res
		}).Only("Index"),

		NewMiddlewareDefinition(func(req *Request, next Closure) any {
			res := next(req)
			if r, ok := res.(*Response); ok {
				r.Header("X-Except-Edit", "true")
			}
			return res
		}).Except("Edit"),
	}
}

func TestControllerHasMiddleware(t *testing.T) {
	r := NewRouter(nil, nil)
	ctrl := &testHasMiddlewareController{}

	r.Get("/items", ControllerAction{Controller: ctrl, Method: "Index"})
	r.Get("/items/{id}", ControllerAction{Controller: ctrl, Method: "Show"})
	r.Get("/items/{id}/edit", ControllerAction{Controller: ctrl, Method: "Edit"})

	// 1. Index should have both middlewares
	reqIndex := httptest.NewRequest("GET", "/items", nil)
	respIndex := r.Dispatch(reqIndex)
	assert.Equal(t, "true", respIndex.Headers().Get("X-Index-Only"))
	assert.Equal(t, "true", respIndex.Headers().Get("X-Except-Edit"))

	// 2. Show should NOT have X-Index-Only, but SHOULD have X-Except-Edit
	reqShow := httptest.NewRequest("GET", "/items/10", nil)
	respShow := r.Dispatch(reqShow)
	assert.Equal(t, "", respShow.Headers().Get("X-Index-Only"))
	assert.Equal(t, "true", respShow.Headers().Get("X-Except-Edit"))

	// 3. Edit should have NEITHER middleware
	reqEdit := httptest.NewRequest("GET", "/items/10/edit", nil)
	respEdit := r.Dispatch(reqEdit)
	assert.Equal(t, "", respEdit.Headers().Get("X-Index-Only"))
	assert.Equal(t, "", respEdit.Headers().Get("X-Except-Edit"))
}

func TestControllerActionPointerDispatch(t *testing.T) {
	r := NewRouter(nil, nil)
	ctrl := &testHasMiddlewareController{}

	r.Get("/pointer-items/{id}", &ControllerAction{Controller: ctrl, Method: "Show"})

	req := httptest.NewRequest("GET", "/pointer-items/99", nil)
	resp := r.Dispatch(req)
	assert.Equal(t, 200, resp.StatusCode())
	assert.Equal(t, "show:99", resp.GetContent())
}
