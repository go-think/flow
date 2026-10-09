package flow

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

// testUserController registers middleware through the embeddable base in its
// constructor.
type testUserController struct {
	Controller
}

func newTestUserController() *testUserController {
	c := &testUserController{}
	c.Middleware(func(req *Request, next Closure) any {
		res := next(req)
		if res2, ok := res.(*Response); ok {
			res2.Header("X-Controller", "yes")
			return res2
		}
		return res
	})
	c.Middleware(func(req *Request, next Closure) any { return next(req) }).Only("Show")
	c.Middleware(func(req *Request, next Closure) any { return next(req) }).Except("Show")
	return c
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
	r.RegisterController("TestUserController", newTestUserController())
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
	r.RegisterController("TestUserController", newTestUserController())
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
		admin.RegisterController("Admin.UserController", newTestUserController())
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
	r.Controller(newTestUserController()).Group(func(users Router) {
		users.Get("/orders/{id}", "Show")
	})
	// String name
	r.RegisterController("CustomUser", newTestUserController())
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

// testCombinedFilterController declares one middleware with both Only and
// Except; the two filters combine with OR, so both must be honored at once.
type testCombinedFilterController struct {
	Controller
}

func newTestCombinedFilterController() *testCombinedFilterController {
	c := &testCombinedFilterController{}
	c.Middleware(func(req *Request, next Closure) any {
		res := next(req)
		if res2, ok := res.(*Response); ok {
			res2.Header("X-Combined", "applied")
			return res2
		}
		return res
	}).Only("Show", "Update").Except("Update")
	return c
}

func (c *testCombinedFilterController) Show(req *Request, id string) *Response {
	return NewResponse().SetContent("show:" + id)
}

func (c *testCombinedFilterController) Update(req *Request, id string) *Response {
	return NewResponse().SetContent("update:" + id)
}

func TestControllerMiddlewareOnlyAndExceptCombine(t *testing.T) {
	r := New(nil, nil)
	r.RegisterController("TestCombinedFilterController", newTestCombinedFilterController())
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

// TestControllerMiddlewareMethodListForms covers both method-list forms of the
// only/except filters: one name per argument, and a single []string.
func TestControllerMiddlewareMethodListForms(t *testing.T) {
	variadic := (&ControllerMiddlewareOptions{}).Only("Show", "Update")
	assert.Equal(t, []string{"Show", "Update"}, variadic.OnlyMethods)

	arrayForm := (&ControllerMiddlewareOptions{}).Except([]string{"Edit", "Destroy"})
	assert.Equal(t, []string{"Edit", "Destroy"}, arrayForm.ExceptMethods)
}

// testCallActionController intercepts dispatch through CallAction, which the
// dispatcher prefers over invoking the method directly.
type testCallActionController struct {
	callActionUsed bool
}

func (c *testCallActionController) CallAction(method string, parameters []reflect.Value) (any, error) {
	c.callActionUsed = true
	if method == "Show" {
		return NewResponse().SetContent("via-callAction:" + fmt.Sprint(parameters[1].Interface())), nil
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

type testHasMiddlewareController struct {
	Controller
}

func newTestHasMiddlewareController() *testHasMiddlewareController {
	c := &testHasMiddlewareController{}
	c.Middleware(func(req *Request, next Closure) any {
		res := next(req)
		if r, ok := res.(*Response); ok {
			r.Header("X-Index-Only", "true")
		}
		return res
	}).Only("Index")

	c.Middleware(func(req *Request, next Closure) any {
		res := next(req)
		if r, ok := res.(*Response); ok {
			r.Header("X-Except-Edit", "true")
		}
		return res
	}).Except("Edit")
	return c
}

func (c *testHasMiddlewareController) Index() string {
	return "index"
}

func (c *testHasMiddlewareController) Show(id string) string {
	return "show:" + id
}

func (c *testHasMiddlewareController) Edit(id string) string {
	return "edit:" + id
}

func TestControllerBaseEntriesFiltering(t *testing.T) {
	r := NewRouter(nil, nil)
	ctrl := newTestHasMiddlewareController()

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
	ctrl := newTestHasMiddlewareController()

	r.Get("/pointer-items/{id}", &ControllerAction{Controller: ctrl, Method: "Show"})

	req := httptest.NewRequest("GET", "/pointer-items/99", nil)
	resp := r.Dispatch(req)
	assert.Equal(t, 200, resp.StatusCode())
	assert.Equal(t, "show:99", resp.GetContent())
}

// --- Begin embeddable base controller tests ---

// testBaseController embeds the Controller base and registers middleware in its
// constructor.
type testBaseController struct {
	Controller
}

func newTestBaseController() *testBaseController {
	c := &testBaseController{}
	c.Middleware(func(req *Request, next Closure) any {
		res := next(req)
		if r, ok := res.(*Response); ok {
			r.Header("X-Base", "always")
		}
		return res
	})
	c.Middleware(func(req *Request, next Closure) any {
		res := next(req)
		if r, ok := res.(*Response); ok {
			r.Header("X-Only-Show", "true")
		}
		return res
	}).Only("Show")
	c.Middleware(func(req *Request, next Closure) any {
		res := next(req)
		if r, ok := res.(*Response); ok {
			r.Header("X-Except-Show", "true")
		}
		return res
	}).Except("Show")
	return c
}

func (c *testBaseController) Show(req *Request, id string) *Response {
	return NewResponse().SetContent("show:" + id)
}

func (c *testBaseController) Update(req *Request, id string) *Response {
	return NewResponse().SetContent("update:" + id)
}

// TestControllerBaseMiddlewareFilters verifies the embedded base applies the
// only/except filters.
func TestControllerBaseMiddlewareFilters(t *testing.T) {
	r := New(nil, nil)
	r.RegisterController("TestBaseController", newTestBaseController())
	r.Get("/base/{id}", "TestBaseController@Show")
	r.Put("/base/{id}", "TestBaseController@Update")
	r.Register()

	showReq := NewRequest(mustRequest("GET", "/base/1"))
	showReq.SetResponseWriter(httptest.NewRecorder())
	showRes := r.Dispatch(showReq)
	assert.Equal(t, "show:1", showRes.GetContent())
	assert.Equal(t, "always", showRes.Headers().Get("X-Base"))
	assert.Equal(t, "true", showRes.Headers().Get("X-Only-Show"))
	assert.Empty(t, showRes.Headers().Get("X-Except-Show"))

	updateReq := NewRequest(mustRequest("PUT", "/base/1"))
	updateReq.SetResponseWriter(httptest.NewRecorder())
	updateRes := r.Dispatch(updateReq)
	assert.Equal(t, "update:1", updateRes.GetContent())
	assert.Equal(t, "always", updateRes.Headers().Get("X-Base"))
	assert.Empty(t, updateRes.Headers().Get("X-Only-Show"))
	assert.Equal(t, "true", updateRes.Headers().Get("X-Except-Show"))
}

// TestControllerBaseStringAliasMiddleware verifies string middleware declared
// through the base is resolved via the router's alias table at gather time,
// including parameterized aliases.
func TestControllerBaseStringAliasMiddleware(t *testing.T) {
	r := New(nil, nil)
	r.AliasMiddleware("auth", HandlerFunc(func(req *Request, next Closure) interface{} {
		res := next(req)
		if resp, ok := res.(*Response); ok {
			resp.Header("X-Auth", "yes")
		}
		return res
	}))
	r.AliasMiddleware("role", func(role string) Middleware {
		return func(req *Request, next Closure) interface{} {
			res := next(req)
			if resp, ok := res.(*Response); ok {
				resp.Header("X-Role", role)
			}
			return res
		}
	})

	ctrl := &testBaseController{}
	ctrl.Middleware("auth")
	ctrl.Middleware("role:admin").Only("Show")
	r.RegisterController("TestAliasBaseController", ctrl)
	r.Get("/alias-base/{id}", "TestAliasBaseController@Show")
	r.Put("/alias-base/{id}", "TestAliasBaseController@Update")
	r.Register()

	showReq := NewRequest(mustRequest("GET", "/alias-base/1"))
	showReq.SetResponseWriter(httptest.NewRecorder())
	showRes := r.Dispatch(showReq)
	assert.Equal(t, "show:1", showRes.GetContent())
	assert.Equal(t, "yes", showRes.Headers().Get("X-Auth"))
	assert.Equal(t, "admin", showRes.Headers().Get("X-Role"))

	updateReq := NewRequest(mustRequest("PUT", "/alias-base/1"))
	updateReq.SetResponseWriter(httptest.NewRecorder())
	updateRes := r.Dispatch(updateReq)
	assert.Equal(t, "yes", updateRes.Headers().Get("X-Auth"))
	assert.Empty(t, updateRes.Headers().Get("X-Role"))
}

// TestControllerBaseOptionsPointerSemantics verifies the fluent options keep
// pointing at the stored entry across further registrations.
func TestControllerBaseOptionsPointerSemantics(t *testing.T) {
	c := &testBaseController{}
	opts := c.Middleware("auth")
	c.Middleware("throttle") // further registrations must not detach opts
	opts.Only("Update")

	entries := c.GetMiddleware()
	assert.Len(t, entries, 2)
	assert.Equal(t, MiddlewareString("auth"), entries[0].Middleware)
	assert.Equal(t, []string{"Update"}, entries[0].Options.OnlyMethods)
	assert.Equal(t, MiddlewareString("throttle"), entries[1].Middleware)
}

// TestControllerMiddlewareListRegistration verifies that a list argument
// registers one entry per member, whether strings, values or middleware
// functions.
func TestControllerMiddlewareListRegistration(t *testing.T) {
	c := &testBaseController{}
	c.Middleware([]string{"auth", "throttle:60"})
	entries := c.GetMiddleware()
	assert.Len(t, entries, 2)
	assert.Equal(t, MiddlewareString("auth"), entries[0].Middleware)
	assert.Equal(t, MiddlewareString("throttle:60"), entries[1].Middleware)

	funcMw := func(req *Request, next Closure) any { return next(req) }
	// A mixed list is expressed through the sealed storage type:
	// []ControllerMiddleware holds both a Middleware and a MiddlewareString — a
	// concrete element type, not []any.
	c2 := &testBaseController{}
	c2.Middleware([]ControllerMiddleware{Middleware(funcMw), MiddlewareString("session")})
	entries2 := c2.GetMiddleware()
	assert.Len(t, entries2, 2)
	// testify cannot compare func values; compare function pointers.
	assert.Equal(t, reflect.ValueOf(funcMw).Pointer(), reflect.ValueOf(entries2[0].Middleware).Pointer())
	assert.Equal(t, MiddlewareString("session"), entries2[1].Middleware)

	c3 := &testBaseController{}
	c3.Middleware([]Middleware{funcMw})
	assert.Len(t, c3.GetMiddleware(), 1)

	c4 := &testBaseController{}
	c4.Middleware([]ControllerMiddleware{MiddlewareString("cache"), Middleware(funcMw)})
	entries4 := c4.GetMiddleware()
	assert.Len(t, entries4, 2)
	assert.Equal(t, MiddlewareString("cache"), entries4[0].Middleware)

	// A Handler is passed through its Process method value.
	c5 := &testBaseController{}
	c5.Middleware(testControllerBaseHandler{}.Process)
	assert.Len(t, c5.GetMiddleware(), 1)
}

// testControllerBaseHandler is a Handler whose Process method value is
// registrable as controller middleware.
type testControllerBaseHandler struct{}

func (testControllerBaseHandler) Process(req *Request, next Closure) any {
	return next(req)
}

// TestControllerMiddlewareOptionsArgument verifies the options argument form:
// Middleware("auth", options) seeds the only/except filters directly.
func TestControllerMiddlewareOptionsArgument(t *testing.T) {
	c := &testBaseController{}
	c.Middleware("auth", ControllerMiddlewareOptions{OnlyMethods: []string{"Show"}, ExceptMethods: []string{"Index"}})

	entries := c.GetMiddleware()
	assert.Len(t, entries, 1)
	assert.Equal(t, []string{"Show"}, entries[0].Options.OnlyMethods)
	assert.Equal(t, []string{"Index"}, entries[0].Options.ExceptMethods)
}

// TestControllerMiddlewareSharedOptions verifies entries of the same call share
// one options pointer: a chained Only/Except mutates every entry of that call,
// while other calls keep their own options.
func TestControllerMiddlewareSharedOptions(t *testing.T) {
	c := &testBaseController{}
	shared := c.Middleware([]string{"m1", "m2", "m3"})
	c.Middleware("other")
	shared.Only("Show")

	entries := c.GetMiddleware()
	assert.Len(t, entries, 4)
	for i := 0; i < 3; i++ {
		assert.Same(t, shared, entries[i].Options)
		assert.Equal(t, []string{"Show"}, entries[i].Options.OnlyMethods)
	}
	assert.NotSame(t, shared, entries[3].Options)
	assert.Empty(t, entries[3].Options.OnlyMethods)
}

// TestControllerMiddlewareSharedOptionsDispatch verifies through a full
// dispatch that options passed to one call filter every entry of that call
// together.
func TestControllerMiddlewareSharedOptionsDispatch(t *testing.T) {
	ctrl := &testBaseController{}
	// One call, two entries, shared options limiting both to Show.
	ctrl.Middleware([]func(*Request, Closure) any{
		func(req *Request, next Closure) any {
			res := next(req)
			if r, ok := res.(*Response); ok {
				r.Header("X-Shared-1", "true")
			}
			return res
		},
		func(req *Request, next Closure) any {
			res := next(req)
			if r, ok := res.(*Response); ok {
				r.Header("X-Shared-2", "true")
			}
			return res
		},
	}, ControllerMiddlewareOptions{OnlyMethods: []string{"Show"}})

	r := New(nil, nil)
	r.RegisterController("TestSharedOptionsController", ctrl)
	r.Get("/shared/{id}", "TestSharedOptionsController@Show")
	r.Put("/shared/{id}", "TestSharedOptionsController@Update")
	r.Register()

	showReq := NewRequest(mustRequest("GET", "/shared/1"))
	showReq.SetResponseWriter(httptest.NewRecorder())
	showRes := r.Dispatch(showReq)
	assert.Equal(t, "show:1", showRes.GetContent())
	assert.Equal(t, "true", showRes.Headers().Get("X-Shared-1"))
	assert.Equal(t, "true", showRes.Headers().Get("X-Shared-2"))

	updateReq := NewRequest(mustRequest("PUT", "/shared/1"))
	updateReq.SetResponseWriter(httptest.NewRecorder())
	updateRes := r.Dispatch(updateReq)
	assert.Equal(t, "update:1", updateRes.GetContent())
	assert.Empty(t, updateRes.Headers().Get("X-Shared-1"))
	assert.Empty(t, updateRes.Headers().Get("X-Shared-2"))
}

// --- Begin HasMiddleware tests ---

// testStaticMiddlewareController declares its middleware through the
// HasMiddleware interface instead of embedding the Controller base.
type testStaticMiddlewareController struct{}

// Middleware is the HasMiddleware declaration: a string alias limited to Index
// plus an unfiltered function middleware.
func (c *testStaticMiddlewareController) Middleware() []*ControllerMiddlewareEntry {
	return []*ControllerMiddlewareEntry{
		{
			Middleware: MiddlewareString("auth"),
			Options:    (&ControllerMiddlewareOptions{}).Only("Index"),
		},
		{
			Middleware: Middleware(func(req *Request, next Closure) any { return next(req) }),
		},
	}
}

func (c *testStaticMiddlewareController) Index() string { return "index" }
func (c *testStaticMiddlewareController) Show() string  { return "show" }

// TestDispatcherGetMiddlewareHasMiddlewareBranch verifies that entries declared
// through HasMiddleware are filtered by only/except and that string middleware
// is returned unwrapped.
func TestDispatcherGetMiddlewareHasMiddlewareBranch(t *testing.T) {
	d := &controllerDispatcher{}

	// Only("Index"): the string alias survives for Index, next to the
	// unfiltered function middleware.
	got := d.GetMiddleware(&testStaticMiddlewareController{}, "Index")
	assert.Len(t, got, 2)
	assert.Equal(t, MiddlewareString("auth"), got[0])

	// Show is excluded by Only("Index"); the unfiltered entry remains.
	gotShow := d.GetMiddleware(&testStaticMiddlewareController{}, "Show")
	assert.Len(t, gotShow, 1)
}

// testHasMiddlewarePrecedence implements both the HasMiddleware declaration and
// the base GetMiddleware accessor to check which one the dispatcher prefers.
type testHasMiddlewarePrecedence struct {
	Controller
}

func (c *testHasMiddlewarePrecedence) Middleware() []*ControllerMiddlewareEntry {
	return []*ControllerMiddlewareEntry{{Middleware: MiddlewareString("has")}}
}

func (c *testHasMiddlewarePrecedence) GetMiddleware() []*ControllerMiddlewareEntry {
	return []*ControllerMiddlewareEntry{{Middleware: MiddlewareString("get")}}
}

// TestDispatcherHasMiddlewareTakesPrecedence verifies that HasMiddleware wins
// over the base GetMiddleware accessor.
func TestDispatcherHasMiddlewareTakesPrecedence(t *testing.T) {
	d := &controllerDispatcher{}
	got := d.GetMiddleware(&testHasMiddlewarePrecedence{}, "Index")
	assert.Equal(t, []ControllerMiddleware{MiddlewareString("has")}, got)
}

// --- Begin controller action accessor tests ---

// TestRouteControllerCallbackAccessors verifies the route accessors for
// controller actions.
func TestRouteControllerCallbackAccessors(t *testing.T) {
	r := New(nil, nil)
	r.Get("/users/{id}", "TestUserController@Show").Name("cb.show")
	r.Get("/closure", func(req *Request) *Response { return NewResponse() }).Name("cb.closure")
	r.Register()

	route := routeByName(r, "cb.show")
	assert.True(t, route.IsControllerAction())
	assert.Equal(t, "TestUserController", route.GetControllerClass())
	assert.Equal(t, "Show", route.GetControllerMethod())
	class, method := route.ParseControllerCallback()
	assert.Equal(t, "TestUserController", class)
	assert.Equal(t, "Show", method)

	closure := routeByName(r, "cb.closure")
	assert.False(t, closure.IsControllerAction())
	assert.Equal(t, "", closure.GetControllerClass())
	assert.Equal(t, "", closure.GetControllerMethod())
}
