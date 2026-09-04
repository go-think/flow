package flow

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustNewRequest builds an *http.Request, panicking on failure.
func mustNewRequest(method, target string) *http.Request {
	httpReq, err := http.NewRequest(method, target, nil)
	if err != nil {
		panic(err)
	}
	return httpReq
}

var errSubBindMissing = errors.New("sub-bind: user missing")

// --- Begin middleware_test.go ---
func TestCorsMiddleware_PreflightAndNormal(t *testing.T) {
	cors := NewCorsMiddleware()

	// 1. Preflight Request
	httpReq, _ := http.NewRequest("OPTIONS", "/api/data", nil)
	httpReq.Header.Set("Origin", "http://example.com")
	req := NewRequest(httpReq)

	res := cors.Process(req, func(r *Request) interface{} {
		return NewResponse().SetContent("ok")
	})

	resp := res.(*Response)
	assert.Equal(t, http.StatusNoContent, resp.GetCode())
	assert.Equal(t, "*", resp.Headers().Get("Access-Control-Allow-Origin"))

	// 2. Normal Request
	httpReq2, _ := http.NewRequest("GET", "/api/data", nil)
	httpReq2.Header.Set("Origin", "http://example.com")
	req2 := NewRequest(httpReq2)

	res2 := cors.Process(req2, func(r *Request) interface{} {
		return NewResponse().SetContent("data")
	})

	resp2 := res2.(*Response)
	assert.Equal(t, "data", resp2.GetContent())
	assert.Equal(t, "*", resp2.Headers().Get("Access-Control-Allow-Origin"))

	// Test backward compatible alias
	aliasCors := NewCorsHandler()
	assert.NotNil(t, aliasCors)
}

func TestTrimStringsMiddleware(t *testing.T) {
	trim := NewTrimStringsMiddleware("password")

	httpReq, _ := http.NewRequest("POST", "/login?username=%20alice%20&password=%20secret%20", nil)
	req := NewRequest(httpReq)

	_ = trim.Process(req, func(r *Request) interface{} {
		return nil
	})

	val, _ := req.Input("username")
	assert.Equal(t, "alice", val)

	pwd, _ := req.Input("password")
	assert.Equal(t, " secret ", pwd)

	// Test backward compatible alias
	aliasTrim := NewTrimStringsHandler("token")
	assert.NotNil(t, aliasTrim)
}

func TestValidateSignatureMiddleware(t *testing.T) {
	r := New(nil, nil)
	r.Get("/secret", func() string {
		return "secret-data"
	}).Name("secret.route")
	r.Register()

	generator := NewUrlGenerator(r, "").SetKeyResolver(func() []string {
		return []string{"test-signature-key"}
	})

	signedUrl := generator.TemporarySignedRoute("secret.route", 10*time.Minute, nil)

	handler := NewValidateSignatureMiddleware(generator)

	// Valid signature
	httpReq, _ := http.NewRequest("GET", signedUrl, nil)
	req := NewRequest(httpReq)
	res := handler.Process(req, func(r *Request) interface{} {
		return NewResponse().SetContent("passed")
	})
	resp := res.(*Response)
	assert.Equal(t, "passed", resp.GetContent())

	// Invalid signature
	httpReqBad, _ := http.NewRequest("GET", "/secret?signature=fake&expires=9999999999", nil)
	reqBad := NewRequest(httpReqBad)
	resBad := handler.Process(reqBad, func(r *Request) interface{} {
		return NewResponse().SetContent("passed")
	})
	respBad := resBad.(*Response)
	assert.Equal(t, http.StatusForbidden, respBad.GetCode())

	// Test backward compatible alias
	aliasHandler := NewValidateSignatureHandler(generator)
	assert.NotNil(t, aliasHandler)
}

// --- End middleware_test.go ---

// relativeSignedURL builds a signed relative URL "/secret?expires=...&signature=..."
// by hand, matching the canonical relative payload the generator replays.
func relativeSignedURL(path, key string, expires int64) string {
	payload := path + "?expires=" + strconv.FormatInt(expires, 10)
	return payload + "&signature=" + signHMAC(payload, key)
}

func TestValidateSignatureRelativeAndAbsolute(t *testing.T) {
	r := New(nil, nil)
	r.Get("/secret", func() string {
		return "secret-data"
	}).Name("secret.route")
	r.Register()

	generator := NewUrlGenerator(r, "").SetKeyResolver(func() []string {
		return []string{"test-signature-key"}
	})
	expires := time.Now().Add(10 * time.Minute).Unix()

	// Relative middleware: accepts a hand-signed relative URL.
	relativeMw := ValidateSignatureRelative(generator)
	req := NewRequest(mustNewRequest("GET", relativeSignedURL("/secret", "test-signature-key", expires)))
	res := relativeMw(req, func(r *Request) interface{} {
		return NewResponse().SetContent("passed")
	}).(*Response)
	assert.Equal(t, "passed", res.GetContent())

	// A tampered signature is rejected with 403 "Invalid signature.".
	reqBad := NewRequest(mustNewRequest("GET", relativeSignedURL("/secret", "test-signature-key", expires)+"x"))
	resBad := relativeMw(reqBad, func(r *Request) interface{} {
		return NewResponse().SetContent("passed")
	}).(*Response)
	assert.Equal(t, http.StatusForbidden, resBad.GetCode())
	assert.Equal(t, "Invalid signature.", resBad.GetContent())

	// Absolute middleware (the default form): accepts the generator's own
	// signed URL round-trip.
	absoluteMw := ValidateSignatureAbsolute(generator)
	signedURL := generator.TemporarySignedRoute("secret.route", 10*time.Minute, nil)
	require.NotEmpty(t, signedURL)
	reqAbs := NewRequest(mustNewRequest("GET", signedURL))
	resAbs := absoluteMw(reqAbs, func(r *Request) interface{} {
		return NewResponse().SetContent("passed")
	}).(*Response)
	assert.Equal(t, "passed", resAbs.GetContent())

	// Absolute middleware rejects garbage as well.
	reqAbsBad := NewRequest(mustNewRequest("GET", "/secret?signature=fake&expires=9999999999"))
	resAbsBad := absoluteMw(reqAbsBad, func(r *Request) interface{} {
		return NewResponse().SetContent("passed")
	}).(*Response)
	assert.Equal(t, http.StatusForbidden, resAbsBad.GetCode())
}

func TestValidateSignatureExceptGlobalTable(t *testing.T) {
	r := New(nil, nil)
	r.Get("/secret", func() string {
		return "secret-data"
	}).Name("secret.route")
	r.Register()

	generator := NewUrlGenerator(r, "").SetKeyResolver(func() []string {
		return []string{"test-signature-key"}
	})

	// Registering the global "never validate" table and appending the extra
	// parameter after signing keeps the URL valid.
	exceptMw := ValidateSignatureExcept(generator, "utm_campaign_flow_test")
	signedURL := generator.TemporarySignedRoute("secret.route", 10*time.Minute, nil) + "&utm_campaign_flow_test=spring"

	req := NewRequest(mustNewRequest("GET", signedURL))
	res := exceptMw(req, func(r *Request) interface{} {
		return NewResponse().SetContent("passed")
	}).(*Response)
	assert.Equal(t, "passed", res.GetContent())

	// A parameter outside the global table still breaks the signature, and
	// the table merged at process time is what saved the first request.
	defaultMw := ValidateSignatureAbsolute(generator, "utm_other")
	signedURL2 := generator.TemporarySignedRoute("secret.route", 10*time.Minute, nil) + "&utm_other=x"
	req2 := NewRequest(mustNewRequest("GET", signedURL2))
	res2 := defaultMw(req2, func(r *Request) interface{} {
		return NewResponse().SetContent("passed")
	}).(*Response)
	assert.Equal(t, "passed", res2.GetContent())

	signedURL3 := generator.TemporarySignedRoute("secret.route", 10*time.Minute, nil) + "&utm_other=x"
	req3 := NewRequest(mustNewRequest("GET", signedURL3))
	res3 := ValidateSignatureRelative(generator)(req3, func(r *Request) interface{} {
		return NewResponse().SetContent("passed")
	}).(*Response)
	assert.Equal(t, http.StatusForbidden, res3.GetCode(), "relative validation without ignores rejects the extra parameter")
}

func TestSubstituteBindingsMiddleware(t *testing.T) {
	type subBindUser struct{ ID string }

	r := NewRouter(nil, nil)
	r.Get("/users/{user}", func(ctx Context) string { return "user" })
	r.Bind("user", func(value string, route *Route) (any, error) {
		if value == "1" {
			return &subBindUser{ID: "1"}, nil
		}
		return nil, errSubBindMissing
	})
	r.Register()

	route := r.GetRoutes()[0]
	rt := r.(*router)
	rt.currentRoute = route

	mw := NewSubstituteBindingsMiddleware(r)

	// Successful binding: the resolved object is stored on the request.
	req := NewRequest(mustNewRequest("GET", "/users/1"))
	req.SetRouteParam("user", "1")
	var bound any
	res := mw.Process(req, func(r *Request) interface{} {
		bound, _ = r.RouteParamObject("user")
		return NewResponse().SetContent("ok")
	}).(*Response)
	assert.Equal(t, "ok", res.GetContent())
	assert.Equal(t, &subBindUser{ID: "1"}, bound)

	// Failed binding: the ModelNotFoundError panic propagates for the router
	// to convert into the missing response / 404.
	reqBad := NewRequest(mustNewRequest("GET", "/users/2"))
	reqBad.SetRouteParam("user", "2")
	assert.Panics(t, func() {
		mw.Process(reqBad, func(r *Request) interface{} {
			return NewResponse().SetContent("ok")
		})
	})
}

func TestSubstituteBindingsMiddlewareWithoutRoute(t *testing.T) {
	r := NewRouter(nil, nil)
	mw := NewSubstituteBindingsMiddleware(r)

	// No current route: the middleware is a no-op passthrough.
	req := NewRequest(mustNewRequest("GET", "/anything"))
	res := mw.Process(req, func(r *Request) interface{} {
		return "next"
	})
	assert.Equal(t, "next", res)

	// A nil router is tolerated as well.
	nilMw := &SubstituteBindingsMiddleware{}
	res2 := nilMw.Process(req, func(r *Request) interface{} {
		return "next"
	})
	assert.Equal(t, "next", res2)
}

// --- End middleware_test.go ---

// --- Begin pipeline_test.go ---
type dummyHandler struct {
	fn func(req *Request, next Closure) interface{}
}

func (d *dummyHandler) Process(req *Request, next Closure) interface{} {
	return d.fn(req, next)
}

func TestPipelineServeHTTPPointerResponse(t *testing.T) {
	p := NewPipeline()
	p.Pipe(&dummyHandler{
		fn: func(req *Request, next Closure) interface{} {
			resp := NewResponse()
			resp.SetCode(http.StatusCreated)
			resp.SetContentType("application/json")
			resp.SetContent(`{"status":"created"}`)
			return resp
		},
	})

	rec := httptest.NewRecorder()
	httpReq, err := http.NewRequest("POST", "/api/item", nil)
	assert.NoError(t, err)

	p.ServeHTTP(rec, httpReq)

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, `{"status":"created"}`, rec.Body.String())
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
}

// --- End pipeline_test.go ---

func TestRecoverMiddleware_PanicRecovery(t *testing.T) {
	// 1. Debug mode returns error details
	recHandlerDebug := NewRecoverMiddleware(true)
	req1 := NewRequest(nil)
	res1 := recHandlerDebug.Process(req1, func(r *Request) interface{} {
		panic("database connection lost")
	})
	resp1 := res1.(*Response)
	assert.Equal(t, 500, resp1.GetCode())
	assert.Contains(t, resp1.GetContent(), "database connection lost")

	// 2. Production mode (debug = false) masks internal message
	recHandlerProd := NewRecoverMiddleware(false)
	req2 := NewRequest(nil)
	res2 := recHandlerProd.Process(req2, func(r *Request) interface{} {
		panic("sensitive internal pointer nil")
	})
	resp2 := res2.(*Response)
	assert.Equal(t, 500, resp2.GetCode())
	assert.Equal(t, "Internal Server Error", resp2.GetContent())

	// Test backward compatible alias
	aliasRecover := NewRecoverHandler(true)
	assert.NotNil(t, aliasRecover)
}

func TestCorsHandler_CustomOrigins(t *testing.T) {
	cfg := CorsConfig{
		AllowOrigins:     []string{"https://app.example.com"},
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Authorization"},
		ExposeHeaders:    []string{"X-Custom-Id"},
		AllowCredentials: true,
		MaxAge:           3600,
	}
	cors := NewCorsHandler(cfg)

	// 1. Matched allowed origin
	httpReq1, _ := http.NewRequest("GET", "/api/user", nil)
	httpReq1.Header.Set("Origin", "https://app.example.com")
	req1 := NewRequest(httpReq1)
	res1 := cors.Process(req1, func(r *Request) interface{} {
		return NewResponse().SetContent("user")
	})
	resp1 := res1.(*Response)
	assert.Equal(t, "https://app.example.com", resp1.Headers().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", resp1.Headers().Get("Access-Control-Allow-Credentials"))

	// 2. Disallowed origin
	httpReq2, _ := http.NewRequest("GET", "/api/user", nil)
	httpReq2.Header.Set("Origin", "https://evil.com")
	req2 := NewRequest(httpReq2)
	res2 := cors.Process(req2, func(r *Request) interface{} {
		return NewResponse().SetContent("user")
	})
	resp2 := res2.(*Response)
	assert.Empty(t, resp2.Headers().Get("Access-Control-Allow-Origin"))
}

func TestPipeline_ThroughAndHandlerFunc(t *testing.T) {
	p := NewPipeline()

	h1 := HandlerFunc(func(req *Request, next Closure) interface{} {
		req.Set("step1", true)
		return next(req)
	})

	h2 := HandlerFunc(func(req *Request, next Closure) interface{} {
		req.Set("step2", true)
		return NewResponse().SetContent("done")
	})

	p.Through([]Handler{h1, h2})

	req := NewRequest(nil)
	res := p.Send(req).Then(nil)
	resp := res.(*Response)
	assert.Equal(t, "done", resp.GetContent())

	s1, _ := req.Get("step1")
	s2, _ := req.Get("step2")
	assert.Equal(t, true, s1)
	assert.Equal(t, true, s2)
}

func TestSessionMiddleware_ProcessFlow(t *testing.T) {
	mw := NewSessionMiddleware(nil)

	httpReq, _ := http.NewRequest("GET", "/profile", nil)
	req := NewRequest(httpReq)

	res := mw.Process(req, func(r *Request) interface{} {
		assert.NotNil(t, r.Session())
		r.Session().Set("username", "bob")
		return NewResponse().SetContent("profile_ok")
	})

	resp := res.(*Response)
	assert.Equal(t, "profile_ok", resp.GetContent())

	rec := httptest.NewRecorder()
	resp.Send(rec)
	assert.NotEmpty(t, rec.Header().Get("Set-Cookie"))
}

func TestSessionMiddleware_CustomConfigAndManager(t *testing.T) {
	// 1. 传入 nil 使用默认配置
	mwDef := NewSessionMiddleware(nil)
	smDef, ok := mwDef.(*SessionMiddleware)
	assert.True(t, ok)
	assert.Equal(t, "file", smDef.Manager.Config.Driver)
	assert.Equal(t, "think_session", smDef.Manager.Config.CookieName)
	assert.Equal(t, 120*time.Minute, smDef.Manager.Config.Lifetime)

	// 2. 传入自定义 *Config（部分覆盖，其余使用默认值）
	customCfg := &Config{
		Driver:     "cookie",
		CookieName: "my_app_session",
	}
	mwCustom := NewSessionMiddleware(customCfg)
	smCustom, ok := mwCustom.(*SessionMiddleware)
	assert.True(t, ok)
	assert.Equal(t, "cookie", smCustom.Manager.Config.Driver)
	assert.Equal(t, "my_app_session", smCustom.Manager.Config.CookieName)
	assert.Equal(t, 120*time.Minute, smCustom.Manager.Config.Lifetime) // 继承默认生命周期

	// 3. 直接通过 struct 注入 Manager
	customMgr := NewManager(&Config{
		Driver:     "file",
		CookieName: "external_mgr_session",
		Lifetime:   60 * time.Minute,
	})
	mwMgr := &SessionMiddleware{Manager: customMgr}
	assert.Equal(t, "external_mgr_session", mwMgr.Manager.Config.CookieName)
}

func TestCookieMiddleware(t *testing.T) {
	// 1. 默认配置
	mw := NewCookieMiddleware()
	httpReq, _ := http.NewRequest("GET", "/", nil)
	req := NewRequest(httpReq)

	_ = mw.Process(req, func(r *Request) any {
		assert.NotNil(t, r.CookieHandler)
		assert.Equal(t, "/", r.CookieHandler.Config.Path)
		assert.Equal(t, true, r.CookieHandler.Config.HttpOnly)
		return NewResponse().SetContent("ok")
	})

	// 2. 自定义配置（Prefix 与 Domain）
	customCfg := &CookieConfig{
		Prefix:   "myapp_",
		Domain:   "example.com",
		Path:     "/api",
		Secure:   true,
		HttpOnly: true,
	}
	customMw := NewCookieMiddleware(customCfg)

	httpReq2, _ := http.NewRequest("GET", "/api/test", nil)
	httpReq2.Header.Set("Cookie", "myapp_token=secret_token")
	req2 := NewRequest(httpReq2)

	res := customMw.Process(req2, func(r *Request) any {
		// 读取 cookie，自动应用 Prefix "myapp_"
		val, err := r.Cookie("token")
		assert.Nil(t, err)
		assert.Equal(t, "secret_token", val)

		// 响应端设置 cookie，自动继承 Domain/Secure/Path
		resp := NewResponse()
		_ = resp.Cookie("user_id", "123")
		return resp
	})

	resp := res.(*Response)
	assert.NotNil(t, resp.CookieHandler)
	assert.Equal(t, "example.com", resp.CookieHandler.Config.Domain)
	assert.Equal(t, true, resp.CookieHandler.Config.Secure)

	cookieObj := resp.GetCookies()["user_id"]
	assert.NotNil(t, cookieObj)
	assert.Equal(t, "example.com", cookieObj.Domain)
	assert.Equal(t, "/api", cookieObj.Path)
	assert.Equal(t, true, cookieObj.Secure)
}

// --- Begin SubstituteBindings missing callback tests ---

func TestSubstituteBindingsMiddlewareMissingCallback(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Get("/users/{user}", func(ctx Context) string { return "user" }).
		Missing(func(request *Request, err error) any {
			return NewResponse().SetCode(http.StatusNotFound).SetContent("missing:" + err.Error())
		})
	r.Bind("user", func(value string, route *Route) (any, error) {
		return nil, errSubBindMissing
	})
	r.Register()

	route := r.GetRoutes()[0]
	rt := r.(*router)
	rt.currentRoute = route

	mw := NewSubstituteBindingsMiddleware(r)

	// the reference implementation L41-50: the ModelNotFoundException is
	// caught, the route's missing callback runs and its result is returned —
	// the next handler is never called.
	reqBad := NewRequest(mustNewRequest("GET", "/users/2"))
	reqBad.SetRouteParam("user", "2")

	nextCalled := false
	res := mw.Process(reqBad, func(r *Request) interface{} {
		nextCalled = true
		return NewResponse().SetContent("ok")
	}).(*Response)

	assert.False(t, nextCalled, "the missing callback must short-circuit the pipeline")
	assert.Equal(t, http.StatusNotFound, res.GetCode())
	assert.Contains(t, res.GetContent(), "missing:")
	assert.Contains(t, res.GetContent(), errSubBindMissing.Error())

	// A route without a missing callback still re-panics the
	// *ModelNotFoundError for the router to handle.
	r2 := NewRouter(nil, nil)
	r2.Get("/users/{user}", func(ctx Context) string { return "user" })
	r2.Bind("user", func(value string, route *Route) (any, error) {
		return nil, errSubBindMissing
	})
	r2.Register()
	mw2 := NewSubstituteBindingsMiddleware(r2)
	r2.(*router).currentRoute = r2.GetRoutes()[0]

	reqBad2 := NewRequest(mustNewRequest("GET", "/users/2"))
	reqBad2.SetRouteParam("user", "2")
	assert.Panics(t, func() {
		mw2.Process(reqBad2, func(r *Request) interface{} {
			return NewResponse().SetContent("ok")
		})
	})
}

// --- MiddlewareNameResolver lookup order ---

func TestMiddlewareNameResolver_ClosureAliasFullStringWinsOverGroup(t *testing.T) {
	// the reference implementation L24-26: the FULL name is checked against the map before the
	// group lookup, and the hit is honored when the mapped value is a Closure.
	closure := HandlerFunc(func(req *Request, next Closure) any { return next(req) })
	r := NewMiddlewareNameResolver(
		map[string]any{"web": closure},
		map[string][]any{"web": {"auth", "session"}},
	)

	got, err := r.Resolve("web")
	require.NoError(t, err)
	require.Len(t, got, 1)
	gotFn, ok := got[0].(HandlerFunc)
	require.True(t, ok, "the closure alias must be returned as-is, got %T", got[0])
	assert.Equal(t, reflect.ValueOf(closure).Pointer(), reflect.ValueOf(gotFn).Pointer(),
		"a closure alias beats the group of the same name")

	// A closure alias registered under the full parameterized name is
	// returned as-is for that exact name too.
	r2 := NewMiddlewareNameResolver(
		map[string]any{"throttle:10": closure},
		map[string][]any{},
	)
	got2, err := r2.Resolve("throttle:10")
	require.NoError(t, err)
	require.Len(t, got2, 1)
	gotFn2, ok := got2[0].(HandlerFunc)
	require.True(t, ok, "the closure alias must be returned as-is, got %T", got2[0])
	assert.Equal(t, reflect.ValueOf(closure).Pointer(), reflect.ValueOf(gotFn2).Pointer())
}

func TestMiddlewareNameResolver_GroupBeforeAliasSplit(t *testing.T) {
	// the reference implementation L29-32: after the closure check, an exact group name expands —
	// even when an alias of the same head exists (a group named like an alias
	// cannot coexist for the plain name, but the group check must precede the
	// parameterized alias split).
	alias := "App\\Auth"
	r := NewMiddlewareNameResolver(
		map[string]any{"auth": alias},
		map[string][]any{"auth": {"auth.basic"}},
	)

	got, err := r.Resolve("auth")
	require.NoError(t, err)
	assert.Equal(t, []any{"auth.basic"}, got, "the group expands before the alias split")
}

func TestMiddlewareNameResolver_ParameterizedGroupNameDoesNotExpand(t *testing.T) {
	// the reference implementation checks group membership with the FULL entry string
	// (a full-string group lookup), so "web:foo" never expands group "web".
	r := NewMiddlewareNameResolver(
		map[string]any{},
		map[string][]any{"web": {"auth"}},
	)

	got, err := r.Resolve("web:foo")
	require.NoError(t, err)
	assert.Equal(t, []any{"web:foo"}, got, "a parameterized group name passes through unresolved")
}

func TestMiddlewareNameResolver_StringAliasWithParamsStillResolves(t *testing.T) {
	// the reference implementation L35-36: a string alias is resolved through the split, with the
	// parameters re-appended; a full-string string alias entry is NOT honored
	// at the top level (only Closures are).
	r := NewMiddlewareNameResolver(
		map[string]any{"throttle:10": "App\\FullString", "throttle": "App\\Throttle"},
		map[string][]any{},
	)

	got, err := r.Resolve("throttle:10")
	require.NoError(t, err)
	assert.Equal(t, []any{"App\\Throttle:10"}, got, "the alias head resolves with the params re-appended")

	got2, err := r.Resolve("throttle")
	require.NoError(t, err)
	assert.Equal(t, []any{"App\\Throttle"}, got2)
}
