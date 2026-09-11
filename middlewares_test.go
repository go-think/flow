package flow

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

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
	r := New(WithSignatureKey("test-signature-key"))
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


