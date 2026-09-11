package flow

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// --- Begin router_test.go ---
func TestConcurrentRouteMatchingParamIsolation(t *testing.T) {
	r := New()
	r.Get("/user/{id}", func(req *Request, id string) string {
		return "user:" + id
	})
	r.Register()

	var wg sync.WaitGroup
	concurrentCount := 100

	for i := 0; i < concurrentCount; i++ {
		wg.Add(1)
		userID := fmt.Sprintf("id_%d", i)
		go func(idStr string) {
			defer wg.Done()
			httpReq, err := http.NewRequest("GET", "/user/"+idStr, nil)
			assert.NoError(t, err)

			req := NewRequest(httpReq)
			route, err := r.MatchRequest(req)
			assert.NoError(t, err)
			assert.NotNil(t, route)

			res := route.Run(req)
			assert.Equal(t, "user:"+idStr, res)
		}(userID)
	}

	wg.Wait()
}

func TestRoutePrefixAndGroup(t *testing.T) {
	r := New()
	r.Get("/ping", func() string {
		return "pong"
	})
	r.Register()

	httpReq, _ := http.NewRequest("GET", "/ping", nil)
	req := NewRequest(httpReq)
	route, err := r.MatchRequest(req)
	assert.NoError(t, err)
	assert.Equal(t, "pong", route.Run(req))
}

func TestRouteWhereConstraints(t *testing.T) {
	r := New()
	// Only allow numeric id
	r.Get("/items/{id}", func(id int) string {
		return fmt.Sprintf("item:%d", id)
	}).WhereNumber("id")

	// Only allow enum role
	r.Get("/roles/{role}", func(role string) string {
		return "role:" + role
	}).WhereIn("role", []string{"admin", "editor"})

	r.Register()

	// 1. Valid numeric id -> should match
	httpReq1, _ := http.NewRequest("GET", "/items/123", nil)
	req1 := NewRequest(httpReq1)
	route1, err1 := r.MatchRequest(req1)
	assert.NoError(t, err1)
	assert.NotNil(t, route1)
	assert.Equal(t, "item:123", route1.Run(req1))

	// 2. Invalid alpha id -> should NOT match
	httpReq2, _ := http.NewRequest("GET", "/items/abc", nil)
	req2 := NewRequest(httpReq2)
	_, err2 := r.MatchRequest(req2)
	assert.Error(t, err2)

	// 3. Valid role enum -> should match
	httpReq3, _ := http.NewRequest("GET", "/roles/admin", nil)
	req3 := NewRequest(httpReq3)
	route3, err3 := r.MatchRequest(req3)
	assert.NoError(t, err3)
	assert.Equal(t, "role:admin", route3.Run(req3))

	// 4. Invalid role enum -> should NOT match
	httpReq4, _ := http.NewRequest("GET", "/roles/guest", nil)
	req4 := NewRequest(httpReq4)
	_, err4 := r.MatchRequest(req4)
	assert.Error(t, err4)
}

func TestSignedUrlAndSignatureValidation(t *testing.T) {
	r := New(WithSignatureKey("test-signature-key"))
	r.Get("/download/{file}", func(file string) string {
		return "download:" + file
	}).Name("file.download")
	r.Register()

	// Generate signed url valid for 1 hour
	signedUrl := r.SignedUrl("file.download", 1*time.Hour, map[string]string{"file": "report.pdf"})
	assert.Contains(t, signedUrl, "/download/report.pdf?")
	assert.Contains(t, signedUrl, "expires=")
	assert.Contains(t, signedUrl, "signature=")

	// Validate valid request
	httpReq, _ := http.NewRequest("GET", signedUrl, nil)
	req := NewRequest(httpReq)
	assert.True(t, r.HasValidSignature(req))

	// Tampered request -> should be invalid
	tamperedUrl := signedUrl + "x"
	httpReqTampered, _ := http.NewRequest("GET", tamperedUrl, nil)
	reqTampered := NewRequest(httpReqTampered)
	assert.False(t, r.HasValidSignature(reqTampered))
}

func TestSignedUrlWithoutKeyFailsClosed(t *testing.T) {
	r := New()
	r.Get("/download/{file}", func(file string) string {
		return "download:" + file
	}).Name("file.download")
	r.Register()

	// No signature key configured: signing must be disabled entirely,
	// never fall back to a built-in default secret.
	assert.Empty(t, r.SignedUrl("file.download", 1*time.Hour, nil))

	httpReq, _ := http.NewRequest("GET", "/download/report.pdf?expires=9999999999&signature=deadbeef", nil)
	assert.False(t, r.HasValidSignature(NewRequest(httpReq)))

	// The key is supplied via the WithSignatureKey option (or UrlGenerator's
	// SetKeyResolver); an explicit router has no runtime key setter.
	r2 := New(WithSignatureKey("configured-key"))
	r2.Get("/download/{file}", func(file string) string {
		return "download:" + file
	}).Name("file.download")
	r2.Register()
	signedUrl := r2.SignedUrl("file.download", 1*time.Hour, map[string]string{"file": "report.pdf"})
	assert.Contains(t, signedUrl, "signature=")
	httpReq2, _ := http.NewRequest("GET", signedUrl, nil)
	assert.True(t, r2.HasValidSignature(NewRequest(httpReq2)))
}

func TestRouteHasAndCurrentNameAndIs(t *testing.T) {
	r := New()
	r.Get("/admin/dashboard", func() string {
		return "admin-ok"
	}).Name("admin.dashboard")
	r.Register()

	// 1. Has
	assert.True(t, r.Has("admin.dashboard"))
	assert.False(t, r.Has("admin.users"))

	// 2. CurrentRouteName & Is
	httpReq, _ := http.NewRequest("GET", "/admin/dashboard", nil)
	req := NewRequest(httpReq)
	res := r.Dispatch(req)
	resp := res
	assert.Equal(t, "admin-ok", resp.GetContent())

	assert.Equal(t, "admin.dashboard", r.CurrentRouteName(req))
	assert.True(t, r.Is(req, "admin.dashboard"))
	assert.True(t, r.Is(req, "admin.*"))
	assert.False(t, r.Is(req, "user.*"))
}

// --- End router_test.go ---

// --- Begin router_group_test.go ---
func TestGroupInheritance(t *testing.T) {
	r := New()
	r.Group(GroupAttributes{Prefix: "/admin", Name: "admin."}, func(group Router) {
		group.Get("/profile", func() {}).Name("profile")
		group.Group(GroupAttributes{Prefix: "/api", Name: "api."}, func(api Router) {
			api.Get("/users", func() {}).Name("users")
		})
	})

	r.Register()

	url1 := r.Url("admin.profile", nil)
	if url1 != "/admin/profile" {
		t.Errorf("Expected /admin/profile, got %s", url1)
	}

	url2 := r.Url("admin.api.users", nil)
	if url2 != "/admin/api/users" {
		t.Errorf("Expected /admin/api/users, got %s", url2)
	}
}

// --- End router_group_test.go ---

// --- Begin controller_test.go ---
type ConfigService struct {
	Greeting string
}

type UserController struct {
	Config *ConfigService
}

func (c *UserController) Index(req *Request, id string) string {
	return fmt.Sprintf("%s user %s", c.Config.Greeting, id)
}

func TestControllerInjection(t *testing.T) {
	config := &ConfigService{Greeting: "Hello"}
	userCtrl := &UserController{Config: config}

	resolver := ParameterResolverFunc(func(paramType reflect.Type, req *Request) (reflect.Value, bool) {
		if paramType == reflect.TypeOf(userCtrl) {
			return reflect.ValueOf(userCtrl), true
		}
		if paramType == reflect.TypeOf(config) {
			return reflect.ValueOf(config), true
		}
		return reflect.Value{}, false
	})

	// 1. Register Route with ParameterResolver
	r := New(WithParameterResolver(resolver))
	r.Get("/user/{id}", (*UserController).Index)
	r.Register()

	// 2. Dispatch Request
	httpReq, _ := http.NewRequest("GET", "/user/123", nil)
	req := NewRequest(httpReq)

	route, err := r.MatchRequest(req)
	assert.NoError(t, err)
	assert.NotNil(t, route)

	res := route.Run(req)
	assert.Equal(t, "Hello user 123", res)
}

// --- End controller_test.go ---

func TestRouteAllHttpVerbs(t *testing.T) {
	r := New()
	r.Post("/items", func() string { return "post_ok" })
	r.Put("/items/{id}", func(id string) string { return "put_" + id })
	r.Patch("/items/{id}", func(id string) string { return "patch_" + id })
	r.Delete("/items/{id}", func(id string) string { return "delete_" + id })
	r.Options("/items", func() string { return "options_ok" })
	r.Any("/any-verb", func(req *Request) string { return "any_" + req.GetMethod() })
	r.Register()

	testCases := []struct {
		method   string
		path     string
		expected string
	}{
		{"POST", "/items", "post_ok"},
		{"PUT", "/items/10", "put_10"},
		{"PATCH", "/items/20", "patch_20"},
		{"DELETE", "/items/30", "delete_30"},
		{"OPTIONS", "/items", "options_ok"},
		{"GET", "/any-verb", "any_GET"},
		{"POST", "/any-verb", "any_POST"},
		{"DELETE", "/any-verb", "any_DELETE"},
	}

	for _, tc := range testCases {
		httpReq, err := http.NewRequest(tc.method, tc.path, nil)
		assert.NoError(t, err)
		req := NewRequest(httpReq)
		res := r.Dispatch(req)
		resp := res
		assert.Equal(t, tc.expected, resp.GetContent())
	}
}

func TestRouteFallback(t *testing.T) {
	r := New()
	r.Get("/valid", func() string { return "valid" })
	r.Fallback(func(req *Request) *Response {
		return NewResponse().SetCode(http.StatusNotFound).SetContent("custom_fallback:" + req.Path())
	})
	r.Register()

	// 1. Valid route
	httpReq1, _ := http.NewRequest("GET", "/valid", nil)
	res1 := r.Dispatch(NewRequest(httpReq1))
	resp1 := res1
	assert.Equal(t, "valid", resp1.GetContent())

	// 2. Unmatched route triggers fallback
	httpReq2, _ := http.NewRequest("GET", "/missing/page", nil)
	res2 := r.Dispatch(NewRequest(httpReq2))
	resp2 := res2
	assert.Equal(t, http.StatusNotFound, resp2.GetCode())
	assert.Equal(t, "custom_fallback:/missing/page", resp2.GetContent())

	// 3. Router without fallback triggers default NotFoundResponse
	rNoFallback := New()
	rNoFallback.Register()
	httpReq3, _ := http.NewRequest("GET", "/not-exist", nil)
	res3 := rNoFallback.Dispatch(NewRequest(httpReq3))
	resp3 := res3
	assert.Equal(t, http.StatusNotFound, resp3.GetCode())
	assert.Equal(t, "Not Found", resp3.GetContent())
}

func TestRouteStaticFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "static_test_*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	subDir := filepath.Join(tmpDir, "assets")
	assert.NoError(t, os.MkdirAll(subDir, 0755))
	testFile := filepath.Join(subDir, "app.js")
	assert.NoError(t, os.WriteFile(testFile, []byte("console.log('test static');"), 0644))

	r := New()
	r.Static("/static", tmpDir)
	r.Register()

	rec := httptest.NewRecorder()
	httpReq, _ := http.NewRequest("GET", "/static/assets/app.js", nil)
	req := NewRequest(httpReq)
	req.SetResponseWriter(rec)
	res := r.Dispatch(req)
	resp := res
	assert.True(t, resp.handled)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "console.log('test static');", rec.Body.String())
}

func TestRouteOptionalParameters(t *testing.T) {
	r := New()

	// 1. 单个末尾可选参数
	r.Get("/user/{name?}", func(req *Request, name string) string {
		paramVal := req.GetRouteParam("name")
		return fmt.Sprintf("arg:%s,req:%s", name, paramVal)
	}).Name("user.show")

	// 2. 连续多个末尾可选参数
	r.Get("/posts/{year?}/{month?}", func(year, month string) string {
		return fmt.Sprintf("y:%s,m:%s", year, month)
	})

	// 3. 中间必选、末尾可选
	r.Get("/groups/{group_id}/members/{member_id?}", func(groupId, memberId string) string {
		return groupId + ":" + memberId
	})

	r.Register()

	// --- 验证 1. 单可选参数 ---
	// 1.1 传参
	httpReq1, _ := http.NewRequest("GET", "/user/alice", nil)
	req1 := NewRequest(httpReq1)
	res1 := r.Dispatch(req1)
	assert.Equal(t, "arg:alice,req:alice", res1.GetContent())

	// 1.2 省略参数
	httpReq2, _ := http.NewRequest("GET", "/user", nil)
	req2 := NewRequest(httpReq2)
	res2 := r.Dispatch(req2)
	assert.Equal(t, "arg:,req:", res2.GetContent())
	val2, err2 := req2.RouteParam("name")
	assert.NoError(t, err2)
	assert.Equal(t, "", val2)

	// --- 验证 2. 多个连续可选参数 ---
	// 2.1 全提供
	httpReq3, _ := http.NewRequest("GET", "/posts/2026/09", nil)
	res3 := r.Dispatch(NewRequest(httpReq3))
	assert.Equal(t, "y:2026,m:09", res3.GetContent())

	// 2.2 提供一个
	httpReq4, _ := http.NewRequest("GET", "/posts/2026", nil)
	res4 := r.Dispatch(NewRequest(httpReq4))
	assert.Equal(t, "y:2026,m:", res4.GetContent())

	// 2.3 全省略
	httpReq5, _ := http.NewRequest("GET", "/posts", nil)
	res5 := r.Dispatch(NewRequest(httpReq5))
	assert.Equal(t, "y:,m:", res5.GetContent())

	// --- 验证 3. 中间必选、末尾可选 ---
	httpReq6, _ := http.NewRequest("GET", "/groups/golang/members/42", nil)
	res6 := r.Dispatch(NewRequest(httpReq6))
	assert.Equal(t, "golang:42", res6.GetContent())

	httpReq7, _ := http.NewRequest("GET", "/groups/golang/members", nil)
	res7 := r.Dispatch(NewRequest(httpReq7))
	assert.Equal(t, "golang:", res7.GetContent())

	// --- 验证 4. 命名路由 Url 生成与清理 ---
	assert.Equal(t, "/user/alice", r.Url("user.show", map[string]string{"name": "alice"}))
	assert.Equal(t, "/user", r.Url("user.show", map[string]string{}))

	// --- 验证 5. 根路径可选参数在独立路由实例测试 ---
	rRoot := New()
	rRoot.Get("/{locale?}", func(locale string) string {
		return "locale:" + locale
	})
	rRoot.Register()

	httpReq8, _ := http.NewRequest("GET", "/zh-CN", nil)
	res8 := rRoot.Dispatch(NewRequest(httpReq8))
	assert.Equal(t, "locale:zh-CN", res8.GetContent())

	httpReq9, _ := http.NewRequest("GET", "/", nil)
	res9 := rRoot.Dispatch(NewRequest(httpReq9))
	assert.Equal(t, "locale:", res9.GetContent())
}

type mockStructResolver struct {
	services map[reflect.Type]any
}

func (m *mockStructResolver) ResolveParameter(paramType reflect.Type, req *Request) (reflect.Value, bool) {
	if s, ok := m.services[paramType]; ok {
		return reflect.ValueOf(s), true
	}
	return reflect.Value{}, false
}

func TestRouter_ParameterResolverInterface(t *testing.T) {
	cfg := &ConfigService{Greeting: "Hi"}
	userCtrl := &UserController{Config: cfg}
	resolver := &mockStructResolver{
		services: map[reflect.Type]any{
			reflect.TypeOf(userCtrl): userCtrl,
			reflect.TypeOf(cfg):      cfg,
		},
	}

	// Initialize router with custom ParameterResolver interface implementation
	r := New(
		WithParameterResolver(resolver),
		WithSignatureKey("custom-secret-key-12345"),
	)

	r.Get("/user/{id}", (*UserController).Index).Name("user.show")
	r.Register()

	// 3. Verify Container autowire execution without ResolveDependency set
	httpReq, _ := http.NewRequest("GET", "/user/999", nil)
	req := NewRequest(httpReq)
	res := r.Dispatch(req)
	assert.Equal(t, "Hi user 999", res.GetContent())

	// 4. Verify Signed URL with instance signatureKey
	signedUrl := r.SignedUrl("user.show", 10*time.Minute, map[string]string{"id": "999"})
	assert.Contains(t, signedUrl, "signature=")

	verifyReq, _ := http.NewRequest("GET", signedUrl, nil)
	assert.True(t, r.HasValidSignature(NewRequest(verifyReq)))

	// Verify tampering signature key fails
	wrongRouter := New(WithSignatureKey("wrong-key"))
	assert.False(t, wrongRouter.HasValidSignature(NewRequest(verifyReq)))
}

func TestRouter_MiddlewareAliasAndGroup(t *testing.T) {
	var executed []string

	r := New()

	// 1. Register native alias and group
	r.AliasMiddleware("auth", HandlerFunc(func(req *Request, next Closure) interface{} {
		executed = append(executed, "auth")
		return next(req)
	}))

	r.AliasMiddleware("role", func(role string) Middleware {
		return func(req *Request, next Closure) interface{} {
			executed = append(executed, "role:"+role)
			return next(req)
		}
	})

	r.MiddlewareGroup("web",
		HandlerFunc(func(req *Request, next Closure) interface{} {
			executed = append(executed, "web_1")
			return next(req)
		}),
		HandlerFunc(func(req *Request, next Closure) interface{} {
			executed = append(executed, "web_2")
			return next(req)
		}),
	)

	// 2. Define routes using string alias, parameterized alias and group
	r.Get("/admin", func() string {
		return "admin_ok"
	}).Middleware("auth")

	r.Get("/user", func() string {
		return "user_ok"
	}).Middleware("role:admin")

	r.Get("/home", func() string {
		return "home_ok"
	}).Middleware("web")

	// 3. Sub-group inheriting aliases
	r.Group(GroupAttributes{Prefix: "/api", Middleware: []interface{}{"auth"}}, func(sub Router) {
		sub.Get("/data", func() string {
			return "data_ok"
		})
	})

	r.Register()

	// Test /admin
	executed = nil
	httpReq1, _ := http.NewRequest("GET", "/admin", nil)
	res1 := r.Dispatch(NewRequest(httpReq1))
	assert.Equal(t, "admin_ok", res1.GetContent())
	assert.Equal(t, []string{"auth"}, executed)

	// Test /user
	executed = nil
	httpReq2, _ := http.NewRequest("GET", "/user", nil)
	res2 := r.Dispatch(NewRequest(httpReq2))
	assert.Equal(t, "user_ok", res2.GetContent())
	assert.Equal(t, []string{"role:admin"}, executed)

	// Test /home
	executed = nil
	httpReq3, _ := http.NewRequest("GET", "/home", nil)
	res3 := r.Dispatch(NewRequest(httpReq3))
	assert.Equal(t, "home_ok", res3.GetContent())
	assert.Equal(t, []string{"web_1", "web_2"}, executed)

	// Test /api/data
	executed = nil
	httpReq4, _ := http.NewRequest("GET", "/api/data", nil)
	res4 := r.Dispatch(NewRequest(httpReq4))
	assert.Equal(t, "data_ok", res4.GetContent())
	assert.Equal(t, []string{"auth"}, executed)
}

func TestRouter_CustomParameterResolver(t *testing.T) {
	// Custom resolver function that always injects "custom_injected" if parameter type is string
	customResolver := ParameterResolverFunc(func(paramType reflect.Type, req *Request) (reflect.Value, bool) {
		if paramType.Kind() == reflect.String {
			return reflect.ValueOf("custom_injected"), true
		}
		return reflect.Value{}, false
	})

	r := New(WithParameterResolver(customResolver))
	r.Get("/custom/{val}", func(s string) string {
		return "got:" + s
	})
	r.Register()

	httpReq, _ := http.NewRequest("GET", "/custom/hello", nil)
	res := r.Dispatch(NewRequest(httpReq))
	assert.Equal(t, "got:custom_injected", res.GetContent())
}



