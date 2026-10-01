package flow

import (
	"bytes"
	"compress/gzip"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-think/flow/session"
	"github.com/stretchr/testify/assert"
)

func newTestSessionStore() *session.Store {
	return session.NewStore("test_sess", &session.CookieHandler{})
}

func TestTrustedProxies(t *testing.T) {
	ResetGlobalTrustedProxies()
	defer ResetGlobalTrustedProxies()

	// 1. Unconfigured: respects X-Forwarded-For for backward compatibility
	httpReq := httptest.NewRequest("GET", "http://example.com/test", nil)
	httpReq.RemoteAddr = "10.0.0.1:1234"
	httpReq.Header.Set("X-Forwarded-For", "203.0.113.195, 10.0.0.1")
	req := NewRequest(httpReq)
	assert.Equal(t, "203.0.113.195", req.ClientIP())

	// 2. Configured trusted proxy CIDR
	req.SetTrustedProxies([]string{"10.0.0.0/8"})
	assert.True(t, req.IsFromTrustedProxy())
	assert.Equal(t, "203.0.113.195", req.ClientIP())

	// 3. Untrusted peer sending spoofed X-Forwarded-For
	untrustedReq := httptest.NewRequest("GET", "http://example.com/test", nil)
	untrustedReq.RemoteAddr = "198.51.100.2:4567"
	untrustedReq.Header.Set("X-Forwarded-For", "1.1.1.1")
	untrustedReq.Header.Set("X-Forwarded-Proto", "https")
	untrustedReq.Header.Set("X-Forwarded-Host", "spoofed.com")
	req2 := NewRequest(untrustedReq)
	req2.SetTrustedProxies([]string{"10.0.0.0/8"})

	assert.False(t, req2.IsFromTrustedProxy())
	// Should ignore spoofed headers and return actual RemoteAddr
	assert.Equal(t, "198.51.100.2", req2.ClientIP())
	assert.Equal(t, "http", req2.Scheme())
	assert.Equal(t, "example.com", req2.Host())

	// 4. TrustProxiesMiddleware
	middleware := NewTrustProxiesMiddleware("198.51.100.0/24")
	req3 := NewRequest(untrustedReq)
	middleware.(Handler).Process(req3, func(r *Request) any {
		assert.True(t, r.IsFromTrustedProxy())
		assert.Equal(t, "1.1.1.1", r.ClientIP())
		assert.Equal(t, "https", r.Scheme())
		assert.Equal(t, "spoofed.com", r.Host())
		return "ok"
	})

	// 5. Port stripping from XFF and X-Real-Ip
	withPortReq := httptest.NewRequest("GET", "http://example.com/test", nil)
	withPortReq.RemoteAddr = "10.0.0.1:9999"
	withPortReq.Header.Set("X-Forwarded-For", "203.0.113.195:8080, 10.0.0.1:9999")
	req4 := NewRequest(withPortReq)
	req4.SetTrustedProxies([]string{"10.0.0.0/8"})
	assert.Equal(t, "203.0.113.195", req4.ClientIP())
}

func TestFlashAndOldInput(t *testing.T) {
	store := newTestSessionStore()
	httpReq := httptest.NewRequest("POST", "http://example.com/form", strings.NewReader("name=Taylor&email=taylor@example.com&password=secret"))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req := NewRequest(httpReq)
	req.SetSession(store)

	// Flash all inputs
	req.Flash()
	assert.True(t, req.HasOldInput("name"))
	assert.Equal(t, "Taylor", req.Old("name"))
	assert.Equal(t, "taylor@example.com", req.Old("email"))
	assert.Equal(t, "default_val", req.Old("non_existent", "default_val"))

	// FlashExcept
	req.FlashExcept("password")
	assert.True(t, req.HasOldInput("name"))
	assert.False(t, req.HasOldInput("password"))
	assert.Equal(t, "", req.Old("password"))

	// FlashOnly
	req.FlashOnly("email")
	assert.True(t, req.HasOldInput("email"))
	assert.False(t, req.HasOldInput("name"))

	// Response.With, WithInput, WithErrors
	res := NewResponse().SetRequest(req)
	res.With("status", "Profile updated!")
	assert.Equal(t, "Profile updated!", store.Get("status"))

	res.WithInput("email")
	assert.Equal(t, "taylor@example.com", req.Old("email"))

	res.WithErrors(map[string]string{"email": "Email already taken"})
	assert.NotNil(t, store.Get("errors"))
}

func TestConvertEmptyStringsToNullMiddleware(t *testing.T) {
	httpReq := httptest.NewRequest("POST", "http://example.com/submit", strings.NewReader("title=Hello&description=&notes=   &except_empty="))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req := NewRequest(httpReq)

	middleware := NewConvertEmptyStringsToNullMiddleware("except_empty")
	middleware.(Handler).Process(req, func(r *Request) any {
		assert.True(t, r.Has("title"))
		assert.False(t, r.Has("description"))
		assert.False(t, r.Has("notes"))
		assert.True(t, r.Has("except_empty"))
		return "ok"
	})
}

func TestVerifyCsrfTokenMiddleware(t *testing.T) {
	store := newTestSessionStore()
	token := store.Token()
	assert.NotEmpty(t, token)

	middleware := NewVerifyCsrfTokenMiddleware("webhook/*")

	// 1. Reading methods (GET) skip verification and attach XSRF-TOKEN cookie
	getReq := NewRequest(httptest.NewRequest("GET", "http://example.com/form", nil))
	getReq.SetSession(store)
	result := middleware.(Handler).Process(getReq, func(r *Request) any {
		return NewResponse().SetContent("form")
	})
	res, ok := result.(*Response)
	assert.True(t, ok)
	assert.NotNil(t, res.GetCookies()["XSRF-TOKEN"])
	assert.Equal(t, token, res.GetCookies()["XSRF-TOKEN"].Value)

	// 2. Except path skips verification
	webhookReq := NewRequest(httptest.NewRequest("POST", "http://example.com/webhook/stripe", nil))
	webhookReq.SetSession(store)
	result = middleware.(Handler).Process(webhookReq, func(r *Request) any {
		return NewResponse().SetContent("webhook processed")
	})
	res = result.(*Response)
	assert.Equal(t, 200, res.StatusCode())
	assert.Equal(t, "webhook processed", res.Body())

	// 3. State-changing method with missing token -> 419 Page Expired
	postReq := NewRequest(httptest.NewRequest("POST", "http://example.com/submit", nil))
	postReq.SetSession(store)
	result = middleware.(Handler).Process(postReq, func(r *Request) any {
		return NewResponse().SetContent("should not reach")
	})
	res = result.(*Response)
	assert.Equal(t, 419, res.StatusCode())
	assert.Equal(t, "Page Expired", res.Body())

	// 4. With JSON request -> 419 JSON error
	jsonReq := NewRequest(httptest.NewRequest("POST", "http://example.com/submit", nil))
	jsonReq.Header("Accept")
	jsonReq.Request.Header.Set("Accept", "application/json")
	jsonReq.SetSession(store)
	result = middleware.(Handler).Process(jsonReq, func(r *Request) any {
		return NewResponse()
	})
	res = result.(*Response)
	assert.Equal(t, 419, res.StatusCode())
	assert.Contains(t, res.Body(), "CSRF token mismatch.")

	// 5. Valid token via Header X-CSRF-TOKEN -> Success
	validHeaderReq := NewRequest(httptest.NewRequest("POST", "http://example.com/submit", nil))
	validHeaderReq.Request.Header.Set("X-CSRF-TOKEN", token)
	validHeaderReq.SetSession(store)
	result = middleware.(Handler).Process(validHeaderReq, func(r *Request) any {
		return NewResponse().SetContent("valid header")
	})
	res = result.(*Response)
	assert.Equal(t, 200, res.StatusCode())
	assert.Equal(t, "valid header", res.Body())

	// 6. Valid token via X-XSRF-TOKEN -> Success
	validXsrfReq := NewRequest(httptest.NewRequest("POST", "http://example.com/submit", nil))
	validXsrfReq.Request.Header.Set("X-XSRF-TOKEN", url.QueryEscape(token))
	validXsrfReq.SetSession(store)
	result = middleware.(Handler).Process(validXsrfReq, func(r *Request) any {
		return NewResponse().SetContent("valid xsrf")
	})
	res = result.(*Response)
	assert.Equal(t, 200, res.StatusCode())
	assert.Equal(t, "valid xsrf", res.Body())

	// 7. Valid token via Form Post -> Success
	formReq := NewRequest(httptest.NewRequest("POST", "http://example.com/submit", strings.NewReader("_token="+token+"&data=test")))
	formReq.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	formReq.SetSession(store)
	result = middleware.(Handler).Process(formReq, func(r *Request) any {
		return NewResponse().SetContent("valid form")
	})
	res = result.(*Response)
	assert.Equal(t, 200, res.StatusCode())
	assert.Equal(t, "valid form", res.Body())
}

func TestResponseCacheAndEtag(t *testing.T) {
	res := NewResponse().SetContent("response content")
	res.SetEtag("etag123")
	res.SetCacheControl("public", "max-age=3600")

	assert.Equal(t, "\"etag123\"", res.Headers().Get("ETag"))
	assert.Equal(t, "public, max-age=3600", res.Headers().Get("Cache-Control"))

	// Test Weak ETag
	resWeak := NewResponse().SetContent("weak content")
	resWeak.SetEtag("weak456", true)
	assert.Equal(t, "W/\"weak456\"", resWeak.Headers().Get("ETag"))

	// Test Last-Modified
	modTime := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	res.SetLastModified(modTime)
	assert.Equal(t, modTime.Format(http.TimeFormat), res.Headers().Get("Last-Modified"))

	// Test IsNotModified with matching ETag -> 304
	reqMatch := NewRequest(httptest.NewRequest("GET", "/", nil))
	reqMatch.Request.Header.Set("If-None-Match", "\"etag123\"")
	assert.True(t, res.IsNotModified(reqMatch))
	assert.Equal(t, 304, res.StatusCode())
	assert.Equal(t, "", res.Body())

	// Test IsNotModified with non-matching ETag -> 200
	res2 := NewResponse().SetContent("content2").SetEtag("etag999")
	reqNoMatch := NewRequest(httptest.NewRequest("GET", "/", nil))
	reqNoMatch.Request.Header.Set("If-None-Match", "\"etag123\"")
	assert.False(t, res2.IsNotModified(reqNoMatch))
	assert.Equal(t, 200, res2.StatusCode())
}

func TestFileStoreAndHashName(t *testing.T) {
	file := &File{
		FileHeader: &multipart.FileHeader{
			Filename: "profile_picture.png",
			Size:     1024,
		},
	}

	hashName := file.HashName()
	assert.True(t, strings.HasSuffix(hashName, ".png"))
	assert.Equal(t, 44, len(hashName)) // 40 hex chars + "." + "png"

	customExt := file.HashName("jpg")
	assert.True(t, strings.HasSuffix(customExt, ".jpg"))
}

func TestRequestIDMiddleware(t *testing.T) {
	middleware := NewRequestIDMiddleware()

	// 1. Missing header: auto generates ID and sets response header
	req := NewRequest(httptest.NewRequest("GET", "/test", nil))
	res := middleware.(Handler).Process(req, func(r *Request) any {
		assert.NotEmpty(t, r.ID())
		return NewResponse().SetContent("ok")
	}).(*Response)

	assert.Equal(t, req.ID(), res.Headers().Get("X-Request-Id"))

	// 2. Incoming X-Request-Id header preserved
	req2 := NewRequest(httptest.NewRequest("GET", "/test", nil))
	req2.Request.Header.Set("X-Request-Id", "custom-trace-id-1234")
	res2 := middleware.(Handler).Process(req2, func(r *Request) any {
		assert.Equal(t, "custom-trace-id-1234", r.ID())
		return NewResponse().SetContent("ok")
	}).(*Response)

	assert.Equal(t, "custom-trace-id-1234", res2.Headers().Get("X-Request-Id"))
}

func TestRequestBodyLimitMiddleware(t *testing.T) {
	middleware := NewRequestBodyLimitMiddleware(100) // 100 bytes limit

	// 1. Normal payload passes
	smallBody := strings.Repeat("a", 50)
	httpReq1 := httptest.NewRequest("POST", "/upload", strings.NewReader(smallBody))
	httpReq1.ContentLength = int64(len(smallBody))
	req1 := NewRequest(httpReq1)
	res1 := middleware.(Handler).Process(req1, func(r *Request) any {
		return NewResponse().SetContent("passed")
	}).(*Response)
	assert.Equal(t, 200, res1.StatusCode())

	// 2. Oversized payload blocked with 413
	largeBody := strings.Repeat("a", 200)
	httpReq2 := httptest.NewRequest("POST", "/upload", strings.NewReader(largeBody))
	httpReq2.ContentLength = int64(len(largeBody))
	req2 := NewRequest(httpReq2)
	res2 := middleware.(Handler).Process(req2, func(r *Request) any {
		return NewResponse().SetContent("should not reach")
	}).(*Response)
	assert.Equal(t, 413, res2.StatusCode())
	assert.Equal(t, "Payload Too Large", res2.Body())
}

func TestSecureHeadersMiddleware(t *testing.T) {
	middleware := NewSecureHeadersMiddleware()

	req := NewRequest(httptest.NewRequest("GET", "/", nil))
	res := middleware.(Handler).Process(req, func(r *Request) any {
		return NewResponse().SetContent("secure")
	}).(*Response)

	assert.Equal(t, "nosniff", res.Headers().Get("X-Content-Type-Options"))
	assert.Equal(t, "SAMEORIGIN", res.Headers().Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", res.Headers().Get("X-XSS-Protection"))
	assert.Equal(t, "strict-origin-when-cross-origin", res.Headers().Get("Referrer-Policy"))
}

func TestGzipMiddleware(t *testing.T) {
	middleware := NewGzipMiddleware(50) // 50 bytes threshold

	largeText := strings.Repeat("Think Framework High Performance Go Routing. ", 20)

	// 1. Client accepts gzip: compresses body
	httpReq := httptest.NewRequest("GET", "/data", nil)
	httpReq.Header.Set("Accept-Encoding", "gzip, deflate")
	req := NewRequest(httpReq)

	res := middleware.(Handler).Process(req, func(r *Request) any {
		return NewResponse().SetContent(largeText)
	}).(*Response)

	assert.Equal(t, "gzip", res.Headers().Get("Content-Encoding"))
	assert.Equal(t, "Accept-Encoding", res.Headers().Get("Vary"))

	// Decompress and verify content
	gr, err := gzip.NewReader(bytes.NewReader([]byte(res.Body())))
	assert.NoError(t, err)
	decompressed, err := io.ReadAll(gr)
	assert.NoError(t, err)
	assert.Equal(t, largeText, string(decompressed))

	// 2. Client does not accept gzip: remains plain
	httpReq2 := httptest.NewRequest("GET", "/data", nil)
	req2 := NewRequest(httpReq2)
	res2 := middleware.(Handler).Process(req2, func(r *Request) any {
		return NewResponse().SetContent(largeText)
	}).(*Response)

	assert.Empty(t, res2.Headers().Get("Content-Encoding"))
	assert.Equal(t, largeText, res2.Body())
}

func TestMaintenanceModeMiddleware(t *testing.T) {
	cfg := &MaintenanceModeConfig{
		Enabled:    true,
		Secret:     "super-secret-bypass",
		AllowedIPs: []string{"192.168.1.100"},
		RetryAfter: 600,
		Message:    "We will be back soon.",
	}
	middleware := NewMaintenanceModeMiddleware(cfg)

	// 1. Regular request blocked with 503
	httpReq1 := httptest.NewRequest("GET", "/api/test", nil)
	httpReq1.RemoteAddr = "203.0.113.5:1234"
	req1 := NewRequest(httpReq1)
	res1 := middleware.(Handler).Process(req1, func(r *Request) any {
		return NewResponse().SetContent("ok")
	}).(*Response)

	assert.Equal(t, 503, res1.StatusCode())
	assert.Equal(t, "600", res1.Headers().Get("Retry-After"))
	assert.Equal(t, "We will be back soon.", res1.Body())

	// 2. Secret query parameter bypasses 503
	httpReq2 := httptest.NewRequest("GET", "/api/test?secret=super-secret-bypass", nil)
	req2 := NewRequest(httpReq2)
	res2 := middleware.(Handler).Process(req2, func(r *Request) any {
		return NewResponse().SetContent("bypassed")
	}).(*Response)

	assert.Equal(t, 200, res2.StatusCode())
	assert.Equal(t, "bypassed", res2.Body())

	// 3. Allowed IP bypasses 503
	httpReq3 := httptest.NewRequest("GET", "/api/test", nil)
	httpReq3.RemoteAddr = "192.168.1.100:4321"
	req3 := NewRequest(httpReq3)
	res3 := middleware.(Handler).Process(req3, func(r *Request) any {
		return NewResponse().SetContent("ip-bypassed")
	}).(*Response)

	assert.Equal(t, 200, res3.StatusCode())
	assert.Equal(t, "ip-bypassed", res3.Body())
}

func TestRequestIPs(t *testing.T) {
	httpReq := httptest.NewRequest("GET", "/", nil)
	httpReq.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18:8080, 150.172.238.178")
	req := NewRequest(httpReq)

	ips := req.IPs()
	assert.Len(t, ips, 3)
	assert.Equal(t, "203.0.113.195", ips[0])
	assert.Equal(t, "70.41.3.18", ips[1])
	assert.Equal(t, "150.172.238.178", ips[2])
}
