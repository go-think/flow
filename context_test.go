package flow

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// --- Begin context_test.go ---
func TestRequestContextAndKV(t *testing.T) {
	req, err := http.NewRequest("GET", "/test", nil)
	assert.NoError(t, err)

	r := NewRequest(req)

	// Test standard context.Context wrapping
	assert.NotNil(t, r.Context())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	r.WithContext(ctx)
	assert.Equal(t, ctx, r.Context())

	// Test request key-value pass-through
	r.Set("trace_id", "abc-123")
	val, ok := r.Get("trace_id")
	assert.Equal(t, "abc-123", val)

	_, ok = r.Get("non_exist")
	assert.False(t, ok)
}

func TestFileResponse(t *testing.T) {
	tmpDir := os.TempDir()
	filePath := filepath.Join(tmpDir, "test_file.txt")
	err := os.WriteFile(filePath, []byte("hello file response"), 0644)
	assert.NoError(t, err)
	defer os.Remove(filePath)

	req, err := http.NewRequest("GET", "/file", nil)
	assert.NoError(t, err)

	r := NewRequest(req)
	resp := FileResponse(filePath).SetRequest(r)

	rec := httptest.NewRecorder()
	resp.Send(rec)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "hello file response", rec.Body.String())
}

func TestRouteParamsIsolation(t *testing.T) {
	req, err := http.NewRequest("GET", "/user/42", nil)
	assert.NoError(t, err)
	r := NewRequest(req)

	r.SetRouteParam("id", "42")
	val, err := r.RouteParam("id")
	assert.NoError(t, err)
	assert.Equal(t, "42", val)
	assert.Equal(t, "42", r.GetRouteParam("id"))

	assert.Equal(t, "default", r.GetRouteParam("non_exist", "default"))
}

func TestCookieNilHandlerSafety(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	assert.NoError(t, err)

	r := NewRequest(req)
	// CookieHandler being nil should not trigger panic
	val, err := r.Cookie("session_id", "default_val")
	assert.NoError(t, err)
	assert.Equal(t, "default_val", val)
}

func TestFileMovePathTraversalProtection(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "file_test_*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "../../malicious.txt")
	assert.NoError(t, err)
	_, _ = part.Write([]byte("malicious content"))
	_ = writer.Close()

	req, err := http.NewRequest("POST", "/upload", body)
	assert.NoError(t, err)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	r := NewRequest(req)
	file, err := r.File("file")
	assert.NoError(t, err)

	targetDir := filepath.Join(tmpDir, "uploads")
	ok, err := file.Move(targetDir)
	assert.NoError(t, err)
	assert.True(t, ok)

	// Ensure path is cleaned by filepath.Base and exists in uploads directory, preventing path traversal
	assert.FileExists(t, filepath.Join(targetDir, "malicious.txt"))
}

func TestConcurrentSetAndGet(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	r := NewRequest(req)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r.Set("key", idx)
			_, _ = r.Get("key")
			r.SetRouteParam("p", "v")
			_ = r.GetRouteParam("p")
		}(i)
	}
	wg.Wait()
}

func TestRequestTypeConversionsAndFingerprint(t *testing.T) {
	req, _ := http.NewRequest("GET", "/test?page=3&rate=3.14&active=true&fallback_check=", nil)
	req.Header.Set("User-Agent", "Go-Test-Agent")
	r := NewRequest(req)

	// Test Integer
	assert.Equal(t, 3, r.Integer("page"))
	assert.Equal(t, 10, r.Integer("non_exist", 10))

	// Test Float
	assert.Equal(t, 3.14, r.Float("rate"))
	assert.Equal(t, 0.5, r.Float("non_exist", 0.5))

	// Test Boolean
	assert.True(t, r.Boolean("active"))
	assert.False(t, r.Boolean("non_exist"))
	assert.True(t, r.Boolean("non_exist", true))

	// Test Merge
	r.Merge(map[string]string{"merged_key": "merged_val"})
	val, err := r.Input("merged_key")
	assert.NoError(t, err)
	assert.Equal(t, "merged_val", val)

	// Test Fingerprint
	fp1 := r.Fingerprint()
	assert.NotEmpty(t, fp1)
	assert.Equal(t, fp1, r.Fingerprint())
}

func TestResponseStreamingAndNoContent(t *testing.T) {
	// Test NoContent
	noContent := NoContent()
	rec := httptest.NewRecorder()
	noContent.Send(rec)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Empty(t, rec.Body.String())

	// Test StreamResponse
	chunks := []string{"chunk1", "chunk2", "chunk3"}
	idx := 0
	streamResp := StreamResponse(func(w io.Writer) bool {
		if idx >= len(chunks) {
			return false
		}
		_, _ = w.Write([]byte(chunks[idx]))
		idx++
		return idx < len(chunks)
	})

	recStream := httptest.NewRecorder()
	streamResp.Send(recStream)
	assert.Equal(t, http.StatusOK, recStream.Code)
	assert.Equal(t, "chunk1chunk2chunk3", recStream.Body.String())
	assert.Equal(t, "text/event-stream", recStream.Header().Get("Content-Type"))
}

func TestRequestPathAndUrlMethods(t *testing.T) {
	httpReq, _ := http.NewRequest("GET", "/api/v1/users/42?sort=asc&page=1", nil)
	httpReq.Header.Set("User-Agent", "ThinkGo-Agent/1.0")
	r := NewRequest(httpReq)
	r.Set("_route_name", "users.show")

	// 1. UserAgent
	assert.Equal(t, "ThinkGo-Agent/1.0", r.UserAgent())

	// 2. Segments & Segment
	segments := r.Segments()
	assert.Equal(t, []string{"api", "v1", "users", "42"}, segments)
	assert.Equal(t, "api", r.Segment(1))
	assert.Equal(t, "42", r.Segment(4))
	assert.Equal(t, "default", r.Segment(5, "default"))

	// 3. Is & RouteIs
	assert.True(t, r.Is("api/*"))
	assert.True(t, r.Is("api/v1/users/42"))
	assert.False(t, r.Is("web/*"))

	assert.True(t, r.RouteIs("users.show"))
	assert.True(t, r.RouteIs("users.*"))
	assert.False(t, r.RouteIs("orders.*"))

	// 4. FullUrlWithQuery & FullUrlWithoutQuery
	withQuery := r.FullUrlWithQuery(map[string]string{"page": "2", "limit": "20"})
	assert.Contains(t, withQuery, "page=2")
	assert.Contains(t, withQuery, "limit=20")
	assert.Contains(t, withQuery, "sort=asc")

	withoutQuery := r.FullUrlWithoutQuery("sort")
	assert.NotContains(t, withoutQuery, "sort=")
	assert.Contains(t, withoutQuery, "page=1")
}

// --- End context_test.go ---

// --- Begin response_test.go ---
func TestJson(t *testing.T) {
	data := map[string]string{"foo": "bar"}
	res := Json(data)

	if res.GetContentType() != "application/json" {
		t.Fatalf("expected content type application/json, got %s", res.GetContentType())
	}

	var parsed map[string]string
	if err := json.Unmarshal([]byte(res.GetContent()), &parsed); err != nil {
		t.Fatalf("failed to parse json content: %v", err)
	}

	if parsed["foo"] != "bar" {
		t.Fatalf("expected foo=bar, got %s", parsed["foo"])
	}
}

func TestText(t *testing.T) {
	text := "hello thinkgo"
	res := Text(text)

	if res.GetContentType() != "text/plain" {
		t.Fatalf("expected content type text/plain, got %s", res.GetContentType())
	}

	if res.GetContent() != text {
		t.Fatalf("expected %s, got %s", text, res.GetContent())
	}
}

func TestHtml(t *testing.T) {
	html := "<h1>hello</h1>"
	res := Html(html)

	if res.GetContentType() != "text/html" {
		t.Fatalf("expected content type text/html, got %s", res.GetContentType())
	}

	if res.GetContent() != html {
		t.Fatalf("expected %s, got %s", html, res.GetContent())
	}
}

func TestDownload(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(tmpFile, []byte("content"), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	res := Download(tmpFile, "custom.txt")
	if res.filePath != tmpFile {
		t.Fatalf("expected filePath %s, got %s", tmpFile, res.filePath)
	}

	disposition := res.Headers().Get("Content-Disposition")
	expected := "attachment; filename=\"custom.txt\""
	if disposition != expected {
		t.Fatalf("expected disposition %s, got %s", expected, disposition)
	}
}

func TestMakeResponse(t *testing.T) {
	// 1. nil
	nilRes := MakeResponse(nil)
	if nilRes.GetContent() != "" {
		t.Fatalf("expected empty content for nil, got %s", nilRes.GetContent())
	}

	// 2. string
	strRes := MakeResponse("plain string")
	if strRes.GetContentType() != "text/plain" || strRes.GetContent() != "plain string" {
		t.Fatalf("unexpected string response: %v, %s", strRes.GetContentType(), strRes.GetContent())
	}

	// 3. map -> json
	mapData := map[string]int{"num": 42}
	mapRes := MakeResponse(mapData)
	if mapRes.GetContentType() != "application/json" {
		t.Fatalf("expected application/json for map, got %s", mapRes.GetContentType())
	}

	// 4. slice -> json
	sliceData := []string{"a", "b"}
	sliceRes := MakeResponse(sliceData)
	if sliceRes.GetContentType() != "application/json" {
		t.Fatalf("expected application/json for slice, got %s", sliceRes.GetContentType())
	}

	// 5. struct -> json
	type Sample struct {
		Name string `json:"name"`
	}
	structRes := MakeResponse(Sample{Name: "think"})
	if structRes.GetContentType() != "application/json" {
		t.Fatalf("expected application/json for struct, got %s", structRes.GetContentType())
	}
}

// --- End response_test.go ---

func TestRequestInputAndAllAndClientIP(t *testing.T) {
	// 1. JSON Body input
	jsonBody := `{"username":"carol","role":"admin"}`
	httpReq1, _ := http.NewRequest("POST", "/api/user?page=2", bytes.NewBufferString(jsonBody))
	httpReq1.Header.Set("Content-Type", "application/json")
	httpReq1.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18")
	r1 := NewRequest(httpReq1)

	userVal, err := r1.Input("username")
	assert.NoError(t, err)
	assert.Equal(t, "carol", userVal)

	pageVal, err := r1.Query("page")
	assert.NoError(t, err)
	assert.Equal(t, "2", pageVal)

	all := r1.All()
	assert.Equal(t, "carol", all["username"])
	assert.Equal(t, "admin", all["role"])
	assert.Equal(t, "2", all["page"])

	// 2. Client IP resolution
	assert.Equal(t, "203.0.113.195", r1.ClientIP())

	// 3. Fallback RemoteAddr
	httpReq2, _ := http.NewRequest("GET", "/", nil)
	httpReq2.RemoteAddr = "192.168.1.100:12345"
	r2 := NewRequest(httpReq2)
	assert.Equal(t, "192.168.1.100", r2.ClientIP())
}

func TestResponseHeadersAndCookies(t *testing.T) {
	res := NewResponse()
	res.SetCode(http.StatusAccepted).
		SetContentType("application/xml").
		SetCharset("gbk").
		SetContent("<xml>ok</xml>")

	assert.Equal(t, http.StatusAccepted, res.GetCode())
	assert.Equal(t, "application/xml", res.GetContentType())
	assert.Equal(t, "gbk", res.GetCharset())

	_ = res.Cookie("auth_token", "secret123")

	rec := httptest.NewRecorder()
	res.Send(rec)

	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.Equal(t, "<xml>ok</xml>", rec.Body.String())
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/xml")
	assert.Contains(t, rec.Header().Get("Content-Type"), "charset=gbk")
	assert.Contains(t, rec.Header().Get("Set-Cookie"), "auth_token=secret123")
}

func TestRequestHelperMethods(t *testing.T) {
	httpReq, _ := http.NewRequest("GET", "/test?name=john&empty=&spaces=%20%20&role=admin", nil)
	r := NewRequest(httpReq)

	// Has: key 存在即为 true（包括空字符串与纯空格）
	assert.True(t, r.Has("name"))
	assert.True(t, r.Has("empty"))
	assert.True(t, r.Has("spaces"))
	assert.True(t, r.Has("name", "role"))
	assert.False(t, r.Has("name", "non_exist"))
	assert.False(t, r.Has("non_exist"))
	assert.False(t, r.Has())

	// Exists: 与 Has 行为一致
	assert.True(t, r.Exists("name", "empty"))
	assert.False(t, r.Exists("non_exist"))

	// HasAny: 任意一个存在即为 true
	assert.True(t, r.HasAny("name", "non_exist"))
	assert.True(t, r.HasAny("empty", "another_missing"))
	assert.False(t, r.HasAny("foo", "bar"))
	assert.False(t, r.HasAny())

	// Filled: 存在且去空格后非空
	assert.True(t, r.Filled("name"))
	assert.True(t, r.Filled("name", "role"))
	assert.False(t, r.Filled("empty"))
	assert.False(t, r.Filled("spaces"))
	assert.False(t, r.Filled("non_exist"))
	assert.False(t, r.Filled("name", "empty"))
	assert.False(t, r.Filled())

	// Missing: 键完全不存在
	assert.True(t, r.Missing("foo"))
	assert.True(t, r.Missing("foo", "bar"))
	assert.False(t, r.Missing("name"))
	assert.False(t, r.Missing("empty"))
	assert.False(t, r.Missing("name", "foo"))
	assert.True(t, r.Missing())
}

func TestRedirectResponse(t *testing.T) {
	// 默认 302 重定向
	resp1 := Redirect("/home")
	assert.Equal(t, http.StatusFound, resp1.GetCode())
	assert.Equal(t, "/home", resp1.Headers().Get("Location"))

	rec1 := httptest.NewRecorder()
	resp1.Send(rec1)
	assert.Equal(t, http.StatusFound, rec1.Code)
	assert.Equal(t, "/home", rec1.Header().Get("Location"))

	// 自定义 301 永久重定向
	resp2 := Redirect("https://example.com/v2", http.StatusMovedPermanently)
	assert.Equal(t, http.StatusMovedPermanently, resp2.GetCode())
	assert.Equal(t, "https://example.com/v2", resp2.Headers().Get("Location"))

	rec2 := httptest.NewRecorder()
	resp2.Send(rec2)
	assert.Equal(t, http.StatusMovedPermanently, rec2.Code)
	assert.Equal(t, "https://example.com/v2", rec2.Header().Get("Location"))
}

