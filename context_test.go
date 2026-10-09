package flow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestFileMethodsAndMultiFileUploads(t *testing.T) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Create single file
	part1, err := writer.CreateFormFile("avatar", "profile.png")
	assert.NoError(t, err)
	_, _ = part1.Write([]byte("image-data-bytes"))

	// Create multi files
	part2, err := writer.CreateFormFile("photos", "photo1.jpg")
	assert.NoError(t, err)
	_, _ = part2.Write([]byte("photo-one"))

	part3, err := writer.CreateFormFile("photos", "photo2.jpg")
	assert.NoError(t, err)
	_, _ = part3.Write([]byte("photo-two"))

	_ = writer.Close()

	httpReq, _ := http.NewRequest("POST", "/upload", body)
	httpReq.Header.Set("Content-Type", writer.FormDataContentType())
	req := NewRequest(httpReq)

	// Single file tests
	avatar, err := req.File("avatar")
	assert.NoError(t, err)
	assert.Equal(t, "profile.png", avatar.Filename())
	assert.Equal(t, "png", avatar.Extension())
	assert.Equal(t, int64(16), avatar.Size())
	assert.True(t, avatar.IsValid())

	// Multi-files test
	photos := req.Files("photos")
	assert.Len(t, photos, 2)
	assert.Equal(t, "photo1.jpg", photos[0].Filename())
	assert.Equal(t, "jpg", photos[0].Extension())
	assert.Equal(t, "photo2.jpg", photos[1].Filename())
	assert.Equal(t, "jpg", photos[1].Extension())
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

	// 5. FullUrl without query shouldn't have trailing ?
	cleanReq := NewRequest(httptest.NewRequest("GET", "http://example.com:8080/users", nil))
	assert.Equal(t, "/users", cleanReq.Url())
	assert.Equal(t, "/users", cleanReq.FullUrl())
	assert.Equal(t, "/users", cleanReq.FullUrlWithQuery(map[string]string{}))

	// 6. Request inspection helpers
	cleanReq.Request.Header.Set("Authorization", "Bearer my-token")
	cleanReq.Request.Header.Set("Content-Type", "application/json; charset=utf-8")
	cleanReq.Request.Header.Set("X-Forwarded-Proto", "https")
	cleanReq.Request.Header.Set("Accept", "text/html,application/json;q=0.9")
	assert.True(t, cleanReq.HasHeader("Authorization"))
	assert.False(t, cleanReq.HasHeader("X-Non-Existent"))
	assert.True(t, cleanReq.IsJson())
	assert.Equal(t, "example.com:8080", cleanReq.Host())
	assert.Equal(t, "https", cleanReq.Scheme())
	assert.True(t, cleanReq.Secure())
	assert.NotEmpty(t, cleanReq.IP())
	assert.Equal(t, cleanReq.IP(), cleanReq.Ip())

	// 7. RouteParams snapshot
	cleanReq.SetRouteParam("id", "123")
	cleanReq.SetRouteParam("slug", "hello-world")
	params := cleanReq.RouteParams()
	assert.Equal(t, "123", params["id"])
	assert.Equal(t, "hello-world", params["slug"])

	// 8. Content negotiation (Accepts & Prefers)
	assert.True(t, cleanReq.Accepts("text/html"))
	assert.True(t, cleanReq.Accepts("application/json"))
	assert.False(t, cleanReq.Accepts("application/xml"))
	assert.Equal(t, "text/html", cleanReq.Prefers("text/html", "application/json"))

	// 9. JSON binding & dot-notation access
	jsonBody := `{"user": {"name": "Bob", "age": 30}, "created_at": "2026-09-30T10:00:00Z"}`
	jsonReq := NewRequest(httptest.NewRequest("POST", "/api/user", strings.NewReader(jsonBody)))
	jsonReq.Request.Header.Set("Content-Type", "application/json")

	type userDTO struct {
		User struct {
			Name string `json:"name"`
			Age  int    `json:"age"`
		} `json:"user"`
	}
	var dto userDTO
	err := jsonReq.BindJson(&dto)
	assert.NoError(t, err)
	assert.Equal(t, "Bob", dto.User.Name)
	assert.Equal(t, 30, dto.User.Age)
	assert.Equal(t, "Bob", jsonReq.Json("user.name"))
	assert.Equal(t, float64(30), jsonReq.Json("user.age"))
	assert.Nil(t, jsonReq.Json("user.non_existent"))

	// 10. Date parsing
	tVal, err := jsonReq.Date("created_at")
	assert.NoError(t, err)
	assert.Equal(t, 2026, tVal.Year())

	// 11. WhenFilled & WhenHas
	filledCalled := false
	jsonReq.WhenFilled("created_at", func(val string) {
		filledCalled = true
		assert.NotEmpty(t, val)
	})
	assert.True(t, filledCalled)

	hasCalled := false
	jsonReq.WhenHas("created_at", func(val string) {
		hasCalled = true
	})
	assert.True(t, hasCalled)

	// 12. Response WithHeaders, WithCookie, WithoutCookie
	res := NewResponse()
	res.WithHeaders(map[string]string{
		"X-Custom-1": "val1",
		"X-Custom-2": "val2",
	})
	assert.Equal(t, "val1", res.Headers().Get("X-Custom-1"))
	assert.Equal(t, "val2", res.Headers().Get("X-Custom-2"))

	res.WithCookie(&http.Cookie{Name: "session", Value: "abc"})
	assert.Equal(t, "abc", res.GetCookies()["session"].Value)
	res.WithoutCookie("session")
	assert.Equal(t, -1, res.GetCookies()["session"].MaxAge)
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

	// Has: true when the key exists (including empty and whitespace-only values).
	assert.True(t, r.Has("name"))
	assert.True(t, r.Has("empty"))
	assert.True(t, r.Has("spaces"))
	assert.True(t, r.Has("name", "role"))
	assert.False(t, r.Has("name", "non_exist"))
	assert.False(t, r.Has("non_exist"))
	assert.False(t, r.Has())

	// Exists behaves the same as Has.
	assert.True(t, r.Exists("name", "empty"))
	assert.False(t, r.Exists("non_exist"))

	// HasAny is true when any one of the keys exists.
	assert.True(t, r.HasAny("name", "non_exist"))
	assert.True(t, r.HasAny("empty", "another_missing"))
	assert.False(t, r.HasAny("foo", "bar"))
	assert.False(t, r.HasAny())

	// Filled: the key exists and is non-empty after trimming.
	assert.True(t, r.Filled("name"))
	assert.True(t, r.Filled("name", "role"))
	assert.False(t, r.Filled("empty"))
	assert.False(t, r.Filled("spaces"))
	assert.False(t, r.Filled("non_exist"))
	assert.False(t, r.Filled("name", "empty"))
	assert.False(t, r.Filled())

	// Missing: the key is entirely absent.
	assert.True(t, r.Missing("foo"))
	assert.True(t, r.Missing("foo", "bar"))
	assert.False(t, r.Missing("name"))
	assert.False(t, r.Missing("empty"))
	assert.False(t, r.Missing("name", "foo"))
	assert.True(t, r.Missing())
}

func TestRedirectResponse(t *testing.T) {
	// Defaults to a 302 redirect.
	resp1 := Redirect("/home")
	assert.Equal(t, http.StatusFound, resp1.GetCode())
	assert.Equal(t, "/home", resp1.Headers().Get("Location"))

	rec1 := httptest.NewRecorder()
	resp1.Send(rec1)
	assert.Equal(t, http.StatusFound, rec1.Code)
	assert.Equal(t, "/home", rec1.Header().Get("Location"))

	// A custom 301 permanent redirect.
	resp2 := Redirect("https://example.com/v2", http.StatusMovedPermanently)
	assert.Equal(t, http.StatusMovedPermanently, resp2.GetCode())
	assert.Equal(t, "https://example.com/v2", resp2.Headers().Get("Location"))

	rec2 := httptest.NewRecorder()
	resp2.Send(rec2)
	assert.Equal(t, http.StatusMovedPermanently, rec2.Code)
	assert.Equal(t, "https://example.com/v2", rec2.Header().Get("Location"))
}

// --- Begin ResponseFactory alignment tests ---

func TestJsonPanicsOnUnencodableValue(t *testing.T) {
	// Json panics on JSON encoding failures instead of sending an empty body.
	assert.PanicsWithError(t, "flow: invalid JSON response: json: unsupported type: func()", func() {
		Json(map[string]any{"fn": func() {}})
	})
}

func TestJsonpUsesTextJavascriptContentType(t *testing.T) {
	// Jsonp sets Content-Type text/javascript and wraps the body in the callback.
	res := Jsonp("cb", map[string]string{"a": "b"})
	assert.Equal(t, "text/javascript", res.GetContentType())
	assert.Equal(t, `cb({"a":"b"});`, res.GetContent())
}

func TestNoContentWithFluentHeaders(t *testing.T) {
	// The minimal-invasive headers capability: Response.Header chains.
	res := NoContent().Header("X-Custom", "v")
	assert.Equal(t, http.StatusNoContent, res.GetCode())
	assert.Equal(t, "v", res.Headers().Get("X-Custom"))
}

func TestStreamDownloadHeadersAndDisposition(t *testing.T) {
	calls := 0
	res := StreamDownload(func(w io.Writer) bool {
		calls++
		fmt.Fprint(w, "chunk")
		return false
	}, "report.txt", map[string]string{"Content-Type": "text/csv", "X-Custom": "v"}, "inline")

	assert.Equal(t, "text/csv", res.Headers().Get("Content-Type"), "explicit headers win over the default")
	assert.Equal(t, "v", res.Headers().Get("X-Custom"))
	assert.Equal(t, `inline; filename="report.txt"`, res.Headers().Get("Content-Disposition"))

	// The stream callback runs when the response streams.
	var buf bytes.Buffer
	res.streamFunc(&buf)
	assert.Equal(t, 1, calls)
	assert.Equal(t, "chunk", buf.String())

	// Default disposition is attachment; the two-argument form keeps the old behavior.
	res2 := StreamDownload(func(w io.Writer) bool { return false }, "data.bin", nil)
	assert.Equal(t, `attachment; filename="data.bin"`, res2.Headers().Get("Content-Disposition"))
	// streamDownload does NOT force a Content-Type; only caller-supplied
	// headers are set.
	assert.Empty(t, res2.Headers().Get("Content-Type"))
}

func TestJsonpPanicsOnUnencodableValue(t *testing.T) {
	// Like Json, Jsonp panics on JSON encoding failures instead of sending an
	// error page.
	assert.PanicsWithError(t, "flow: invalid JSON response: json: unsupported type: func()", func() {
		Jsonp("cb", map[string]any{"fn": func() {}})
	})
}

func TestStreamResponsesDisableAccelBuffering(t *testing.T) {
	// EventStream sends Cache-Control: no-cache plus X-Accel-Buffering: no;
	// StreamResponse sends X-Accel-Buffering: no.
	es := EventStream(func(w io.Writer) bool { return false })
	assert.Equal(t, "no", es.Headers().Get("X-Accel-Buffering"))
	assert.Equal(t, "no-cache", es.Headers().Get("Cache-Control"))

	sr := StreamResponse(func(w io.Writer) bool { return false })
	assert.Equal(t, "no", sr.Headers().Get("X-Accel-Buffering"))
}

func TestStreamDownloadWrapsStreamPanics(t *testing.T) {
	// StreamDownload wraps a panic from the callback in StreamedResponseError.
	res := StreamDownload(func(w io.Writer) bool { panic(errors.New("boom")) }, "f.txt", nil)

	var wrapped *StreamedResponseError
	func() {
		defer func() {
			wrapped, _ = recover().(*StreamedResponseError)
		}()
		res.streamFunc(io.Discard)
	}()
	require.NotNil(t, wrapped)
	assert.EqualError(t, wrapped.Inner, "boom")
}

func TestDownloadWithDisposition(t *testing.T) {
	res := DownloadWithDisposition("/tmp/report.pdf", "doc.pdf", "inline")
	assert.Equal(t, `inline; filename="doc.pdf"`, res.Headers().Get("Content-Disposition"))

	// Percent signs are stripped from the fallback name used for filenames that
	// are not printable ASCII.
	res2 := DownloadWithDisposition("/tmp/report.pdf", "résumé%.pdf", "attachment")
	assert.Equal(t, `attachment; filename="résumé.pdf"`, res2.Headers().Get("Content-Disposition"))
}
