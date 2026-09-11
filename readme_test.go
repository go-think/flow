package flow_test

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-think/flow"
	"github.com/stretchr/testify/assert"
)

// Validate QuickStart in README.md compiles and runs without error
func TestReadme_QuickStart(t *testing.T) {
	r := flow.New()

	r.Get("/", func() *flow.Response {
		return flow.Text("Hello Flow!")
	})

	r.Get("/ping", func() *flow.Response {
		return flow.Json(map[string]string{
			"message": "pong",
		})
	})

	r.Get("/user/{name}", func(req *flow.Request, name string) *flow.Response {
		return flow.Text(fmt.Sprintf("Hello, %s!", name))
	})

	r.Register()

	pipeline := flow.NewPipeline()
	pipeline.Pipe(flow.NewRecoverMiddleware(true))
	pipeline.Pipe(flow.NewCorsMiddleware())
	pipeline.Pipe(flow.NewRouteMiddleware(r))

	// Test GET /
	rec := httptest.NewRecorder()
	httpReq, _ := http.NewRequest("GET", "/", nil)
	pipeline.ServeHTTP(rec, httpReq)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "Hello Flow!", rec.Body.String())

	// Test GET /ping
	recPing := httptest.NewRecorder()
	httpReqPing, _ := http.NewRequest("GET", "/ping", nil)
	pipeline.ServeHTTP(recPing, httpReqPing)
	assert.Equal(t, http.StatusOK, recPing.Code)
	assert.Contains(t, recPing.Body.String(), `"message":"pong"`)

	// Test GET /user/think
	recUser := httptest.NewRecorder()
	httpReqUser, _ := http.NewRequest("GET", "/user/think", nil)
	pipeline.ServeHTTP(recUser, httpReqUser)
	assert.Equal(t, http.StatusOK, recUser.Code)
	assert.Equal(t, "Hello, think!", recUser.Body.String())
}

// Validate File Upload snippet in README.md
func TestReadme_FileUploadSnippet(t *testing.T) {
	uploadHandler := func(req *flow.Request) *flow.Response {
		file, err := req.File("avatar")
		if err != nil {
			return flow.NewResponse().SetCode(400).SetContent("No file uploaded")
		}

		tmpDir := t.TempDir()
		ok, err := file.Move(tmpDir, "avatar.png")
		if err != nil || !ok {
			return flow.NewResponse().SetCode(500).SetContent("Failed to save file")
		}

		return flow.Text("Uploaded avatar.png successfully")
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("avatar", "original.png")
	_, _ = part.Write([]byte("avatar content"))
	_ = writer.Close()

	httpReq, _ := http.NewRequest("POST", "/upload", body)
	httpReq.Header.Set("Content-Type", writer.FormDataContentType())
	req := flow.NewRequest(httpReq)

	res := uploadHandler(req)
	assert.Equal(t, 200, res.GetCode())
	assert.Equal(t, "Uploaded avatar.png successfully", res.GetContent())
}

// Validate Custom Middleware snippet in README.md
type TimingMiddleware struct{}

func (m *TimingMiddleware) Process(req *flow.Request, next flow.Closure) interface{} {
	start := time.Now()
	res := next(req)
	duration := time.Since(start)
	if response, ok := res.(*flow.Response); ok {
		response.Header("X-Response-Time", duration.String())
	}
	return res
}

func TestReadme_MiddlewareSnippet(t *testing.T) {
	tm := &TimingMiddleware{}
	req := flow.NewRequest(nil)
	res := tm.Process(req, func(r *flow.Request) interface{} {
		return flow.Text("ok")
	})
	resp, ok := res.(*flow.Response)
	assert.True(t, ok)
	assert.NotEmpty(t, resp.Headers().Get("X-Response-Time"))
}

// Validate Session snippet in README.md
func TestReadme_SessionSnippet(t *testing.T) {
	sessionDemoHandler := func(req *flow.Request) *flow.Response {
		session := req.Session()

		session.Set("user_id", 1001)
		userID := session.Get("user_id")
		hasUser := session.Has("user_id")

		session.Flash("alert", "Profile updated successfully")
		session.Reflash()
		session.Regenerate()
		session.Invalidate()

		return flow.Json(map[string]interface{}{
			"user_id":  userID,
			"has_user": hasUser,
		})
	}

	mw := flow.NewSessionMiddleware(flow.DefaultSessionConfig())
	httpReq, _ := http.NewRequest("GET", "/demo", nil)
	req := flow.NewRequest(httpReq)

	res := mw.Process(req, func(r *flow.Request) interface{} {
		return sessionDemoHandler(r)
	})
	resp, ok := res.(*flow.Response)
	assert.True(t, ok)
	assert.Contains(t, resp.GetContent(), `"user_id":1001`)
	assert.Contains(t, resp.GetContent(), `"has_user":true`)
}

// Validate Streaming & Download snippets in README.md
func TestReadme_StreamingAndResponse(t *testing.T) {
	streamResp := flow.StreamResponse(func(w io.Writer) bool {
		fmt.Fprintf(w, "data: %s\n\n", "test")
		return false
	})
	assert.Equal(t, "text/event-stream", streamResp.GetContentType())

	res := flow.NewResponse().
		SetCode(http.StatusCreated).
		SetContentType("application/json").
		SetContent(`{"created": true}`)
	res.Header("X-Custom-Header", "Value")
	_ = res.Cookie("session_id", "session-token-value")
	assert.Equal(t, http.StatusCreated, res.GetCode())
}

// Validate Optional Route snippet in README.md
func TestReadme_OptionalRouteSnippet(t *testing.T) {
	r := flow.New()
	r.Get("/profile/{tab?}", func(tab string) *flow.Response {
		if tab == "" {
			tab = "overview"
		}
		return flow.Text("Tab: " + tab)
	})
	r.Register()

	httpReq1, _ := http.NewRequest("GET", "/profile", nil)
	res1 := r.Dispatch(flow.NewRequest(httpReq1))
	assert.Equal(t, "Tab: overview", res1.GetContent())

	httpReq2, _ := http.NewRequest("GET", "/profile/security", nil)
	res2 := r.Dispatch(flow.NewRequest(httpReq2))
	assert.Equal(t, "Tab: security", res2.GetContent())
}

// Validate Request helpers snippet in README.md
func TestReadme_RequestHelpersSnippet(t *testing.T) {
	handler := func(req *flow.Request) *flow.Response {
		name, _ := req.Input("name")
		pageStr, _ := req.Query("page")
		email, _ := req.Post("email")

		page := req.Integer("page", 1)
		isAdmin := req.Boolean("is_admin", false)
		price := req.Float("price", 0.0)

		hasName := req.Has("name")
		hasAny := req.HasAny("phone", "email")
		isFilled := req.Filled("name")
		isMissing := req.Missing("avatar")

		credentials := req.Only("username", "password")
		safeInputs := req.Except("password", "token")
		all := req.All()

		_ = name
		_ = pageStr
		_ = email
		_ = page
		_ = isAdmin
		_ = price
		_ = hasName
		_ = hasAny
		_ = isFilled
		_ = isMissing
		_ = credentials
		_ = safeInputs

		return flow.Json(all)
	}

	httpReq, _ := http.NewRequest("GET", "/test?name=john&page=2", nil)
	req := flow.NewRequest(httpReq)
	res := handler(req)
	assert.Equal(t, 200, res.GetCode())
}

// Validate Redirect snippet in README.md
func TestReadme_RedirectSnippet(t *testing.T) {
	r1 := flow.Redirect("/dashboard")
	assert.Equal(t, http.StatusFound, r1.GetCode())
	assert.Equal(t, "/dashboard", r1.Headers().Get("Location"))

	r2 := flow.Redirect("/legacy-path", http.StatusMovedPermanently)
	assert.Equal(t, http.StatusMovedPermanently, r2.GetCode())
	assert.Equal(t, "/legacy-path", r2.Headers().Get("Location"))
}
