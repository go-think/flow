package flow

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUrlGeneratorRequestHelpers(t *testing.T) {
	current := "/current/path"
	ug := NewUrlGenerator(fakeRouteSource{}).SetRequestProvider(func() *Request {
		httpReq, _ := http.NewRequest("GET", current, nil)
		return NewRequest(httpReq)
	})

	assert.Equal(t, "/current/path", ug.Current())
	assert.Equal(t, "/normalized", ug.To("normalized"))
	assert.Equal(t, "/already", ug.To("/already"))
	// No session: Previous falls back to the given value (or "/").
	assert.Equal(t, "/", ug.Previous(""))
	assert.Equal(t, "/fallback", ug.Previous("/fallback"))
}

func TestRouteGenerationErrorOnMissingParams(t *testing.T) {
	r := New()
	r.Get("/users/{id}/posts/{post}", func() string { return "x" }).Name("user.post")
	r.Register()
	ug := NewUrlGenerator(r)

	_, err := ug.Route("user.post", map[string]string{"id": "1"})
	genErr, ok := err.(*UrlGenerationError)
	assert.True(t, ok)
	assert.Equal(t, "user.post", genErr.RouteName)
	assert.Contains(t, genErr.Missing, "{post}")

	url, err := ug.Route("user.post", map[string]string{"id": "1", "post": "9"})
	assert.NoError(t, err)
	assert.Equal(t, "/users/1/posts/9", url)

	// Signed generation fails closed on generation errors.
	assert.Empty(t, ug.SignedRoute("user.post", map[string]string{"id": "1"}, 0))
}

type cacheableController struct{}

func (c *cacheableController) Show(req *Request, id string) *Response {
	return NewResponse().SetContent("cached:" + id)
}

func TestRouteCacheRoundTrip(t *testing.T) {
	r := New()
	r.RegisterController("Cacheable", &cacheableController{})
	r.Get("/cached/{id}", "Cacheable@Show").Name("cached.show")
	r.Get("/closure", func() string { return "nope" })
	r.Register()

	_, err := r.Compile()
	assert.Error(t, err, "closures must make Compile fail")

	// A router containing a closure route cannot be cached.
	r2 := New()
	r2.RegisterController("Cacheable", &cacheableController{})
	r2.Get("/closure", func() string { return "nope" })
	r2.Register()
	_, err = r2.Compile()
	assert.Error(t, err)

	// Only serializable (controller-action) routes cache cleanly, and the
	// restored router dispatches them.
	r3 := New()
	r3.RegisterController("Cacheable", &cacheableController{})
	r3.Get("/cached/{id}", "Cacheable@Show").Name("cached.show")
	r3.Register()
	data, err := r3.Compile()
	assert.NoError(t, err)

	assert.NoError(t, r2.RestoreCompiled(data))
	assert.Len(t, r2.GetRoutes(), 1)

	httpReq, _ := http.NewRequest("GET", "/cached/9", nil)
	req := NewRequest(httpReq)
	req.SetResponseWriter(httptest.NewRecorder())
	res := r2.Dispatch(req).(*Response)
	assert.Equal(t, "cached:9", res.GetContent())
}

func TestRedirector(t *testing.T) {
	r := New()
	r.Get("/target", func() string { return "t" }).Name("target.route")
	r.Register()

	ug := NewUrlGenerator(r)
	current := "/here"
	rd := NewRedirector(ug).SetRequestProvider(func() *Request {
		httpReq, _ := http.NewRequest("GET", current, nil)
		return NewRequest(httpReq)
	})

	// Route redirect resolves through the generator.
	res := rd.Route("target.route", nil)
	assert.Equal(t, 302, res.GetCode())
	assert.Equal(t, "/target", res.Header.Get("Location"))

	// Custom status.
	res = rd.Route("target.route", nil, 301)
	assert.Equal(t, 301, res.GetCode())

	// Refresh redirects to the current path.
	res = rd.Refresh()
	assert.Equal(t, "/here", res.Header.Get("Location"))

	// To with custom status.
	res = rd.To("/somewhere", 303)
	assert.Equal(t, 303, res.GetCode())

	// Signed route redirect.
	ug.SetKeyResolver(func() []string { return []string{"k"} })
	res = rd.SignedRoute("target.route", nil)
	assert.Contains(t, res.Header.Get("Location"), "signature=")
}

func TestRedirectRoutes(t *testing.T) {
	r := New()
	r.Redirect("/old", "/new", 302)
	r.PermanentRedirect("/legacy", "/new")
	r.Register()

	rec := httptest.NewRecorder()
	httpReq, _ := http.NewRequest("GET", "/old", nil)
	req := NewRequest(httpReq)
	req.SetResponseWriter(rec)
	res := r.Dispatch(req).(*Response)
	assert.Equal(t, 302, res.GetCode())
	assert.Equal(t, "/new", res.Header.Get("Location"))

	rec2 := httptest.NewRecorder()
	httpReq2, _ := http.NewRequest("GET", "/legacy", nil)
	req2 := NewRequest(httpReq2)
	req2.SetResponseWriter(rec2)
	res2 := r.Dispatch(req2).(*Response)
	assert.Equal(t, 301, res2.GetCode())
}

func TestSignedRouteAbsolute(t *testing.T) {
	r := New()
	r.Get("/download/{file}", func(file string) string { return "x" }).Name("file.download")
	r.Register()

	httpReq, _ := http.NewRequest("GET", "https://example.com/start", nil)
	ug := NewUrlGenerator(r).SetKeyResolver(func() []string { return []string{"key-a"} }).SetRequestProvider(func() *Request {
		return NewRequest(httpReq)
	})

	signed := ug.SignedRouteAbsolute("file.download", map[string]string{"file": "a.pdf"}, time.Hour)
	assert.Contains(t, signed, "https://example.com/download/a.pdf?")
	assert.Contains(t, signed, "expires=")

	verifyReq, _ := http.NewRequest("GET", signed, nil)
	assert.True(t, ug.HasValidSignatureAbsolute(NewRequest(verifyReq)))

	// Tampered signature rejected.
	bad, _ := http.NewRequest("GET", signed+"x", nil)
	assert.False(t, ug.HasValidSignatureAbsolute(NewRequest(bad)))
}
