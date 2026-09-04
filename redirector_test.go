package flow

import (
	"net/http"
	"testing"
	"time"

	"github.com/go-think/flow/session"
	"github.com/stretchr/testify/assert"
)

func TestRedirectorToAbsolutizesPath(t *testing.T) {
	r := New(nil, nil)
	r.Get("/target", func() string { return "t" }).Name("target.route")
	r.Register()

	ug := NewUrlGenerator(r, "https://example.test")
	rd := NewRedirector(ug).SetRequestProvider(func() *Request {
		httpReq, _ := http.NewRequest("GET", "https://example.test/here", nil)
		return NewRequest(httpReq)
	})

	res := rd.To("/somewhere")
	assert.Equal(t, 302, res.GetCode())
	assert.Equal(t, "https://example.test/somewhere", res.Headers().Get("Location"))

	// Refresh resolves through the generator as well.
	res = rd.Refresh()
	assert.Equal(t, "https://example.test/here", res.Headers().Get("Location"))

	// Away skips normalization entirely.
	res = rd.Away("http://external.test/x")
	assert.Equal(t, "http://external.test/x", res.Headers().Get("Location"))
}

func TestRedirectorBack(t *testing.T) {
	r := New(nil, nil)
	r.Register()

	ug := NewUrlGenerator(r, "https://example.test").SetRequestProvider(func() *Request {
		httpReq, _ := http.NewRequest("GET", "https://example.test/here", nil)
		return NewRequest(httpReq)
	})
	store := session.NewStore("t", &session.CookieHandler{})
	rd := NewRedirector(ug)

	// No previous URL: the "/" fallback applies (trailing slash trimmed like
	// the reference format).
	assert.Equal(t, "https://example.test", rd.Back("").Headers().Get("Location"))

	// A recorded previous URL wins and passes through untouched.
	store.SetPreviousUrl("http://old.test/page")
	ug.SetRequestProvider(func() *Request {
		httpReq, _ := http.NewRequest("GET", "https://example.test/here", nil)
		req := NewRequest(httpReq)
		req.SetSession(store)
		return req
	})
	assert.Equal(t, "http://old.test/page", rd.Back("/fallback").Headers().Get("Location"))
}

func TestRedirectorGuestAndIntendedUseDedicatedKey(t *testing.T) {
	r := New(nil, nil)
	r.Get("/current", func() string { return "c" }).Name("current.route")
	r.Get("/login", func() string { return "l" }).Name("login.route")
	r.Register()

	ug := NewUrlGenerator(r, "https://example.test")
	store := session.NewStore("t", &session.CookieHandler{})
	currentRequest := func() *Request {
		httpReq, _ := http.NewRequest("GET", "http://example.test/current?a=1", nil)
		req := NewRequest(httpReq)
		req.SetSession(store)
		req.SetRoute(r.Routes().GetByName("current.route"))
		return req
	}
	ug.SetRequestProvider(currentRequest)
	rd := NewRedirector(ug).SetRequestProvider(currentRequest)

	// Guest on a routable GET stores the FULL current URL under url.intended.
	res := rd.Guest("/login")
	assert.Equal(t, 302, res.GetCode())
	assert.Equal(t, "https://example.test/login", res.Headers().Get("Location"))
	assert.Equal(t, "http://example.test/current?a=1", store.IntendedUrl())
	assert.Equal(t, "http://example.test/current?a=1", rd.GetIntendedUrl())
	// The _previous_url attribute stays untouched.
	assert.Empty(t, store.PreviousUrl())

	// Intended consumes the stored URL once...
	res = rd.Intended("/")
	assert.Equal(t, "http://example.test/current?a=1", res.Headers().Get("Location"))
	assert.Empty(t, store.IntendedUrl())
	//...and falls back to "/" afterwards.
	assert.Equal(t, "https://example.test", rd.Intended("").Headers().Get("Location"))
}

func TestRedirectorGuestStoresPreviousForNonRoutableRequest(t *testing.T) {
	r := New(nil, nil)
	r.Register()

	ug := NewUrlGenerator(r, "https://example.test")
	store := session.NewStore("t", &session.CookieHandler{})
	rd := NewRedirector(ug).SetRequestProvider(func() *Request {
		httpReq, _ := http.NewRequest("POST", "https://example.test/submit", nil)
		req := NewRequest(httpReq)
		req.SetSession(store)
		return req
	})

	// Without a matched route the intended URL is the previous URL, which
	// here collapses to the generated "/" URL.
	rd.Guest("/login")
	assert.Equal(t, "https://example.test", store.IntendedUrl())
}

func TestRedirectorSetIntendedUrlRoundTrip(t *testing.T) {
	r := New(nil, nil)
	r.Register()

	ug := NewUrlGenerator(r, "https://example.test")
	store := session.NewStore("t", &session.CookieHandler{})
	rd := NewRedirector(ug).SetRequestProvider(func() *Request {
		httpReq, _ := http.NewRequest("GET", "https://example.test/here", nil)
		req := NewRequest(httpReq)
		req.SetSession(store)
		return req
	})

	rd.SetIntendedUrl("/dashboard")
	assert.Equal(t, "/dashboard", rd.GetIntendedUrl())
	assert.Equal(t, "https://example.test/dashboard", rd.Intended("/").Headers().Get("Location"))
}

func TestSessionIntendedUrlIndependentOfPreviousUrl(t *testing.T) {
	store := session.NewStore("t", &session.CookieHandler{})
	assert.Empty(t, store.IntendedUrl())

	store.SetPreviousUrl("https://example.test/prev")
	store.SetIntendedUrl("https://example.test/intended")
	assert.Equal(t, "https://example.test/prev", store.PreviousUrl())
	assert.Equal(t, "https://example.test/intended", store.IntendedUrl())

	assert.Equal(t, "https://example.test/intended", store.PullIntendedUrl("/"))
	assert.Empty(t, store.IntendedUrl())
	assert.Equal(t, "/", store.PullIntendedUrl("/"))
}

func TestRedirectorSignedRouteExpiration(t *testing.T) {
	r := New(nil, nil)
	r.Get("/signed", func() string { return "s" }).Name("signed")
	r.Register()

	ug := NewUrlGenerator(r, "http://example.test").SetKeyResolver(func() []string { return []string{"k"} })
	rd := NewRedirector(ug)

	withDuration := rd.SignedRoute("signed", nil, time.Minute).Headers().Get("Location")
	assert.Contains(t, withDuration, "http://example.test/signed?")
	assert.Contains(t, withDuration, "expires=")
	assert.Contains(t, withDuration, "signature=")

	// Expiration in seconds is accepted too.
	withSeconds := rd.SignedRoute("signed", nil, 60).Headers().Get("Location")
	assert.Contains(t, withSeconds, "expires=")

	// A nil expiration produces a permanent signature.
	permanent := rd.SignedRoute("signed", nil, nil).Headers().Get("Location")
	assert.Contains(t, permanent, "signature=")
	assert.NotContains(t, permanent, "expires=")
}
