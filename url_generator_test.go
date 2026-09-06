package flow

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUrlGeneratorSigningAndRotation(t *testing.T) {
	r := New()
	keys := []string{"key-a"}
	ug := NewUrlGenerator(r) // created before any route exists
	ug.SetKeyResolver(func() []string { return keys })

	r.Get("/download/{file}", func(file string) string {
		return "download:" + file
	}).Name("file.download")
	r.Register()

	// Routes registered after generator creation are visible.
	routeUrl, err := ug.Route("file.download", map[string]string{"file": "report.pdf"})
	assert.NoError(t, err)
	assert.Equal(t, "/download/report.pdf", routeUrl)

	oldSigned := ug.SignedRoute("file.download", map[string]string{"file": "report.pdf"}, 1*time.Hour)
	assert.Contains(t, oldSigned, "signature=")

	req := func(rawURL string) *Request {
		httpReq, err := http.NewRequest("GET", rawURL, nil)
		assert.NoError(t, err)
		return NewRequest(httpReq)
	}

	// Rotate: key-b becomes current, key-a stays as a previous key.
	keys = []string{"key-b", "key-a"}

	// Old URL still validates via the previous key.
	assert.True(t, ug.HasValidSignature(req(oldSigned)))

	// New URLs are signed with the current key and validate.
	freshSigned := ug.SignedRoute("file.download", map[string]string{"file": "report.pdf"}, 1*time.Hour)
	assert.True(t, ug.HasValidSignature(req(freshSigned)))
	assert.NotEqual(t,
		oldSigned[strings.LastIndex(oldSigned, "=")+1:],
		freshSigned[strings.LastIndex(freshSigned, "=")+1:],
		"signatures must differ after rotation to a new current key",
	)

	// Retiring the previous key invalidates links signed with it.
	keys = []string{"key-b"}
	assert.True(t, ug.HasValidSignature(req(freshSigned)))
	assert.False(t, ug.HasValidSignature(req(oldSigned)))

	// Tampered signature rejected.
	assert.False(t, ug.HasValidSignature(req(freshSigned+"x")))
}

func TestUrlGeneratorFailsClosedWithoutKeys(t *testing.T) {
	r := New()
	r.Get("/download/{file}", func(file string) string { return "x" }).Name("file.download")
	r.Register()

	// No resolver at all.
	ug := NewUrlGenerator(r)
	assert.Empty(t, ug.SignedRoute("file.download", nil, time.Hour))

	// Resolver returning empty/blank strings.
	ug.SetKeyResolver(func() []string { return []string{"", ""} })
	assert.Empty(t, ug.SignedRoute("file.download", nil, time.Hour))

	httpReq, _ := http.NewRequest("GET", "/download/a.pdf?expires=9999999999&signature=deadbeef", nil)
	assert.False(t, ug.HasValidSignature(NewRequest(httpReq)))
}

func TestUrlGeneratorResolvesGroupRouterToRoot(t *testing.T) {
	r := New()
	var admin Router
	r.Group(GroupAttributes{Prefix: "/admin"}, func(group Router) {
		admin = group
		group.Get("/report/{id}", func(id string) string { return id }).Name("admin.report")
	})
	r.Register()

	// Generator built from the group router still sees root's named routes.
	ug := NewUrlGenerator(admin).SetKeyResolver(func() []string { return []string{"k"} })
	signed := ug.SignedRoute("admin.report", map[string]string{"id": "7"}, time.Hour)
	assert.Contains(t, signed, "/admin/report/7?")

	httpReq, _ := http.NewRequest("GET", signed, nil)
	assert.True(t, ug.HasValidSignature(NewRequest(httpReq)))
}

func TestUrlGeneratorMissingRoute(t *testing.T) {
	r := New()
	r.Register()
	ug := NewUrlGenerator(r).SetKeyResolver(func() []string { return []string{"k"} })

	// Missing route -> RouteNotFoundError, and signed variants fail closed.
	url, err := ug.Route("missing.route", nil)
	assert.Empty(t, url)
	var notFound *RouteNotFoundError
	assert.ErrorAs(t, err, &notFound)
	assert.Equal(t, "missing.route", notFound.RouteName)
	assert.Empty(t, ug.SignedRoute("missing.route", nil, time.Hour))
	assert.Empty(t, ug.SignedRoute("missing.route", nil))

	// The missing-route resolver gets the last word; returning a URL wins.
	ug.SetMissingNamedRouteResolver(func(name string, params map[string]string) string {
		return "/fallback/" + name
	})
	url, err = ug.Route("missing.route", nil)
	assert.NoError(t, err)
	assert.Equal(t, "/fallback/missing.route", url)

	// A resolver returning "" falls through to the error.
	ug.SetMissingNamedRouteResolver(func(name string, params map[string]string) string {
		return ""
	})
	_, err = ug.Route("missing.route", nil)
	assert.ErrorAs(t, err, &notFound)
}

func TestSignedRouteWithoutExpiry(t *testing.T) {
	r := New()
	keys := []string{"key-a"}
	ug := NewUrlGenerator(r).SetKeyResolver(func() []string { return keys })
	r.Get("/download/{file}", func(file string) string { return "x" }).Name("file.download")
	r.Register()

	signed := ug.SignedRoute("file.download", map[string]string{"file": "report.pdf"})
	assert.Contains(t, signed, "/download/report.pdf?signature=")
	assert.NotContains(t, signed, "expires=", "permanent signatures must not carry an expiry")

	req := func(rawURL string) *Request {
		httpReq, err := http.NewRequest("GET", rawURL, nil)
		assert.NoError(t, err)
		return NewRequest(httpReq)
	}

	// No expires parameter -> never expires, validates as-is.
	assert.True(t, ug.HasValidSignature(req(signed)))
	assert.False(t, ug.HasValidSignature(req(signed+"x")))

	// Retiring the key fails closed even for permanent signatures.
	keys = []string{}
	assert.False(t, ug.HasValidSignature(req(signed)))
}

func TestNewUrlGeneratorRejectsNilSource(t *testing.T) {
	assert.Panics(t, func() { NewUrlGenerator(nil) })
}

// fakeRouteSource is a minimal NamedRouteSource independent of the built-in
// router: the generator must work with any implementation.
type fakeRouteSource struct {
	patterns map[string]string
}

func (f fakeRouteSource) NamedRoutePattern(name string) (string, bool) {
	p, ok := f.patterns[name]
	return p, ok
}

func TestUrlGeneratorWorksWithAnyNamedRouteSource(t *testing.T) {
	ug := NewUrlGenerator(fakeRouteSource{
		patterns: map[string]string{"file.download": "/download/{file}"},
	}).SetKeyResolver(func() []string { return []string{"key-a"} })

	signed := ug.SignedRoute("file.download", map[string]string{"file": "report.pdf"}, time.Hour)
	assert.Contains(t, signed, "/download/report.pdf?expires=")

	httpReq, _ := http.NewRequest("GET", signed, nil)
	assert.True(t, ug.HasValidSignature(NewRequest(httpReq)))
}

func TestRouteParameterExpansion(t *testing.T) {
	r := New()
	ug := NewUrlGenerator(r).SetKeyResolver(func() []string { return []string{"k"} })
	r.Get("/download/{file}", func(file string) string { return "x" }).Name("file.download")
	r.Get("/profile/{tab?}", func(tab string) string { return tab }).Name("profile.tab")
	r.Register()

	req := func(rawURL string) *Request {
		httpReq, err := http.NewRequest("GET", rawURL, nil)
		assert.NoError(t, err)
		return NewRequest(httpReq)
	}

	// Extra parameters that match no placeholder become the query string.
	// The signed payload covers the canonicalized (sorted) query.
	signed := ug.SignedRoute("file.download", map[string]string{
		"file": "report.pdf",
		"utm":  "email",
	}, time.Hour)
	assert.Contains(t, signed, "/download/report.pdf?expires=")
	assert.Contains(t, signed, "&utm=email")

	// The signed payload covers the query, so the plain check passes...
	assert.True(t, ug.HasValidSignature(req(signed)))
	// ...and a mutated extra parameter breaks it.
	assert.False(t, ug.HasValidSignature(req(strings.Replace(signed, "utm=email", "utm=web", 1))))

	// Parameter values are rawurlencoded per path segment; '/' is preserved.
	routeUrl, routeErr := ug.Route("file.download", map[string]string{"file": "a/b"})
	assert.NoError(t, routeErr)
	assert.Equal(t, "/download/a/b", routeUrl)
	routeUrl, _ = ug.Route("file.download", map[string]string{"file": "?q=&"})
	assert.Equal(t, "/download/%3Fq%3D%26", routeUrl)
	// Escaping prevents values from injecting placeholders into the pattern.
	routeUrl, _ = ug.Route("file.download", map[string]string{"file": "{id}"})
	assert.Equal(t, "/download/%7Bid%7D", routeUrl)

	// Provided optional parameters fill in; missing ones are stripped.
	routeUrl, _ = ug.Route("profile.tab", map[string]string{"tab": "security"})
	assert.Equal(t, "/profile/security", routeUrl)
	routeUrl, _ = ug.Route("profile.tab", nil)
	assert.Equal(t, "/profile", routeUrl)
}

func TestHasValidSignatureWhileIgnoring(t *testing.T) {
	r := New()
	ug := NewUrlGenerator(r).SetKeyResolver(func() []string { return []string{"key-a"} })
	r.Get("/download", func() string { return "x" }).Name("file.download")
	r.Register()

	signed := ug.TemporarySignedRoute("file.download", 1*time.Hour, nil)
	withTracking := signed + "&utm_source=email&fbclid=abc"

	req := func(rawURL string) *Request {
		httpReq, err := http.NewRequest("GET", rawURL, nil)
		assert.NoError(t, err)
		return NewRequest(httpReq)
	}

	// Extra query parameters appended after signing break the plain check...
	assert.False(t, ug.HasValidSignature(req(withTracking)))
	// ...but are tolerated when ignored.
	assert.True(t, ug.HasValidSignatureWhileIgnoring(req(withTracking), "utm_source", "fbclid"))
	// Ignoring parameters that are not present is harmless.
	assert.True(t, ug.HasValidSignatureWhileIgnoring(req(signed), "utm_source"))
	// Ignoring a parameter that IS part of the signed payload must fail.
	assert.False(t, ug.HasValidSignatureWhileIgnoring(req(signed), "expires"))
	// Ignoring does not relax the expiry check.
	expired := ug.TemporarySignedRoute("file.download", -1*time.Minute, nil)
	assert.False(t, ug.HasValidSignatureWhileIgnoring(req(expired), "utm_source"))
}
