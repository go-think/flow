package flow

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-think/flow/session"
	"github.com/stretchr/testify/assert"
)

func TestUrlGeneratorSigningAndRotation(t *testing.T) {
	r := New(nil, nil)
	keys := []string{"key-a"}
	ug := NewUrlGenerator(r, "") // created before any route exists
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
	r := New(nil, nil)
	r.Get("/download/{file}", func(file string) string { return "x" }).Name("file.download")
	r.Register()

	// No resolver at all.
	ug := NewUrlGenerator(r, "")
	assert.Empty(t, ug.SignedRoute("file.download", nil, time.Hour))

	// Resolver returning empty/blank strings.
	ug.SetKeyResolver(func() []string { return []string{"", ""} })
	assert.Empty(t, ug.SignedRoute("file.download", nil, time.Hour))

	httpReq, _ := http.NewRequest("GET", "/download/a.pdf?expires=9999999999&signature=deadbeef", nil)
	assert.False(t, ug.HasValidSignature(NewRequest(httpReq)))
}

func TestUrlGeneratorResolvesGroupRouterToRoot(t *testing.T) {
	r := New(nil, nil)
	var admin Router
	r.Group(GroupAttributes{Prefix: "/admin"}, func(group Router) {
		admin = group
		group.Get("/report/{id}", func(id string) string { return id }).Name("admin.report")
	})
	r.Register()

	// Generator built from the group router still sees root's named routes.
	ug := NewUrlGenerator(admin, "").SetKeyResolver(func() []string { return []string{"k"} })
	signed := ug.SignedRoute("admin.report", map[string]string{"id": "7"}, time.Hour)
	assert.Contains(t, signed, "/admin/report/7?")

	httpReq, _ := http.NewRequest("GET", signed, nil)
	assert.True(t, ug.HasValidSignature(NewRequest(httpReq)))
}

func TestUrlGeneratorMissingRoute(t *testing.T) {
	r := New(nil, nil)
	r.Register()
	ug := NewUrlGenerator(r, "").SetKeyResolver(func() []string { return []string{"k"} })

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
	r := New(nil, nil)
	keys := []string{"key-a"}
	ug := NewUrlGenerator(r, "").SetKeyResolver(func() []string { return keys })
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
	assert.Panics(t, func() { NewUrlGenerator(nil, "") })
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
	}, "").SetKeyResolver(func() []string { return []string{"key-a"} })

	signed := ug.SignedRoute("file.download", map[string]string{"file": "report.pdf"}, time.Hour)
	assert.Contains(t, signed, "/download/report.pdf?expires=")

	httpReq, _ := http.NewRequest("GET", signed, nil)
	assert.True(t, ug.HasValidSignature(NewRequest(httpReq)))
}

func TestRouteParameterExpansion(t *testing.T) {
	r := New(nil, nil)
	ug := NewUrlGenerator(r, "").SetKeyResolver(func() []string { return []string{"k"} })
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
	//...and a mutated extra parameter breaks it.
	assert.False(t, ug.HasValidSignature(req(strings.Replace(signed, "utm=email", "utm=web", 1))))

	// Parameter values are rawurlencoded per path segment; '/' is preserved.
	routeUrl, routeErr := ug.Route("file.download", map[string]string{"file": "a/b"})
	assert.NoError(t, routeErr)
	assert.Equal(t, "/download/a/b", routeUrl)
	routeUrl, _ = ug.Route("file.download", map[string]string{"file": "?q=&"})
	// keeps ? = & characters raw in parameters.
	assert.Equal(t, "/download/?q=&", routeUrl)
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
	r := New(nil, nil)
	ug := NewUrlGenerator(r, "").SetKeyResolver(func() []string { return []string{"key-a"} })
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
	//...but are tolerated when ignored.
	assert.True(t, ug.HasValidSignatureWhileIgnoring(req(withTracking), "utm_source", "fbclid"))
	// Ignoring parameters that are not present is harmless.
	assert.True(t, ug.HasValidSignatureWhileIgnoring(req(signed), "utm_source"))
	// Ignoring a parameter that IS part of the signed payload must fail.
	assert.False(t, ug.HasValidSignatureWhileIgnoring(req(signed), "expires"))
	// Ignoring does not relax the expiry check.
	expired := ug.TemporarySignedRoute("file.download", -1*time.Minute, nil)
	assert.False(t, ug.HasValidSignatureWhileIgnoring(req(expired), "utm_source"))
}

func TestUrlGeneratorDefaultsAndQueryEncoding(t *testing.T) {
	r := New(nil, nil)
	r.Get("/users/{locale}/{id}", func() string { return "ok" }).Name("users.show")
	r.Register()

	ug := NewUrlGenerator(r, "").Defaults(map[string]string{"locale": "en"})
	urlPath, err := ug.Route("users.show", map[string]string{"id": "a b"}, false)
	assert.NoError(t, err)
	assert.Equal(t, "/users/en/a%20b", urlPath)

	assert.Equal(t, "/search?q=a+b&tag=x%26y", ug.Query("/search", map[string]string{
		"tag": "x&y",
		"q":   "a b",
	}))
	// Valid URLs pass through to() untouched.
	assert.Equal(t, "https://example.test/search?q=ok", ug.To("https://example.test/search?q=ok"))
}

func TestUrlGeneratorToAbsolutizesPath(t *testing.T) {
	ug := NewUrlGenerator(fakeRouteSource{}, "https://example.test")

	assert.Equal(t, "https://example.test/search", ug.To("search"))
	assert.Equal(t, "https://example.test/x/y", ug.To("/x/y"))
	// Extra segments are rawurlencoded and appended as the path tail.
	assert.Equal(t, "https://example.test/users/john%20doe/50%25", ug.To("users", "john doe", "50%"))
	// A query string embedded in the path is preserved verbatim, in order.
	assert.Equal(t, "https://example.test/search?b=2&a=1", ug.To("/search?b=2&a=1"))
	// Valid URLs pass through untouched.
	assert.Equal(t, "http://other.com/a", ug.To("http://other.com/a"))
	assert.Equal(t, "//cdn.example.com/lib.js", ug.To("//cdn.example.com/lib.js"))
	assert.Equal(t, "#anchor", ug.To("#anchor"))
	assert.Equal(t, "mailto:user@test.dev", ug.To("mailto:user@test.dev"))
	assert.Equal(t, "tel:+1234", ug.To("tel:+1234"))
	assert.Equal(t, "sms:+1234", ug.To("sms:+1234"))

	// Without a resolvable root the normalized relative path is returned.
	rootless := NewUrlGenerator(fakeRouteSource{}, "")
	assert.Equal(t, "/search", rootless.To("search"))
}

func TestUrlGeneratorSecureForcesHttps(t *testing.T) {
	ug := NewUrlGenerator(fakeRouteSource{}, "http://example.test")
	assert.Equal(t, "https://example.test/page", ug.Secure("page"))
	// Already-valid URLs are returned untouched (secure delegates to to()).
	assert.Equal(t, "http://other.com/", ug.Secure("http://other.com/"))
}

func TestUrlGeneratorQueryMergesPreservingOrder(t *testing.T) {
	ug := NewUrlGenerator(fakeRouteSource{}, "https://example.test")

	// Existing pair order is preserved; new keys are appended sorted.
	assert.Equal(t, "https://example.test/search?b=2&a=1&c=3",
		ug.Query("/search?b=2&a=1", map[string]string{"c": "3"}))
	// Values of existing keys are overridden in place.
	assert.Equal(t, "https://example.test/search?b=2&a=9",
		ug.Query("/search?b=2&a=1", map[string]string{"a": "9"}))
	// Merging nothing keeps the existing query.
	assert.Equal(t, "https://example.test/search?b=2&a=1", ug.Query("/search?b=2&a=1", nil))
}

func TestCurrentReturnsAbsoluteURL(t *testing.T) {
	ug := NewUrlGenerator(fakeRouteSource{}, "https://example.test").SetRequestProvider(func() *Request {
		httpReq, _ := http.NewRequest("GET", "/current/path", nil)
		return NewRequest(httpReq)
	})
	assert.Equal(t, "https://example.test/current/path", ug.Current())
}

func TestPreviousNormalizesReferer(t *testing.T) {
	ug := NewUrlGenerator(fakeRouteSource{}, "https://example.test").SetRequestProvider(func() *Request {
		httpReq, _ := http.NewRequest("GET", "https://example.test/page", nil)
		httpReq.Header.Set("Referer", "/relative/page")
		return NewRequest(httpReq)
	})
	// A relative referer is absolutized through to().
	assert.Equal(t, "https://example.test/relative/page", ug.Previous("/fb"))
}

func TestPreviousPathStripsBaseAndTrimsSlash(t *testing.T) {
	store := session.NewStore("t", &session.CookieHandler{})
	store.SetPreviousUrl("https://example.test/base/users/")
	ug := NewUrlGenerator(fakeRouteSource{}, "https://example.test/base").SetRequestProvider(func() *Request {
		httpReq, _ := http.NewRequest("GET", "https://example.test/base/now", nil)
		req := NewRequest(httpReq)
		req.SetSession(store)
		return req
	})
	assert.Equal(t, "/users", ug.PreviousPath("/"))
}

func TestFormatRootKeepsNonStandardPort(t *testing.T) {
	ug := NewUrlGenerator(fakeRouteSource{}, "").SetRequestProvider(func() *Request {
		httpReq, _ := http.NewRequest("GET", "http://example.test:8080/path", nil)
		return NewRequest(httpReq)
	})
	assert.Equal(t, "http://example.test:8080", ug.FormatRoot("http", ""))
	assert.Equal(t, "https://example.test:8080", ug.FormatRoot("https", ""))
	assert.Equal(t, "http://example.test:8080", ug.FormatRoot("", ""))
	// An explicit root replaces the scheme of that root.
	assert.Equal(t, "https://cdn.test:8080", ug.FormatRoot("https", "http://cdn.test:8080"))

	// The standard port for the scheme is stripped.
	standard := NewUrlGenerator(fakeRouteSource{}, "").SetRequestProvider(func() *Request {
		httpReq, _ := http.NewRequest("GET", "https://example.test/path", nil)
		return NewRequest(httpReq)
	})
	assert.Equal(t, "https://example.test", standard.FormatRoot("https", ""))
}

func TestSignedUrlsAreAbsoluteByDefault(t *testing.T) {
	r := New(nil, nil)
	r.Get("/download/{file}", func(file string) string { return "x" }).Name("file.download")
	r.Register()

	keys := []string{"key-a"}
	ug := NewUrlGenerator(r, "https://example.test").SetKeyResolver(func() []string { return keys })

	signed := ug.SignedRoute("file.download", map[string]string{"file": "a.pdf"}, time.Hour)
	assert.True(t, strings.HasPrefix(signed, "https://example.test/download/a.pdf?"))

	req := func(rawURL string) *Request {
		httpReq, err := http.NewRequest("GET", rawURL, nil)
		assert.NoError(t, err)
		return NewRequest(httpReq)
	}

	// An absolute signature verifies as absolute...
	assert.True(t, ug.HasValidSignature(req(signed)))
	assert.True(t, ug.HasCorrectSignature(req(signed)))
	//...but MUST fail when verified as relative.
	assert.False(t, ug.HasValidSignature(req(signed), false))
	assert.False(t, ug.HasValidRelativeSignature(req(signed)))
	assert.False(t, ug.HasCorrectSignature(req(signed), false))

	// And vice versa: a relative signature never verifies as absolute.
	relativeGenerator := NewUrlGenerator(r, "").SetKeyResolver(func() []string { return keys })
	relativeSigned := relativeGenerator.SignedRoute("file.download", map[string]string{"file": "a.pdf"}, time.Hour, false)
	assert.True(t, strings.HasPrefix(relativeSigned, "/download/a.pdf?"))

	hostedRequest := req("https://example.test" + relativeSigned)
	assert.False(t, ug.HasValidSignature(hostedRequest))
	assert.True(t, ug.HasValidSignature(hostedRequest, false))
	assert.True(t, ug.HasValidRelativeSignature(hostedRequest))
}

func TestUrlGenerationErrorMessageFormat(t *testing.T) {
	r := New(nil, nil)
	r.Get("/users/{id}/posts/{post}", func() string { return "x" }).Name("user.post")
	r.Get("/a/{x}/{y}", func() string { return "x" }).Name("pair.route")
	r.Register()

	ug := NewUrlGenerator(r, "")

	_, err := ug.Route("user.post", map[string]string{"id": "1"})
	genErr, ok := err.(*UrlGenerationError)
	assert.True(t, ok)
	assert.Equal(t,
		"Missing required parameter for [Route: user.post] [URI: /users/{id}/posts/{post}] [Missing parameter: post].",
		genErr.Error())

	// An empty parameter value counts as missing too.
	_, err = ug.Route("user.post", map[string]string{"id": "1", "post": ""})
	assert.EqualError(t, err,
		"Missing required parameter for [Route: user.post] [URI: /users/{id}/posts/{post}] [Missing parameter: post].")

	// Two missing parameters pluralize the label.
	_, err = ug.Route("pair.route", nil)
	assert.EqualError(t, err,
		"Missing required parameters for [Route: pair.route] [URI: /a/{x}/{y}] [Missing parameters: x, y].")
}

func TestRouteDontEncodeKeepsReservedCharacters(t *testing.T) {
	r := New(nil, nil)
	r.Get("/files/{name}", func() string { return "x" }).Name("files.show")
	r.Register()

	ug := NewUrlGenerator(r, "")

	url, err := ug.Route("files.show", map[string]string{"name": "a@b:c=d"})
	assert.NoError(t, err)
	assert.Equal(t, "/files/a@b:c=d", url)

	// Slashes stay separators and '%' is not double-encoded.
	url, _ = ug.Route("files.show", map[string]string{"name": "50%25/a b"})
	assert.Equal(t, "/files/50%25/a%20b", url)
}

func TestForceSchemeAndOrigin(t *testing.T) {
	r := New(nil, nil)
	ug := NewUrlGenerator(r, "http://origin.test")

	// Both bare and suffixed scheme forms are accepted.
	assert.Equal(t, "https://origin.test/x", ug.ForceScheme("https").To("x"))
	assert.Equal(t, "https://origin.test/x", ug.ForceScheme("https://").To("x"))
	// The forced scheme overrides the forced root's scheme too.
	assert.Equal(t, "https://other.test/x", ug.UseOrigin("http://other.test/").To("x"))
	// ForceHttps aliases ForceScheme("https"); false leaves it untouched.
	assert.Equal(t, "https://other.test/x", ug.ForceHttps().To("x"))
	assert.Equal(t, "https://other.test/x", ug.ForceHttps(false).To("x"))

	ug.SetRequestProvider(func() *Request {
		httpReq, _ := http.NewRequest("GET", "/now", nil)
		return NewRequest(httpReq)
	})
	assert.NotNil(t, ug.GetRequest())
}

func TestWithKeyResolverReturnsClone(t *testing.T) {
	r := New(nil, nil)
	original := NewUrlGenerator(r, "").SetKeyResolver(func() []string { return []string{"original-key"} })
	clone := original.WithKeyResolver(func() []string { return []string{"clone-key"} })

	assert.NotSame(t, original, clone)
	assert.Equal(t, []string{"original-key"}, original.keys())
	assert.Equal(t, []string{"clone-key"}, clone.keys())
}

func TestFormatAppliesFormatterCallbacks(t *testing.T) {
	ug := NewUrlGenerator(fakeRouteSource{}, "")
	// Without callbacks the path formatter falls back to the identity.
	assert.NotNil(t, ug.GetPathFormatter())

	ug.SetHostFormatter(func(host string) string {
		return strings.Replace(host, "http://", "https://", 1)
	}).SetPathFormatter(func(path string) string {
		return "/prefix" + path
	})

	assert.Equal(t, "https://example.test/prefix/page", ug.Format("http://example.test", "/page"))
}

func TestUrlGeneratorMissingRouteMessage(t *testing.T) {
	// Error message casing and punctuation: "Route [x] not defined."
	// and "Action [x] not defined.".
	r := New(nil, nil)
	r.Register()
	ug := NewUrlGenerator(r, "")

	_, err := ug.Route("missing.route", nil)
	assert.EqualError(t, err, "Route [missing.route] not defined.")

	_, err = ug.Action("MissingController@index", nil)
	assert.EqualError(t, err, "Action [MissingController@index] not defined.")
}

func TestSignatureHasNotExpiredSemantics(t *testing.T) {
	req := func(rawQuery string) *Request {
		httpReq, _ := http.NewRequest("GET", "/p?"+rawQuery, nil)
		return NewRequest(httpReq)
	}
	ug := NewUrlGenerator(fakeRouteSource{}, "")

	// Empty and "0" expiry values mean the URL never expires.
	assert.True(t, ug.SignatureHasNotExpired(req("")))
	assert.True(t, ug.SignatureHasNotExpired(req("expires=")))
	assert.True(t, ug.SignatureHasNotExpired(req("expires=0")))

	// "0.0" compares numerically as 0, so now > 0.0 holds and the URL counts
	// as expired.
	assert.False(t, ug.SignatureHasNotExpired(req("expires=0.0")))

	// A non-numeric value compares as 0: expired.
	assert.False(t, ug.SignatureHasNotExpired(req("expires=abc")))

	// Numeric comparisons for real timestamps.
	assert.True(t, ug.SignatureHasNotExpired(req("expires=9999999999")))
	assert.False(t, ug.SignatureHasNotExpired(req("expires=1")))
}

func TestJoinSignedPayloadRtrimSemantics(t *testing.T) {
	// Absolute form: the right trim cuts the path's
	// trailing slashes before the '?' join.
	assert.Equal(t, "https://h", joinSignedPayload("https://h", "/", ""))
	assert.Equal(t, "https://h/p?a=1", joinSignedPayload("https://h", "/p/", "a=1"))

	// the second right trim only cuts trailing '?'
	// characters from the concatenation.
	assert.Equal(t, "https://h/p?a=1", joinSignedPayload("https://h", "/p", "a=1?"))
	assert.Equal(t, "https://h/p", joinSignedPayload("https://h", "/p", ""))

	// Relative form: '/'+request path, which trims slashes.
	assert.Equal(t, "/foo", joinSignedPayload("", "/foo/", ""))
	// An empty path is treated as "/", so the relative form is '/'.'/' = '//'.
	assert.Equal(t, "//", joinSignedPayload("", "/", ""))
}

func TestHasValidSignatureTrailingSlashRequestPath(t *testing.T) {
	// The absolute URL is right-trimmed, so the same signed URL requested with
	// a trailing path slash still verifies.
	r := New(nil, nil)
	r.Get("/download/{file}", func(file string) string { return "x" }).Name("file.download")
	r.Register()
	ug := NewUrlGenerator(r, "").SetKeyResolver(func() []string { return []string{"k"} })

	signed := ug.SignedRoute("file.download", map[string]string{"file": "a.pdf"})
	httpReq, _ := http.NewRequest("GET", signed, nil)
	assert.True(t, ug.HasValidSignature(NewRequest(httpReq)))

	httpReq2, _ := http.NewRequest("GET", signed, nil)
	httpReq2.URL.Path += "/"
	assert.True(t, ug.HasValidSignature(NewRequest(httpReq2)))
	assert.True(t, ug.HasValidRelativeSignature(NewRequest(httpReq2)))
}

// domainRouteSource extends fakeRouteSource with a fixed route domain.
type domainRouteSource struct {
	fakeRouteSource
	domain string
}

func (f domainRouteSource) NamedRouteDomain(name string) (string, bool) {
	return f.domain, true
}

func TestAddRequestPortUsesRequestScheme(t *testing.T) {
	// addRequestPort decides the standard port against the REQUEST scheme,
	// not the route's scheme.

	// toRoute path: the route side speaks https (forced scheme) while the
	// request is plain http carrying the standard port 80 — the port is
	// standard for the REQUEST scheme and must be omitted (the old behavior
	// compared against the route/forced https scheme and appended ":80").
	src := domainRouteSource{
		fakeRouteSource: fakeRouteSource{
			patterns: map[string]string{"secure.thing": "/secure/thing"},
		},
		domain: "example.test",
	}
	ug := NewUrlGenerator(src, "").ForceScheme("https").SetRequestProvider(func() *Request {
		httpReq, _ := http.NewRequest("GET", "http://example.test:80/path", nil)
		return NewRequest(httpReq)
	})
	urlStr, err := ug.Route("secure.thing", nil)
	assert.NoError(t, err)
	assert.Equal(t, "https://example.test/secure/thing", urlStr)

	// Non-standard ports are kept.
	ug8080 := NewUrlGenerator(src, "").ForceScheme("https").SetRequestProvider(func() *Request {
		httpReq, _ := http.NewRequest("GET", "http://example.test:8080/path", nil)
		return NewRequest(httpReq)
	})
	urlStr, err = ug8080.Route("secure.thing", nil)
	assert.NoError(t, err)
	assert.Equal(t, "https://example.test:8080/secure/thing", urlStr)

	// FormatDomain path (url_generator_full.go): an https-only route's domain
	// with the same plain-http:80 request omits the port.
	real := New(nil, nil)
	real.Get("/secure/thing", func() string { return "x" }).Name("secure.thing").Domain("example.test")
	real.Register()
	real.Routes().GetByName("secure.thing").Secure()
	ugReal := NewUrlGenerator(real, "").SetRequestProvider(func() *Request {
		httpReq, _ := http.NewRequest("GET", "http://example.test:80/path", nil)
		return NewRequest(httpReq)
	})
	assert.Equal(t, "https://example.test", ugReal.GetRouteDomain(real.Routes().GetByName("secure.thing")))
}

func TestUrlGeneratorEmptyParamWithDefaultStaysInQuery(t *testing.T) {
	// The default branch does NOT consume the parameter, so an explicitly
	// supplied EMPTY parameter survives and lands in the query string as
	// "id=".
	r := New(nil, nil)
	r.Get("/users/{id?}", func() string { return "ok" }).Name("users.show")
	r.Register()

	ug := NewUrlGenerator(r, "").Defaults(map[string]string{"id": "1"})

	// Empty supplied value: the default fills the path, the empty parameter
	// resurfaces in the query string.
	urlPath, err := ug.Route("users.show", map[string]string{"id": ""}, false)
	assert.NoError(t, err)
	assert.Equal(t, "/users/1?id=", urlPath)

	// A non-empty supplied value replaces the default and is consumed.
	urlPath, err = ug.Route("users.show", map[string]string{"id": "5"}, false)
	assert.NoError(t, err)
	assert.Equal(t, "/users/5", urlPath)

	// A genuinely missing parameter: default fills, nothing in the query.
	urlPath, err = ug.Route("users.show", nil, false)
	assert.NoError(t, err)
	assert.Equal(t, "/users/1", urlPath)

	// Without a default the empty optional parameter is stripped and consumed.
	noDefault := NewUrlGenerator(r, "")
	urlPath, err = noDefault.Route("users.show", map[string]string{"id": ""}, false)
	assert.NoError(t, err)
	assert.Equal(t, "/users", urlPath)
}

func TestNamedRouteDomainViaRouter(t *testing.T) {
	r := NewRouter(nil, nil)
	_, ok := r.NamedRouteDomain("missing.route")
	assert.False(t, ok, "unknown route has no domain")

	r.Domain("{sub}.example.com").Get("/users/{user}", func(user string) string {
		return user
	}).Name("users.show")

	domain, ok := r.NamedRouteDomain("users.show")
	assert.True(t, ok)
	assert.Equal(t, "{sub}.example.com", domain)

	gen := NewUrlGenerator(r, "")
	url, err := gen.Route("users.show", map[string]string{"sub": "api", "user": "42"})
	assert.NoError(t, err)
	assert.Equal(t, "http://api.example.com/users/42", url)
}

func TestDomainRouteDispatchAndUrl(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Domain("admin.example.com").Get("/dashboard", func() string { return "dash" }).Name("dash")

	// URL generation first (no dispatch happened yet).
	gen := NewUrlGenerator(r, "")
	dashURL, err := gen.Route("dash", nil)
	assert.NoError(t, err)
	assert.Equal(t, "http://admin.example.com/dashboard", dashURL)

	// Dispatch still works against the host.
	httpReq := httptest.NewRequest("GET", "http://admin.example.com/dashboard", nil)
	res := r.Dispatch(NewRequest(httpReq))
	assert.Equal(t, 200, res.GetCode())
}

func TestRouteFragmentMovedAfterQuery(t *testing.T) {
	r := NewRouter(nil, nil)
	r.RegisterController("fragmentCtl", &domainTestController{})
	r.Get("/page/{id}#section", "fragmentCtl@Index").Name("page.section")

	gen := NewUrlGenerator(r, "")
	url, err := gen.Route("page.section", map[string]string{"id": "9"})
	assert.NoError(t, err)
	assert.Equal(t, "/page/9#section", url)
}
