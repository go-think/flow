package flow

import (
	"fmt"
	"strings"

	"github.com/go-think/flow/session"
)

// intendedURLKey is the session attribute holding the URL a user was heading
// to before being intercepted. It is
// independent of the "_previous_url" attribute.
const intendedURLKey = "url.intended"

// UrlGenerationError reports that a named route URL could not be generated
// because required parameters were missing.
type UrlGenerationError struct {
	RouteName string
	RouteURI  string
	Missing   []string
}

// ForMissingParameters creates a UrlGenerationError for a named route with
// missing parameters. The missing entries carry their "{placeholder}" braces;
// the rendered message strips them.
func ForMissingParameters(routeName, routeURI string, missing []string) *UrlGenerationError {
	return &UrlGenerationError{RouteName: routeName, RouteURI: routeURI, Missing: missing}
}

func (e *UrlGenerationError) Error() string {
	label := "parameter"
	if len(e.Missing) != 1 {
		label = "parameters"
	}
	message := fmt.Sprintf("Missing required %s for [Route: %s] [URI: %s]", label, e.RouteName, e.RouteURI)
	if len(e.Missing) > 0 {
		names := make([]string, 0, len(e.Missing))
		for _, m := range e.Missing {
			names = append(names, strings.Trim(m, "{}"))
		}
		message += fmt.Sprintf(" [Missing %s: %s]", label, strings.Join(names, ", "))
	}
	return message + "."
}

// Redirector builds redirect responses. It resolves named and signed routes
// through the URL generator and reads session state (previous URL, intended
// URL) through the request provider. Per-redirect headers are supplied through
// WithHeaders, which returns a clone.
type Redirector struct {
	generator       *UrlGenerator
	requestProvider func() *Request
	headers         map[string]string
}

// NewRedirector creates a Redirector bound to a URL generator.
func NewRedirector(generator *UrlGenerator) *Redirector {
	return &Redirector{generator: generator}
}

// SetRequestProvider registers the accessor for the request being handled.
func (r *Redirector) SetRequestProvider(fn func() *Request) *Redirector {
	r.requestProvider = fn
	return r
}

// gen returns the generator, panicking if nil (programming error).
func (r *Redirector) gen() *UrlGenerator {
	if r == nil || r.generator == nil {
		panic("flow: Redirector not initialized")
	}
	return r.generator
}

// currentRequest returns the request from the provider, if configured.
func (r *Redirector) currentRequest() *Request {
	if r.requestProvider == nil {
		return nil
	}
	return r.requestProvider()
}

// WithHeaders returns a clone of the redirector that stamps the given headers
// onto every redirect it creates. Existing headers are preserved.
func (r *Redirector) WithHeaders(headers map[string]string) *Redirector {
	clone := *r
	merged := make(map[string]string, len(r.headers)+len(headers))
	for k, v := range r.headers {
		merged[k] = v
	}
	for k, v := range headers {
		merged[k] = v
	}
	clone.headers = merged
	return &clone
}

// createRedirect centralizes redirect response construction: the status code
// and Location come from the shared Redirect factory, the redirector's headers
// are stamped on, and the current request is attached when available.
func (r *Redirector) createRedirect(path string, status int) *Response {
	res := Redirect(path, status)
	for k, v := range r.headers {
		res.Header(k, v)
	}
	if req := r.currentRequest(); req != nil {
		res.SetRequest(req)
	}
	return res
}

// To creates a redirect response to the given path, absolutized through the
// URL generator.
func (r *Redirector) To(path string, status ...int) *Response {
	return r.createRedirect(r.gen().To(path), redirectStatus(status))
}

// Away redirects to an external URL without any normalization.
func (r *Redirector) Away(url string, status ...int) *Response {
	return r.createRedirect(url, redirectStatus(status))
}

// Refresh redirects back to the current path.
func (r *Redirector) Refresh(status ...int) *Response {
	req := r.currentRequest()
	if req == nil {
		return r.To("/", status...)
	}
	return r.To(req.Path(), status...)
}

// Back redirects to the previous URL recorded in the session (or to the
// fallback, defaulting to "/", when unavailable) via the URL generator's
// Previous.
func (r *Redirector) Back(fallback string, status ...int) *Response {
	return r.To(r.gen().Previous(fallback), status...)
}

// Route redirects to a named route. A missing route or missing parameters
// panics with the generation error; use RouteWithError for the error-returning
// variant.
func (r *Redirector) Route(name string, params map[string]string, status ...int) *Response {
	url, err := r.gen().Route(name, params)
	if err != nil {
		panic(err)
	}
	return r.To(url, status...)
}

// RouteWithError redirects to a named route, returning the generation error
// instead of panicking.
func (r *Redirector) RouteWithError(name string, params map[string]string, status ...int) (*Response, error) {
	url, err := r.gen().Route(name, params)
	if err != nil {
		return nil, err
	}
	return r.To(url, status...), nil
}

// Action redirects to a route associated with a controller action. A missing
// action panics with the error; use ActionWithError for the error-returning
// variant.
func (r *Redirector) Action(action string, params map[string]string, status ...int) *Response {
	url, err := r.gen().Action(action, params)
	if err != nil {
		panic(err)
	}
	return r.To(url, status...)
}

// ActionWithError redirects to a controller action, returning the generation
// error instead of panicking.
func (r *Redirector) ActionWithError(action string, params map[string]string, status ...int) (*Response, error) {
	url, err := r.gen().Action(action, params)
	if err != nil {
		return nil, err
	}
	return r.To(url, status...), nil
}

// SignedRoute redirects to a signed named route. The variadic expiration
// accepts nil (never expires), time.Duration, int/int64 seconds or a
// time.Time deadline. A failure to build
// the signed URL (missing route or signing key) panics, consistent with
// Route/Action — an empty Location must never be produced.
func (r *Redirector) SignedRoute(name string, params map[string]string, expiration ...any) *Response {
	url := r.gen().SignedRoute(name, params, expiration...)
	if url == "" {
		panic(fmt.Errorf("flow: unable to create signed route [%s] (route not defined or no signing key)", name))
	}
	return r.To(url)
}

// TemporarySignedRoute redirects to an expiring signed named route. Failures
// panic like SignedRoute.
func (r *Redirector) TemporarySignedRoute(name string, expiration any, params map[string]string, status ...int) *Response {
	url := r.gen().TemporarySignedRoute(name, expiration, params)
	if url == "" {
		panic(fmt.Errorf("flow: unable to create signed route [%s] (route not defined or no signing key)", name))
	}
	return r.createRedirect(url, redirectStatus(status))
}

// Secure redirects to an HTTPS URL.
func (r *Redirector) Secure(path string, status ...int) *Response {
	return r.To(r.gen().Secure(path), status...)
}

// GetIntendedUrl reads the intended redirect URL from the session.
func (r *Redirector) GetIntendedUrl() string {
	req := r.currentRequest()
	if req == nil {
		return ""
	}
	s := req.Session()
	if s == nil {
		return ""
	}
	if store, ok := s.(*session.Store); ok {
		return store.IntendedUrl()
	}
	if intended, ok := s.Get(intendedURLKey).(string); ok {
		return intended
	}
	return ""
}

// GetUrlGenerator returns the underlying URL generator.
func (r *Redirector) GetUrlGenerator() *UrlGenerator {
	return r.generator
}

// Guest stores the current URL as the intended destination and redirects to
// the given path, typically a login page. The intended URL
// is the request's full URL when the request is a routable GET (and does not
// expect JSON), otherwise the previous URL; it is stored under the dedicated
// "url.intended" session key and only when non-empty.
func (r *Redirector) Guest(path string, status ...int) *Response {
	intended := ""
	if req := r.currentRequest(); req != nil {
		if req.IsMethod("GET") && req.Route() != nil && !req.ExpectsJson() {
			intended = r.gen().Full()
		} else {
			intended = r.gen().Previous("")
		}
	}
	if intended != "" {
		r.SetIntendedUrl(intended)
	}
	return r.To(path, status...)
}

// PreviousPath redirects to the path of the previous URL.
func (r *Redirector) PreviousPath(fallback string, status ...int) *Response {
	return r.To(r.gen().PreviousPath(fallback), status...)
}

// Intended redirects to the URL the user was heading to before being
// intercepted, or to the given default, which is passed through as-is (no "/"
// is forced). The stored URL is consumed on read.
func (r *Redirector) Intended(defaultPath string, status ...int) *Response {
	target := defaultPath
	if req := r.currentRequest(); req != nil {
		if s := req.Session(); s != nil {
			target = r.pullIntendedUrl(s, target)
		}
	}
	return r.To(target, status...)
}

// pullIntendedUrl reads and clears the intended URL from the session,
// falling back to the given default.
func (r *Redirector) pullIntendedUrl(s session.Session, fallback string) string {
	if store, ok := s.(*session.Store); ok {
		return store.PullIntendedUrl(fallback)
	}
	if intended, ok := s.Get(intendedURLKey).(string); ok && intended != "" {
		s.Forget(intendedURLKey)
		return intended
	}
	return fallback
}

// SetIntendedUrl records the URL to redirect to after interception.
func (r *Redirector) SetIntendedUrl(url string) {
	req := r.currentRequest()
	if req == nil {
		return
	}
	if s := req.Session(); s != nil {
		if store, ok := s.(*session.Store); ok {
			store.SetIntendedUrl(url)
			return
		}
		s.Set(intendedURLKey, url)
	}
}

func redirectStatus(status []int) int {
	if len(status) > 0 {
		return status[0]
	}
	return 302
}
