package flow

import (
	"fmt"
	"strings"
)

// UrlGenerationError reports that a named route URL could not be generated
// because required parameters were missing.
type UrlGenerationError struct {
	RouteName string
	Missing   []string
}

func (e *UrlGenerationError) Error() string {
	return fmt.Sprintf("flow: missing required parameters for route [%s]: %s",
		e.RouteName, strings.Join(e.Missing, ", "))
}

// Redirector builds redirect responses, mirroring the response-side helpers:
// it resolves named routes and signed routes through the URL generator and
// reads session state (previous URL, intended URL) through the request
// provider.
type Redirector struct {
	generator       *UrlGenerator
	requestProvider func() *Request
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

// currentRequest returns the request from the provider, if configured.
func (r *Redirector) currentRequest() *Request {
	if r.requestProvider == nil {
		return nil
	}
	return r.requestProvider()
}

// To redirects to a path.
func (r *Redirector) To(path string, status ...int) *Response {
	code := redirectStatus(status)
	return Redirect(path, code)
}

// Away redirects to an external URL without normalization.
func (r *Redirector) Away(url string, status ...int) *Response {
	return r.To(url, status...)
}

// Refresh redirects back to the current path.
func (r *Redirector) Refresh(status ...int) *Response {
	req := r.currentRequest()
	if req == nil {
		return r.To("/", status...)
	}
	return r.To(req.Path(), status...)
}

// Back redirects to the previous URL recorded in the session, or to the
// fallback (default "/") when unavailable.
func (r *Redirector) Back(fallback string, status ...int) *Response {
	return r.To(r.generator.Previous(fallback), status...)
}

// Route redirects to a named route.
func (r *Redirector) Route(name string, params map[string]string, status ...int) *Response {
	url, err := r.generator.Route(name, params)
	if err != nil {
		panic(err)
	}
	return r.To(url, status...)
}

// Action redirects to a route associated with a controller action.
func (r *Redirector) Action(action string, params map[string]string, status ...int) *Response {
	url, err := r.generator.Action(action, params)
	if err != nil {
		panic(err)
	}
	return r.To(url, status...)
}

// SignedRoute redirects to a signed named route.
func (r *Redirector) SignedRoute(name string, params map[string]string, status ...int) *Response {
	return r.To(r.generator.SignedRoute(name, params), status...)
}

// TemporarySignedRoute redirects to an expiring signed named route.
func (r *Redirector) TemporarySignedRoute(name string, expiration any, params map[string]string, status ...int) *Response {
	return r.To(r.generator.SignedRoute(name, params), status...)
}

// Guest stores the current URL as the intended destination and redirects to
// the given path (typically a login page).
func (r *Redirector) Guest(path string, status ...int) *Response {
	req := r.currentRequest()
	if req != nil && req.Path() != path {
		r.SetIntendedUrl(req.Path())
	}
	return r.To(path, status...)
}

// Intended redirects to the URL the user was heading to before being
// intercepted, or to the default.
func (r *Redirector) Intended(defaultPath string, status ...int) *Response {
	req := r.currentRequest()
	if req != nil {
		if session := req.Session(); session != nil {
			if intended := session.PreviousUrl(); intended != "" {
				session.SetPreviousUrl("")
				return r.To(intended, status...)
			}
		}
	}
	return r.To(defaultPath, status...)
}

// SetIntendedUrl records the URL to redirect to after interception.
func (r *Redirector) SetIntendedUrl(url string) {
	req := r.currentRequest()
	if req == nil {
		return
	}
	if session := req.Session(); session != nil {
		session.SetPreviousUrl(url)
	}
}

func redirectStatus(status []int) int {
	if len(status) > 0 {
		return status[0]
	}
	return 302
}
