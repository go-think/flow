package flow

import (
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-think/flow/session"
)

// HandlerFunc type is an adapter to allow the use of ordinary functions as HTTP middleware.
type HandlerFunc func(request *Request, next Closure) any

// Process calls f(request, next).
func (f HandlerFunc) Process(request *Request, next Closure) any {
	return f(request, next)
}

// Terminable Terminable Middleware interface
type Terminable interface {
	Terminate(request *Request, response any)
}

// --- Begin middleware.go ---
// Middleware Handle an incoming request.
type Middleware func(request *Request, next Closure) any

// ParameterizedMiddleware Handle an incoming request with parameters.
type ParameterizedMiddleware func(params ...string) Middleware

// --- Begin recover.go ---
var HandleException func(err interface{}) *Response

type RecoverMiddleware struct {
	debug bool
}

// NewRecoverMiddleware creates a new panic recovery middleware.
func NewRecoverMiddleware(debug bool) Handler {
	return &RecoverMiddleware{
		debug: debug,
	}
}

// Deprecated: Use RecoverMiddleware instead.
type RecoverHandler = RecoverMiddleware

// Deprecated: Use NewRecoverMiddleware instead.
func NewRecoverHandler(debug bool) Handler {
	return NewRecoverMiddleware(debug)
}

// Process Process the request to a router and return the response.
func (h *RecoverMiddleware) Process(req *Request, next Closure) (result interface{}) {
	defer func() {
		if err := recover(); err != nil {
			if HandleException != nil {
				if custom := HandleException(err); custom != nil {
					result = custom
					return
				}
			}

			var stacktrace string
			for i := 1; ; i++ {
				_, f, l, got := runtime.Caller(i)
				if !got {
					break
				}
				stacktrace += fmt.Sprintf("%s:%d\n", f, l)
			}

			logMessage := fmt.Sprintf("Trace: %v\n\n%s", err, stacktrace)
			response := NewResponse()
			response.SetCode(500)
			if h.debug {
				response.SetContent(logMessage)
			} else {
				response.SetContent("Internal Server Error")
			}
			result = response
		}
	}()

	return next(req)
}

// --- End recover.go ---

// --- Begin cors.go ---
// CorsConfig defines the configuration options for CORS middleware.
type CorsConfig struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials bool
	MaxAge           int
}

// DefaultCorsConfig returns standard default CORS configuration.
func DefaultCorsConfig() CorsConfig {
	return CorsConfig{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With", "X-CSRF-Token"},
		ExposeHeaders:    []string{},
		AllowCredentials: true,
		MaxAge:           86400,
	}
}

type CorsMiddleware struct {
	config CorsConfig
}

// NewCorsMiddleware creates a new CORS middleware.
func NewCorsMiddleware(config ...CorsConfig) Handler {
	cfg := DefaultCorsConfig()
	if len(config) > 0 {
		cfg = config[0]
	}
	return &CorsMiddleware{config: cfg}
}

// Deprecated: Use CorsMiddleware instead.
type CorsHandler = CorsMiddleware

// Deprecated: Use NewCorsMiddleware instead.
func NewCorsHandler(config ...CorsConfig) Handler {
	return NewCorsMiddleware(config...)
}

func (h *CorsMiddleware) Process(req *Request, next Closure) interface{} {
	origin := req.Header("Origin")

	// If not CORS request, proceed normally
	if origin == "" {
		return next(req)
	}

	allowOrigin := h.determineAllowedOrigin(origin)

	// Preflight request handling
	if req.IsMethod("OPTIONS") {
		res := NewResponse().SetCode(http.StatusNoContent)
		h.applyHeaders(res, allowOrigin)
		return res
	}

	// Actual request handling
	result := next(req)
	if res, ok := result.(*Response); ok {
		h.applyHeaders(res, allowOrigin)
	}

	return result
}

func (h *CorsMiddleware) determineAllowedOrigin(origin string) string {
	for _, allowed := range h.config.AllowOrigins {
		if allowed == "*" {
			return "*"
		}
		if allowed == origin {
			return origin
		}
	}
	return ""
}

func (h *CorsMiddleware) applyHeaders(res *Response, allowOrigin string) {
	if allowOrigin != "" {
		res.Header.Set("Access-Control-Allow-Origin", allowOrigin)
	}
	if len(h.config.AllowMethods) > 0 {
		res.Header.Set("Access-Control-Allow-Methods", strings.Join(h.config.AllowMethods, ", "))
	}
	if len(h.config.AllowHeaders) > 0 {
		res.Header.Set("Access-Control-Allow-Headers", strings.Join(h.config.AllowHeaders, ", "))
	}
	if len(h.config.ExposeHeaders) > 0 {
		res.Header.Set("Access-Control-Expose-Headers", strings.Join(h.config.ExposeHeaders, ", "))
	}
	if h.config.AllowCredentials && allowOrigin != "*" {
		res.Header.Set("Access-Control-Allow-Credentials", "true")
	}
	if h.config.MaxAge > 0 {
		res.Header.Set("Access-Control-Max-Age", strconv.Itoa(h.config.MaxAge))
	}
}

// --- End cors.go ---

// --- Begin trim.go ---
type TrimStringsMiddleware struct {
	except []string
}

// NewTrimStringsMiddleware creates a new parameter trimming middleware.
func NewTrimStringsMiddleware(except ...string) Handler {
	return &TrimStringsMiddleware{except: except}
}

// Deprecated: Use TrimStringsMiddleware instead.
type TrimStringsHandler = TrimStringsMiddleware

// Deprecated: Use NewTrimStringsMiddleware instead.
func NewTrimStringsHandler(except ...string) Handler {
	return NewTrimStringsMiddleware(except...)
}

func (h *TrimStringsMiddleware) Process(req *Request, next Closure) interface{} {
	allInput := req.All()
	if len(allInput) > 0 {
		cleaned := make(map[string]string, len(allInput))
		for k, v := range allInput {
			if h.isExcepted(k) {
				continue
			}
			cleaned[k] = strings.TrimSpace(v)
		}
		req.Merge(cleaned)
	}

	return next(req)
}

// CleanValue recursively trims strings in nested maps and slices.
func CleanValue(val interface{}) interface{} {
	switch v := val.(type) {
	case string:
		return strings.TrimSpace(v)
	case map[string]interface{}:
		res := make(map[string]interface{}, len(v))
		for k, item := range v {
			res[k] = CleanValue(item)
		}
		return res
	case []interface{}:
		res := make([]interface{}, len(v))
		for i, item := range v {
			res[i] = CleanValue(item)
		}
		return res
	default:
		return v
	}
}

func (h *TrimStringsMiddleware) isExcepted(key string) bool {
	for _, ex := range h.except {
		if ex == key {
			return true
		}
	}
	return false
}

// --- End trim.go ---

// --- Begin validate_signature.go ---
type ValidateSignatureMiddleware struct {
	router Router
}

// NewValidateSignatureMiddleware creates a new URL signature validation middleware.
func NewValidateSignatureMiddleware(r ...Router) Handler {
	var targetRouter Router
	if len(r) > 0 && r[0] != nil {
		targetRouter = r[0]
	}
	return &ValidateSignatureMiddleware{router: targetRouter}
}

// Deprecated: Use ValidateSignatureMiddleware instead.
type ValidateSignatureHandler = ValidateSignatureMiddleware

// Deprecated: Use NewValidateSignatureMiddleware instead.
func NewValidateSignatureHandler(r ...Router) Handler {
	return NewValidateSignatureMiddleware(r...)
}

func (h *ValidateSignatureMiddleware) Process(req *Request, next Closure) interface{} {
	r := h.router

	if r != nil {
		if !r.HasValidSignature(req) {
			return NewResponse().
				SetCode(http.StatusForbidden).
				SetContent("Invalid signature.")
		}
	}

	return next(req)
}

// --- End validate_signature.go ---

// --- Begin route.go ---
type RouteMiddleware struct {
	Router Router
}

// NewRouteMiddleware creates a new route dispatcher middleware.
func NewRouteMiddleware(r Router) Handler {
	return &RouteMiddleware{
		Router: r,
	}
}

// Deprecated: Use RouteMiddleware instead.
type RouteHandler = RouteMiddleware

// Deprecated: Use NewRouteMiddleware instead.
func NewRouteHandler(r Router) Handler {
	return NewRouteMiddleware(r)
}

// Process Process the request to a router and return the response.
func (h *RouteMiddleware) Process(request *Request, next Closure) interface{} {
	return h.Router.Dispatch(request)
}

// --- End route.go ---

// --- Begin middleware_session.go ---
type SessionMiddleware struct {
	Manager *Manager
}

// DefaultSessionConfig returns the default session configuration.
func DefaultSessionConfig() *Config {
	return &Config{
		Driver:     "file",
		CookieName: "think_session",
		Lifetime:   120 * time.Minute,
		Encrypt:    false,
		Files:      "storage/framework/sessions",
	}
}

func mergeSessionConfig(userCfg *Config) *Config {
	def := DefaultSessionConfig()
	if userCfg == nil {
		return def
	}
	cfg := *userCfg
	if cfg.Driver == "" {
		cfg.Driver = def.Driver
	}
	if cfg.CookieName == "" {
		cfg.CookieName = def.CookieName
	}
	if cfg.Lifetime <= 0 {
		cfg.Lifetime = def.Lifetime
	}
	if cfg.Files == "" {
		cfg.Files = def.Files
	}
	return &cfg
}

// NewSessionMiddleware creates a new session management middleware with the specified configuration.
func NewSessionMiddleware(cfg *Config) Handler {
	return &SessionMiddleware{
		Manager: NewManager(mergeSessionConfig(cfg)),
	}
}

func (h *SessionMiddleware) Process(req *Request, next Closure) interface{} {
	store := h.startSession(req)

	req.SetSession(store)

	result := next(req)

	if res, ok := result.(*Response); ok {
		h.saveSession(res, store)
	}

	return result
}

func (h *SessionMiddleware) startSession(req *Request) *session.Store {
	return h.Manager.SessionStart(req)
}

func (h *SessionMiddleware) saveSession(res *Response, store *session.Store) {
	h.Manager.SessionSave(res, store)
}

// --- End middleware_session.go ---

// --- Begin middleware_cookie.go ---

// CookieMiddleware manages Cookie configuration for incoming requests and outgoing responses.
type CookieMiddleware struct {
	config *CookieConfig
}

// NewCookieMiddleware creates a new CookieMiddleware with the given configuration.
func NewCookieMiddleware(cfg ...*CookieConfig) Handler {
	var config *CookieConfig
	if len(cfg) > 0 && cfg[0] != nil {
		config = cfg[0]
	} else {
		config = DefaultCookieConfig()
	}
	return &CookieMiddleware{
		config: config,
	}
}

// Process configures CookieHandler on request and response.
func (m *CookieMiddleware) Process(req *Request, next Closure) any {
	if req.CookieHandler == nil {
		req.CookieHandler = &Cookie{Config: m.config}
	} else if req.CookieHandler.Config == nil {
		req.CookieHandler.Config = m.config
	}

	result := next(req)

	if res, ok := result.(*Response); ok {
		res.CookieHandler = req.CookieHandler
		if m.config != nil {
			for _, c := range res.cookies {
				if (c.Path == "" || c.Path == "/") && m.config.Path != "" {
					c.Path = m.config.Path
				}
				if c.Domain == "" && m.config.Domain != "" {
					c.Domain = m.config.Domain
				}
				if !c.Secure && m.config.Secure {
					c.Secure = m.config.Secure
				}
				if !c.HttpOnly && m.config.HttpOnly {
					c.HttpOnly = m.config.HttpOnly
				}
			}
		}
	}

	return result
}

// --- End middleware_cookie.go ---

