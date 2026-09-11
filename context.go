package flow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-think/flow/session"
)

// --- Begin request.go ---
// Request HTTP request
type Request struct {
	Request          *http.Request
	ctx              context.Context
	method           string
	path             string
	query            map[string]string
	queryValues      url.Values
	post             map[string]string
	postValues       url.Values
	routeParams      map[string]string
	routeParamsMu    sync.RWMutex
	routeMiddlewares []interface{}
	files            map[string]*File
	bodyContent      []byte
	session          session.Session
	CookieHandler    *Cookie
	writer           http.ResponseWriter
	keys             map[string]interface{}
	keysMu           sync.RWMutex
	parseOnce        sync.Once
	canonical        *Response
}

// CanonicalResponse returns the lazily-created response bound to this
// request. The Context type and response-preparation share this instance so
// header mutations from middlewares reach the final output.
func (r *Request) CanonicalResponse() *Response {
	if r.canonical == nil {
		r.canonical = NewResponse()
	}
	return r.canonical
}

// Context is the request-scoped handle given to route actions: it wraps the
// request, its route parameters and the canonical response.
type Context struct {
	*Request
	response *Response
}

// contextType is the reflect type used for Context argument injection.
var contextType = reflect.TypeOf(Context{})

// newContext builds a Context bound to the request's canonical response.
func newContext(request *Request) Context {
	return Context{Request: request, response: request.CanonicalResponse()}
}

// Param returns a route parameter value for the current request.
func (c Context) Param(name string) string {
	return c.Request.GetRouteParam(name)
}

// Response returns the canonical response for the current request; header
// mutations made through it reach the final output.
func (c Context) Response() *Response {
	return c.response
}

// String writes a plain-text response body with the given status code.
func (c Context) String(code int, body string) Response {
	res := c.response
	res.SetCode(code).SetContent(body)
	return *res
}

// Header sets a single response header.
func (r *Response) Header(name, value string) *Response {
	if r.headers == nil {
		r.headers = make(http.Header)
	}
	r.headers.Set(name, value)
	return r
}

// Headers returns the full response header map.
func (r *Response) Headers() http.Header {
	if r.headers == nil {
		r.headers = make(http.Header)
	}
	return r.headers
}

// StatusCode returns the HTTP status code of the response.
func (r *Response) StatusCode() int {
	return r.code
}

// Body returns the response content.
func (r *Response) Body() string {
	return r.content
}

// ResponseWriter returns the native http.ResponseWriter associated with this request.
func (r *Request) ResponseWriter() http.ResponseWriter {
	return r.writer
}

// SetResponseWriter sets the native http.ResponseWriter for direct writing.
func (r *Request) SetResponseWriter(w http.ResponseWriter) *Request {
	r.writer = w
	return r
}

// NewRequest create a new HTTP request from *http.Request
func NewRequest(req *http.Request) *Request {
	ctx := context.Background()
	method := ""
	path := ""
	if req != nil {
		if req.Context() != nil {
			ctx = req.Context()
		}
		method = req.Method
		if req.URL != nil {
			path = req.URL.Path
		}
	}
	return &Request{
		Request:     req,
		ctx:         ctx,
		method:      method,
		path:        path,
		routeParams: make(map[string]string),
		files:       make(map[string]*File),
		keys:        make(map[string]interface{}),
	}
}

// Context returns the request's context.Context
func (r *Request) Context() context.Context {
	if r.ctx == nil {
		return context.Background()
	}
	return r.ctx
}

// WithContext sets the request's context.Context
func (r *Request) WithContext(ctx context.Context) *Request {
	if ctx == nil {
		return r
	}
	r.ctx = ctx
	if r.Request != nil {
		r.Request = r.Request.WithContext(ctx)
	}
	return r
}

// Set store a new key/value pair in this context
func (r *Request) Set(key string, value interface{}) {
	r.keysMu.Lock()
	defer r.keysMu.Unlock()
	if r.keys == nil {
		r.keys = make(map[string]interface{})
	}
	r.keys[key] = value
}

// Get returns the value for the given key
func (r *Request) Get(key string) (value interface{}, exists bool) {
	r.keysMu.RLock()
	defer r.keysMu.RUnlock()
	value, exists = r.keys[key]
	return
}

// GetMethod get the request method.
func (r *Request) GetMethod() string {
	return r.method
}

// GetPath get the request path.
func (r *Request) GetPath() string {
	return r.path
}

// GetHttpRequest get Current *http.Request
func (r *Request) GetHttpRequest() *http.Request {
	return r.Request
}

// IsMethod checks if the request method is of specified type.
func (r *Request) IsMethod(m string) bool {
	return strings.ToUpper(m) == r.GetMethod()
}

// SetRouteParam sets a route parameter by name
func (r *Request) SetRouteParam(name, value string) {
	r.routeParamsMu.Lock()
	defer r.routeParamsMu.Unlock()
	r.routeParams[name] = value
}

// RouteMiddlewares Returns the route middlewares matched for the request.
func (r *Request) RouteMiddlewares() []interface{} {
	return r.routeMiddlewares
}

// SetRouteMiddlewares Sets the route middlewares matched for the request.
func (r *Request) SetRouteMiddlewares(middlewares []interface{}) {
	r.routeMiddlewares = append(r.routeMiddlewares, middlewares...)
}

// GetRouteParam gets a route parameter
func (r *Request) GetRouteParam(key string, defaultValue ...string) string {
	r.routeParamsMu.RLock()
	defer r.routeParamsMu.RUnlock()
	if v, ok := r.routeParams[key]; ok {
		return v
	}
	if len(defaultValue) > 0 {
		return defaultValue[0]
	}
	return ""
}

// RouteParam returns a route parameter with error if not present
func (r *Request) RouteParam(key string, defaultValue ...string) (string, error) {
	r.routeParamsMu.RLock()
	defer r.routeParamsMu.RUnlock()
	if v, ok := r.routeParams[key]; ok {
		return v, nil
	}
	if len(defaultValue) > 0 {
		return defaultValue[0], nil
	}
	return "", errors.New("route parameter not present")
}

func (r *Request) parseInputOnce() {
	r.parseOnce.Do(func() {
		if r.Request != nil && r.Request.URL != nil {
			r.queryValues = r.Request.URL.Query()
			r.query = parseQuery(r.queryValues)
		}
		if r.Request != nil {
			r.postValues, r.post = parsePost(r.Request)

			// Parse JSON body if applicable
			if strings.Contains(r.Request.Header.Get("Content-Type"), "application/json") {
				body, _ := r.GetContent()
				if len(body) > 0 {
					var jsonData map[string]interface{}
					if err := json.Unmarshal(body, &jsonData); err == nil {
						for k, v := range jsonData {
							r.post[k] = fmt.Sprintf("%v", v)
						}
					}
				}
			}
		}
	})
}

// Query returns a query string item from the request.
func (r *Request) Query(key string, value ...string) (string, error) {
	r.parseInputOnce()
	if v, ok := r.query[key]; ok {
		return v, nil
	}
	if len(value) > 0 {
		return value[0], nil
	}
	return "", errors.New("named query not present")
}

// Input returns a input item from the request.
func (r *Request) Input(key string, value ...string) (string, error) {
	r.parseInputOnce()
	if v, ok := r.post[key]; ok {
		return v, nil
	}

	if v, ok := r.query[key]; ok {
		return v, nil
	}

	if len(value) > 0 {
		return value[0], nil
	}
	return "", errors.New("named input not present")
}

// Post returns a post item from the request.
func (r *Request) Post(key string, value ...string) (string, error) {
	r.parseInputOnce()
	if v, ok := r.post[key]; ok {
		return v, nil
	}

	if len(value) > 0 {
		return value[0], nil
	}
	return "", errors.New("named post not present")
}

// Cookie Retrieve a cookie from the request.
func (r *Request) Cookie(key string, value ...string) (string, error) {
	var err error
	if r.Request == nil {
		if len(value) > 0 {
			return value[0], nil
		}
		return "", errors.New("nil http request")
	}
	if r.CookieHandler == nil {
		r.CookieHandler = ParseCookieHandler()
	}
	prefix := ""
	if r.CookieHandler != nil && r.CookieHandler.Config != nil {
		prefix = r.CookieHandler.Config.Prefix
	}
	key = prefix + key
	cookie, err := r.Request.Cookie(key)
	if err == nil {
		c, _ := url.QueryUnescape(cookie.Value)
		return c, err
	}
	if len(value) > 0 {
		return value[0], nil
	}
	return "", err
}

// SetCookieHandler sets the Cookie handler for the request.
func (r *Request) SetCookieHandler(handler *Cookie) {
	r.CookieHandler = handler
}

// File returns a file from the request.
func (r *Request) File(key string) (*File, error) {
	if f, ok := r.files[key]; ok {
		return f, nil
	}
	if r.Request == nil {
		return nil, errors.New("nil http request")
	}
	_, fh, err := r.Request.FormFile(key)
	if err != nil {
		return nil, err
	}
	r.files[key] = &File{fh}

	return r.files[key], nil
}

// HasFile determines if the uploaded data contains a file.
func (r *Request) HasFile(key string) bool {
	if _, ok := r.files[key]; ok {
		return true
	}
	if r.Request == nil {
		return false
	}
	_, _, err := r.Request.FormFile(key)
	return err == nil
}

// AllFiles returns all files from the request.
func (r *Request) AllFiles() (map[string]*File, error) {
	if r.Request == nil {
		return nil, errors.New("nil http request")
	}
	err := r.Request.ParseMultipartForm(32 << 20)
	if err != nil && err != http.ErrNotMultipart {
		return nil, err
	}
	if r.Request.MultipartForm != nil && r.Request.MultipartForm.File != nil {
		for key, fh := range r.Request.MultipartForm.File {
			if len(fh) > 0 {
				r.files[key] = &File{fh[0]}
			}
		}
	}
	return r.files, nil
}

// All get all of the input and query for the request.
func (r *Request) All(keys ...string) map[string]string {
	r.parseInputOnce()
	all := mergeForm(r.query, r.post)

	if len(keys) == 0 {
		return all
	}

	result := make(map[string]string)

	for _, key := range keys {
		if v, ok := all[key]; ok {
			result[key] = v
		} else {
			result[key] = ""
		}
	}

	return result
}

// Only get a subset of the items from the input data.
func (r *Request) Only(keys ...string) map[string]string {
	all := r.All()

	result := make(map[string]string)

	for _, key := range keys {
		if v, ok := all[key]; ok {
			result[key] = v
		}
	}

	return result
}

// Except Get all of the input except for a specified array of items.
func (r *Request) Except(keys ...string) map[string]string {
	all := r.All()

	for _, key := range keys {
		delete(all, key)
	}

	return all
}

// Has Determine if the request contains a given input item key (including empty strings).
func (r *Request) Has(keys ...string) bool {
	if len(keys) == 0 {
		return false
	}
	all := r.All()
	for _, key := range keys {
		if _, ok := all[key]; !ok {
			return false
		}
	}
	return true
}

// HasAny Determine if the request contains any of the given keys.
func (r *Request) HasAny(keys ...string) bool {
	if len(keys) == 0 {
		return false
	}
	all := r.All()
	for _, key := range keys {
		if _, ok := all[key]; ok {
			return true
		}
	}
	return false
}

// Filled Determine if the request contains a non-empty value for an input item.
func (r *Request) Filled(keys ...string) bool {
	if len(keys) == 0 {
		return false
	}
	all := r.All()
	for _, key := range keys {
		v, ok := all[key]
		if !ok || strings.TrimSpace(v) == "" {
			return false
		}
	}
	return true
}

// Missing Determine if the given input key is completely missing from the request.
func (r *Request) Missing(keys ...string) bool {
	if len(keys) == 0 {
		return true
	}
	all := r.All()
	for _, key := range keys {
		if _, ok := all[key]; ok {
			return false
		}
	}
	return true
}

// Exists Determine if the request contains a given input item key (alias of Has).
func (r *Request) Exists(keys ...string) bool {
	return r.Has(keys...)
}

// Url get the URL (no query string) for the request.
func (r *Request) Url() string {
	return r.Request.URL.Path
}

// FullUrl get the full URL for the request.
func (r *Request) FullUrl() string {
	return r.Url() + "?" + r.Request.URL.RawQuery
}

// Path get the current path info for the request.
func (r *Request) Path() string {
	return r.path
}

// Method get the current method for the request.
func (r *Request) Method() string {
	return r.method
}

// GetContent Returns the request body content.
func (r *Request) GetContent() ([]byte, error) {
	if r.bodyContent != nil {
		return r.bodyContent, nil
	}

	if r.Request == nil || r.Request.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(r.Request.Body)
	if err != nil {
		return nil, err
	}

	r.bodyContent = body
	r.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	return body, nil
}

// Session get the session associated with the request.
func (r *Request) Session() session.Session {
	return r.session
}

// Session set the session associated with the request.
func (r *Request) SetSession(s session.Session) {
	r.session = s
}

func parseQuery(q url.Values) map[string]string {
	query := make(map[string]string)
	for k, v := range q {
		if len(v) > 0 {
			query[k] = v[0]
		}
	}
	return query
}

func parsePost(r *http.Request) (url.Values, map[string]string) {
	postMap := make(map[string]string)
	if r == nil {
		return nil, postMap
	}

	_ = r.ParseForm()
	values := url.Values{}

	for k, v := range r.PostForm {
		values[k] = append(values[k], v...)
		if len(v) > 0 {
			postMap[k] = v[0]
		}
	}

	_ = r.ParseMultipartForm(32 << 20)
	if r.MultipartForm != nil {
		for k, v := range r.MultipartForm.Value {
			values[k] = append(values[k], v...)
			if len(v) > 0 {
				postMap[k] = v[0]
			}
		}
	}

	return values, postMap
}

func mergeForm(slices ...map[string]string) map[string]string {
	r := make(map[string]string)

	for _, slice := range slices {
		for k, v := range slice {
			r[k] = v
		}
	}

	return r
}

// Header returns the value of the given header key.
func (r *Request) Header(key string) string {
	if r.Request != nil {
		return r.Request.Header.Get(key)
	}
	return ""
}

// BearerToken returns the Bearer token from the Authorization header.
func (r *Request) BearerToken() string {
	auth := r.Header("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

// ClientIP returns the client IP.
func (r *Request) ClientIP() string {
	if r.Request == nil {
		return ""
	}
	if ip := r.Header("X-Real-Ip"); ip != "" {
		return ip
	}
	if ip := r.Header("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}

	// RemoteAddr could be IP:port
	addr := r.Request.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// WantsJson returns true if the request asks for a JSON response.
func (r *Request) WantsJson() bool {
	accept := r.Header("Accept")
	return strings.Contains(accept, "/json") || strings.Contains(accept, "+json")
}

// ExpectsJson returns true if the request expects a JSON response.
func (r *Request) ExpectsJson() bool {
	return r.IsAjax() || r.WantsJson()
}

// IsAjax returns true if the request is an AJAX request.
func (r *Request) IsAjax() bool {
	return r.Header("X-Requested-With") == "XMLHttpRequest"
}

// Boolean retrieves an input item as a boolean.
func (r *Request) Boolean(key string, defaultValue ...bool) bool {
	val, err := r.Input(key)
	if err != nil || val == "" {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return false
	}

	lower := strings.ToLower(strings.TrimSpace(val))
	switch lower {
	case "1", "true", "t", "yes", "y", "on":
		return true
	case "0", "false", "f", "no", "n", "off":
		return false
	}

	if len(defaultValue) > 0 {
		return defaultValue[0]
	}
	return false
}

// Integer retrieves an input item as an integer.
func (r *Request) Integer(key string, defaultValue ...int) int {
	val, err := r.Input(key)
	if err != nil || val == "" {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return 0
	}

	intVal, err := strconv.Atoi(strings.TrimSpace(val))
	if err != nil {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return 0
	}

	return intVal
}

// Float retrieves an input item as a float64.
func (r *Request) Float(key string, defaultValue ...float64) float64 {
	val, err := r.Input(key)
	if err != nil || val == "" {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return 0.0
	}

	floatVal, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
	if err != nil {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return 0.0
	}

	return floatVal
}

// Merge merges new input into the current request's user input.
func (r *Request) Merge(values map[string]string) *Request {
	r.parseInputOnce()
	if r.post == nil {
		r.post = make(map[string]string)
	}
	for k, v := range values {
		r.post[k] = v
		if r.query != nil {
			if _, ok := r.query[k]; ok {
				r.query[k] = v
			}
		}
	}
	return r
}

// Fingerprint gets a unique fingerprint for the request.
func (r *Request) Fingerprint() string {
	ip := r.ClientIP()
	ua := r.Header("User-Agent")
	route := r.GetPath()
	method := r.GetMethod()

	hash := sha256.Sum256(fmt.Appendf(nil, "%s|%s|%s|%s", method, route, ip, ua))
	return hex.EncodeToString(hash[:])
}

// UserAgent returns the client User-Agent header.
func (r *Request) UserAgent() string {
	return r.Header("User-Agent")
}

// Segments gets all segments of the request path.
func (r *Request) Segments() []string {
	trimmed := strings.Trim(r.Path(), "/")
	if trimmed == "" {
		return []string{}
	}
	return strings.Split(trimmed, "/")
}

// Segment gets a 1-indexed segment of the path.
func (r *Request) Segment(index int, defaultValue ...string) string {
	segments := r.Segments()
	if index > 0 && index <= len(segments) {
		return segments[index-1]
	}
	if len(defaultValue) > 0 {
		return defaultValue[0]
	}
	return ""
}

// Is determines if the current request path matches given patterns.
func (r *Request) Is(patterns ...string) bool {
	path := strings.Trim(r.Path(), "/")
	for _, pattern := range patterns {
		pattern = strings.Trim(pattern, "/")
		if pattern == path {
			return true
		}
		if strings.Contains(pattern, "*") {
			pat := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$"
			if matched, _ := regexp.MatchString(pat, path); matched {
				return true
			}
		}
	}
	return false
}

// RouteIs determines if the current route name matches given patterns.
func (r *Request) RouteIs(patterns ...string) bool {
	routeName := ""
	if nameVal, ok := r.Get("_route_name"); ok {
		if nameStr, ok := nameVal.(string); ok {
			routeName = nameStr
		}
	}
	if routeName == "" {
		return false
	}
	for _, pattern := range patterns {
		if pattern == routeName {
			return true
		}
		if strings.Contains(pattern, "*") {
			pat := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$"
			if matched, _ := regexp.MatchString(pat, routeName); matched {
				return true
			}
		}
	}
	return false
}

// FullUrlWithQuery appends or replaces query parameters to current full URL.
func (r *Request) FullUrlWithQuery(query map[string]string) string {
	if r.Request == nil || r.Request.URL == nil {
		return ""
	}
	q := r.Request.URL.Query()
	for k, v := range query {
		q.Set(k, v)
	}
	return r.Url() + "?" + q.Encode()
}

// FullUrlWithoutQuery removes specified query parameters from current full URL.
func (r *Request) FullUrlWithoutQuery(keys ...string) string {
	if r.Request == nil || r.Request.URL == nil {
		return ""
	}
	q := r.Request.URL.Query()
	for _, k := range keys {
		q.Del(k)
	}
	encoded := q.Encode()
	if encoded == "" {
		return r.Url()
	}
	return r.Url() + "?" + encoded
}

// --- End request.go ---

// --- Begin response.go ---
type Response struct {
	// Writer      ResponseWriter
	contentType   string
	charset       string
	code          int
	content       string
	filePath      string
	Request       *Request
	cookies       map[string]*http.Cookie
	CookieHandler *Cookie
	headers       http.Header
	streamFunc    func(w io.Writer) bool
	handled       bool
}

// HandledResponse creates a response indicating that output was directly handled.
func HandledResponse() *Response {
	r := NewResponse()
	r.handled = true
	return r
}

// IsHandled returns whether the response was already handled directly.
func (r *Response) IsHandled() bool {
	return r.handled
}

// FileResponse Create a response that serves a file
func FileResponse(filepath string) *Response {
	r := NewResponse()
	r.filePath = filepath
	return r
}

// SetFile set a file path to be served
func (r *Response) SetFile(filepath string) *Response {
	r.filePath = filepath
	return r
}

// SetRequest bind original request for file serving
func (r *Response) SetRequest(req *Request) *Response {
	r.Request = req
	return r
}

// GetContentType sets the Content-Type on the response.
func (r *Response) SetContentType(val string) *Response {
	r.contentType = val
	return r
}

// GetContentType sets the Charset on the response.
func (r *Response) SetCharset(val string) *Response {
	r.charset = val
	return r
}

// SetCode sets the status code on the response.
func (r *Response) SetCode(val int) *Response {
	r.code = val
	return r
}

// SetContent sets the content on the response.
func (r *Response) SetContent(val string) *Response {
	r.content = val
	return r
}

func FormatContent(v interface{}) string {
	if v == nil {
		return ""
	}
	t := reflect.TypeOf(v)
	switch t.Kind() {
	case reflect.Bool:
		return fmt.Sprintf("%t", v)
	case reflect.String:
		return fmt.Sprintf("%s", v)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return fmt.Sprintf("%d", v)
	case reflect.Float32, reflect.Float64:
		return fmt.Sprintf("%v", v)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

// GetContentType get the Content-Type on the response.
func (r *Response) GetContentType() string {
	return r.contentType
}

// GetContentType get the Charset on the response.
func (r *Response) GetCharset() string {
	return r.charset
}

// GetCode get the response status code.
func (r *Response) GetCode() int {
	return r.code
}

// GetCode get the response content.
func (r *Response) GetContent() string {
	return r.content
}

// Cookie Add a cookie to the response.
func (r *Response) Cookie(name interface{}, params ...interface{}) error {
	if r.CookieHandler == nil {
		r.CookieHandler = ParseCookieHandler()
	}
	cookie, err := r.CookieHandler.Set(name, params...)

	if err == nil && cookie != nil {
		if r.cookies == nil {
			r.cookies = make(map[string]*http.Cookie)
		}
		r.cookies[cookie.Name] = cookie
	}

	return err
}

// SetCookieHandler sets the Cookie handler for the response.
func (r *Response) SetCookieHandler(handler *Cookie) *Response {
	r.CookieHandler = handler
	return r
}

// GetCookies returns the response cookies map.
func (r *Response) GetCookies() map[string]*http.Cookie {
	return r.cookies
}

// Send Sends HTTP headers and content.
func (r *Response) Send(w http.ResponseWriter) {
	if r.handled {
		return
	}

	for _, cookie := range r.cookies {
		http.SetCookie(w, cookie)
	}
	for key, value := range r.headers {
		for _, val := range value {
			w.Header().Add(key, val)
		}
	}

	// If filePath is set, prioritize using http.ServeFile to serve the file
	if r.filePath != "" {
		if r.Request != nil && r.Request.Request != nil {
			http.ServeFile(w, r.Request.Request, r.filePath)
		}
		return
	}

	// If streamFunc is set, handle streaming output (stream / SSE)
	if r.streamFunc != nil {
		if r.GetContentType() != "" {
			w.Header().Set("Content-Type", r.GetContentType())
		}
		w.WriteHeader(r.GetCode())

		flusher, isFlusher := w.(http.Flusher)
		for {
			keepStreaming := r.streamFunc(w)
			if isFlusher {
				flusher.Flush()
			}
			if !keepStreaming {
				break
			}
		}
		return
	}

	w.Header().Set("Content-Type", r.GetContentType()+";"+" charset="+r.GetCharset())
	// r.Header.Write(w)
	w.WriteHeader(r.GetCode())
	w.Write([]byte(r.GetContent()))
}

// NewResponse Create a new HTTP Response
func NewResponse() *Response {
	r := &Response{
		headers: make(http.Header),
	}
	r.SetCode(http.StatusOK)
	r.SetContentType("text/html")
	r.SetCharset("utf-8")
	r.CookieHandler = ParseCookieHandler()
	return r
}

// NotFoundResponse Create a new HTTP NotFoundResponse
func NotFoundResponse() *Response {
	return NewResponse().SetCode(http.StatusNotFound).SetContent("Not Found")
}

// DownloadResponse Create a new HTTP Download Response
func DownloadResponse(filePath string, filename ...string) *Response {
	r := NewResponse()
	r.filePath = filePath

	name := filepath.Base(filePath)
	if len(filename) > 0 {
		name = filename[0]
	}

	r.Header("Content-Disposition", "attachment; filename=\""+name+"\"")
	r.Header("Content-Type", "application/octet-stream")
	return r
}

// NotFoundResponse Create a new HTTP Error Response
func ErrorResponse() *Response {
	return NewResponse().SetCode(http.StatusInternalServerError).SetContent("Server Error")
}

// Redirect Create a new HTTP Redirect Response (default 302 Found).
func Redirect(to string, status ...int) *Response {
	code := http.StatusFound
	if len(status) > 0 && status[0] > 0 {
		code = status[0]
	}
	r := NewResponse().SetCode(code)
	r.Header("Location", to)
	return r
}

// SetStream sets a streaming callback for the response.
func (r *Response) SetStream(streamFunc func(w io.Writer) bool) *Response {
	r.streamFunc = streamFunc
	return r
}

// StreamResponse creates a new streaming HTTP Response.
func StreamResponse(streamFunc func(w io.Writer) bool) *Response {
	r := NewResponse()
	r.SetContentType("text/event-stream")
	r.Header("Cache-Control", "no-cache")
	r.Header("Connection", "keep-alive")
	r.streamFunc = streamFunc
	return r
}

// StreamDownload creates a new streaming download response.
func StreamDownload(streamFunc func(w io.Writer) bool, filename string) *Response {
	r := NewResponse()
	r.Header("Content-Disposition", "attachment; filename=\""+filename+"\"")
	r.Header("Content-Type", "application/octet-stream")
	r.streamFunc = streamFunc
	return r
}

// NoContent creates a new 204 No Content Response.
func NoContent(status ...int) *Response {
	code := http.StatusNoContent
	if len(status) > 0 {
		code = status[0]
	}
	return NewResponse().SetCode(code).SetContent("")
}

// Json Create a new HTTP Response with JSON data
func Json(v interface{}) *Response {
	c, err := json.Marshal(v)
	if err != nil {
		return NewResponse().SetContent("").SetContentType("application/json")
	}
	return NewResponse().SetContent(string(c)).SetContentType("application/json")
}

// Text Create a new HTTP Response with TEXT data
func Text(s string) *Response {
	return NewResponse().SetContent(s).SetContentType("text/plain")
}

// Html Create a new HTTP Response with HTML data
func Html(s string) *Response {
	return NewResponse().SetContent(s)
}

// Download Create a new HTTP Download Response
func Download(filePath string, filename ...string) *Response {
	return DownloadResponse(filePath, filename...)
}

// MakeResponse Create a new HTTP Response by auto detecting content type
// Jsonp creates a JSONP response with the given callback name.
func Jsonp(callback string, v interface{}) *Response {
	body, err := json.Marshal(v)
	if err != nil {
		return ErrorResponse()
	}
	r := NewResponse().SetContentType("application/javascript")
	r.SetContent(callback + "(" + string(body) + ");")
	return r
}

// StreamJson creates a streaming JSON response: each encoded item is written
// per iteration and flushed; the stream ends after the last item.
func StreamJson(data []any, status ...int) *Response {
	code := http.StatusOK
	if len(status) > 0 {
		code = status[0]
	}
	r := NewResponse().SetCode(code).SetContentType("application/json")
	r.SetStream(func(w io.Writer) bool {
		enc := json.NewEncoder(w)
		for _, item := range data {
			if err := enc.Encode(item); err != nil {
				return false
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		return false
	})
	return r
}

// EventStream creates a server-sent events response; the callback writes one
// event per invocation and returns false to end the stream.
func EventStream(write func(w io.Writer) bool) *Response {
	r := NewResponse().SetContentType("text/event-stream")
	r.Header("Cache-Control", "no-cache")
	r.SetStream(write)
	return r
}

func MakeResponse(v interface{}) *Response {
	r := NewResponse()
	if v == nil {
		return r.SetContent("")
	}

	content := FormatContent(v)
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Map || t.Kind() == reflect.Slice || t.Kind() == reflect.Struct {
		r.SetContentType("application/json")
	} else {
		r.SetContentType("text/plain")
	}
	r.SetContent(content)

	return r
}

// --- End response.go ---

// --- Begin cookie.go ---
type CookieConfig struct {
	Prefix          string
	Path            string        // optional
	Domain          string        // optional
	ExpiresDuration time.Duration // Expiration duration configuration
	RawExpires      string        // for reading cookies only

	MaxAge   int
	Secure   bool
	HttpOnly bool
	Raw      string
	Unparsed []string
}

type Cookie struct {
	Config *CookieConfig
}

func (c *Cookie) Set(name interface{}, params ...interface{}) (*http.Cookie, error) {
	var cookie *http.Cookie

	switch v := name.(type) {
	case *http.Cookie:
		cookie = v
	case string:
		if len(params) == 0 {
			return nil, errors.New("Invalid parameters for Cookie.")
		}

		cookie = &http.Cookie{
			Name:  v,
			Value: url.QueryEscape(params[0].(string)),
		}

		if len(params) > 1 {
			switch p := params[1].(type) {
			case int:
				cookie.MaxAge = p
			case time.Duration:
				cookie.Expires = time.Now().Add(p)
			case time.Time:
				cookie.Expires = p
			}
		}

		if len(params) > 2 {
			cookie.Path = params[2].(string)
		}

		if len(params) > 3 {
			cookie.Domain = params[3].(string)
		}

		if len(params) > 4 {
			cookie.Secure = params[4].(bool)
		}

		if len(params) > 5 {
			cookie.HttpOnly = params[5].(bool)
		}

		if c.Config != nil {
			if cookie.Path == "" {
				cookie.Path = c.Config.Path
			}
			if cookie.Domain == "" {
				cookie.Domain = c.Config.Domain
			}
			if !cookie.Secure && c.Config.Secure {
				cookie.Secure = c.Config.Secure
			}
			if !cookie.HttpOnly && c.Config.HttpOnly {
				cookie.HttpOnly = c.Config.HttpOnly
			}
			if cookie.Expires.IsZero() && c.Config.ExpiresDuration > 0 {
				cookie.Expires = time.Now().Add(c.Config.ExpiresDuration)
			}
		}
	default:
		return nil, errors.New("Invalid parameters for Cookie.")
	}
	return cookie, nil
}

// DefaultCookieConfig returns a new default CookieConfig.
func DefaultCookieConfig() *CookieConfig {
	return &CookieConfig{
		Prefix:          "",
		Path:            "/",
		Domain:          "",
		ExpiresDuration: time.Hour * 4,
		MaxAge:          0,
		Secure:          false,
		HttpOnly:        true,
	}
}

// ParseCookieHandler returns a Cookie instance with given or default configuration.
func ParseCookieHandler(cfg ...*CookieConfig) *Cookie {
	if len(cfg) > 0 && cfg[0] != nil {
		return &Cookie{Config: cfg[0]}
	}

	return &Cookie{
		Config: DefaultCookieConfig(),
	}
}

// --- End cookie.go ---

// --- Begin file.go ---
type File struct {
	FileHeader *multipart.FileHeader
}

func (f *File) Move(directory string, name ...string) (bool, error) {
	if f.FileHeader == nil {
		return false, errors.New("nil file header")
	}

	src, err := f.FileHeader.Open()
	if err != nil {
		return false, err
	}
	defer src.Close()

	fname := filepath.Base(f.FileHeader.Filename)
	if len(name) > 0 && name[0] != "" {
		fname = filepath.Base(name[0])
	}

	if err := os.MkdirAll(directory, 0755); err != nil {
		return false, err
	}

	dst := filepath.Join(directory, fname)

	out, err := os.Create(dst)
	if err != nil {
		return false, err
	}
	defer out.Close()

	if _, err = io.Copy(out, src); err != nil {
		return false, err
	}

	return true, nil
}

// --- End file.go ---
