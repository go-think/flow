package flow

import (
	"fmt"
	"net/http"
	"strings"
)

// RoutingEvent is fired before a request is matched to a route.
type RoutingEvent struct {
	Request *Request
}

// RouteMatchedEvent is fired after a request is matched to a route.
type RouteMatchedEvent struct {
	Route   *Route
	Request *Request
}

// PreparingResponseEvent is fired before the response is prepared.
type PreparingResponseEvent struct {
	Request *Request
	Result  any
}

// ResponsePreparedEvent is fired after the response is prepared.
type ResponsePreparedEvent struct {
	Request  *Request
	Response *Response
}

// EventDispatcher is the narrow interface the Router needs for broadcasting
// routing lifecycle events.
type EventDispatcher interface {
	Dispatch(eventName string, payload any)
	Listen(eventName string, listener any)
	HasListeners(eventName string) bool
	Forget(eventName string)
}

// InvalidSignatureError is returned when signature validation fails; it renders
// as a 403 with the message "Invalid signature.".
type InvalidSignatureError struct{}

func (e *InvalidSignatureError) Error() string {
	return "Invalid signature."
}

// Render converts the error into the 403 "Invalid signature." response.
func (e *InvalidSignatureError) Render() *Response {
	return NewResponse().SetCode(http.StatusForbidden).SetContent("Invalid signature.")
}

// StreamedResponseError wraps an error that occurred during streaming.
type StreamedResponseError struct {
	Inner error
}

func (e *StreamedResponseError) Error() string {
	return fmt.Sprintf("flow: streamed response error: %v", e.Inner)
}

func (e *StreamedResponseError) Unwrap() error {
	return e.Inner
}

// Render converts the streamed error into a 500 response.
func (e *StreamedResponseError) Render() *Response {
	return NewResponse().SetCode(500).SetContent("Streamed response failed")
}

// GetInnerException returns the wrapped error.
func (e *StreamedResponseError) GetInnerException() error {
	return e.Inner
}

// MissingRateLimiterError is returned when a named rate limiter is not
// registered ("Rate limiter [name] is not defined.").
type MissingRateLimiterError struct {
	Limiter string
}

func (e *MissingRateLimiterError) Error() string {
	return fmt.Sprintf("Rate limiter [%s] is not defined.", e.Limiter)
}

// ForMissingRateLimiter creates a MissingRateLimiterError for a named limiter.
func ForMissingRateLimiter(limiter string) *MissingRateLimiterError {
	return &MissingRateLimiterError{Limiter: limiter}
}

// ForMissingRateLimiterAndUser creates a MissingRateLimiterError whose limiter
// name is the "model::name" pair.
func ForMissingRateLimiterAndUser(limiter string, model string) *MissingRateLimiterError {
	return &MissingRateLimiterError{Limiter: model + "::" + limiter}
}

// ThrottleRequestsException is returned when a rate limit is exceeded. It
// carries the Retry-After and X-RateLimit-* headers, and the throttle middleware
// renders it with Render into the 429 response.
type ThrottleRequestsException struct {
	// Message is the exception message ("Too Many Attempts.").
	Message string
	// RetryAfter is the seconds until the next retry.
	RetryAfter int
	// Headers are the rate-limit headers attached to the rendered response.
	Headers map[string]string
}

func (e *ThrottleRequestsException) Error() string {
	return e.Message
}

// Render converts the exception into the 429 response with its rate-limit
// headers.
func (e *ThrottleRequestsException) Render() *Response {
	res := NewResponse().SetCode(http.StatusTooManyRequests).SetContent(e.Message)
	for name, value := range e.Headers {
		res.Header(name, value)
	}
	return res
}

// MethodNotAllowedResponse returns a 405 response with an Allow header.
func MethodNotAllowedResponse(allowed []string) *Response {
	res := NewResponse().SetCode(http.StatusMethodNotAllowed)
	res.Header("Allow", strings.Join(allowed, ", "))
	return res
}

// NewEventDispatcher creates a simple in-process event dispatcher.
func NewEventDispatcher() *eventDispatcher {
	return &eventDispatcher{listeners: make(map[string][]func(payload any))}
}

type eventDispatcher struct {
	listeners map[string][]func(payload any)
}

func (d *eventDispatcher) Dispatch(eventName string, payload any) {
	if fns, ok := d.listeners[eventName]; ok {
		for _, fn := range fns {
			fn(payload)
		}
	}
}

func (d *eventDispatcher) Listen(eventName string, listener any) {
	if fn, ok := listener.(func(payload any)); ok {
		d.listeners[eventName] = append(d.listeners[eventName], fn)
	}
}

func (d *eventDispatcher) HasListeners(eventName string) bool {
	return len(d.listeners[eventName]) > 0
}

func (d *eventDispatcher) Forget(eventName string) {
	delete(d.listeners, eventName)
}
