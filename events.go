package flow

import (
	"fmt"
	"net/http"
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

// InvalidSignatureError is returned when signature validation fails.
type InvalidSignatureError struct{}

func (e *InvalidSignatureError) Error() string {
	return "flow: invalid signature"
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

// MissingRateLimiterError is returned when a named rate limiter is not
// registered.
type MissingRateLimiterError struct {
	Limiter string
}

func (e *MissingRateLimiterError) Error() string {
	return fmt.Sprintf("flow: rate limiter [%s] is not defined", e.Limiter)
}

// MethodNotAllowedResponse returns a 405 response with an Allow header.
func MethodNotAllowedResponse(allowed []string) *Response {
	res := NewResponse().SetCode(http.StatusMethodNotAllowed)
	res.Header("Allow", joinStrings(allowed, ", "))
	return res
}
