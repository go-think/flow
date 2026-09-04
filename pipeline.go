package flow

import (
	"html/template"
	"net/http"
)

// Closure Anonymous function, Used in Middleware Handler
type Closure func(req *Request) any

// Handler Middleware Handler interface
type Handler interface {
	Process(request *Request, next Closure) any
}

type Pipeline struct {
	passable *Request
	handlers []Handler
}

// NewPipeline returns a new Pipeline
func NewPipeline() *Pipeline {
	return &Pipeline{
		handlers: make([]Handler, 0),
	}
}

// Send sets the object being sent through the pipeline. Like the reference implementation
// send() it mutates the pipeline in place and returns itself.
func (p *Pipeline) Send(req *Request) *Pipeline {
	p.passable = req
	return p
}

// Pipe Push a Middleware Handler to the pipeline, appending to the existing
// ones).
func (p *Pipeline) Pipe(m Handler) *Pipeline {
	p.handlers = append(p.handlers, m)
	return p
}

// Through sets the Middleware Handlers of the pipeline, replacing any pipes
// configured previously).
func (p *Pipeline) Through(hls []Handler) *Pipeline {
	p.handlers = hls
	return p
}

// Then runs the pipeline with a final destination callback
func (p *Pipeline) Then(destination Closure) any {
	return p.dispatch(0, p.passable, destination)
}

// ThenReturn runs the pipeline and returns the result
func (p *Pipeline) ThenReturn() any {
	return p.Then(func(req *Request) any {
		return req
	})
}

func (p *Pipeline) dispatch(index int, req *Request, destination Closure) any {
	if index >= len(p.handlers) {
		if destination != nil {
			return destination(req)
		}
		return nil
	}
	handler := p.handlers[index]
	result := handler.Process(req, func(nextReq *Request) any {
		return p.dispatch(index+1, nextReq, destination)
	})
	// A Responsable pipe result is converted into a response before being
	// handed back (the reference implementation: —
	// a Responsable result is converted through ToResponse).
	// Responsable is defined in router.go alongside the response preparation
	// that shares the contract.
	if responsable, ok := result.(Responsable); ok {
		return responsable.ToResponse(req)
	}
	return result
}

// ServeHTTP Implement http.Handler safely
func (p *Pipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	request := NewRequest(r)
	request.SetResponseWriter(w)
	request.CookieHandler = ParseCookieHandler()

	result := p.Send(request).Then(nil)

	switch res := result.(type) {
	case *Response:
		res.Send(w)
	case Response:
		res.Send(w)
	case template.HTML:
		NewResponse().SetContent(string(res)).Send(w)
	case http.Handler:
		res.ServeHTTP(w, r)
	default:
		NewResponse().SetContent(FormatContent(result)).Send(w)
	}
}
