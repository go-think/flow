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

// Send sets the object being sent through the pipeline
func (p *Pipeline) Send(req *Request) *Pipeline {
	clone := *p
	clone.passable = req
	return &clone
}

// Pipe Push a Middleware Handler to the pipeline
func (p *Pipeline) Pipe(m Handler) *Pipeline {
	p.handlers = append(p.handlers, m)
	return p
}

// Through Batch push Middleware Handlers to the pipeline
func (p *Pipeline) Through(hls []Handler) *Pipeline {
	p.handlers = append(p.handlers, hls...)
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
	return handler.Process(req, func(nextReq *Request) any {
		return p.dispatch(index+1, nextReq, destination)
	})
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
