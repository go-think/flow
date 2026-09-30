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

// ExceptionHandler defines the contract for handling exceptions within the pipeline.
type ExceptionHandler interface {
	Report(err any)
	Render(req *Request, err any) any
}

type Pipeline struct {
	passable         *Request
	handlers         []Handler
	exceptionHandler ExceptionHandler
}

// NewPipeline returns a new Pipeline
func NewPipeline() *Pipeline {
	return &Pipeline{
		handlers: make([]Handler, 0),
	}
}

// WithExceptionHandler sets the exception handler for this pipeline run.
func (p *Pipeline) WithExceptionHandler(handler ExceptionHandler) *Pipeline {
	p.exceptionHandler = handler
	return p
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

// handleCarry converts a Responsable result to a Response.
func (p *Pipeline) handleCarry(req *Request, result any) any {
	if responsable, ok := result.(Responsable); ok {
		return responsable.ToResponse(req)
	}
	return result
}

// handleException handles an exception occurring within a pipe slice.
func (p *Pipeline) handleException(req *Request, e any) any {
	if p.exceptionHandler == nil {
		panic(e)
	}
	p.exceptionHandler.Report(e)
	response := p.exceptionHandler.Render(req, e)
	return p.handleCarry(req, response)
}

func (p *Pipeline) dispatch(index int, req *Request, destination Closure) (result any) {
	if index >= len(p.handlers) {
		if destination != nil {
			if p.exceptionHandler != nil {
				defer func() {
					if rec := recover(); rec != nil {
						result = p.handleException(req, rec)
					}
				}()
			}
			return destination(req)
		}
		return nil
	}
	handler := p.handlers[index]
	if p.exceptionHandler != nil {
		defer func() {
			if rec := recover(); rec != nil {
				result = p.handleException(req, rec)
			}
		}()
	}
	raw := handler.Process(req, func(nextReq *Request) any {
		return p.dispatch(index+1, nextReq, destination)
	})
	return p.handleCarry(req, raw)
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
