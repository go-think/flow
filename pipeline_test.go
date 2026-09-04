package flow

import (
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPipeline_BasicAndOrder(t *testing.T) {
	var trace []string

	p := NewPipeline()
	p.Pipe(HandlerFunc(func(req *Request, next Closure) any {
		trace = append(trace, "m1_in")
		res := next(req)
		trace = append(trace, "m1_out")
		return res
	}))
	p.Pipe(HandlerFunc(func(req *Request, next Closure) any {
		trace = append(trace, "m2_in")
		res := next(req)
		trace = append(trace, "m2_out")
		return res
	}))

	httpReq, _ := http.NewRequest("GET", "/test", nil)
	req := NewRequest(httpReq)

	res := p.Send(req).Then(func(r *Request) any {
		trace = append(trace, "destination")
		return "result"
	})

	assert.Equal(t, "result", res)
	expectedTrace := []string{"m1_in", "m2_in", "destination", "m2_out", "m1_out"}
	assert.Equal(t, expectedTrace, trace)
}

func TestPipeline_ShortCircuit(t *testing.T) {
	var trace []string

	p := NewPipeline()
	p.Pipe(HandlerFunc(func(req *Request, next Closure) any {
		trace = append(trace, "m1_in")
		return "short_circuited"
	}))
	p.Pipe(HandlerFunc(func(req *Request, next Closure) any {
		trace = append(trace, "m2_in")
		return next(req)
	}))

	httpReq, _ := http.NewRequest("GET", "/test", nil)
	req := NewRequest(httpReq)

	res := p.Send(req).Then(func(r *Request) any {
		trace = append(trace, "destination")
		return "dest"
	})

	assert.Equal(t, "short_circuited", res)
	assert.Equal(t, []string{"m1_in"}, trace)
}

func TestPipeline_WithoutDestination(t *testing.T) {
	p := NewPipeline()
	executed := false
	p.Pipe(HandlerFunc(func(req *Request, next Closure) any {
		executed = true
		return next(req)
	}))

	httpReq, _ := http.NewRequest("GET", "/test", nil)
	req := NewRequest(httpReq)

	res := p.Send(req).Then(nil)
	assert.True(t, executed)
	assert.Nil(t, res)
}

func TestPipeline_Empty(t *testing.T) {
	p := NewPipeline()
	httpReq, _ := http.NewRequest("GET", "/test", nil)
	req := NewRequest(httpReq)

	// Empty pipeline with destination
	res1 := p.Send(req).Then(func(r *Request) any {
		return "dest_empty"
	})
	assert.Equal(t, "dest_empty", res1)

	// Empty pipeline without destination
	res2 := p.Send(req).Then(nil)
	assert.Nil(t, res2)
}

func TestPipeline_Through(t *testing.T) {
	p := NewPipeline()
	var list []int

	h1 := HandlerFunc(func(req *Request, next Closure) any {
		list = append(list, 1)
		return next(req)
	})
	h2 := HandlerFunc(func(req *Request, next Closure) any {
		list = append(list, 2)
		return next(req)
	})

	p.Through([]Handler{h1, h2})

	httpReq, _ := http.NewRequest("GET", "/test", nil)
	req := NewRequest(httpReq)
	p.Send(req).Then(nil)

	assert.Equal(t, []int{1, 2}, list)
}

func TestPipeline_ServeHTTP(t *testing.T) {
	// 1. Response
	p1 := NewPipeline()
	p1.Pipe(HandlerFunc(func(req *Request, next Closure) any {
		return NewResponse().SetContent("hello response")
	}))
	w1 := httptest.NewRecorder()
	r1, _ := http.NewRequest("GET", "/", nil)
	p1.ServeHTTP(w1, r1)
	assert.Equal(t, "hello response", w1.Body.String())

	// 2. HTML template
	p2 := NewPipeline()
	p2.Pipe(HandlerFunc(func(req *Request, next Closure) any {
		return template.HTML("<b>bold</b>")
	}))
	w2 := httptest.NewRecorder()
	r2, _ := http.NewRequest("GET", "/", nil)
	p2.ServeHTTP(w2, r2)
	assert.Equal(t, "<b>bold</b>", w2.Body.String())

	// 3. String content
	p3 := NewPipeline()
	p3.Pipe(HandlerFunc(func(req *Request, next Closure) any {
		return "plain string"
	}))
	w3 := httptest.NewRecorder()
	r3, _ := http.NewRequest("GET", "/", nil)
	p3.ServeHTTP(w3, r3)
	assert.Equal(t, "plain string", w3.Body.String())
}

func TestPipeline_SendThenAndThenReturn(t *testing.T) {
	// 1. Send().Through().Then()
	httpReq, _ := http.NewRequest("GET", "/send-then", nil)
	req := NewRequest(httpReq)

	res := NewPipeline().
		Send(req).
		Through([]Handler{
			HandlerFunc(func(r *Request, next Closure) any {
				r.Set("visited", true)
				return next(r)
			}),
		}).
		Then(func(r *Request) any {
			val, _ := r.Get("visited")
			return val
		})

	assert.Equal(t, true, res)

	// 2. Send().Through().ThenReturn()
	httpReq2, _ := http.NewRequest("GET", "/then-return", nil)
	req2 := NewRequest(httpReq2)

	returned := NewPipeline().
		Send(req2).
		Through([]Handler{
			HandlerFunc(func(r *Request, next Closure) any {
				r.Set("cleaned", "yes")
				return next(r)
			}),
		}).
		ThenReturn()

	assert.Equal(t, req2, returned)
	cleanedVal, _ := req2.Get("cleaned")
	assert.Equal(t, "yes", cleanedVal)
}

func TestPipeline_ConcurrentSend(t *testing.T) {
	globalPipe := NewPipeline()
	globalPipe.Pipe(HandlerFunc(func(req *Request, next Closure) any {
		return next(req)
	}))

	const concurrency = 50
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			path := fmt.Sprintf("/user/%d", idx)
			httpReq, _ := http.NewRequest("GET", path, nil)
			req := NewRequest(httpReq)

			res := globalPipe.Send(req).Then(func(r *Request) any {
				return r.Request.URL.Path
			})

			assert.Equal(t, path, res)
		}(i)
	}

	wg.Wait()
}


