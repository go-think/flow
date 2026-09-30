package flow

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type customInterceptingCallableDispatcher struct {
	called bool
}

func (d *customInterceptingCallableDispatcher) Dispatch(route *Route, callable any, request *Request, params []*parameter) (any, error) {
	d.called = true
	// Execute default dispatcher first
	res, err := defaultCallableDispatcherInstance.Dispatch(route, callable, request, params)
	if err != nil {
		return nil, err
	}
	// Intercept and wrap result
	return fmt.Sprintf("intercepted:[%v]", res), nil
}

func TestCallableDispatcher_CustomInterception(t *testing.T) {
	r := NewRouter(nil, nil)
	customDispatcher := &customInterceptingCallableDispatcher{}
	r.SetCallableDispatcher(customDispatcher)

	if r.GetCallableDispatcher() != customDispatcher {
		t.Fatalf("expected GetCallableDispatcher to return customDispatcher")
	}

	r.Get("/hello/{name}", func(name string) string {
		return "hello " + name
	})

	req := httptest.NewRequest("GET", "/hello/gopher", nil)
	resp := r.Dispatch(req)

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode())
	}
	if !customDispatcher.called {
		t.Fatalf("expected custom CallableDispatcher to be called")
	}
	if resp.GetContent() != "intercepted:[hello gopher]" {
		t.Fatalf("expected 'intercepted:[hello gopher]', got '%s'", resp.GetContent())
	}
}
