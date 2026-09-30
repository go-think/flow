package flow

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRouteRegistrar_FluentGroup(t *testing.T) {
	r := NewRouter(nil, nil)

	r.Registrar().
		Prefix("/admin").
		As("admin.").
		WhereNumber("id").
		Group(func(group Router) {
			group.Get("/users/{id}", func(id string) string {
				return "user:" + id
			})
		})

	// Valid number id
	req := httptest.NewRequest("GET", "/admin/users/42", nil)
	resp := r.Dispatch(req)
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode())
	}
	if resp.GetContent() != "user:42" {
		t.Fatalf("expected 'user:42', got '%s'", resp.GetContent())
	}

	// Non-number id rejected by constraint
	reqInvalid := httptest.NewRequest("GET", "/admin/users/abc", nil)
	respInvalid := r.Dispatch(reqInvalid)
	if respInvalid.StatusCode() != http.StatusNotFound {
		t.Fatalf("expected 404 for non-number id, got %d", respInvalid.StatusCode())
	}
}

func TestRouteRegistrar_DirectVerbRegistration(t *testing.T) {
	r := NewRouter(nil, nil)

	r.Registrar().
		Prefix("/api").
		Middleware(func(req *Request, next Closure) any {
			req.Request.Header.Set("X-Api-Middleware", "active")
			return next(req)
		}).
		Get("/ping", func(req *Request) string {
			return req.Header("X-Api-Middleware")
		})

	req := httptest.NewRequest("GET", "/api/ping", nil)
	resp := r.Dispatch(req)
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode())
	}
	if resp.GetContent() != "active" {
		t.Fatalf("expected 'active', got '%s'", resp.GetContent())
	}
}

func TestRouteRegistrar_ZeroArgGroup(t *testing.T) {
	r := NewRouter(nil, nil)

	r.Registrar().Prefix("/v1").Group(func() {
		r.Get("/v1/hello", func() string {
			return "world"
		})
	})

	req := httptest.NewRequest("GET", "/v1/hello", nil)
	resp := r.Dispatch(req)
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode())
	}
	if resp.GetContent() != "world" {
		t.Fatalf("expected 'world', got '%s'", resp.GetContent())
	}
}

func TestWhereMap_RouteAndRouter(t *testing.T) {
	r := NewRouter(nil, nil)

	r.WhereMap(map[string]string{
		"category": "[a-z]+",
		"item":     "[0-9]+",
	}).Get("/shop/{category}/{item}", func(category, item string) string {
		return category + ":" + item
	})

	// Match valid
	reqValid := httptest.NewRequest("GET", "/shop/books/123", nil)
	respValid := r.Dispatch(reqValid)
	if respValid.StatusCode() != http.StatusOK || respValid.GetContent() != "books:123" {
		t.Fatalf("expected books:123, got code %d content '%s'", respValid.StatusCode(), respValid.GetContent())
	}

	// Match invalid category
	reqInvalidCat := httptest.NewRequest("GET", "/shop/123/123", nil)
	respInvalidCat := r.Dispatch(reqInvalidCat)
	if respInvalidCat.StatusCode() != http.StatusNotFound {
		t.Fatalf("expected 404 for invalid category, got %d", respInvalidCat.StatusCode())
	}

	// Match invalid item
	reqInvalidItem := httptest.NewRequest("GET", "/shop/books/abc", nil)
	respInvalidItem := r.Dispatch(reqInvalidItem)
	if respInvalidItem.StatusCode() != http.StatusNotFound {
		t.Fatalf("expected 404 for invalid item, got %d", respInvalidItem.StatusCode())
	}
}

func TestRouteRegistrar_DefaultsAndMetadata(t *testing.T) {
	r := NewRouter(nil, nil)

	r.Registrar().
		Prefix("/loc").
		Default("locale", "en").
		Defaults(map[string]any{"format": "json"}).
		Metadata(map[string]any{"section": "localization"}).
		Group(func(group Router) {
			group.Get("/welcome/{locale?}", func(req *Request) string {
				loc := req.GetRouteParam("locale")
				sec := req.Route().Metadata("section")
				return loc + ":" + sec.(string)
			})
		})

	req := httptest.NewRequest("GET", "/loc/welcome", nil)
	resp := r.Dispatch(req)
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode())
	}
	if resp.GetContent() != "en:localization" {
		t.Fatalf("expected 'en:localization', got '%s'", resp.GetContent())
	}
}

