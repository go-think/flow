package flow

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type sampleController struct{}

func (s *sampleController) Show(id string) string {
	return "sample:" + id
}

func TestRouteList_And_Summary(t *testing.T) {
	r := NewRouter(nil, nil)

	r.Get("/users/{id}", func(id string) string {
		return "user:" + id
	}).As("users.show").Middleware("auth", "throttle:60,1")

	r.Post("/users", func() string {
		return "created"
	}).As("users.store")

	r.Get("/profile/{id}", &ControllerAction{
		Controller: &sampleController{},
		Method:     "Show",
	}).As("profile.show")

	summaries := r.RouteList()
	if len(summaries) < 3 {
		t.Fatalf("expected at least 3 routes, got %d", len(summaries))
	}

	// Verify route details
	var usersShowFound, profileShowFound bool
	for _, s := range summaries {
		if s.Name == "users.show" {
			usersShowFound = true
			if s.URI != "/users/{id}" {
				t.Errorf("expected URI /users/{id}, got %s", s.URI)
			}
			if len(s.Middleware) != 2 || s.Middleware[0] != "auth" {
				t.Errorf("unexpected middleware list: %v", s.Middleware)
			}
		}
		if s.Name == "profile.show" {
			profileShowFound = true
			if !strings.Contains(s.Action, "Show") {
				t.Errorf("expected action to contain Show, got %s", s.Action)
			}
		}
	}

	if !usersShowFound {
		t.Errorf("users.show route was not found in summary")
	}
	if !profileShowFound {
		t.Errorf("profile.show route was not found in summary")
	}

	// Verify formatted table output
	formatted := r.FormatRouteList()
	if !strings.Contains(formatted, "METHOD") || !strings.Contains(formatted, "URI") {
		t.Fatalf("expected formatted table to have headers, got:\n%s", formatted)
	}
	if !strings.Contains(formatted, "/users/{id}") || !strings.Contains(formatted, "users.show") {
		t.Fatalf("expected formatted table to contain route entries, got:\n%s", formatted)
	}
}

func TestRoute_GetController(t *testing.T) {
	r := NewRouter(nil, nil)
	ctrl := &sampleController{}

	route := r.Get("/sample/{id}", &ControllerAction{
		Controller: ctrl,
		Method:     "Show",
	})

	if rc, ok := route.(*routeChain); ok {
		if rc.route.GetController() != ctrl {
			t.Fatalf("expected GetController to return ctrl instance")
		}
		if rc.route.Controller() != ctrl {
			t.Fatalf("expected Controller() to return ctrl instance")
		}
	}
}

func TestGroupStack(t *testing.T) {
	r := NewRouter(nil, nil)

	if r.HasGroupStack() {
		t.Fatalf("expected root router HasGroupStack() to be false")
	}

	r.Prefix("/admin").Name("admin.").Middleware("auth").Group(func(adminGroup Router) {
		if !adminGroup.HasGroupStack() {
			t.Fatalf("expected adminGroup HasGroupStack() to be true")
		}
		stack := adminGroup.GetGroupStack()
		if len(stack) != 1 {
			t.Fatalf("expected stack length 1, got %d", len(stack))
		}
		if stack[0].Prefix != "/admin" || stack[0].Name != "admin." {
			t.Fatalf("unexpected group stack attributes: %+v", stack[0])
		}

		adminGroup.Prefix("/users").Group(func(userGroup Router) {
			if !userGroup.HasGroupStack() {
				t.Fatalf("expected userGroup HasGroupStack() to be true")
			}
			nestedStack := userGroup.GetGroupStack()
			if len(nestedStack) != 2 {
				t.Fatalf("expected nested stack length 2, got %d", len(nestedStack))
			}

			userGroup.Get("/{id}", func(id string) string {
				return "admin-user:" + id
			}).As("show")
		})
	})

	// Dispatch to verify routing works as declared
	req := httptest.NewRequest("GET", "/admin/users/42", nil)
	resp := r.Dispatch(req)
	if resp.StatusCode() != http.StatusOK || resp.GetContent() != "admin-user:42" {
		t.Fatalf("expected 200 admin-user:42, got %d '%s'", resp.StatusCode(), resp.GetContent())
	}
}
