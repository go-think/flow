package flow

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResourceRegistration(t *testing.T) {
	r := New()
	r.Resource("photos", "PhotoController")
	r.Register()

	expected := map[string]string{
		"GET /photos":              "PhotoController@Index",
		"POST /photos":             "PhotoController@Store",
		"GET /photos/create":       "PhotoController@Create",
		"GET /photos/{photo}":      "PhotoController@Show",
		"GET /photos/{photo}/edit": "PhotoController@Edit",
		"PUT /photos/{photo}":      "PhotoController@Update",
		"DELETE /photos/{photo}":   "PhotoController@Destroy",
	}
	for key, action := range expected {
		assert.True(t, routeRegistered(r, key, action), "expected %s -> %s", key, action)
	}

	// Route names.
	assert.True(t, r.Has("photos.index"))
	assert.True(t, r.Has("photos.show"))
	assert.Equal(t, "/photos/7", r.Url("photos.show", map[string]string{"photo": "7"}))
}

func TestAPIResourceExcludesFormHelpers(t *testing.T) {
	r := New()
	r.APIResource("tasks", "TaskController")
	r.Register()

	assert.False(t, r.Has("tasks.create"))
	assert.False(t, r.Has("tasks.edit"))
	assert.True(t, r.Has("tasks.index"))
	assert.True(t, r.Has("tasks.update"))
}

func TestResourceOnlyExcept(t *testing.T) {
	r := New()
	r.Resource("notes", "NoteController").Only("Index", "Show")
	r.Register()
	assert.True(t, r.Has("notes.index"))
	assert.True(t, r.Has("notes.show"))
	assert.False(t, r.Has("notes.store"))

	r2 := New()
	r2.Resource("tags", "TagController").Except("Destroy")
	r2.Register()
	assert.True(t, r2.Has("tags.update"))
	assert.False(t, r2.Has("tags.destroy"))
}

func TestNestedResource(t *testing.T) {
	r := New()
	r.Resource("albums.photos", "PhotoController")
	r.Register()

	assert.Equal(t, "/albums/{album}/photos", r.Url("photos.index", nil))
	assert.Equal(t, "/albums/{album}/photos/3", r.Url("photos.show", map[string]string{"photo": "3"}))
}

func TestShallowNestedResource(t *testing.T) {
	r := New()
	r.Resource("albums.photos", "PhotoController").Shallow()
	r.Register()

	assert.Equal(t, "/albums/{album}/photos", r.Url("photos.index", nil))
	assert.Equal(t, "/photos/3", r.Url("photos.show", map[string]string{"photo": "3"}))
}

func TestSingletonResource(t *testing.T) {
	r := New()
	r.Singleton("profile", "ProfileController")
	r.Register()

	assert.True(t, r.Has("profile.show"))
	assert.True(t, r.Has("profile.edit"))
	assert.True(t, r.Has("profile.update"))
	assert.True(t, r.Has("profile.destroy"))
	assert.False(t, r.Has("profile.store"))
	assert.Equal(t, "/profile", r.Url("profile.show", nil))
}

func TestResourceNamesOverride(t *testing.T) {
	r := New()
	r.Resource("photos", "PhotoController").Names(map[string]string{"show": "photos.display"})
	r.Register()
	assert.True(t, r.Has("photos.display"))
	assert.False(t, r.Has("photos.show"))
}

func TestResourceMiddleware(t *testing.T) {
	r := New()
	seen := ""
	r.RegisterController("PhotoController", &testUserController{})
	r.Resource("photos", "PhotoController").Middleware(func(req *Request, next Closure) any {
		seen = "resource-mw"
		return next(req)
	}).Only("Show")
	r.Register()

	httpReq, _ := http.NewRequest("GET", "/photos/1", nil)
	req := NewRequest(httpReq)
	req.SetResponseWriter(httptest.NewRecorder())
	_ = r.Dispatch(req)
	assert.Equal(t, "resource-mw", seen)
}

func routeRegistered(r Router, key, action string) bool {
	var method, uri string
	fmt.Sscanf(key, "%s %s", &method, &uri)
	for _, route := range r.GetRoutes() {
		if route.URI() != uri {
			continue
		}
		if matchMethods(method, route.Methods()) {
			if ca, ok := route.Handler().(ControllerAction); ok {
				return fmt.Sprintf("%s@%s", ca.Controller, ca.Method) == action
			}
		}
	}
	return false
}
