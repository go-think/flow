package flow

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResourceRegistration(t *testing.T) {
	r := New(nil, nil)
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
	r := New(nil, nil)
	r.APIResource("tasks", "TaskController")
	r.Register()

	assert.False(t, r.Has("tasks.create"))
	assert.False(t, r.Has("tasks.edit"))
	assert.True(t, r.Has("tasks.index"))
	assert.True(t, r.Has("tasks.update"))
}

func TestResourceOnlyExcept(t *testing.T) {
	r := New(nil, nil)
	r.Resource("notes", "NoteController").Only("Index", "Show")
	r.Register()
	assert.True(t, r.Has("notes.index"))
	assert.True(t, r.Has("notes.show"))
	assert.False(t, r.Has("notes.store"))

	r2 := New(nil, nil)
	r2.Resource("tags", "TagController").Except("Destroy")
	r2.Register()
	assert.True(t, r2.Has("tags.update"))
	assert.False(t, r2.Has("tags.destroy"))
}

func TestNestedResource(t *testing.T) {
	r := New(nil, nil)
	r.Resource("albums.photos", "PhotoController")
	r.Register()

	assert.Equal(t, "/albums/{album}/photos", r.Url("albums.photos.index", nil))
	assert.Equal(t, "/albums/{album}/photos/3", r.Url("albums.photos.show", map[string]string{"photo": "3"}))
}

func TestShallowNestedResource(t *testing.T) {
	r := New(nil, nil)
	r.Resource("albums.photos", "PhotoController").Shallow()
	r.Register()

	assert.Equal(t, "/albums/{album}/photos", r.Url("albums.photos.index", nil))
	assert.Equal(t, "/photos/3", r.Url("photos.show", map[string]string{"photo": "3"}))
}

func TestSingletonResource(t *testing.T) {
	r := New(nil, nil)
	r.Singleton("profile", "ProfileController")
	r.Register()

	assert.True(t, r.Has("profile.show"))
	assert.True(t, r.Has("profile.edit"))
	assert.True(t, r.Has("profile.update"))
	// the reference implementation singletons only expose destroy when creatable/destroyable.
	assert.False(t, r.Has("profile.destroy"))
	assert.False(t, r.Has("profile.store"))
	assert.Equal(t, "/profile", r.Url("profile.show", nil))

	rd := New(nil, nil)
	rd.Singleton("session", "SessionController").Destroyable()
	rd.Register()
	assert.True(t, rd.Has("session.destroy"))

	rc := New(nil, nil)
	rc.Singleton("settings", "SettingController").Creatable()
	rc.Register()
	assert.True(t, rc.Has("settings.create"))
	assert.True(t, rc.Has("settings.store"))
	assert.True(t, rc.Has("settings.destroy"))
}

func TestResourceNamesOverride(t *testing.T) {
	r := New(nil, nil)
	r.Resource("photos", "PhotoController").Names(map[string]string{"show": "photos.display"})
	r.Register()
	assert.True(t, r.Has("photos.display"))
	assert.False(t, r.Has("photos.show"))
}

func TestResourceMiddleware(t *testing.T) {
	r := New(nil, nil)
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

func routeByName(r Router, name string) *Route {
	for _, route := range r.GetRoutes() {
		if route.GetName() == name {
			return route
		}
	}
	return nil
}

// TestResourceWithTrashedOptIn verifies that withTrashed only applies when
// WithTrashed was called), targets the
// member actions by default, honours an explicit list, and never applies to
// singletons.
func TestResourceWithTrashedOptIn(t *testing.T) {
	// Without WithTrashed nothing is trashed.
	r := New(nil, nil)
	r.Resource("photos", "PhotoController")
	r.Register()
	for _, action := range []string{"index", "show", "edit", "update", "destroy"} {
		route := routeByName(r, "photos."+action)
		if assert.NotNil(t, route) {
			assert.False(t, route.AllowsTrashedBindings(), "photos.%s", action)
		}
	}

	// WithTrashed() marks the member actions only.
	r2 := New(nil, nil)
	r2.Resource("photos", "PhotoController").WithTrashed()
	r2.Register()
	assert.False(t, routeByName(r2, "photos.index").AllowsTrashedBindings())
	for _, action := range []string{"show", "edit", "update"} {
		assert.True(t, routeByName(r2, "photos."+action).AllowsTrashedBindings(), "photos.%s", action)
	}

	// An explicit list restricts the marked actions.
	r3 := New(nil, nil)
	r3.Resource("photos", "PhotoController").WithTrashed("Show")
	r3.Register()
	assert.True(t, routeByName(r3, "photos.show").AllowsTrashedBindings())
	assert.False(t, routeByName(r3, "photos.edit").AllowsTrashedBindings())
	assert.False(t, routeByName(r3, "photos.update").AllowsTrashedBindings())

	// Singletons never get withTrashed.
	r4 := New(nil, nil)
	r4.Singleton("profile", "ProfileController").WithTrashed()
	r4.Register()
	for _, action := range []string{"show", "edit", "update"} {
		assert.False(t, routeByName(r4, "profile."+action).AllowsTrashedBindings())
	}
}

// TestResourceMissingNotOnCollectionActions verifies the missing callback is
// not carried by the collection actions
// in addResourceIndex/Create/Store and addSingletonCreate/Store/Show).
func TestResourceMissingNotOnCollectionActions(t *testing.T) {
	missing := func(req *Request, err error) any { return nil }
	r := New(nil, nil)
	r.Resource("photos", "PhotoController").Missing(missing)
	r.Register()
	for _, action := range []string{"index", "create", "store"} {
		assert.Nil(t, routeByName(r, "photos."+action).GetMissing(), "photos.%s", action)
	}
	for _, action := range []string{"show", "edit", "update", "destroy"} {
		assert.NotNil(t, routeByName(r, "photos."+action).GetMissing(), "photos.%s", action)
	}

	// Singleton: create/store/show carry no missing callback.
	r2 := New(nil, nil)
	r2.Singleton("settings", "SettingController").Creatable().Missing(missing)
	r2.Register()
	for _, action := range []string{"create", "store", "show"} {
		assert.Nil(t, routeByName(r2, "settings."+action).GetMissing(), "settings.%s", action)
	}
	for _, action := range []string{"edit", "update", "destroy"} {
		assert.NotNil(t, routeByName(r2, "settings."+action).GetMissing(), "settings.%s", action)
	}
}

// TestResourceMiddlewareForOrderAndDedup verifies the the reference implementation semantics of
// middlewareFor: the base list is merged in front of the action-specific one
// and deduplicated keeping the first occurrence; a later Middleware() call
// re-merges the per-action lists with the new base behind them
// (the reference implementation: /middlewareFor +
// ).
func TestResourceMiddlewareForOrderAndDedup(t *testing.T) {
	r := New(nil, nil)
	r.Resource("photos", "PhotoController").Middleware("m1", "m2").
		MiddlewareFor([]string{"Show"}, "m2", "m3")
	r.Register()

	show := routeByName(r, "photos.show")
	assert.Equal(t, []any{"m1", "m2", "m3"}, show.GetMiddleware())
	index := routeByName(r, "photos.index")
	assert.Equal(t, []any{"m1", "m2"}, index.GetMiddleware())

	// middleware() after middlewareFor puts the new base behind the
	// per-action list.
	r2 := New(nil, nil)
	r2.Resource("photos", "PhotoController").
		MiddlewareFor([]string{"Show"}, "f").Middleware("b")
	r2.Register()
	assert.Equal(t, []any{"f", "b"}, routeByName(r2, "photos.show").GetMiddleware())
	assert.Equal(t, []any{"b"}, routeByName(r2, "photos.index").GetMiddleware())
}

// TestResourceExcludedMiddlewareForDedup verifies the excluded list is
// merged with the base and deduplicated
// )).
func TestResourceExcludedMiddlewareForDedup(t *testing.T) {
	r := New(nil, nil)
	r.Resource("photos", "PhotoController").WithoutMiddleware("x").
		WithoutMiddlewareFor([]string{"Show"}, "x", "y")
	r.Register()

	assert.Equal(t, []any{"x", "y"}, routeByName(r, "photos.show").ExcludedMiddleware())
	assert.Equal(t, []any{"x"}, routeByName(r, "photos.index").ExcludedMiddleware())
}

// TestResourceVariadicOptions verifies the variadic option functions are
// applied in order before registration.
func TestResourceVariadicOptions(t *testing.T) {
	r := New(nil, nil)
	r.Resource("photos", "PhotoController",
		WithBaseName("gallery"),
		func(o *ResourceOptions) { o.Only = []string{"Show"} },
		func(o *ResourceOptions) { o.Middleware = []any{"auth"} },
	).As("admin")
	r.Register()

	assert.NotNil(t, routeByName(r, "admin.gallery.show"))
	assert.Nil(t, routeByName(r, "photos.index"))
	assert.Equal(t, []any{"auth"}, routeByName(r, "admin.gallery.show").GetMiddleware())

	// Bulk registrations forward the options too.
	r2 := New(nil, nil)
	r2.Resources(map[string]any{"photos": "PhotoController"},
		func(o *ResourceOptions) { o.Only = []string{"Index"} })
	r2.Register()
	assert.NotNil(t, routeByName(r2, "photos.index"))
	assert.Nil(t, routeByName(r2, "photos.show"))

	// APIResource options compose with the API default (user Only wins).
	r3 := New(nil, nil)
	r3.APIResource("tasks", "TaskController",
		func(o *ResourceOptions) { o.Only = []string{"Index", "Store"} })
	r3.Register()
	assert.NotNil(t, routeByName(r3, "tasks.index"))
	assert.NotNil(t, routeByName(r3, "tasks.store"))
	assert.Nil(t, routeByName(r3, "tasks.show"))
}

// TestResourceBaseNameAndAsPrefix verifies the string form of names and the
// "as" name prefix.
func TestResourceBaseNameAndAsPrefix(t *testing.T) {
	r := New(nil, nil)
	r.Resource("photos", "PhotoController").BaseName("media")
	r.Register()
	assert.NotNil(t, routeByName(r, "media.show"))
	assert.Nil(t, routeByName(r, "photos.show"))

	// As() joins the prefix with a dot.
	r2 := New(nil, nil)
	r2.Resource("photos", "PhotoController").As("admin")
	r2.Register()
	assert.NotNil(t, routeByName(r2, "admin.photos.show"))
	assert.NotNil(t, routeByName(r2, "admin.photos.index"))
}

// TestPendingResourceWhereConstraints verifies the regular expression
// convenience methods (the reference implementation: CreatesRegularExpressionRouteConstraints on
// the pending resource registrations).
func TestPendingResourceWhereConstraints(t *testing.T) {
	r := New(nil, nil)
	r.Resource("photos", "PhotoController").WhereNumber("photo")
	r.Register()
	assert.Equal(t, "[0-9]+", routeByName(r, "photos.show").Wheres()["photo"])

	r2 := New(nil, nil)
	r2.Resource("photos", "PhotoController").WhereAlpha("photo")
	r2.Register()
	assert.Equal(t, "[a-zA-Z]+", routeByName(r2, "photos.show").Wheres()["photo"])

	r3 := New(nil, nil)
	r3.Resource("photos", "PhotoController").WhereAlphaNumeric("photo")
	r3.Register()
	assert.Equal(t, "[a-zA-Z0-9]+", routeByName(r3, "photos.show").Wheres()["photo"])

	r4 := New(nil, nil)
	r4.Resource("photos", "PhotoController").WhereUuid("photo")
	r4.Register()
	assert.Equal(t, `[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}`,
		routeByName(r4, "photos.show").Wheres()["photo"])

	r5 := New(nil, nil)
	r5.Resource("photos", "PhotoController").WhereUlid("photo")
	r5.Register()
	assert.Equal(t, `[0-7][0-9a-hjkmnp-tv-zA-HJKMNP-TV-Z]{25}`, routeByName(r5, "photos.show").Wheres()["photo"])

	r6 := New(nil, nil)
	r6.Resource("photos", "PhotoController").WhereIn("photo", []string{"one", "two"})
	r6.Register()
	assert.Equal(t, "one|two", routeByName(r6, "photos.show").Wheres()["photo"])
}

// TestGetResourceParametersAndVerbs verifies the global getters
// .
func TestGetResourceParametersAndVerbs(t *testing.T) {
	r := New(nil, nil)
	assert.Empty(t, r.GetResourceParameters())
	assert.Empty(t, r.GetResourceVerbs())

	rt := r.(*router)
	rt.SetResourceParameters(map[string]string{"users": "admin_user"})
	rt.SetResourceVerbs(map[string]string{"create": "build"})
	assert.Equal(t, map[string]string{"users": "admin_user"}, r.GetResourceParameters())
	assert.Equal(t, map[string]string{"create": "build"}, r.GetResourceVerbs())
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

// TestResourceScopedFieldsFilteredByURI verifies that scoped binding fields
// are applied only for the parameters that actually occur in a route's URI
// (the reference implementation: setResourceBindingFields —
// preg_match_all over the URI placeholders): collection routes (index/store/
// create) carry no id placeholder and receive no binding field for it.
func TestResourceScopedFieldsFilteredByURI(t *testing.T) {
	r := NewRouter(nil, nil)
	r.Resource("users.posts", "PostController").
		Scoped(map[string]string{"post": "slug", "user": "uuid"})
	r.Register()

	// Member routes carry both placeholders: both fields apply.
	show := routeByName(r, "users.posts.show")
	require.NotNil(t, show)
	assert.Contains(t, show.GetUri(), "{user}")
	assert.Contains(t, show.GetUri(), "{post}")
	assert.Equal(t, "uuid", show.BindingFieldFor("user"))
	assert.Equal(t, "slug", show.BindingFieldFor("post"))

	// Collection routes carry no {post} placeholder: the post field is not
	// applied there (the reference implementation array_fill_keys/array_intersect_key on the URI
	// matches), while the {user} field still is.
	index := routeByName(r, "users.posts.index")
	require.NotNil(t, index)
	assert.Contains(t, index.GetUri(), "{user}")
	assert.NotContains(t, index.GetUri(), "{post}")
	assert.Equal(t, "uuid", index.BindingFieldFor("user"))
	assert.Equal(t, "", index.BindingFieldFor("post"), "no {post} placeholder in the index URI")

	store := routeByName(r, "users.posts.store")
	require.NotNil(t, store)
	assert.Equal(t, "", store.BindingFieldFor("post"))

	create := routeByName(r, "users.posts.create")
	require.NotNil(t, create)
	assert.Equal(t, "", create.BindingFieldFor("post"))
	assert.Equal(t, "uuid", create.BindingFieldFor("user"))
}

// TestResourceActionNamesAreCaseSensitive verifies the the reference implementation-mirrored
// case handling of only/except: user-provided action names are normalized
// once ("index" → "Index") and then compared exactly
// , so arbitrary casing does not match.
func TestResourceActionNamesAreCaseSensitive(t *testing.T) {
	// The conventional lower-case spellings normalize onto the canonical
	// capitalized verb names.
	r := New(nil, nil)
	r.Resource("notes", "NoteController").Only("index", "show")
	r.Register()
	assert.True(t, r.Has("notes.index"))
	assert.True(t, r.Has("notes.show"))
	assert.False(t, r.Has("notes.store"))

	r2 := New(nil, nil)
	r2.Resource("tags", "TagController").Except("destroy")
	r2.Register()
	assert.True(t, r2.Has("tags.update"))
	assert.False(t, r2.Has("tags.destroy"))

	// Beyond the normalization the match is exact: a name that is neither the
	// canonical nor the conventional spelling matches nothing.
	r3 := New(nil, nil)
	r3.Resource("pics", "PicController").Only("INDEX")
	r3.Register()
	assert.False(t, r3.Has("pics.index"), "case-sensitive beyond the normalization: INDEX does not match Index")
	assert.False(t, r3.Has("pics.store"))
}
