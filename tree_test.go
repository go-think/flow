package flow

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRadixTree_BasicAndParams(t *testing.T) {
	root := &node{}

	root.addRoute("/", "root_handler")
	root.addRoute("/user/:id", "user_detail")
	root.addRoute("/user/:id/posts", "user_posts")
	root.addRoute("/static/*filepath", "static_handler")

	// 1. Test root node matching
	h, ps, tsr := root.getValue("/")
	assert.Equal(t, "root_handler", h)
	assert.False(t, tsr)
	assert.Empty(t, ps)

	// 2. Test named parameter extraction
	h, ps, tsr = root.getValue("/user/123")
	assert.Equal(t, "user_detail", h)
	assert.False(t, tsr)
	val, ok := ps.Get("id")
	assert.True(t, ok)
	assert.Equal(t, "123", val)

	// 3. Test deep named parameters
	h, ps, tsr = root.getValue("/user/456/posts")
	assert.Equal(t, "user_posts", h)
	val, ok = ps.Get("id")
	assert.Equal(t, "456", val)

	// 4. Test wildcard matching
	h, ps, tsr = root.getValue("/static/css/style.css")
	assert.Equal(t, "static_handler", h)
	val, ok = ps.Get("filepath")
	assert.Equal(t, "css/style.css", val)
}

func TestRadixTree_PrefixSplittingAndNotFound(t *testing.T) {
	root := &node{}

	root.addRoute("/search", "search_all")
	root.addRoute("/see", "see_page")
	root.addRoute("/season", "season_page")

	// 1. Matched routes with split prefixes
	h1, _, _ := root.getValue("/search")
	assert.Equal(t, "search_all", h1)

	h2, _, _ := root.getValue("/see")
	assert.Equal(t, "see_page", h2)

	h3, _, _ := root.getValue("/season")
	assert.Equal(t, "season_page", h3)

	// 2. Unmatched path
	hMissing, _, _ := root.getValue("/sea")
	assert.Nil(t, hMissing)

	hNotExists, _, _ := root.getValue("/other")
	assert.Nil(t, hNotExists)
}

