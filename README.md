# Flow

**Flow is a modular HTTP engine, trie-based router, and middleware pipeline for Go.**

[![Build Status](https://github.com/go-think/flow/actions/workflows/build.yml/badge.svg)](https://github.com/go-think/flow/actions/workflows/build.yml)
[![Coverage Status](https://coveralls.io/repos/github/go-think/flow/badge.svg)](https://coveralls.io/github/go-think/flow)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-think/flow.svg)](https://pkg.go.dev/github.com/go-think/flow)
[![Latest Stable Version](https://img.shields.io/github/release/go-think/flow.svg)](https://github.com/go-think/flow/releases)
[![License](https://img.shields.io/github/license/go-think/flow.svg)](LICENSE)


## Requirements

- Go 1.27 or higher

## Installation

```bash
go get -u github.com/go-think/flow
```

---

## Quick Start

`flow` can be used standalone with standard `net/http` servers by leveraging its `Router` and `Pipeline`:

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/go-think/flow"
)

func main() {
	// 1. Initialize router
	r := flow.New()

	// 2. Define routes
	r.Get("/", func() *flow.Response {
		return flow.Text("Hello Flow!")
	})

	r.Get("/ping", func() *flow.Response {
		return flow.Json(map[string]string{
			"message": "pong",
		})
	})

	// Route parameters & dependency injection
	r.Get("/user/{name}", func(req *flow.Request, name string) *flow.Response {
		return flow.Text(fmt.Sprintf("Hello, %s!", name))
	})

	// Compile route trees & rules
	r.Register()

	// 3. Assemble middleware pipeline
	pipeline := flow.NewPipeline()
	pipeline.Pipe(flow.NewRecoverMiddleware(true)) // Panic recovery
	pipeline.Pipe(flow.NewCorsMiddleware())        // CORS handler
	pipeline.Pipe(flow.NewRouteMiddleware(r))      // Router dispatcher

	// 4. Run HTTP server (pipeline implements http.Handler)
	fmt.Println("Server running at http://127.0.0.1:8080")
	if err := http.ListenAndServe(":8080", pipeline); err != nil {
		panic(err)
	}
}
```

---

## Features

- [Routing Engine](#routing-engine)
  - [Basic Routing](#basic-routing)
  - [Route Verbs](#route-verbs)
  - [Route Parameters & Handler Signatures](#route-parameters--handler-signatures)
  - [Parameter Constraints (Where)](#parameter-constraints-where)
  - [Route Prefixes & Groups](#route-prefixes--groups)
  - [Named Routes & URL Generation](#named-routes--url-generation)
  - [Signed URLs](#signed-urls)
  - [Fallback Route](#fallback-route)
- [HTTP Request](#http-request)
  - [Parameter Retrieval & Type Conversion](#parameter-retrieval--type-conversion)
  - [File Uploads](#file-uploads)
  - [Client Inspection & Fingerprint](#client-inspection--fingerprint)
- [HTTP Response](#http-response)
  - [Factory Helpers](#factory-helpers)
  - [Custom Status, Headers & Cookies](#custom-status-headers--cookies)
  - [Streaming & File Downloads](#streaming--file-downloads)
- [Middleware & Pipeline](#middleware--pipeline)
  - [Writing Custom Middlewares](#writing-custom-middlewares)
  - [Built-in Middlewares](#built-in-middlewares)
  - [Pipeline Architecture](#pipeline-architecture)
- [HTTP Session](#http-session)
  - [Session Operations & Flash](#session-operations--flash)
  - [Storage Drivers (File, Cookie, Custom)](#storage-drivers)
- [License](#license)

---

## Routing Engine

The routing engine uses prefix-tree (radix tree) matching supporting dynamic parameters, constraints, and groups.

#### Basic Routing

Register routes by binding path patterns to handler functions:

```go
r.Get("/hello", func() *flow.Response {
	return flow.Text("Hello World")
})
```

Handlers can return `*flow.Response`, `flow.Response`, `string`, `map`, `struct`, or any serializable type. Flow formats the payload and sets the appropriate `Content-Type`.

#### Route Verbs

Flow supports standard HTTP verbs and catch-all methods:

```go
r.Get("/users", listUsers)
r.Post("/users", createUser)
r.Put("/users/{id}", updateUser)
r.Delete("/users/{id}", deleteUser)
r.Patch("/users/{id}", patchUser)
r.Options("/users", optionsHandler)

// Match any HTTP verb
r.Any("/any", anyHandler)

// Match custom combination of methods
r.Add([]string{"GET", "POST"}, "/multi", multiHandler)
```

#### Route Parameters & Handler Signatures

Route parameters are defined using `{param}` placeholders (or `{param?}` for optional parameters). Handlers support flexible parameter binding:

```go
// 1. Bound directly via argument reflection
r.Get("/posts/{post}/comments/{comment}", func(post, comment string) *flow.Response {
	return flow.Json(map[string]string{
		"post_id":    post,
		"comment_id": comment,
	})
})

// 2. Bound alongside *flow.Request
r.Get("/user/{id}", func(req *flow.Request, id string) *flow.Response {
	return flow.Text(fmt.Sprintf("Request URI: %s, User ID: %s", req.Path(), id))
})

// 3. Optional route parameters (using {param?})
// When omitted from URL (e.g. GET /profile), empty string "" is automatically injected
r.Get("/profile/{tab?}", func(tab string) *flow.Response {
	if tab == "" {
		tab = "overview"
	}
	return flow.Text("Tab: " + tab)
})
```

#### Parameter Constraints (Where)

Constrain parameter formats using regex rules:

```go
// Match only digits
r.Get("/user/{id}", getUser).WhereNumber("id")

// Match only alphabetic letters
r.Get("/user/{name}", getUser).WhereAlpha("name")

// Match against allowed enum list
r.Get("/order/{status}", getOrder).WhereIn("status", []string{"pending", "paid", "shipped"})

// Custom regular expression
r.Get("/order/{code}", getOrder).Where("code", `^[A-Z]{3}-[0-9]{4}$`)
```

#### Route Prefixes & Groups

Organize routes logically and share prefixes or middlewares:

```go
r.Prefix("/admin").Group(func(admin flow.Router) {
	admin.Get("/dashboard", adminDashboard)

	admin.Prefix("/users").Group(func(users flow.Router) {
		users.Get("", listAdminUsers)
		users.Get("/{id}", getAdminUser)
	})
})
```

#### Named Routes & URL Generation

Assign names to routes to resolve URLs dynamically:

```go
r.Get("/user/{id}/profile", showProfile).Name("user.profile")

// Compile routes
r.Register()

// Generate URL: "/user/42/profile"
url := r.Url("user.profile", map[string]string{"id": "42"})
```

#### Signed URLs

Generate tamper-proof URLs with cryptographic HMAC-SHA256 signatures:

```go
// Generate signed URL valid for 30 minutes
signedUrl := r.SignedUrl("unsubscribe", 30*time.Minute, map[string]string{"user": "123"})

// Validate signature inside handler or middleware
if !r.HasValidSignature(req) {
	return flow.NewResponse().SetCode(http.StatusForbidden).SetContent("Invalid or expired signature")
}
```

#### Fallback Route

Define a catch-all handler for unmatched routes:

```go
r.Fallback(func(req *flow.Request) *flow.Response {
	return flow.NewResponse().SetCode(http.StatusNotFound).SetContent("Page Not Found")
})
```

---

## HTTP Request

Flow encapsulates incoming `*http.Request` inside `*flow.Request` with abundant helpers:

#### Parameter Retrieval & Type Conversion

```go
func Handler(req *flow.Request) *flow.Response {
	// Unified parameter lookup (Query, Form, JSON Body)
	name, _ := req.Input("name")

	// Source-specific access
	pageStr, _ := req.Query("page")
	email, _   := req.Post("email")

	// Type-safe conversions with fallback defaults
	page    := req.Integer("page", 1)
	isAdmin := req.Boolean("is_admin", false)
	price   := req.Float("price", 0.0)

	// Key existence & non-empty checks
	hasName   := req.Has("name")              // True if key exists (including empty string)
	hasAny    := req.HasAny("phone", "email") // True if any of the keys exist
	isFilled  := req.Filled("name")           // True if key exists and trimmed value is non-empty
	isMissing := req.Missing("avatar")        // True if key is not present in request

	// Input whitelisting & blacklisting
	credentials := req.Only("username", "password")
	safeInputs  := req.Except("password", "token")

	// Retrieve all parsed inputs as map[string]string
	all := req.All()

	return flow.Json(all)
}
```

#### File Uploads

```go
func UploadHandler(req *flow.Request) *flow.Response {
	file, err := req.File("avatar")
	if err != nil {
		return flow.NewResponse().SetCode(400).SetContent("No file uploaded")
	}

	// Move and persist file to disk
	ok, err := file.Move("./storage/uploads", "avatar.png")
	if err != nil || !ok {
		return flow.NewResponse().SetCode(500).SetContent("Failed to save file")
	}

	return flow.Text("Uploaded avatar.png successfully")
}
```

#### Client Inspection & Fingerprint

```go
ip          := req.ClientIP()        // Client IP address (with X-Forwarded-For parsing)
userAgent   := req.UserAgent()       // User-Agent string
fingerprint := req.Fingerprint()     // SHA-256 fingerprint based on client traits
path        := req.Path()            // Request path
isMatch     := req.Is("admin/*")     // Wildcard path matching
```

---

## HTTP Response

All response factories and builders are provided directly by `flow`:

#### Factory Helpers

```go
// JSON response (application/json)
flow.Json(map[string]interface{}{"status": "success", "code": 200})

// Plain text response (text/plain)
flow.Text("Hello World")

// HTML response (text/html)
flow.Html("<h1>Welcome</h1>")

// HTTP Redirect (default 302 Found)
flow.Redirect("/dashboard")

// HTTP Redirect with custom status (e.g. 301 Moved Permanently)
flow.Redirect("/legacy-path", http.StatusMovedPermanently)

// 204 No Content response
flow.NoContent()

// Dynamic auto-detecting response (struct/slice/map -> JSON, other -> Text)
flow.MakeResponse(data)
```

#### Custom Status, Headers & Cookies

```go
res := flow.NewResponse().
	SetCode(http.StatusCreated).
	SetContentType("application/json").
	SetContent(`{"created": true}`)

res.Header.Set("X-Custom-Header", "Value")
res.Cookie("session_id", "session-token-value")
```

#### Streaming & File Downloads

```go
// File download
flow.Download("/var/data/report.pdf", "report.pdf")

// Server-Sent Events (SSE) or streaming
flow.StreamResponse(func(w io.Writer) bool {
	fmt.Fprintf(w, "data: %s\n\n", time.Now().Format(time.RFC3339))
	time.Sleep(1 * time.Second)
	return true // return false to stop streaming
})

// Stream download
flow.StreamDownload(func(w io.Writer) bool {
	w.Write([]byte("chunk-data..."))
	return false
}, "archive.zip")
```

---

## Middleware & Pipeline

Flow features an onion-layered `Pipeline` to execute requests sequentially across middleware chains.

#### Writing Custom Middlewares

Implement standard middleware using `flow.Handler` or `flow.Closure`:

```go
// 1. Using closure function
func AuthMiddleware(req *flow.Request, next flow.Closure) interface{} {
	token := req.Header("Authorization")
	if token == "" {
		return flow.NewResponse().SetCode(http.StatusUnauthorized).SetContent("Unauthorized")
	}
	return next(req)
}

// 2. Using struct implementing flow.Handler
type TimingMiddleware struct{}

func (m *TimingMiddleware) Process(req *flow.Request, next flow.Closure) interface{} {
	start := time.Now()
	res := next(req)
	duration := time.Since(start)
	if response, ok := res.(*flow.Response); ok {
		response.Header.Set("X-Response-Time", duration.String())
	}
	return res
}
```

Attach middleware to specific routes or groups:

```go
r.Get("/secret", secretHandler).Middleware(AuthMiddleware)
```

#### Built-in Middlewares

Flow provides production-ready built-in middlewares:

- **`flow.NewRecoverMiddleware(debug bool)`**: Recovers from panics, generates stacktraces, and prevents process crashes.
- **`flow.NewCorsMiddleware(config ...flow.CorsConfig)`**: Handles CORS headers and preflight `OPTIONS` requests.
- **`flow.NewCookieMiddleware(cfg ...*flow.CookieConfig)`**: Manages cookie lifecycle, prefix, secure/httpOnly, and domain settings.
- **`flow.NewTrimStringsMiddleware(except ...string)`**: Automatically trims whitespace from incoming request inputs.
- **`flow.NewValidateSignatureMiddleware(router ...*flow.Route)`**: Verifies signed URLs.
- **`flow.NewRouteMiddleware(router flow.Router)`**: Connects the compiled router into the pipeline.
- **`flow.NewSessionMiddleware(cfg *flow.Config)`**: Manages session lifecycle automatically with specified or default (`nil`) configuration.

#### Pipeline Architecture

`flow.Pipeline` provides an onion architecture supporting both fluid execution and standard `http.Handler` integration:

1. **Fluid Pipeline**:
```go
result := flow.NewPipeline().
	Send(request).
	Through([]flow.Handler{
		flow.NewRecoverMiddleware(true),
		flow.NewCorsMiddleware(),
	}).
	Then(func(req *flow.Request) any {
		return flow.Text("Executed through pipeline")
	})
```

2. **HTTP Server Integration (`http.Handler`)**:
```go
pipe := flow.NewPipeline()
pipe.Pipe(flow.NewRecoverMiddleware(true))
pipe.Pipe(flow.NewCorsMiddleware())
pipe.Pipe(flow.NewRouteMiddleware(r))

http.ListenAndServe(":8080", pipe)
```

---

## HTTP Session

Flow provides a robust session system with multi-driver support:

#### Session Operations & Flash

```go
func SessionDemoHandler(req *flow.Request) *flow.Response {
	session := req.Session()

	// Read & Write session data
	session.Set("user_id", 1001)
	userID := session.Get("user_id")

	// Check existence
	hasUser := session.Has("user_id")

	// Flash data (persisted for the next request only)
	session.Flash("alert", "Profile updated successfully")

	// Re-flash all or specific keys
	session.Reflash()

	// Regenerate ID (session fixation mitigation)
	session.Regenerate()

	// Invalidate & destroy session
	session.Invalidate()

	return flow.Json(map[string]interface{}{
		"user_id":  userID,
		"has_user": hasUser,
	})
}
```

#### Storage Drivers

Flow supports pluggable session storage handlers:

- **File Handler (`file`)**: Persists serialized session state to disk directory.
- **Cookie Handler (`cookie`)**: Stores session state on client cookies.
- **Custom Handlers**: Implement the `session.SessionHandler` interface for external backends (Redis, Memcached, etc.):
  ```go
  type SessionHandler interface {
      Read(id string) string
      Write(id string, data string)
  }
  ```

---

## License

Flow is open-sourced software licensed under the [Apache 2.0 license](LICENSE).
