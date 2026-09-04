package flow

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-think/flow/session"
)

// --- Begin manager.go ---
type Config struct {
	// Default Session Driver
	Driver string

	CookieName string

	// Session Lifetime
	Lifetime time.Duration

	// Session Encryption
	Encrypt bool

	// Session File Location
	Files string
}

type Manager struct {
	Config   *Config
	handlers map[string]session.SessionHandler
	mu       sync.RWMutex
}

func NewManager(config *Config) *Manager {
	return &Manager{
		Config:   config,
		handlers: make(map[string]session.SessionHandler),
	}
}

// Extend registers a custom session driver on this Manager instance.
func (m *Manager) Extend(driver string, handler session.SessionHandler) *Manager {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.handlers == nil {
		m.handlers = make(map[string]session.SessionHandler)
	}
	m.handlers[driver] = handler
	return m
}

func (m *Manager) SessionStart(req *Request) *session.Store {
	storeHandler := m.parseStoreHandler()
	store := session.NewStore(m.Config.CookieName, storeHandler)

	if handler, ok := storeHandler.(*session.CookieHandler); ok {
		handler.SetRequest(req)
	}

	cookieId, _ := req.Cookie(store.GetName())
	store.SetId(cookieId)
	store.Start()
	return store
}

func (m *Manager) SessionSave(res *Response, store *session.Store) {
	if store == nil {
		return
	}
	if handler, ok := store.GetHandler().(*session.CookieHandler); ok {
		handler.SetResponse(res)
	}
	_ = res.Cookie(store.GetName(), store.GetId())
	store.Save()
}

func (m *Manager) parseStoreHandler() session.SessionHandler {
	switch m.Config.Driver {
	case "cookie":
		return &session.CookieHandler{}
	case "file":
		return &session.FileHandler{
			Path:     m.Config.Files,
			Lifetime: m.Config.Lifetime,
		}
	default:
		m.mu.RLock()
		handler, ok := m.handlers[m.Config.Driver]
		m.mu.RUnlock()
		if ok {
			return handler
		}
		panic(fmt.Sprintf("Unsupported session driver: %s", m.Config.Driver))
	}
}

// --- End manager.go ---

