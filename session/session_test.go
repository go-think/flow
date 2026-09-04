package session_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-think/flow/session"
	"github.com/stretchr/testify/assert"
)

type memoryHandler struct {
	data map[string]string
}

func newMemoryHandler() *memoryHandler {
	return &memoryHandler{data: make(map[string]string)}
}

func (m *memoryHandler) Read(id string) string {
	return m.data[id]
}

func (m *memoryHandler) Write(id string, val string) {
	m.data[id] = val
}

func TestStandaloneSessionStore(t *testing.T) {
	handler := newMemoryHandler()
	store := session.NewStore("test_sess", handler)
	store.Start()

	// 1. Basic Set & Get
	store.Set("key1", "val1")
	assert.Equal(t, "val1", store.Get("key1"))
	assert.True(t, store.Has("key1"))
	assert.False(t, store.Has("not_exist"))

	// 2. Flash
	store.Flash("flash_key", "flash_val")
	assert.Equal(t, "flash_val", store.Get("flash_key"))

	// 3. Save & reload
	store.Save()
	id := store.GetId()
	assert.NotEmpty(t, id)

	store2 := session.NewStore("test_sess", handler)
	store2.SetId(id)
	store2.Start()
	assert.Equal(t, "val1", store2.Get("key1"))
}

func TestStandaloneFileHandler(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sub_session_test_*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	fh := &session.FileHandler{
		Path:     filepath.Join(tmpDir, "sessions"),
		Lifetime: time.Hour,
	}

	fh.Write("sess_123", "encrypted_payload_data")
	readData := fh.Read("sess_123")
	assert.Equal(t, "encrypted_payload_data", readData)

	assert.Empty(t, fh.Read("non_existent"))
}

type mockRequest struct {
	cookies map[string]string
}

func (m *mockRequest) Cookie(key string, value ...string) (string, error) {
	if val, ok := m.cookies[key]; ok {
		return val, nil
	}
	return "", nil
}

type mockResponse struct {
	cookies map[string]string
}

func (m *mockResponse) Cookie(name interface{}, params ...interface{}) error {
	if s, ok := name.(string); ok && len(params) > 0 {
		if val, okVal := params[0].(string); okVal {
			m.cookies[s] = val
		}
	}
	return nil
}

func TestStandaloneCookieHandler(t *testing.T) {
	req := &mockRequest{cookies: map[string]string{"cookie_id": "val_123"}}
	resp := &mockResponse{cookies: make(map[string]string)}

	ch := session.NewCookieHandler()
	ch.SetRequest(req)
	ch.SetResponse(resp)

	assert.Equal(t, "val_123", ch.Read("cookie_id"))
	assert.Empty(t, ch.Read("unknown"))

	ch.Write("session_key", "session_value")
	assert.Equal(t, "session_value", resp.cookies["session_key"])
}

