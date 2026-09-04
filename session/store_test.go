package session

import (
	"encoding/base64"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockMemoryHandler struct {
	mu   sync.RWMutex
	data map[string]string
}

func newMockMemoryHandler() *mockMemoryHandler {
	return &mockMemoryHandler{data: make(map[string]string)}
}

func (m *mockMemoryHandler) Read(id string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.data[id]
}

func (m *mockMemoryHandler) Write(id string, val string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[id] = val
}

func TestStore_BasicLifecycleAndGetters(t *testing.T) {
	handler := newMockMemoryHandler()
	store := NewStore("test_session", handler)

	// 1. Getters before start
	assert.Equal(t, "test_session", store.GetName())
	assert.Equal(t, handler, store.GetHandler())
	assert.Empty(t, store.GetId())
	assert.False(t, store.IsStarted())

	// 2. Start initializes ID and CSRF token
	ok := store.Start()
	assert.True(t, ok)
	assert.NotEmpty(t, store.GetId())
	assert.True(t, store.IsStarted())

	// 3. Token & RegenerateToken
	tok := store.Token()
	assert.NotEmpty(t, tok)
	newTok := store.RegenerateToken()
	assert.NotEmpty(t, newTok)
	assert.NotEqual(t, tok, newTok)
	assert.Equal(t, newTok, store.Token())

	// 4. SetId & Regenerate
	oldId := store.GetId()
	store.SetId("custom_id_123")
	assert.Equal(t, "custom_id_123", store.GetId())

	store.Regenerate()
	assert.NotEmpty(t, store.GetId())
	assert.NotEqual(t, oldId, store.GetId())
	assert.NotEqual(t, "custom_id_123", store.GetId())
}

func TestStore_AttributesOperations(t *testing.T) {
	handler := newMockMemoryHandler()
	store := NewStore("app_session", handler)
	store.Start()

	// 1. Set, Get, Has
	store.Set("username", "john_doe")
	store.Set("role", "admin")
	store.Set("is_active", true)

	assert.True(t, store.Has("username"))
	assert.False(t, store.Has("unknown_key"))

	assert.Equal(t, "john_doe", store.Get("username"))
	assert.Equal(t, "default_val", store.Get("unknown_key", "default_val"))
	assert.Nil(t, store.Get("unknown_key"))

	// 2. All
	all := store.All()
	assert.Equal(t, "john_doe", all["username"])
	assert.Equal(t, "admin", all["role"])
	assert.Equal(t, true, all["is_active"])

	// 3. Only & Except
	only := store.Only("username", "role")
	assert.Len(t, only, 2)
	assert.Equal(t, "john_doe", only["username"])
	assert.Equal(t, "admin", only["role"])

	except := store.Except("role")
	assert.Nil(t, except["role"])
	assert.Equal(t, "john_doe", except["username"])
	assert.Equal(t, true, except["is_active"])

	// 4. Pull
	pulled := store.Pull("username")
	assert.Equal(t, "john_doe", pulled)
	assert.False(t, store.Has("username"))

	pulledDefault := store.Pull("non_existent", "fallback")
	assert.Equal(t, "fallback", pulledDefault)

	// 5. Remove & Forget
	store.Set("k1", "v1")
	store.Set("k2", "v2")
	store.Set("k3", "v3")

	removed := store.Remove("k1")
	assert.Equal(t, "v1", removed)
	assert.False(t, store.Has("k1"))

	store.Forget("k2", "k3")
	assert.False(t, store.Has("k2"))
	assert.False(t, store.Has("k3"))

	// 6. Clear & Invalidate
	store.Set("temp", "data")
	store.Clear()
	assert.False(t, store.Has("temp"))

	store.Set("user", "alice")
	prevId := store.GetId()
	store.Invalidate()
	assert.False(t, store.Has("user"))
	assert.NotEqual(t, prevId, store.GetId())
}

func TestStore_IncrementAndDecrement(t *testing.T) {
	handler := newMockMemoryHandler()
	store := NewStore("sess", handler)
	store.Start()

	// 1. Initial increment from non-existent key
	c1 := store.Increment("counter")
	assert.Equal(t, 1, c1)

	// 2. Increment by step
	c2 := store.Increment("counter", 5)
	assert.Equal(t, 6, c2)

	// 3. Decrement
	d1 := store.Decrement("counter")
	assert.Equal(t, 5, d1)

	// 4. Decrement by step
	d2 := store.Decrement("counter", 3)
	assert.Equal(t, 2, d2)

	// 5. Increment from float64 and string
	store.Set("float_count", float64(10))
	assert.Equal(t, 11, store.Increment("float_count"))

	store.Set("str_count", "20")
	assert.Equal(t, 21, store.Increment("str_count"))
}

func TestStore_PreviousUrl(t *testing.T) {
	handler := newMockMemoryHandler()
	store := NewStore("sess", handler)
	store.Start()

	assert.Empty(t, store.PreviousUrl())

	store.SetPreviousUrl("https://example.com/login")
	assert.Equal(t, "https://example.com/login", store.PreviousUrl())
}

func TestStore_FlashLifecycleAndDecayAcrossRequests(t *testing.T) {
	handler := newMockMemoryHandler()

	// --- Request 1: Flash & Now & Save ---
	s1 := NewStore("sess", handler)
	s1.Start()
	sessId := s1.GetId()

	s1.Flash("success", "Operation successful")
	s1.Flash("code", 200)
	s1.Now("temp_alert", "Only visible this request")

	assert.Equal(t, "Operation successful", s1.Get("success"))
	assert.Equal(t, 200, s1.Get("code"))
	assert.Equal(t, "Only visible this request", s1.Get("temp_alert"))

	s1.Save()

	// --- Request 2: Reload from handler (Now is gone, Flash is visible) ---
	s2 := NewStore("sess", handler)
	s2.SetId(sessId)
	s2.Start()

	assert.Equal(t, "Operation successful", s2.Get("success"))
	assert.Equal(t, float64(200), s2.Get("code")) // JSON numbers unmarshal as float64
	assert.Nil(t, s2.Get("temp_alert"))

	// Keep "code" for one more cycle
	s2.Keep("code")
	s2.Save()

	// --- Request 3: Reload from handler ("success" decayed and gone, "code" still kept) ---
	s3 := NewStore("sess", handler)
	s3.SetId(sessId)
	s3.Start()

	assert.Nil(t, s3.Get("success"))
	assert.Equal(t, float64(200), s3.Get("code"))

	// Reflash everything
	s3.Reflash()
	s3.Save()

	// --- Request 4: Reload from handler ("code" is still present due to Reflash) ---
	s4 := NewStore("sess", handler)
	s4.SetId(sessId)
	s4.Start()

	assert.Equal(t, float64(200), s4.Get("code"))
	s4.Save() // No reflash or keep -> will decay

	// --- Request 5: Reload from handler ("code" is completely gone) ---
	s5 := NewStore("sess", handler)
	s5.SetId(sessId)
	s5.Start()

	assert.Nil(t, s5.Get("code"))
}

func TestStore_CorruptedAndInvalidPayload(t *testing.T) {
	handler := newMockMemoryHandler()

	// 1. Invalid base64
	handler.Write("corrupt_b64", "!!!not-valid-base64???")
	s1 := NewStore("sess", handler)
	s1.SetId("corrupt_b64")
	s1.Start()
	assert.NotEqual(t, "corrupt_b64", s1.GetId(), "Should generate new ID when base64 is corrupted")

	// 2. Invalid JSON
	invalidJson := base64.StdEncoding.EncodeToString([]byte("not valid json"))
	handler.Write("corrupt_json", invalidJson)
	s2 := NewStore("sess", handler)
	s2.SetId("corrupt_json")
	s2.Start()
	assert.NotEqual(t, "corrupt_json", s2.GetId(), "Should generate new ID when JSON is corrupted")
}

func TestStore_ConcurrentOperations(t *testing.T) {
	handler := newMockMemoryHandler()
	store := NewStore("sess", handler)
	store.Start()

	const concurrency = 30
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			key := fmt.Sprintf("key_%d", idx)
			store.Set(key, idx)
			_ = store.Get(key)
			_ = store.Has(key)
			_ = store.Increment("concurrent_counter")
			store.Flash(fmt.Sprintf("flash_%d", idx), "flash_val")
			store.Save()
		}(i)
	}

	wg.Wait()

	assert.Equal(t, concurrency, store.Get("concurrent_counter"))
}
