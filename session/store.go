package session

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"
)

type Store struct {
	mu         sync.RWMutex
	name       string
	id         string
	handler    SessionHandler
	attributes map[string]interface{}
}

func NewStore(name string, handler SessionHandler) *Store {
	return &Store{
		name:       name,
		handler:    handler,
		attributes: make(map[string]interface{}),
	}
}

func (s *Store) GetHandler() SessionHandler {
	return s.handler
}

func (s *Store) GetId() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.id
}

func (s *Store) SetId(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.id = id
}

func (s *Store) GetName() string {
	return s.name
}

func (s *Store) Start() bool {
	s.loadSession()
	if !s.Has("_token") {
		s.RegenerateToken()
	}
	return true
}

func (s *Store) IsStarted() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.attributes) > 0
}

func (s *Store) loadSession() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.attributes = make(map[string]interface{})
	if s.id == "" {
		s.id = generateSessionId()
		return
	}

	data := s.handler.Read(s.id)
	if data == "" {
		s.id = generateSessionId()
		return
	}

	decodeData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		s.id = generateSessionId()
		return
	}

	var attributes map[string]interface{}
	if err := json.Unmarshal(decodeData, &attributes); err != nil {
		s.id = generateSessionId()
		return
	}

	s.attributes = attributes
}

func (s *Store) Has(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.attributes[name]
	return ok
}

func (s *Store) Get(name string, value ...interface{}) interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if val, ok := s.attributes[name]; ok {
		return val
	}

	if len(value) > 0 {
		return value[0]
	}

	return nil
}

func (s *Store) Pull(name string, value ...interface{}) interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	if val, ok := s.attributes[name]; ok {
		delete(s.attributes, name)
		return val
	}

	if len(value) > 0 {
		return value[0]
	}

	return nil
}

func (s *Store) Set(name string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attributes[name] = value
}

func (s *Store) getFlashesLocked() map[string][]string {
	raw, ok := s.attributes["_flash"]
	if !ok || raw == nil {
		return map[string][]string{"new": {}, "old": {}}
	}
	if f, ok := raw.(map[string][]string); ok {
		return f
	}
	res := map[string][]string{"new": {}, "old": {}}
	if m, ok := raw.(map[string]interface{}); ok {
		for _, key := range []string{"new", "old"} {
			if arr, ok := m[key]; ok {
				switch list := arr.(type) {
				case []string:
					res[key] = append(res[key], list...)
				case []interface{}:
					for _, item := range list {
						if str, ok := item.(string); ok {
							res[key] = append(res[key], str)
						}
					}
				}
			}
		}
	}
	return res
}

func (s *Store) Flash(name string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attributes[name] = value

	flashes := s.getFlashesLocked()
	flashes["new"] = append(flashes["new"], name)
	s.attributes["_flash"] = flashes
}

func (s *Store) Reflash() {
	s.mu.Lock()
	defer s.mu.Unlock()

	flashes := s.getFlashesLocked()
	flashes["new"] = append(flashes["new"], flashes["old"]...)
	flashes["old"] = []string{}
	s.attributes["_flash"] = flashes
}

func (s *Store) Keep(names ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	flashes := s.getFlashesLocked()
	for _, name := range names {
		for i, oldName := range flashes["old"] {
			if oldName == name {
				flashes["old"] = append(flashes["old"][:i], flashes["old"][i+1:]...)
				flashes["new"] = append(flashes["new"], name)
				break
			}
		}
	}
	s.attributes["_flash"] = flashes
}

func (s *Store) Now(name string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attributes[name] = value

	flashes := s.getFlashesLocked()
	flashes["old"] = append(flashes["old"], name)
	s.attributes["_flash"] = flashes
}

func (s *Store) Token() string {
	token := s.Get("_token")
	if tokenStr, ok := token.(string); ok && tokenStr != "" {
		return tokenStr
	}
	return s.RegenerateToken()
}

func (s *Store) RegenerateToken() string {
	token := generateSessionId()
	s.Set("_token", token)
	return token
}

func (s *Store) Only(names ...string) map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]interface{})
	for _, name := range names {
		if val, ok := s.attributes[name]; ok {
			result[name] = val
		}
	}
	return result
}

func (s *Store) Except(names ...string) map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]interface{})
	exceptMap := make(map[string]struct{})
	for _, name := range names {
		exceptMap[name] = struct{}{}
	}

	for k, v := range s.attributes {
		if _, ok := exceptMap[k]; !ok {
			result[k] = v
		}
	}
	return result
}

func (s *Store) PreviousUrl() string {
	val := s.Get("_previous_url")
	if str, ok := val.(string); ok {
		return str
	}
	return ""
}

func (s *Store) SetPreviousUrl(url string) {
	s.Set("_previous_url", url)
}

func (s *Store) All() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]interface{}, len(s.attributes))
	for k, v := range s.attributes {
		result[k] = v
	}
	return result
}

func (s *Store) Remove(name string) interface{} {
	return s.Pull(name)
}

func (s *Store) Forget(names ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, name := range names {
		delete(s.attributes, name)
	}
}

func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attributes = make(map[string]interface{})
}

func (s *Store) Regenerate() {
	s.SetId(generateSessionId())
}

func (s *Store) Invalidate() {
	s.Clear()
	s.Regenerate()
}

func (s *Store) Increment(key string, amount ...int) int {
	step := 1
	if len(amount) > 0 {
		step = amount[0]
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	val, ok := s.attributes[key]
	var current int
	if ok {
		switch v := val.(type) {
		case int:
			current = v
		case float64:
			current = int(v)
		case string:
			current, _ = strconv.Atoi(v)
		}
	}

	current += step
	s.attributes[key] = current
	return current
}

func (s *Store) Decrement(key string, amount ...int) int {
	step := 1
	if len(amount) > 0 {
		step = amount[0]
	}
	return s.Increment(key, -step)
}

func (s *Store) Save() {
	s.mu.Lock()
	flashes := s.getFlashesLocked()
	for _, oldName := range flashes["old"] {
		delete(s.attributes, oldName)
	}
	flashes["old"] = flashes["new"]
	flashes["new"] = []string{}
	s.attributes["_flash"] = flashes

	data, err := json.Marshal(s.attributes)
	id := s.id
	handler := s.handler
	s.mu.Unlock()

	if err != nil {
		return
	}

	encodeData := base64.StdEncoding.EncodeToString(data)
	handler.Write(id, encodeData)
}

func generateSessionId() string {
	id := strconv.FormatInt(time.Now().UnixNano(), 10)
	b := make([]byte, 48)
	_, _ = io.ReadFull(rand.Reader, b)
	id = id + base64.URLEncoding.EncodeToString(b)

	h := sha1.New()
	h.Write([]byte(id))

	return fmt.Sprintf("%x", h.Sum(nil))
}
