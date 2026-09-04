package session

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockSessionRequest struct {
	cookies map[string]string
}

func newMockSessionRequest() *mockSessionRequest {
	return &mockSessionRequest{cookies: make(map[string]string)}
}

func (m *mockSessionRequest) Cookie(key string, value ...string) (string, error) {
	if val, ok := m.cookies[key]; ok {
		return val, nil
	}
	if len(value) > 0 {
		return value[0], nil
	}
	return "", errors.New("cookie not found")
}

type mockSessionResponse struct {
	cookies map[string]string
}

func newMockSessionResponse() *mockSessionResponse {
	return &mockSessionResponse{cookies: make(map[string]string)}
}

func (m *mockSessionResponse) Cookie(name interface{}, params ...interface{}) error {
	if s, ok := name.(string); ok && len(params) > 0 {
		if val, okVal := params[0].(string); okVal {
			m.cookies[s] = val
		}
	}
	return nil
}

func TestCookieHandler_BasicAndNilSafety(t *testing.T) {
	ch := NewCookieHandler()
	assert.NotNil(t, ch)

	// 1. Read with nil request returns empty string safely
	assert.Empty(t, ch.Read("any_id"))

	// 2. Write with nil response returns safely without panic
	assert.NotPanics(t, func() {
		ch.Write("any_id", "some_payload")
	})
}

func TestCookieHandler_ReadAndWrite(t *testing.T) {
	ch := NewCookieHandler()

	req := newMockSessionRequest()
	resp := newMockSessionResponse()

	ch.SetRequest(req)
	ch.SetResponse(resp)

	// 1. Read non-existent cookie
	assert.Empty(t, ch.Read("sess_token"))

	// 2. Read existing cookie
	req.cookies["sess_token"] = "mock_session_content_123"
	assert.Equal(t, "mock_session_content_123", ch.Read("sess_token"))

	// 3. Write updates response cookie
	ch.Write("sess_token", "updated_session_content_456")
	assert.Equal(t, "updated_session_content_456", resp.cookies["sess_token"])
}
