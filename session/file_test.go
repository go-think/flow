package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFileHandler_ReadAndWrite(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "file_handler_test_*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	sessionsDir := filepath.Join(tmpDir, "nested", "sessions")
	fh := &FileHandler{
		Path:     sessionsDir,
		Lifetime: 2 * time.Hour,
	}

	// 1. Read non-existent session
	assert.Empty(t, fh.Read("non_existent_id"))

	// 2. Empty ID handling
	assert.Empty(t, fh.Read(""))
	fh.Write("", "some_payload") // should safely no-op

	// 3. Normal Write & Read
	sessID := "sess_abc_12345"
	payload := "base64_encoded_serialized_session_content"

	fh.Write(sessID, payload)

	// Verify file was physically written to disk
	savePath := fh.getSavePath(sessID)
	assert.FileExists(t, savePath)

	// Verify Read retrieves exact payload
	readVal := fh.Read(sessID)
	assert.Equal(t, payload, readVal)

	// 4. Overwrite existing session
	updatedPayload := "updated_session_payload"
	fh.Write(sessID, updatedPayload)
	assert.Equal(t, updatedPayload, fh.Read(sessID))
}

func TestFileHandler_LifetimeExpiration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "file_handler_expire_*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	lifetime := 10 * time.Minute
	fh := &FileHandler{
		Path:     tmpDir,
		Lifetime: lifetime,
	}

	sessID := "sess_expiring"
	payload := "valid_data"
	fh.Write(sessID, payload)

	savePath := fh.getSavePath(sessID)
	assert.FileExists(t, savePath)

	// Verify it can be read immediately
	assert.Equal(t, payload, fh.Read(sessID))

	// Manually set ModTime to expired (15 minutes ago, while lifetime is 10 minutes)
	expiredTime := time.Now().Add(-15 * time.Minute)
	err = os.Chtimes(savePath, expiredTime, expiredTime)
	assert.NoError(t, err)

	// Verify expired session returns empty string
	assert.Empty(t, fh.Read(sessID))
}

func TestFileHandler_DirectoryEdgeCases(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "file_handler_dir_*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	fh := &FileHandler{
		Path:     tmpDir,
		Lifetime: time.Hour,
	}

	// If the path pointed to by getSavePath happens to be a directory instead of a file
	sessID := "dir_test_id"
	savePath := fh.getSavePath(sessID)
	err = os.MkdirAll(savePath, 0755)
	assert.NoError(t, err)

	// Read should safely return empty because it is a directory
	assert.Empty(t, fh.Read(sessID))
}
