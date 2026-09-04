package session

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"
)

type FileHandler struct {
	Path     string
	Lifetime time.Duration
}

func (c *FileHandler) getSavePath(id string) string {
	if id == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(id))
	filename := hex.EncodeToString(hash[:])
	return filepath.Join(c.Path, filename)
}

func (c *FileHandler) Read(id string) string {
	savePath := c.getSavePath(id)
	if savePath == "" {
		return ""
	}

	if info, err := os.Stat(savePath); err == nil && !info.IsDir() {
		if info.ModTime().After(time.Now().Add(-c.Lifetime)) {
			data, err := os.ReadFile(savePath)
			if err != nil {
				return ""
			}
			return string(data)
		}
	}
	return ""
}

func (c *FileHandler) Write(id string, data string) {
	savePath := c.getSavePath(id)
	if savePath == "" {
		return
	}

	dir := filepath.Dir(savePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		_ = os.MkdirAll(dir, 0755)
	}

	_ = os.WriteFile(savePath, []byte(data), 0644)
}
