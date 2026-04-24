package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FileStore manages files available for download by clients.
type FileStore struct {
	baseDir string
}

// NewFileStore creates a file store rooted at the given directory.
func NewFileStore(dir string) *FileStore {
	return &FileStore{baseDir: dir}
}

// Get reads a file by name. Names are sanitized to prevent path traversal.
func (fs *FileStore) Get(name string) ([]byte, error) {
	// Sanitize: strip path separators, prevent traversal
	clean := filepath.Base(name)
	if clean == "." || clean == ".." || strings.ContainsAny(clean, "/\\") {
		return nil, fmt.Errorf("invalid file name: %q", name)
	}

	path := filepath.Join(fs.baseDir, clean)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("file not found: %s", clean)
	}
	return data, nil
}

// List returns the names and sizes of available files.
func (fs *FileStore) List() ([]string, error) {
	entries, err := os.ReadDir(fs.baseDir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			info, err := e.Info()
			if err != nil {
				names = append(names, e.Name())
			} else {
				names = append(names, fmt.Sprintf("%s\t%d", e.Name(), info.Size()))
			}
		}
	}
	return names, nil
}
