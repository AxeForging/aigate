package integration

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTree writes files (path relative to root → content), creating
// parent dirs as needed.
func writeTree(t *testing.T, root string, perm os.FileMode, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), perm); err != nil {
			t.Fatal(err)
		}
	}
}

// mkdirs creates dirs (relative to root).
func mkdirs(t *testing.T, root string, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
}
