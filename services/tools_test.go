package services

import (
	"os"
	"path/filepath"
	"testing"
)

func fakeTool(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestFindTool: PATH first, then the sbin dirs Debian keeps off a user's
// PATH; earlier names win; non-executables don't count.
func TestFindTool(t *testing.T) {
	pathDir, sbin := t.TempDir(), t.TempDir()
	t.Setenv("PATH", pathDir)
	old := sbinDirs
	sbinDirs = []string{sbin}
	t.Cleanup(func() { sbinDirs = old })

	onlySbin := fakeTool(t, sbin, "only-in-sbin")
	inPath := fakeTool(t, pathDir, "both")
	fakeTool(t, sbin, "both")
	nft := fakeTool(t, sbin, "tool-nft")
	fakeTool(t, pathDir, "tool")
	if err := os.WriteFile(filepath.Join(sbin, "not-exec"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		names []string
		want  string
	}{
		{[]string{"only-in-sbin"}, onlySbin},
		{[]string{"both"}, inPath},
		{[]string{"tool-nft", "tool"}, nft}, // first name wins, wherever it lives
		{[]string{"not-exec"}, ""},
		{[]string{"missing"}, ""},
	}
	for _, c := range cases {
		got, err := FindTool(c.names...)
		if got != c.want || (c.want == "") != (err != nil) {
			t.Errorf("FindTool(%v) = %q, %v; want %q", c.names, got, err, c.want)
		}
	}
}
