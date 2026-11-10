//go:build linux

package services

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestLateDenyWatch(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	work := "/w"
	abs, dirs := lateDenyWatch([]string{".env", "*.pem", "secrets/", "~/.ssh/", "config/*/key", "/etc/shadow"}, work)

	wantDirs := []string{"/w", home, "/etc"} // config/*/key: glob in the folder part, not watched
	if !slices.Equal(dirs, wantDirs) {
		t.Errorf("dirs = %v, want %v", dirs, wantDirs)
	}
	cases := []struct {
		path string
		want bool
	}{
		{"/w/.env", true},
		{"/w/server.pem", true},
		{"/w/secrets", true},
		{filepath.Join(home, ".ssh"), true},
		{"/w/.env.example", false},
		{"/w/notes.txt", false},
		{"/w/sub/.env", false}, // deny_read patterns are relative to the working dir's top level
	}
	for _, c := range cases {
		if got := matchesAnyPattern(c.path, abs); got != c.want {
			t.Errorf("matchesAnyPattern(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}
