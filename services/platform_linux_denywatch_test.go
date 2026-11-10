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

func TestLoopbackUp(t *testing.T) {
	up := `Main:
  +-- 127.0.0.0/8 2 0 2
     +-- 127.0.0.0/31 1 0 0
        |-- 127.0.0.0
           /8 host LOCAL
        |-- 127.0.0.1
           /32 host LOCAL
     |-- 127.255.255.255
        /32 link BROADCAST
`
	cases := map[string]struct {
		in   string
		want bool
	}{
		"lo up":                  {up, true},
		"fresh namespace":        {"Main:\nLocal:\n", false},
		"address, not local yet": {"Main:\n        |-- 127.0.0.1\n           /8 host UNICAST\n", false},
		"empty":                  {"", false},
	}
	for name, c := range cases {
		if got := loopbackUp(c.in); got != c.want {
			t.Errorf("%s: loopbackUp = %v, want %v", name, got, c.want)
		}
	}
}
