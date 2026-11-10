package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AxeForging/aigate/domain"
)

func TestScopeHidesCommand(t *testing.T) {
	home := t.TempDir()
	work := t.TempDir()
	t.Setenv("HOME", home)
	userBin := filepath.Join(home, ".local", "bin")
	sysBin := t.TempDir() // outside $HOME: always visible (read-only)
	for _, p := range []string{filepath.Join(userBin, "claude"), filepath.Join(userBin, "tool"), filepath.Join(sysBin, "systool")} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", userBin+":"+sysBin)

	cases := []struct {
		name    string
		allowed []string
		cmd     string
		hidden  bool
		fix     string
	}{
		{"scope off", nil, "tool", false, ""},
		{"outside home", []string{"~/.cache"}, "systool", false, ""},
		{"inside allowed path", []string{"~/.local"}, "tool", false, ""},
		{"hidden tool", []string{"~/.cache"}, "tool", true, "aigate allow path ~/.local/bin"},
		{"hidden claude adds its logins", []string{"~/.cache"}, "claude", true, "aigate allow path ~/.local/bin ~/.claude ~/.claude.json"},
		{"claude logins already allowed", []string{"~/.claude", "~/.claude.json"}, "claude", true, "aigate allow path ~/.local/bin"},
		{"not installed", []string{"~/.cache"}, "no-such-tool", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profile := domain.SandboxProfile{WorkDir: work, Config: domain.Config{AllowedPaths: tc.allowed}}
			b, hidden := scopeHidesCommand(profile, tc.cmd)
			if hidden != tc.hidden {
				t.Fatalf("hidden = %v, want %v (%+v)", hidden, tc.hidden, b)
			}
			if b.Fix != tc.fix {
				t.Errorf("fix = %q, want %q", b.Fix, tc.fix)
			}
		})
	}
}

func TestDefaultScopeFix_ListsAgentFolders(t *testing.T) {
	fix := DefaultScopeFix()
	for _, want := range []string{"~/.cache", "~/.local", "~/.claude", "~/.claude.json"} {
		if !strings.Contains(fix, want) {
			t.Errorf("%q missing from %q", want, fix)
		}
	}
}
