package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A user's settings file with odd formatting and their own hook, to prove
// uninstall restores it byte for byte.
const userSettings = `{
    "model":"opus",
  "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [ { "type": "command", "command": "my-linter" } ] } ] }
}
`

func judgeCmd(t *testing.T, bin, home, dir string, args ...string) (string, error) {
	t.Helper()
	return aigateIn(t, bin, home, dir, append([]string{"judge"}, args...)...)
}

func countOurs(t *testing.T, settings, bin string) map[string]int {
	t.Helper()
	var doc struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	b, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("settings not JSON: %v\n%s", err, b)
	}
	// The hook names the binary's resolved path (/private/var/… on macOS).
	real, _ := filepath.EvalSymlinks(bin)
	n := map[string]int{}
	for ev, groups := range doc.Hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				if h.Command == bin+" judge" || h.Command == real+" judge" {
					n[ev]++
				}
			}
		}
	}
	return n
}

func TestJudgeInstall_RoundTripRestoresExactly(t *testing.T) {
	bin := buildBinary(t)
	home := judgeHome(t, false)
	settings := filepath.Join(home, ".claude", "settings.json")
	writeTree(t, home, 0o600, map[string]string{".claude/settings.json": userSettings})

	out, err := judgeCmd(t, bin, home, home, "install")
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	mustContain(t, out, "Installed the aigate judge hook in ~/.claude/settings.json", "Turned the judge on", "aigate judge uninstall")
	if n := countOurs(t, settings, bin); n["PreToolUse"] != 1 || n["PostToolUse"] != 1 {
		t.Errorf("want one hook per event, got %v", n)
	}
	mustContain(t, readFile(t, settings), "my-linter")
	mustContain(t, readFile(t, filepath.Join(home, ".aigate", "config.yaml")), "enabled: true")

	out, _ = judgeCmd(t, bin, home, home, "install")
	mustContain(t, out, "already installed")
	if n := countOurs(t, settings, bin); n["PreToolUse"] != 1 {
		t.Errorf("second install must not duplicate: %v", n)
	}

	out, err = judgeCmd(t, bin, home, home, "uninstall")
	if err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	mustContain(t, out, "restored exactly as before install")
	if got := readFile(t, settings); got != userSettings {
		t.Errorf("settings not byte-identical after round trip:\n%q", got)
	}
}

func TestJudgeInstall_CreatedFileIsRemovedAgain(t *testing.T) {
	bin := buildBinary(t)
	home := judgeHome(t, false)
	settings := filepath.Join(home, ".claude", "settings.json")
	if _, err := judgeCmd(t, bin, home, home, "install"); err != nil {
		t.Fatal(err)
	}
	if _, err := judgeCmd(t, bin, home, home, "uninstall"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		t.Error("a settings file install created must be gone after uninstall")
	}
	out, _ := judgeCmd(t, bin, home, home, "uninstall")
	mustContain(t, out, "nothing to remove")
}

func TestJudgeInstall_EditedAfterInstallKeepsUserChanges(t *testing.T) {
	bin := buildBinary(t)
	home := judgeHome(t, false)
	settings := filepath.Join(home, ".claude", "settings.json")
	writeTree(t, home, 0o600, map[string]string{".claude/settings.json": userSettings})
	if _, err := judgeCmd(t, bin, home, home, "install"); err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(readFile(t, settings), `"opus"`, `"sonnet"`, 1)
	writeTree(t, home, 0o600, map[string]string{".claude/settings.json": edited})

	out, err := judgeCmd(t, bin, home, home, "uninstall")
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out, "formatting may differ")
	got := readFile(t, settings)
	mustContain(t, got, `"sonnet"`, "my-linter")
	if n := countOurs(t, settings, bin); len(n) != 0 {
		t.Errorf("aigate hooks must be gone: %v", n)
	}
}

func TestJudgeInstall_UsesActiveIdentityAndRefusesBadJSON(t *testing.T) {
	bin := buildBinary(t)
	home := cliHome(t, identityCLIConfig+"identity_bindings:\n  ~/work: work\n")
	out, err := judgeCmd(t, bin, home, filepath.Join(home, "work", "api"), "install")
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	mustContain(t, out, "~/.claude-work/settings.json (identity work)")
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Error("the default ~/.claude must not be touched when an identity is active")
	}

	writeTree(t, home, 0o600, map[string]string{".claude/settings.json": "{not json"})
	out, err = judgeCmd(t, bin, home, filepath.Join(home, "oss"), "install", "--identity", "personal")
	if err == nil || !strings.Contains(out, "is not valid JSON") {
		t.Errorf("invalid settings must be refused: %v\n%s", err, out)
	}
	if readFile(t, filepath.Join(home, ".claude", "settings.json")) != "{not json" {
		t.Error("a refused install must not change the file")
	}
}
