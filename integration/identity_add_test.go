package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	expect "github.com/Netflix/go-expect"
)

// Stub CLIs stand in for the real claude/gh: they record which config dir
// they were given and whether another identity's files were visible.
const stubClaude = `#!/bin/sh
# Like Claude Code: no CLAUDE_CONFIG_DIR means ~/.claude.
cfg=${CLAUDE_CONFIG_DIR:-$HOME/.claude}
{ echo "dir=$cfg env=${CLAUDE_CONFIG_DIR:-unset} args=$*"; cat "$HOME/.claude-other/creds" 2>/dev/null; } > "$cfg/stub-login"
`
const stubGh = `#!/bin/sh
{ echo "dir=$GH_CONFIG_DIR args=$*"; cat "$HOME/.claude-other/creds" 2>/dev/null; } > "$GH_CONFIG_DIR/stub-login"
`

// addHome is a temp HOME with aigate initialized, stub claude/gh in
// ~/.local/bin (visible inside identity sandboxes) and optional existing
// identity "other" holding a canary.
func addHome(t *testing.T, withOther bool) (home string, env []string) {
	t.Helper()
	home = t.TempDir()
	cfg := "group: ai-agents\nuser: ai-runner\ndeny_read: []\ndeny_exec: []\nallow_net: [api.anthropic.com]\n"
	if withOther {
		cfg += "identities:\n  other:\n    claude_dir: ~/.claude-other\n    gh_dir: ~/.config/gh-other\n    git: { name: O, email: o@example.test }\n"
	}
	files := map[string]string{
		".aigate/config.yaml":     cfg,
		".local/bin/claude":       stubClaude,
		".local/bin/gh":           stubGh,
		".claude-other/creds":     "canary-other-identity",
		".config/gh-other/.keep":  "",
		"projects/app/.gitignore": "",
	}
	writeTree(t, home, 0o755, files)
	env = append(os.Environ(), "HOME="+home, "PATH="+filepath.Join(home, ".local/bin")+":"+os.Getenv("PATH"))
	return home, env
}

func runAdd(t *testing.T, bin string, env []string, dir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"identity", "add"}, args...)...)
	cmd.Env = env
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, _ := os.ReadFile(path)
	return string(b)
}

func TestIdentityAdd_NonInteractiveCreatesWithoutLogin(t *testing.T) {
	bin := buildBinary(t)
	home, env := addHome(t, false)

	out, err := runAdd(t, bin, env, filepath.Join(home, "projects/app"),
		"work", "--yes", "--use", "--git-name", "Test Work", "--git-email", "work@example.test")
	if err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	mustContain(t, out, `Created identity "work" (default).`, "~/projects/app now uses it.",
		"Log in to Claude later with: aigate run --identity work -- claude",
		"Log in to GitHub CLI later with: aigate run --identity work -- gh auth login")

	for _, d := range []string{".claude-work", ".config/gh-work"} {
		fi, err := os.Stat(filepath.Join(home, d))
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s should exist with 0700, got %v %v", d, fi, err)
		}
		if _, err := os.Stat(filepath.Join(home, d, "stub-login")); err == nil {
			t.Errorf("--yes must not run logins (%s)", d)
		}
	}
	cfg := readFile(t, filepath.Join(home, ".aigate/config.yaml"))
	mustContain(t, cfg, "default_identity: work", "claude_dir: ~/.claude-work", "gh_dir: ~/.config/gh-work",
		"email: work@example.test", "~/projects/app: work")
}

func TestIdentityAdd_LoginsRunInsideIdentitySandbox(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	skipWithoutSandbox(t)
	bin := buildBinary(t)
	home, env := addHome(t, true)

	out, err := runAdd(t, bin, env, home, "work", "--yes", "--login", "--git-email", "work@example.test")
	if err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	claude := readFile(t, filepath.Join(home, ".claude-work/stub-login"))
	gh := readFile(t, filepath.Join(home, ".config/gh-work/stub-login"))
	if !strings.Contains(claude, "dir="+filepath.Join(home, ".claude-work")+" env="+filepath.Join(home, ".claude-work")) {
		t.Errorf("claude login should get the identity's CLAUDE_CONFIG_DIR, got %q\n%s", claude, out)
	}
	if !strings.Contains(gh, "dir="+filepath.Join(home, ".config/gh-work")+" args=auth login") {
		t.Errorf("gh login should run `gh auth login` with the identity's GH_CONFIG_DIR, got %q\n%s", gh, out)
	}
	refuteLeak(t, claude+gh, "canary-other-identity")
	if strings.Contains(readFile(t, filepath.Join(home, ".aigate/config.yaml")), "default_identity: work") {
		t.Error("a second identity must not become default without --default")
	}
}

func TestIdentityAdd_RefusesDuplicateAndInvalidWithoutSaving(t *testing.T) {
	bin := buildBinary(t)
	home, env := addHome(t, true)
	before := readFile(t, filepath.Join(home, ".aigate/config.yaml"))

	out, err := runAdd(t, bin, env, home, "other", "--yes")
	if err == nil || !strings.Contains(out, `identity "other" already exists. See: aigate identity show other`) {
		t.Errorf("duplicate should be refused: %v\n%s", err, out)
	}
	out, err = runAdd(t, bin, env, home, "Bad Name", "--yes")
	if err == nil || !strings.Contains(out, "invalid identity name") {
		t.Errorf("invalid name should be refused: %v\n%s", err, out)
	}
	out, err = runAdd(t, bin, env, home, "dup", "--yes", "--claude-dir", "~/.claude-other")
	if err == nil || !strings.Contains(out, "overlaps") {
		t.Errorf("reusing another identity's dir should be refused: %v\n%s", err, out)
	}
	if after := readFile(t, filepath.Join(home, ".aigate/config.yaml")); after != before {
		t.Errorf("refused adds must not change config:\n%s", after)
	}
}

func TestIdentityAdd_InteractiveAdoptsExistingLogins(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	skipWithoutSandbox(t)
	bin := buildBinary(t)
	home, env := addHome(t, false)
	mkdirs(t, home, ".config/gh")
	writeTree(t, home, 0o600, map[string]string{".claude/existing": "mine", ".ssh/id_test": "fake-key-for-tests"})

	c, err := expect.NewConsole(expect.WithDefaultTimeout(15 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() //nolint:errcheck
	cmd := exec.Command(bin, "identity", "add", "personal")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Tty(), c.Tty(), c.Tty()
	cmd.Env = env
	cmd.Dir = home
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill() //nolint:errcheck

	steps := []struct{ expect, send string }{
		{"Use them for \"personal\" (nothing is moved)? [Y/n]", ""},
		{"Git author name", "Test Me"},
		{"Git author email", "me@example.test"},
		{"1) ~/.ssh/id_test", ""},
		{"Choice:", "9"},
		{"Enter a number from 1 to 1", ""},
		{"Choice:", "1"},
		{"Log in to Claude for \"personal\" now? [Y/n]", "y"},
		{"Log in to GitHub CLI for \"personal\" now? [Y/n]", "n"},
		{"Log in to GitHub CLI later with: aigate run --identity personal -- gh auth login", ""},
	}
	for _, s := range steps {
		if _, err := c.ExpectString(s.expect); err != nil {
			t.Fatalf("waiting for %q: %v", s.expect, err)
		}
		if s.send != "" || strings.HasSuffix(s.expect, "[Y/n]") {
			if _, err := c.SendLine(s.send); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("add exited with error: %v", err)
	}

	cfg := readFile(t, filepath.Join(home, ".aigate/config.yaml"))
	mustContain(t, cfg, "claude_dir: ~/.claude", "gh_dir: ~/.config/gh", "ssh_key: ~/.ssh/id_test", "default_identity: personal")
	if readFile(t, filepath.Join(home, ".claude/existing")) != "mine" {
		t.Error("adopting existing logins must not touch them")
	}
	// Adopted default dir: CLAUDE_CONFIG_DIR stays unset, so Claude uses the
	// same settings file and macOS Keychain item as before.
	mustContain(t, readFile(t, filepath.Join(home, ".claude/stub-login")), "dir="+filepath.Join(home, ".claude")+" env=unset")
	if _, err := os.Stat(filepath.Join(home, ".config/gh/stub-login")); err == nil {
		t.Error("declined gh login must not run")
	}
}
