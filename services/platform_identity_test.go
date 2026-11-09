package services

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/AxeForging/aigate/domain"
)

// skipWithoutSandbox skips unless this OS's sandbox tool is available.
func skipWithoutSandbox(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping real-exec test in short mode")
	}
	tool := map[string]string{"linux": "bwrap", "darwin": "sandbox-exec"}[runtime.GOOS]
	if tool == "" {
		t.Skipf("no sandbox on %s", runtime.GOOS)
	}
	if _, err := exec.LookPath(tool); err != nil {
		t.Skipf("%s not installed", tool)
	}
}

// runAsIdentity runs script in the real sandbox as the named identity, with
// the init-default allowed_paths narrowed to it and ~/.ssh/ denied.
func runAsIdentity(t *testing.T, cfg *domain.Config, name, workDir, script string) string {
	t.Helper()
	svc := NewIdentityService()
	id, err := svc.Resolve(cfg, name, workDir)
	if err != nil {
		t.Fatal(err)
	}
	c := *cfg
	c.AllowedPaths = NewConfigService().InitDefaultConfig().AllowedPaths
	allowed, err := svc.EffectiveAllowedPaths(&c, id, workDir)
	if err != nil {
		t.Fatal(err)
	}
	profile := domain.SandboxProfile{
		Config:   domain.Config{DenyRead: []string{"~/.ssh/"}, AllowedPaths: allowed},
		WorkDir:  workDir,
		Identity: id,
	}
	var out bytes.Buffer
	p := DetectPlatformWithExecutor(&RealExecutor{})
	if err := p.RunSandboxed(profile, "sh", []string{"-c", script}, &out, &out); err != nil {
		t.Fatalf("RunSandboxed: %v\n%s", err, out.String())
	}
	return out.String()
}

const identityProbe = `cat "$HOME/.claude-work/creds" "$HOME/.claude/creds" "$HOME/.claude.json" "$HOME/.config/gh/hosts.yml" 2>/dev/null; echo
cat "$HOME/.ssh/id_work" 2>/dev/null; echo
echo "CCD=${CLAUDE_CONFIG_DIR:-} GHD=$GH_CONFIG_DIR WHO=$AIGATE_IDENTITY"
echo "AUTHOR=${GIT_AUTHOR_NAME:-} <${GIT_AUTHOR_EMAIL:-}>"
echo "TOKENS=${GH_TOKEN:-}${ANTHROPIC_API_KEY:-}"
echo MARKER_DONE`

func identityCanaries(t *testing.T, home string) {
	t.Helper()
	for rel, content := range map[string]string{
		".claude-work/creds":   "work-own-login",
		".claude/creds":        "canary-personal-claude",
		".claude.json":         "canary-personal-settings",
		".config/gh/hosts.yml": "canary-personal-gh",
	} {
		if err := os.WriteFile(filepath.Join(home, rel), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GH_TOKEN", "canary-host-gh-token")
	t.Setenv("ANTHROPIC_API_KEY", "canary-host-anthropic")
	t.Setenv("CLAUDE_CONFIG_DIR", "/canary/inherited/dir")
}

func assertOutput(t *testing.T, got string, want, leaks []string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in sandbox output:\n%s", w, got)
		}
	}
	for _, l := range leaks {
		if strings.Contains(got, l) {
			t.Errorf("leaked %q into the sandbox:\n%s", l, got)
		}
	}
}

// TestRunSandboxed_IdentityIsolation: the work identity sees its own dirs,
// key and author; personal's dirs, settings file and host tokens are gone.
func TestRunSandboxed_IdentityIsolation(t *testing.T) {
	skipWithoutSandbox(t)
	home, cfg := identityHome(t)
	identityCanaries(t, home)

	got := runAsIdentity(t, cfg, "work", home+"/work/api", identityProbe)
	assertOutput(t, got,
		[]string{"work-own-login", "fake-key-for-tests",
			"CCD=" + home + "/.claude-work GHD=" + home + "/.config/gh-work WHO=work",
			"AUTHOR=Test Work <work@example.test>", "TOKENS=\n", "MARKER_DONE"},
		[]string{"canary-personal-claude", "canary-personal-settings", "canary-personal-gh",
			"canary-host-gh-token", "canary-host-anthropic"})
}

// TestRunSandboxed_DefaultClaudeDirIdentity: the identity using ~/.claude
// keeps Claude Code's default behavior: CLAUDE_CONFIG_DIR unset (same
// settings file and macOS Keychain item as a plain `claude`) and
// ~/.claude.json visible; the work identity's files stay hidden.
func TestRunSandboxed_DefaultClaudeDirIdentity(t *testing.T) {
	skipWithoutSandbox(t)
	home, cfg := identityHome(t)
	identityCanaries(t, home)

	got := runAsIdentity(t, cfg, "personal", home+"/oss", identityProbe)
	assertOutput(t, got,
		[]string{"canary-personal-claude", "canary-personal-settings", "canary-personal-gh",
			"CCD= GHD=" + home + "/.config/gh WHO=personal", "MARKER_DONE"},
		[]string{"work-own-login", "fake-key-for-tests", "/canary/inherited/dir"})
}
