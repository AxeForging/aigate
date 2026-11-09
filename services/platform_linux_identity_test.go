//go:build linux

package services

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AxeForging/aigate/domain"
)

func TestBwrapIdentityArgs_NoIdentityAddsNothing(t *testing.T) {
	if args := bwrapIdentityArgs(nil); len(args) != 0 {
		t.Errorf("want no args without identity, got %v", args)
	}
}

func TestBuildBwrapArgs_IdentityKeyMountedAfterSSHDeny(t *testing.T) {
	home, cfg := identityHome(t)
	id, err := NewIdentityService().Resolve(cfg, "work", home)
	if err != nil {
		t.Fatal(err)
	}
	profile := domain.SandboxProfile{
		Config:   domain.Config{DenyRead: []string{"~/.ssh/"}},
		WorkDir:  home + "/work/api",
		Identity: id,
	}
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	denyIdx, keyIdx := -1, -1
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--tmpfs" && args[i+1] == home+"/.ssh" {
			denyIdx = i
		}
		if args[i] == "--ro-bind" && args[i+1] == id.SSHKey && args[i+2] == id.SSHKey {
			keyIdx = i
		}
	}
	if keyIdx == -1 {
		t.Fatalf("ssh key not mounted read-only: %v", args)
	}
	if denyIdx != -1 && denyIdx > keyIdx {
		t.Errorf("ssh key mount (%d) must come after the ~/.ssh deny (%d)", keyIdx, denyIdx)
	}
	if !containsTriple(args, "--setenv", "CLAUDE_CONFIG_DIR", home+"/.claude-work") {
		t.Errorf("CLAUDE_CONFIG_DIR not set to identity dir: %v", args)
	}
}

func TestBuildIdentityOverrides_ExportsQuotedAndUnsets(t *testing.T) {
	id := &domain.ResolvedIdentity{Name: "work", Identity: domain.Identity{
		ClaudeDir: "/h/.claude work", GhDir: "/h/gh",
		Git: domain.GitAuthor{Name: "O'Brien", Email: "o@example.test"},
	}}
	script := buildIdentityOverrides(domain.SandboxProfile{Identity: id})
	for _, want := range []string{
		"export CLAUDE_CONFIG_DIR='/h/.claude work'",
		`export GIT_AUTHOR_NAME='O'\''Brien'`,
		"unset ANTHROPIC_API_KEY",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q:\n%s", want, script)
		}
	}
	if buildIdentityOverrides(domain.SandboxProfile{}) != "" {
		t.Error("no identity must produce an empty script")
	}
}

func TestCheckFallbackIdentity_RefusesSSHKeyWithFix(t *testing.T) {
	err := checkFallbackIdentity(domain.SandboxProfile{Identity: &domain.ResolvedIdentity{
		Name: "work", Identity: domain.Identity{SSHKey: "/k"},
	}})
	if err == nil || !strings.Contains(err.Error(), "bubblewrap") {
		t.Errorf("want refusal pointing at bubblewrap, got %v", err)
	}
	if checkFallbackIdentity(domain.SandboxProfile{}) != nil {
		t.Error("no identity must pass")
	}
}

// TestRunSandboxed_IdentityIsolation runs real bwrap: the work identity sees
// its own dirs, key and author, while personal's dirs and host tokens are gone.
func TestRunSandboxed_IdentityIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-exec test in short mode")
	}
	if !hasBwrap() {
		t.Skip("bwrap not installed")
	}
	home, cfg := identityHome(t)
	write := func(rel, content string) {
		if err := os.WriteFile(filepath.Join(home, rel), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".claude-work/creds", "work-own-login")
	write(".claude/creds", "canary-personal-claude")
	write(".config/gh/hosts.yml", "canary-personal-gh")
	t.Setenv("GH_TOKEN", "canary-host-gh-token")
	t.Setenv("ANTHROPIC_API_KEY", "canary-host-anthropic")

	svc := NewIdentityService()
	workDir := home + "/work/api"
	id, err := svc.Resolve(cfg, "", workDir)
	if err != nil || id == nil || id.Name != "work" {
		t.Fatalf("resolve: %+v %v", id, err)
	}
	cfg.AllowedPaths = NewConfigService().InitDefaultConfig().AllowedPaths
	allowed, err := svc.EffectiveAllowedPaths(cfg, id, workDir)
	if err != nil {
		t.Fatal(err)
	}
	profile := domain.SandboxProfile{
		Config:   domain.Config{DenyRead: []string{"~/.ssh/"}, AllowedPaths: allowed},
		WorkDir:  workDir,
		Identity: id,
	}

	script := `cat "$HOME/.claude-work/creds"; echo
cat "$HOME/.claude/creds" "$HOME/.config/gh/hosts.yml" 2>/dev/null
cat "$HOME/.ssh/id_work"; echo
echo "CCD=$CLAUDE_CONFIG_DIR GHD=$GH_CONFIG_DIR WHO=$AIGATE_IDENTITY"
echo "AUTHOR=$GIT_AUTHOR_NAME <$GIT_AUTHOR_EMAIL>"
echo "TOKENS=${GH_TOKEN:-}${ANTHROPIC_API_KEY:-}"
echo MARKER_DONE`
	var out bytes.Buffer
	p := &LinuxPlatform{exec: &RealExecutor{}}
	if err := p.RunSandboxed(profile, "sh", []string{"-c", script}, &out, &out); err != nil {
		t.Fatalf("RunSandboxed: %v\n%s", err, out.String())
	}
	got := out.String()
	for _, want := range []string{
		"work-own-login", "fake-key-for-tests",
		"CCD=" + home + "/.claude-work GHD=" + home + "/.config/gh-work WHO=work",
		"AUTHOR=Test Work <work@example.test>", "TOKENS=\n", "MARKER_DONE",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in sandbox output:\n%s", want, got)
		}
	}
	for _, leak := range []string{"canary-personal-claude", "canary-personal-gh", "canary-host-gh-token", "canary-host-anthropic"} {
		if strings.Contains(got, leak) {
			t.Errorf("leaked %q into the work sandbox:\n%s", leak, got)
		}
	}
}
