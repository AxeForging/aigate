//go:build linux

package services

import (
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
