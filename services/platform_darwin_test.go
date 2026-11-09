//go:build darwin

package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AxeForging/aigate/domain"
)

func TestRealPath_ResolvesSymlinkedTemp(t *testing.T) {
	if got := realPath("/tmp"); got != "/private/tmp" {
		t.Errorf("realPath(/tmp) = %q, want /private/tmp", got)
	}
	if got := realPath("/does/not/exist"); got != "/does/not/exist" {
		t.Errorf("missing paths must be returned unchanged, got %q", got)
	}
}

func TestGenerateSeatbeltProfile_IdentityRuleOrder(t *testing.T) {
	home, cfg := identityHome(t)
	svc := NewIdentityService()
	id, err := svc.Resolve(cfg, "work", home)
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := svc.EffectiveAllowedPaths(cfg, id, home+"/work/api")
	if err != nil {
		t.Fatal(err)
	}
	sb := generateSeatbeltProfile(domain.SandboxProfile{
		Config:   domain.Config{DenyRead: []string{"~/.ssh/"}, AllowedPaths: allowed},
		WorkDir:  home + "/work/api",
		Identity: id,
	})
	realHome := realPath(home)
	idx := func(rule string) int {
		i := strings.Index(sb, rule)
		if i < 0 {
			t.Fatalf("profile missing %q:\n%s", rule, sb)
		}
		return i
	}
	tempAllow := idx(`(allow file-write* (subpath "/private/var/folders"))`)
	homeDeny := idx(`(deny file-read* file-write* (subpath "` + realHome + `"))`)
	claudeAllow := idx(`(allow file-read* file-write* (subpath "` + realHome + `/.claude-work"))`)
	sshDeny := idx(`(deny file-read* (subpath "` + realHome + `/.ssh"))`)
	keyAllow := idx(`(allow file-read* (literal "` + realHome + `/.ssh/id_work"))`)

	if homeDeny < tempAllow {
		t.Error("$HOME deny must come after temp allows, or a HOME under /var/folders stays writable")
	}
	if claudeAllow < homeDeny {
		t.Error("identity dir allow must come after the $HOME deny")
	}
	if keyAllow < sshDeny {
		t.Error("identity ssh key allow must come after the ~/.ssh deny")
	}
	if strings.Contains(sb, filepath.Join(realHome, ".claude")+`"))`) {
		t.Errorf("personal's ~/.claude must not be allowed for work:\n%s", sb)
	}
}

func TestIdentityEnvCommand(t *testing.T) {
	if got := identityEnvCommand(domain.SandboxProfile{}); got != nil {
		t.Errorf("no identity → no env wrapper, got %v", got)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	got := identityEnvCommand(domain.SandboxProfile{Identity: &domain.ResolvedIdentity{Name: "work", Identity: domain.Identity{
		ClaudeDir: home + "/.claude-work", GhDir: home + "/gh",
	}}})
	if got[0] != "/usr/bin/env" {
		t.Fatalf("want /usr/bin/env wrapper, got %v", got)
	}
	joined := strings.Join(got, " ")
	for _, want := range []string{"-u ANTHROPIC_API_KEY", "CLAUDE_CONFIG_DIR=" + home + "/.claude-work", "AIGATE_IDENTITY=work"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	if _, err := os.Stat("/usr/bin/env"); err != nil {
		t.Errorf("/usr/bin/env must exist on macOS: %v", err)
	}
}

func TestParentsWithin(t *testing.T) {
	got := parentsWithin("/Users/me/work/api", "/Users/me")
	want := []string{"/Users/me/work", "/Users/me"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("parentsWithin = %v, want %v", got, want)
	}
	if got := parentsWithin("/opt/x", "/Users/me"); got != nil {
		t.Errorf("outside root → nothing, got %v", got)
	}
	if got := parentsWithin("/Users/meow/x", "/Users/me"); got != nil {
		t.Errorf("prefix-but-not-child must not match, got %v", got)
	}
}

func TestGenerateSeatbeltProfile_ParentMetadataOnly(t *testing.T) {
	home, cfg := identityHome(t)
	svc := NewIdentityService()
	id, _ := svc.Resolve(cfg, "work", home)
	allowed, _ := svc.EffectiveAllowedPaths(cfg, id, home+"/work/api")
	sb := generateSeatbeltProfile(domain.SandboxProfile{
		Config: domain.Config{AllowedPaths: allowed}, WorkDir: home + "/work/api", Identity: id,
	})
	rh := realPath(home)
	for _, want := range []string{
		`(allow file-read-metadata (literal "` + rh + `/work"))`,
		`(allow file-read-metadata (literal "` + rh + `"))`,
	} {
		if !strings.Contains(sb, want) {
			t.Errorf("missing %s:\n%s", want, sb)
		}
	}
	if strings.Contains(sb, `(allow file-read* (subpath "`+rh+`"))`) || strings.Contains(sb, `file-read-data (literal "`+rh+`")`) {
		t.Errorf("$HOME itself must not become listable/readable:\n%s", sb)
	}
}
