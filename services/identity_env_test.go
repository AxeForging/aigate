package services

import (
	"testing"

	"github.com/AxeForging/aigate/domain"
)

func envMap(set []EnvVar) map[string]string {
	m := map[string]string{}
	for _, v := range set {
		m[v.Name] = v.Value
	}
	return m
}

func TestIdentityEnv_SetsIdentityValues(t *testing.T) {
	id := &domain.ResolvedIdentity{Name: "work", Identity: domain.Identity{
		ClaudeDir: "/h/.claude-work", GhDir: "/h/gh-work",
		Git:    domain.GitAuthor{Name: "Test Work", Email: "work@example.test"},
		SSHKey: "/h/.ssh/id work",
	}}
	set, _ := identityEnv(id)
	m := envMap(set)
	want := map[string]string{
		"CLAUDE_CONFIG_DIR":   "/h/.claude-work",
		"GH_CONFIG_DIR":       "/h/gh-work",
		"AIGATE_IDENTITY":     "work",
		"GIT_AUTHOR_NAME":     "Test Work",
		"GIT_COMMITTER_NAME":  "Test Work",
		"GIT_AUTHOR_EMAIL":    "work@example.test",
		"GIT_COMMITTER_EMAIL": "work@example.test",
		"GIT_SSH_COMMAND":     "ssh -i '/h/.ssh/id work' -o IdentitiesOnly=yes -o IdentityAgent=none",
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %q, want %q", k, m[k], v)
		}
	}
}

func TestIdentityEnv_OptionalValuesOmitted(t *testing.T) {
	set, _ := identityEnv(&domain.ResolvedIdentity{Name: "p", Identity: domain.Identity{ClaudeDir: "/c", GhDir: "/g"}})
	m := envMap(set)
	for _, k := range []string{"GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_SSH_COMMAND"} {
		if _, ok := m[k]; ok {
			t.Errorf("%s should not be set when not configured", k)
		}
	}
}

func TestIdentityEnv_UnsetsCredentialsExceptPassEnv(t *testing.T) {
	_, unset := identityEnv(&domain.ResolvedIdentity{Identity: domain.Identity{PassEnv: []string{"GH_TOKEN"}}})
	has := map[string]bool{}
	for _, v := range unset {
		has[v] = true
	}
	if has["GH_TOKEN"] {
		t.Error("GH_TOKEN is in pass_env and must not be unset")
	}
	for _, v := range []string{"ANTHROPIC_API_KEY", "GITHUB_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"} {
		if !has[v] {
			t.Errorf("%s must be unset", v)
		}
	}
}

func TestIdentityEnv_NilIdentity(t *testing.T) {
	if set, unset := identityEnv(nil); set != nil || unset != nil {
		t.Errorf("nil identity must change nothing, got %v %v", set, unset)
	}
}

func TestSingleQuote(t *testing.T) {
	for in, want := range map[string]string{"/a/b": "'/a/b'", "it's": `'it'\''s'`, "": "''"} {
		if got := singleQuote(in); got != want {
			t.Errorf("singleQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIdentityEnv_DefaultClaudeDirLeavesConfigDirUnset(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	set, unset := identityEnv(&domain.ResolvedIdentity{Name: "personal", Identity: domain.Identity{
		ClaudeDir: home + "/.claude", GhDir: home + "/.config/gh",
	}})
	if _, ok := envMap(set)["CLAUDE_CONFIG_DIR"]; ok {
		t.Error("default ~/.claude must not set CLAUDE_CONFIG_DIR (changes settings file + Keychain item)")
	}
	found := false
	for _, v := range unset {
		found = found || v == "CLAUDE_CONFIG_DIR"
	}
	if !found {
		t.Error("an inherited CLAUDE_CONFIG_DIR must be unset for the default-dir identity")
	}
}
