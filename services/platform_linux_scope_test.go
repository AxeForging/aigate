//go:build linux

package services

import (
	"os"
	"strings"
	"testing"

	"github.com/AxeForging/aigate/domain"
)

// ── buildBwrapArgs: allowed_paths scope mode ─────────────────────────────────

// scopeProfile returns a profile with scope mode on: home with a secret file,
// an allowed ~/.cache dir, and a workdir inside home.
func scopeProfile(t *testing.T, allowed []string) (domain.SandboxProfile, string) {
	t.Helper()
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	if err := os.MkdirAll(tmpHome+"/project", 0o755); err != nil {
		t.Fatal(err)
	}
	profile := domain.SandboxProfile{
		Config:  domain.Config{AllowedPaths: allowed},
		WorkDir: tmpHome + "/project",
	}
	return profile, tmpHome
}

func TestBuildBwrapArgs_ScopeHidesHomeWithTmpfs(t *testing.T) {
	profile, tmpHome := scopeProfile(t, []string{"~/.cache"})
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	if !containsPair(args, "--tmpfs", tmpHome) {
		t.Errorf("scope mode should mount --tmpfs over home %q, got: %v", tmpHome, args)
	}
	if containsTriple(args, "--bind", tmpHome, tmpHome) {
		t.Errorf("scope mode must NOT bind home read-write, got: %v", args)
	}
}

func TestBuildBwrapArgs_ScopeWorkdirBoundInsideHome(t *testing.T) {
	profile, tmpHome := scopeProfile(t, []string{"~/.cache"})
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	workDir := tmpHome + "/project"
	if !containsTriple(args, "--bind", workDir, workDir) {
		t.Errorf("scope mode should bind workdir %q back in read-write, got: %v", workDir, args)
	}
}

func TestBuildBwrapArgs_ScopeAllowedPathsBound(t *testing.T) {
	profile, tmpHome := scopeProfile(t, []string{"~/.cache", "~/.claude.json"})
	if err := os.MkdirAll(tmpHome+"/.cache", 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, tmpHome+"/.claude.json", "{}")

	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	for _, p := range []string{tmpHome + "/.cache", tmpHome + "/.claude.json"} {
		if !containsTriple(args, "--bind", p, p) {
			t.Errorf("allowed path %q should be bound read-write, got: %v", p, args)
		}
	}
}

func TestBuildBwrapArgs_ScopeSkipsMissingAllowedPaths(t *testing.T) {
	profile, tmpHome := scopeProfile(t, []string{"~/.does-not-exist"})
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	missing := tmpHome + "/.does-not-exist"
	if containsTriple(args, "--bind", missing, missing) {
		t.Errorf("non-existent allowed path should be skipped (bwrap would fail), got: %v", args)
	}
	// Scope itself must still be active.
	if !containsPair(args, "--tmpfs", tmpHome) {
		t.Errorf("scope should stay active even when allowed paths are missing, got: %v", args)
	}
}

func TestBuildBwrapArgs_ScopeSensitiveDotfilesStayHidden(t *testing.T) {
	profile, tmpHome := scopeProfile(t, []string{"~/.cache"})
	if err := os.MkdirAll(tmpHome+"/.ssh", 0o700); err != nil {
		t.Fatal(err)
	}

	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	sshPath := tmpHome + "/.ssh"
	// An ro-bind would re-expose .ssh content on top of the hiding tmpfs.
	if containsTriple(args, "--ro-bind", sshPath, sshPath) {
		t.Errorf(".ssh outside the scope must stay hidden by the home tmpfs, not be ro-bound back in, got: %v", args)
	}
}

func TestBuildBwrapArgs_ScopeSensitiveReExposedGetsReadOnly(t *testing.T) {
	// Workdir == home: scope is unenforceable (home is bound back in rw), so
	// the sensitive dotfiles must regain their read-only overlays.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	if err := os.MkdirAll(tmpHome+"/.ssh", 0o700); err != nil {
		t.Fatal(err)
	}
	profile := domain.SandboxProfile{
		Config:  domain.Config{AllowedPaths: []string{"~/.cache"}},
		WorkDir: tmpHome,
	}

	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	sshPath := tmpHome + "/.ssh"
	if !containsTriple(args, "--ro-bind", sshPath, sshPath) {
		t.Errorf(".ssh re-exposed through the workdir bind must be ro-bound, got: %v", args)
	}
}

// argIndex returns the index of the first element of a consecutive triple, or -1.
func argIndex(args []string, a, b, c string) int {
	for i := 0; i+2 < len(args); i++ {
		if args[i] == a && args[i+1] == b && args[i+2] == c {
			return i
		}
	}
	return -1
}

func TestBuildBwrapArgs_ScopeDenyReadWinsOverAllowedPath(t *testing.T) {
	profile, tmpHome := scopeProfile(t, []string{"~/.cache"})
	if err := os.MkdirAll(tmpHome+"/.cache", 0o755); err != nil {
		t.Fatal(err)
	}
	secret := tmpHome + "/.cache/token"
	writeTestFile(t, secret, "supersecret")
	profile.Config.DenyRead = []string{"~/.cache/token"}

	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	if !hasBwrapBindDest(args, secret) {
		t.Fatalf("deny_read file inside an allowed path should get a deny-marker bind, got: %v", args)
	}

	// bwrap applies mounts in argument order — the deny marker must come after
	// the allowed-path bind or the secret would be readable.
	allowIdx := argIndex(args, "--bind", tmpHome+"/.cache", tmpHome+"/.cache")
	denyIdx := -1
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--bind" && args[i+2] == secret {
			denyIdx = i
			break
		}
	}
	if allowIdx == -1 || denyIdx == -1 || denyIdx < allowIdx {
		t.Errorf("deny marker (idx %d) must be mounted after the allowed-path bind (idx %d)", denyIdx, allowIdx)
	}
}

func TestPolicyFileContent_AllowedPaths(t *testing.T) {
	profile := domain.SandboxProfile{
		Config: domain.Config{AllowedPaths: []string{"~/.cache", "~/.config"}},
	}
	content := policyFileContent(profile)
	if !strings.Contains(content, "allowed_paths: ~/.cache, ~/.config") {
		t.Errorf("policy file should list allowed_paths, got: %q", content)
	}
	if !strings.Contains(content, "hidden") {
		t.Errorf("policy file should explain non-scoped home is hidden, got: %q", content)
	}
}

// ── buildScopeOverrides (unshare fallback) ───────────────────────────────────

func TestBuildScopeOverrides_EmptyWhenScopeOff(t *testing.T) {
	profile := domain.SandboxProfile{Config: domain.Config{}, WorkDir: "/tmp/project"}
	if got := buildScopeOverrides(profile); got != "" {
		t.Errorf("no allowed_paths should produce no scope script, got: %q", got)
	}
}

func TestBuildScopeOverrides_HidesHomeAndRebinds(t *testing.T) {
	profile, tmpHome := scopeProfile(t, []string{"~/.cache"})
	if err := os.MkdirAll(tmpHome+"/.cache", 0o755); err != nil {
		t.Fatal(err)
	}

	script := buildScopeOverrides(profile)

	for _, want := range []string{
		"mktemp -d /tmp/.aigate-scope-",
		"mount --rbind \"" + tmpHome + "\"",
		"mount -t tmpfs tmpfs \"" + tmpHome + "\"",
		"$_scope_stage/project\" \"" + tmpHome + "/project\"",
		"$_scope_stage/.cache\" \"" + tmpHome + "/.cache\"",
		"umount -l \"$_scope_stage\"",
		"exit 125", // fail-closed when the hide cannot be established
	} {
		if !strings.Contains(script, want) {
			t.Errorf("scope script missing %q:\n%s", want, script)
		}
	}
}

func TestBuildScopeOverrides_UnenforceableFromHome(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	profile := domain.SandboxProfile{
		Config:  domain.Config{AllowedPaths: []string{"~/.cache"}},
		WorkDir: tmpHome,
	}
	if got := buildScopeOverrides(profile); got != "" {
		t.Errorf("workdir == home cannot be scoped; expected empty script, got: %q", got)
	}
}

func TestBuildScopeOverrides_OutsideHomePathIgnored(t *testing.T) {
	profile, _ := scopeProfile(t, []string{"/opt/data"})
	if err := os.MkdirAll("/tmp/aigate-test-opt", 0o755); err != nil {
		t.Fatal(err)
	}
	script := buildScopeOverrides(profile)
	// The breadcrumb README may mention the path; only an actual bind-mount
	// of it would be wrong (outside-home paths need no rebind in fallback mode).
	if strings.Contains(script, "mount --bind \"$_scope_stage//opt") || strings.Contains(script, "mkdir -p \"/opt") {
		t.Errorf("paths outside home need no rebind in fallback mode, got:\n%s", script)
	}
}

func TestBuildNetFilterScript_IncludesScopeOverrides(t *testing.T) {
	profile, tmpHome := scopeProfile(t, []string{"~/.cache"})
	profile.Config.AllowNet = []string{"api.anthropic.com"}

	script := buildNetFilterScript(profile.Config.AllowNet, []string{"1.1.1.1"}, nil, false, profile, "echo", []string{"hi"})
	if !strings.Contains(script, "mount -t tmpfs tmpfs \""+tmpHome+"\"") {
		t.Errorf("net-filter script should include the scope hide for home, got:\n%s", script)
	}
}
