package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// identityFixture is a temp HOME with two identities (work, personal), canary
// files in each identity's dirs, and the init-default allowed_paths.
type identityFixture struct {
	home, workDir, ossDir string
	env                   []string
}

const identityBaseConfig = `group: ai-agents
user: ai-runner
deny_read: ["~/.ssh/"]
deny_exec: []
allow_net: []
allowed_paths: ["~/.cache", "~/.config", "~/.local", "~/.claude", "~/.claude.json", "~/.npm"%s]
default_identity: ""
identities:
  work:
    claude_dir: ~/.claude-work
    gh_dir: ~/.config/gh-work
    git: { name: Test Work, email: work@example.test }
    ssh_key: ~/.ssh/id_work
    pass_env: [%s]
  personal:
    claude_dir: ~/.claude
    gh_dir: ~/.config/gh
    git: { name: Test Me, email: me@example.test }
identity_bindings:
  ~/work: work
  ~/oss: personal
`

func newIdentityFixture(t *testing.T, extraAllowed, passEnv string) identityFixture {
	t.Helper()
	skipWithoutBwrap(t)
	home := t.TempDir()
	files := map[string]string{
		".claude-work/creds":     "canary-work-claude",
		".config/gh-work/hosts":  "canary-work-gh",
		".claude/creds":          "canary-personal-claude",
		".config/gh/hosts":       "canary-personal-gh",
		".ssh/id_work":           "canary-work-sshkey",
		".ssh/id_personal":       "canary-personal-sshkey",
		".aigate/config.yaml":    fmt.Sprintf(identityBaseConfig, extraAllowed, passEnv),
		"work/api/README.md":     "work repo",
		"oss/lib/README.md":      "oss repo",
		".cache/.keep":           "",
		".config/other-app/conf": "unrelated",
	}
	for rel, content := range files {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env := append(os.Environ(),
		"HOME="+home,
		"GH_TOKEN=canary-host-gh-token",
		"ANTHROPIC_API_KEY=canary-host-anthropic",
	)
	return identityFixture{home: home, workDir: filepath.Join(home, "work/api"), ossDir: filepath.Join(home, "oss/lib"), env: env}
}

// runAs runs `aigate run [flags] -- sh -c script` in dir; stdout+stderr.
func (f identityFixture) runAs(t *testing.T, bin, dir string, flags []string, script string) (string, error) {
	t.Helper()
	args := append([]string{"run"}, flags...)
	args = append(args, "--", "/bin/sh", "-c", script)
	cmd := exec.Command(bin, args...)
	cmd.Env = f.env
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

const probeAllIdentities = `cat ~/.claude-work/creds ~/.config/gh-work/hosts 2>/dev/null; echo
cat ~/.claude/creds ~/.config/gh/hosts ~/.ssh/id_work ~/.ssh/id_personal 2>/dev/null; echo
ls -a ~ ~/.config 2>/dev/null
echo "CCD=$CLAUDE_CONFIG_DIR GHD=$GH_CONFIG_DIR WHO=$AIGATE_IDENTITY"
echo "TOKENS=${GH_TOKEN:-}${ANTHROPIC_API_KEY:-}"
echo MARKER_DONE`

func TestIdentity_BoundFolderSelectsAndIsolates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	f := newIdentityFixture(t, "", "")

	out := mustRun(t, f, bin, f.workDir, nil, probeAllIdentities)
	for _, want := range []string{
		"[aigate] identity: work (folder ~/work)",
		"canary-work-claude", "canary-work-gh", "canary-work-sshkey",
		"CCD=" + f.home + "/.claude-work GHD=" + f.home + "/.config/gh-work WHO=work",
		"TOKENS=\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	refuteLeak(t, out, "canary-personal-claude", "canary-personal-gh", "canary-personal-sshkey",
		"canary-host-gh-token", "canary-host-anthropic", "other-app", "id_personal")
}

func TestIdentity_FlagOverridesBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	f := newIdentityFixture(t, "", "")

	out := mustRun(t, f, bin, f.workDir, []string{"--identity", "personal"}, probeAllIdentities)
	for _, want := range []string{"[aigate] identity: personal (--identity flag)", "canary-personal-claude", "canary-personal-gh"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	refuteLeak(t, out, "canary-work-claude", "canary-work-gh", "canary-work-sshkey", "canary-personal-sshkey")
}

func TestIdentity_CannotWriteOtherIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	f := newIdentityFixture(t, "", "")

	mustRun(t, f, bin, f.workDir, nil,
		`echo tampered > ~/.claude/creds 2>/dev/null; echo tampered > ~/.config/gh/hosts 2>/dev/null; echo MARKER_DONE`)
	for _, rel := range []string{".claude/creds", ".config/gh/hosts"} {
		b, _ := os.ReadFile(filepath.Join(f.home, rel))
		if strings.Contains(string(b), "tampered") {
			t.Errorf("work session modified personal's %s", rel)
		}
	}
}

func TestIdentity_GitCommitUsesIdentityAuthor(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	bin := buildBinary(t)
	f := newIdentityFixture(t, "", "")

	out := mustRun(t, f, bin, f.workDir, nil,
		`git init -q && git -c commit.gpgsign=false commit -q --allow-empty -m probe && git log -1 --format='AUTH=%an <%ae> COMMIT=%cn <%ce>'; echo MARKER_DONE`)
	if !strings.Contains(out, "AUTH=Test Work <work@example.test> COMMIT=Test Work <work@example.test>") {
		t.Errorf("commit not authored by the work identity:\n%s", out)
	}
}

func TestIdentity_PassEnvKeepsListedVar(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	f := newIdentityFixture(t, "", "GH_TOKEN")

	out := mustRun(t, f, bin, f.workDir, nil, `echo "GH=${GH_TOKEN:-} AK=${ANTHROPIC_API_KEY:-}"; echo MARKER_DONE`)
	if !strings.Contains(out, "GH=canary-host-gh-token AK=\n") {
		t.Errorf("pass_env GH_TOKEN should pass, ANTHROPIC_API_KEY should not:\n%s", out)
	}
}

func TestIdentity_AllowedPathExposingOtherIdentityRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	f := newIdentityFixture(t, `, "~/.config/gh"`, "")

	out, err := f.runAs(t, bin, f.workDir, nil, "echo SHOULD_NOT_RUN")
	if err == nil || strings.Contains(out, "SHOULD_NOT_RUN") {
		t.Fatalf("run should be refused:\n%s", out)
	}
	if !strings.Contains(out, `exposes identity "personal"`) {
		t.Errorf("refusal should name the exposed identity:\n%s", out)
	}
}

func TestIdentity_ProjectConfigCannotChooseIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	f := newIdentityFixture(t, "", "")
	if err := os.WriteFile(filepath.Join(f.ossDir, ".aigate.yaml"), []byte("identity: work\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := f.runAs(t, bin, f.ossDir, nil, "echo SHOULD_NOT_RUN")
	if err == nil || strings.Contains(out, "SHOULD_NOT_RUN") || !strings.Contains(out, "aigate identity use") {
		t.Errorf("repo config selecting identity must be refused with the bind command:\n%s", out)
	}
}

func TestIdentity_BrokenProjectConfigStopsRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	f := newIdentityFixture(t, "", "")
	if err := os.WriteFile(filepath.Join(f.ossDir, ".aigate.yaml"), []byte("deny_read: [unclosed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := f.runAs(t, bin, f.ossDir, nil, "echo SHOULD_NOT_RUN")
	if err == nil || strings.Contains(out, "SHOULD_NOT_RUN") {
		t.Errorf("a broken project config must stop the run, not be ignored:\n%s", out)
	}
}

func TestIdentity_UnknownFlagListsIdentities(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	f := newIdentityFixture(t, "", "")

	out, err := f.runAs(t, bin, f.workDir, []string{"--identity", "ghost"}, "echo SHOULD_NOT_RUN")
	if err == nil || !strings.Contains(out, "personal, work") || !strings.Contains(out, "aigate identity add ghost") {
		t.Errorf("unknown identity should list options and the add command:\n%s", out)
	}
}

func TestIdentity_UnboundFolderSaysNone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	f := newIdentityFixture(t, "", "")
	other := filepath.Join(f.home, "elsewhere")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}

	out := mustRun(t, f, bin, other, nil, "echo MARKER_DONE")
	if !strings.Contains(out, "[aigate] identity: none (pick one with --identity NAME") {
		t.Errorf("unbound folder should explain how to pick an identity:\n%s", out)
	}
}

func TestIdentity_AuditRecordsIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	f := newIdentityFixture(t, "", "")

	mustRun(t, f, bin, f.workDir, nil, "echo MARKER_DONE")
	b, err := os.ReadFile(filepath.Join(f.home, ".aigate", "audit.jsonl"))
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	if !strings.Contains(string(b), `"identity":"work"`) {
		t.Errorf("audit entry should record the identity:\n%s", b)
	}
}

func TestIdentity_NoIdentitiesNoBanner(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)
	cmd := exec.Command(bin, "run", "--", "/bin/sh", "-c", "echo MARKER_DONE")
	cmd.Env = env
	cmd.Dir = tmpHome
	out, err := cmd.CombinedOutput()
	if err != nil || strings.Contains(string(out), "identity:") {
		t.Errorf("without identities nothing identity-related should appear: %v\n%s", err, out)
	}
}

func mustRun(t *testing.T, f identityFixture, bin, dir string, flags []string, script string) string {
	t.Helper()
	out, err := f.runAs(t, bin, dir, flags, script)
	if err != nil || !strings.Contains(out, "MARKER_DONE") {
		t.Fatalf("run failed: %v\n%s", err, out)
	}
	return out
}
