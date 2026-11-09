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
	skipWithoutSandbox(t)
	home := t.TempDir()
	files := map[string]string{
		".claude-work/creds":     "canary-work-claude",
		".config/gh-work/hosts":  "canary-work-gh",
		".claude/creds":          "canary-personal-claude",
		".claude.json":           "canary-personal-settings",
		".config/gh/hosts":       "canary-personal-gh",
		".ssh/id_work":           "canary-work-sshkey",
		".ssh/id_personal":       "canary-personal-sshkey",
		".aigate/config.yaml":    fmt.Sprintf(identityBaseConfig, extraAllowed, passEnv),
		"work/api/README.md":     "work repo",
		"oss/lib/README.md":      "oss repo",
		".cache/.keep":           "",
		".config/other-app/conf": "unrelated",
	}
	writeTree(t, home, 0o600, files)
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
cat ~/.claude/creds ~/.claude.json ~/.config/gh/hosts ~/.ssh/id_work ~/.ssh/id_personal 2>/dev/null; echo
ls -a ~ ~/.config 2>/dev/null
echo "CCD=${CLAUDE_CONFIG_DIR:-} GHD=$GH_CONFIG_DIR WHO=$AIGATE_IDENTITY"
echo "TOKENS=${GH_TOKEN:-}${ANTHROPIC_API_KEY:-}"
echo MARKER_DONE`

func TestIdentity_BoundFolderSelectsAndIsolates(t *testing.T) {
	bin, f := identitySetup(t, "", "")

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
	refuteLeak(t, out, "canary-personal-claude", "canary-personal-settings", "canary-personal-gh", "canary-personal-sshkey",
		"canary-host-gh-token", "canary-host-anthropic", "other-app", "id_personal")
}

func TestIdentity_FlagOverridesBinding(t *testing.T) {
	bin, f := identitySetup(t, "", "")

	out := mustRun(t, f, bin, f.workDir, []string{"--identity", "personal"}, probeAllIdentities)
	for _, want := range []string{"[aigate] identity: personal (--identity flag)", "canary-personal-claude",
		"canary-personal-settings", "canary-personal-gh", "CCD= GHD=" + f.home + "/.config/gh WHO=personal"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	refuteLeak(t, out, "canary-work-claude", "canary-work-gh", "canary-work-sshkey", "canary-personal-sshkey")
}

func TestIdentity_CannotWriteOtherIdentity(t *testing.T) {
	bin, f := identitySetup(t, "", "")

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
	bin, f := identitySetup(t, "", "GH_TOKEN")

	out := mustRun(t, f, bin, f.workDir, nil, `echo "GH=${GH_TOKEN:-} AK=${ANTHROPIC_API_KEY:-}"; echo MARKER_DONE`)
	if !strings.Contains(out, "GH=canary-host-gh-token AK=\n") {
		t.Errorf("pass_env GH_TOKEN should pass, ANTHROPIC_API_KEY should not:\n%s", out)
	}
}

// TestIdentity_Refusals: each case must stop before the command runs and say
// how to fix it.
func TestIdentity_Refusals(t *testing.T) {
	tests := []struct {
		name          string
		extraAllowed  string // appended to global allowed_paths
		projectConfig string // .aigate.yaml in the oss folder
		inOss         bool
		flags         []string
		want          []string
	}{
		{name: "allowed path exposes another identity", extraAllowed: `, "~/.config/gh"`,
			want: []string{`exposes identity "personal"`}},
		{name: "repo config selects identity", projectConfig: "identity: work\n", inOss: true,
			want: []string{"aigate identity use"}},
		{name: "broken project config", projectConfig: "deny_read: [unclosed\n", inOss: true},
		{name: "unknown --identity", flags: []string{"--identity", "ghost"},
			want: []string{"personal, work", "aigate identity add ghost"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bin, f := identitySetup(t, tt.extraAllowed, "")
			dir := f.workDir
			if tt.inOss {
				dir = f.ossDir
			}
			if tt.projectConfig != "" {
				writeTree(t, dir, 0o644, map[string]string{".aigate.yaml": tt.projectConfig})
			}
			out, err := f.runAs(t, bin, dir, tt.flags, "echo SHOULD_NOT_RUN")
			if err == nil || strings.Contains(out, "SHOULD_NOT_RUN") {
				t.Fatalf("run should be refused:\n%s", out)
			}
			mustContain(t, out, tt.want...)
		})
	}
}

func TestIdentity_UnboundFolderSaysNone(t *testing.T) {
	bin, f := identitySetup(t, "", "")
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
	bin, f := identitySetup(t, "", "")

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

// identitySetup skips in -short mode, then builds aigate and the fixture.
func identitySetup(t *testing.T, extraAllowed, passEnv string) (string, identityFixture) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	f := newIdentityFixture(t, extraAllowed, passEnv)
	return buildBinary(t), f
}

func mustRun(t *testing.T, f identityFixture, bin, dir string, flags []string, script string) string {
	t.Helper()
	out, err := f.runAs(t, bin, dir, flags, script)
	if err != nil || !strings.Contains(out, "MARKER_DONE") {
		t.Fatalf("run failed: %v\n%s", err, out)
	}
	return out
}
