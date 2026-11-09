package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const identityCLIConfig = `group: ai-agents
user: ai-runner
default_identity: personal
identities:
  work:
    claude_dir: ~/.claude-work
    gh_dir: ~/.config/gh-work
    git: { name: Test Work, email: work@example.test }
  personal:
    claude_dir: ~/.claude
    gh_dir: ~/.config/gh
    git: { name: Test Me, email: me@example.test }
`

// cliHome is a temp HOME with identityCLIConfig and the identity dirs.
func cliHome(t *testing.T, config string) string {
	t.Helper()
	home := t.TempDir()
	mkdirs(t, home, ".claude-work", ".config/gh-work", ".claude", ".config/gh", "work/api", "oss")
	writeTree(t, home, 0o644, map[string]string{".aigate/config.yaml": config})
	return home
}

func aigateIn(t *testing.T, bin, home, dir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func mustContain(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
}

func TestIdentityCLI_UseThenWhoamiInNestedFolder(t *testing.T) {
	bin := buildBinary(t)
	home := cliHome(t, identityCLIConfig)

	out, err := aigateIn(t, bin, home, filepath.Join(home, "work"), "identity", "use", "work")
	if err != nil {
		t.Fatalf("use: %v\n%s", err, out)
	}
	mustContain(t, out, `~/work (and folders inside it) now use identity "work"`, "aigate whoami")

	out, err = aigateIn(t, bin, home, filepath.Join(home, "work", "api"), "whoami")
	if err != nil {
		t.Fatalf("whoami: %v\n%s", err, out)
	}
	mustContain(t, out, "identity: work", "~/.claude-work", "Test Work <work@example.test>", "why:      folder ~/work")

	cfg, _ := os.ReadFile(filepath.Join(home, ".aigate", "config.yaml"))
	mustContain(t, string(cfg), "~/work: work")
}

func TestIdentityCLI_UseNoneUnbinds(t *testing.T) {
	bin := buildBinary(t)
	home := cliHome(t, identityCLIConfig+"identity_bindings:\n  ~/work: work\n")
	work := filepath.Join(home, "work")

	out, err := aigateIn(t, bin, home, work, "identity", "use", "none")
	if err != nil {
		t.Fatalf("use none: %v\n%s", err, out)
	}
	mustContain(t, out, "~/work is no longer bound")
	out, _ = aigateIn(t, bin, home, work, "whoami")
	mustContain(t, out, "identity: personal (default)")

	out, _ = aigateIn(t, bin, home, work, "identity", "use", "none")
	mustContain(t, out, "has no identity binding. Nothing to do.")
}

func TestIdentityCLI_UseRejectsUnknownIdentityAndNonFolder(t *testing.T) {
	bin := buildBinary(t)
	home := cliHome(t, identityCLIConfig)

	out, err := aigateIn(t, bin, home, home, "identity", "use", "ghost")
	if err == nil {
		t.Fatalf("unknown identity should fail:\n%s", out)
	}
	mustContain(t, out, "personal, work", "aigate identity add ghost")

	if err := os.WriteFile(filepath.Join(home, "file.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = aigateIn(t, bin, home, home, "identity", "use", "work", "file.txt")
	if err == nil || !strings.Contains(out, "is not a folder") {
		t.Errorf("binding a file should fail clearly: %v\n%s", err, out)
	}
	cfg, _ := os.ReadFile(filepath.Join(home, ".aigate", "config.yaml"))
	if strings.Contains(string(cfg), "identity_bindings") {
		t.Errorf("failed use must not change config:\n%s", cfg)
	}
}

func TestIdentityCLI_ListMarksActiveAndDefault(t *testing.T) {
	bin := buildBinary(t)
	home := cliHome(t, identityCLIConfig+"identity_bindings:\n  ~/work: work\n")

	out, err := aigateIn(t, bin, home, filepath.Join(home, "work", "api"), "identity", "list")
	if err != nil {
		t.Fatalf("list: %v\n%s", err, out)
	}
	mustContain(t, out, "personal (default)", "* active here (folder ~/work)")
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "~/.claude-work") && !strings.HasPrefix(line, "*") {
			t.Errorf("work row should be marked active: %q", line)
		}
	}
}

func TestIdentityCLI_ListEmptyPointsToAdd(t *testing.T) {
	bin := buildBinary(t)
	home := cliHome(t, "group: ai-agents\nuser: ai-runner\n")
	out, err := aigateIn(t, bin, home, home, "identity", "list")
	if err != nil {
		t.Fatalf("list: %v\n%s", err, out)
	}
	mustContain(t, out, "No identities yet. Create one: aigate identity add NAME")
}

func TestIdentityCLI_ShowReportsProblemsWithFix(t *testing.T) {
	bin := buildBinary(t)
	home := cliHome(t, identityCLIConfig)
	if err := os.RemoveAll(filepath.Join(home, ".config", "gh-work")); err != nil {
		t.Fatal(err)
	}
	out, err := aigateIn(t, bin, home, home, "identity", "show", "work")
	if err != nil {
		t.Fatalf("show: %v\n%s", err, out)
	}
	mustContain(t, out, "identity: work", "problem:", "does not exist", "fix: mkdir -p "+filepath.Join(home, ".config", "gh-work"))
}

func TestIdentityCLI_RemoveKeepsLoginsAndCleansReferences(t *testing.T) {
	bin := buildBinary(t)
	home := cliHome(t, identityCLIConfig+"identity_bindings:\n  ~/work: work\n  ~/oss: personal\n")
	if err := os.WriteFile(filepath.Join(home, ".claude", "creds"), []byte("keep-me"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := aigateIn(t, bin, home, home, "identity", "remove", "personal")
	if err != nil {
		t.Fatalf("remove: %v\n%s", err, out)
	}
	mustContain(t, out, `Removed identity "personal" and its folder bindings (~/oss)`, "Its logins were kept: ~/.claude, ~/.config/gh")

	if b, _ := os.ReadFile(filepath.Join(home, ".claude", "creds")); string(b) != "keep-me" {
		t.Error("remove must never touch login dirs")
	}
	cfg, _ := os.ReadFile(filepath.Join(home, ".aigate", "config.yaml"))
	for _, gone := range []string{"personal", "~/oss", "default_identity: personal"} {
		if strings.Contains(string(cfg), gone) {
			t.Errorf("config still references %q:\n%s", gone, cfg)
		}
	}
	mustContain(t, string(cfg), "~/work: work")
}

func TestIdentityCLI_WhoamiExplainsNone(t *testing.T) {
	bin := buildBinary(t)

	home := cliHome(t, "group: ai-agents\nuser: ai-runner\n")
	out, _ := aigateIn(t, bin, home, home, "whoami")
	mustContain(t, out, "no identities configured", "aigate identity add NAME")

	noDefault := strings.Replace(identityCLIConfig, "default_identity: personal\n", "", 1)
	home = cliHome(t, noDefault)
	out, _ = aigateIn(t, bin, home, filepath.Join(home, "oss"), "whoami")
	mustContain(t, out, "~/oss isn't bound to an identity", "aigate identity use NAME")
}

func TestIdentityCLI_WhoamiFlagAndNotInitialized(t *testing.T) {
	bin := buildBinary(t)
	home := cliHome(t, identityCLIConfig)
	out, _ := aigateIn(t, bin, home, home, "whoami", "--identity", "work")
	mustContain(t, out, "identity: work", "why:      --identity flag")

	empty := t.TempDir()
	out, err := aigateIn(t, bin, empty, empty, "whoami")
	if err == nil || !strings.Contains(out, "aigate init") {
		t.Errorf("uninitialized whoami should point to init: %v\n%s", err, out)
	}
}

// TestHelp_DocumentsIdentityCommands keeps help text in step with the commands.
func TestHelp_DocumentsIdentityCommands(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()
	out, _ := aigateIn(t, bin, home, home, "help-ai")
	mustContain(t, out, "aigate identity add work", "aigate identity use none", "aigate whoami", "aigate run --identity personal -- claude")
	out, _ = aigateIn(t, bin, home, home, "identity", "--help")
	mustContain(t, out, "add", "use", "list", "show", "remove")
	out, _ = aigateIn(t, bin, home, home, "run", "--help")
	mustContain(t, out, "--identity", "aigate run --identity work -- claude")
}
