package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// scopeEnv returns a tmpHome with scope mode active (allowed_paths:
// [~/.cache]), a secret file outside the scope, and a separate workdir.
func scopeEnv(t *testing.T) (tmpHome, workDir string, env []string) {
	t.Helper()
	tmpHome = t.TempDir()
	workDir = t.TempDir()
	configDir := filepath.Join(tmpHome, ".aigate")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "group: ai-agents\nuser: ai-runner\ndeny_read: []\ndeny_exec: []\nallow_net: []\nallowed_paths: [\"~/.cache\"]\n"
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmpHome, ".cache"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpHome, "secret.txt"), []byte("scope-secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env = append(os.Environ(), "HOME="+tmpHome)
	return tmpHome, workDir, env
}

// runScoped runs a shell snippet inside the scoped sandbox and returns output.
func runScoped(t *testing.T, bin, workDir string, env []string, script string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, "run", "--", "/bin/sh", "-c", script)
	cmd.Env = env
	cmd.Dir = workDir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestScope_HomeHiddenFromReads verifies non-scoped home files are invisible:
// neither their content nor their names leak into the sandbox.
func TestScope_HomeHiddenFromReads(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	skipWithoutBwrap(t)
	bin := buildBinary(t)
	tmpHome, workDir, env := scopeEnv(t)

	// cat stderr is silenced: its "No such file" error would echo the file
	// name and false-positive the name-leak assertion below.
	out, _ := runScoped(t, bin, workDir, env,
		fmt.Sprintf("cat %s/secret.txt 2>/dev/null; ls -a %s; echo MARKER_DONE", tmpHome, tmpHome))
	if !strings.Contains(out, "MARKER_DONE") {
		t.Fatalf("sandbox did not run to completion: %s", out)
	}
	if strings.Contains(out, "scope-secret") {
		t.Errorf("scope leaked file CONTENT outside allowed paths: %s", out)
	}
	if strings.Contains(out, "secret.txt") {
		t.Errorf("scope leaked file NAME outside allowed paths (home listing): %s", out)
	}

	// The hidden home must explain itself: a breadcrumb README tells the agent
	// the scope is active and where the full policy lives.
	out, err := runScoped(t, bin, workDir, env, fmt.Sprintf("cat %s/.aigate-scope-README", tmpHome))
	if err != nil {
		t.Fatalf("scope README should be readable inside the sandbox: %v\n%s", err, out)
	}
	if !strings.Contains(out, "[aigate] filesystem scope active") {
		t.Errorf("scope README should explain the hidden home, got: %s", out)
	}
	if !strings.Contains(out, "/tmp/.aigate-policy") {
		t.Errorf("scope README should point to the policy file, got: %s", out)
	}
}

// TestScope_AllowedPathReadWrite verifies allowed paths stay fully usable and
// writes to them persist on the host.
func TestScope_AllowedPathReadWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	skipWithoutBwrap(t)
	bin := buildBinary(t)
	tmpHome, workDir, env := scopeEnv(t)

	if err := os.WriteFile(filepath.Join(tmpHome, ".cache", "existing.txt"), []byte("cache-data\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runScoped(t, bin, workDir, env,
		fmt.Sprintf("cat %s/.cache/existing.txt && echo persisted > %s/.cache/written.txt", tmpHome, tmpHome))
	if err != nil {
		t.Fatalf("allowed-path access failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "cache-data") {
		t.Errorf("expected to read allowed path content, got: %s", out)
	}

	data, err := os.ReadFile(filepath.Join(tmpHome, ".cache", "written.txt"))
	if err != nil || !strings.Contains(string(data), "persisted") {
		t.Errorf("write inside allowed path should persist on host, got: %q err=%v", data, err)
	}
}

// TestScope_WritesOutsideScopeDoNotReachHost verifies writes to non-scoped
// home locations never land on the real filesystem.
func TestScope_WritesOutsideScopeDoNotReachHost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	skipWithoutBwrap(t)
	bin := buildBinary(t)
	tmpHome, workDir, env := scopeEnv(t)

	out, _ := runScoped(t, bin, workDir, env,
		fmt.Sprintf("echo evil > %s/evil.txt; echo tampered > %s/secret.txt; echo MARKER_DONE", tmpHome, tmpHome))
	if !strings.Contains(out, "MARKER_DONE") {
		t.Fatalf("sandbox did not run to completion: %s", out)
	}

	if _, err := os.Stat(filepath.Join(tmpHome, "evil.txt")); err == nil {
		t.Error("write outside scope reached the host filesystem")
	}
	data, err := os.ReadFile(filepath.Join(tmpHome, "secret.txt"))
	if err != nil || string(data) != "scope-secret\n" {
		t.Errorf("non-scoped host file was modified: %q err=%v", data, err)
	}
}

// TestScope_WorkdirAlwaysAccessible verifies the working directory keeps full
// read-write access and its writes persist.
func TestScope_WorkdirAlwaysAccessible(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	skipWithoutBwrap(t)
	bin := buildBinary(t)
	_, workDir, env := scopeEnv(t)

	out, err := runScoped(t, bin, workDir, env, "echo from-sandbox > out.txt && cat out.txt")
	if err != nil {
		t.Fatalf("workdir write failed: %v\n%s", err, out)
	}
	data, err := os.ReadFile(filepath.Join(workDir, "out.txt"))
	if err != nil || !strings.Contains(string(data), "from-sandbox") {
		t.Errorf("workdir write should persist on host, got: %q err=%v", data, err)
	}
}

// TestScope_SymlinkEscapeBlocked verifies a symlink planted in the workdir
// pointing at a non-scoped home file cannot be used to read it.
func TestScope_SymlinkEscapeBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	skipWithoutBwrap(t)
	bin := buildBinary(t)
	tmpHome, workDir, env := scopeEnv(t)

	link := filepath.Join(workDir, "innocent-link")
	if err := os.Symlink(filepath.Join(tmpHome, "secret.txt"), link); err != nil {
		t.Fatal(err)
	}

	out, _ := runScoped(t, bin, workDir, env, "cat innocent-link; echo MARKER_DONE")
	if !strings.Contains(out, "MARKER_DONE") {
		t.Fatalf("sandbox did not run to completion: %s", out)
	}
	if strings.Contains(out, "scope-secret") {
		t.Errorf("symlink escape leaked non-scoped content: %s", out)
	}
}

// TestScope_SymlinkCreationEscapeBlocked verifies a symlink created INSIDE the
// sandbox pointing outside the scope resolves against the hidden view, not the
// host filesystem.
func TestScope_SymlinkCreationEscapeBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	skipWithoutBwrap(t)
	bin := buildBinary(t)
	tmpHome, workDir, env := scopeEnv(t)

	out, _ := runScoped(t, bin, workDir, env,
		fmt.Sprintf("ln -s %s/secret.txt stolen && cat stolen; echo MARKER_DONE", tmpHome))
	if !strings.Contains(out, "MARKER_DONE") {
		t.Fatalf("sandbox did not run to completion: %s", out)
	}
	if strings.Contains(out, "scope-secret") {
		t.Errorf("in-sandbox symlink creation leaked non-scoped content: %s", out)
	}
}

// TestScope_HardlinkEscapeBlocked verifies hardlinks to non-scoped files
// cannot be created from inside the sandbox (the target path is invisible).
func TestScope_HardlinkEscapeBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	skipWithoutBwrap(t)
	bin := buildBinary(t)
	tmpHome, workDir, env := scopeEnv(t)

	out, _ := runScoped(t, bin, workDir, env,
		fmt.Sprintf("ln %s/secret.txt hard-stolen && cat hard-stolen; echo MARKER_DONE", tmpHome))
	if !strings.Contains(out, "MARKER_DONE") {
		t.Fatalf("sandbox did not run to completion: %s", out)
	}
	if strings.Contains(out, "scope-secret") {
		t.Errorf("hardlink escape leaked non-scoped content: %s", out)
	}
}

// TestScope_DotDotTraversalBlocked verifies that when the workdir sits inside
// $HOME, `..` traversal out of it hits the hidden home view.
func TestScope_DotDotTraversalBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	skipWithoutBwrap(t)
	bin := buildBinary(t)
	tmpHome, _, env := scopeEnv(t)

	insideWorkDir := filepath.Join(tmpHome, "project")
	if err := os.MkdirAll(insideWorkDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// cat stderr silenced — its error message would echo the probed name.
	out, _ := runScoped(t, bin, insideWorkDir, env, "cat ../secret.txt 2>/dev/null; ls ..; echo MARKER_DONE")
	if !strings.Contains(out, "MARKER_DONE") {
		t.Fatalf("sandbox did not run to completion: %s", out)
	}
	if strings.Contains(out, "scope-secret") {
		t.Errorf("..-traversal leaked non-scoped content: %s", out)
	}
	if strings.Contains(out, "secret.txt") {
		t.Errorf("..-traversal leaked non-scoped file names: %s", out)
	}
}

// TestScope_AbsolutePathVariantsBlocked verifies path-normalization tricks
// (double slashes, dot segments, $HOME expansion) don't reach hidden files.
func TestScope_AbsolutePathVariantsBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	skipWithoutBwrap(t)
	bin := buildBinary(t)
	tmpHome, workDir, env := scopeEnv(t)

	variants := []string{
		tmpHome + "//secret.txt",
		tmpHome + "/./secret.txt",
		tmpHome + "/.cache/../secret.txt",
		"$HOME/secret.txt",
	}
	for _, v := range variants {
		out, _ := runScoped(t, bin, workDir, env, fmt.Sprintf("cat %s; echo MARKER_DONE", v))
		if !strings.Contains(out, "MARKER_DONE") {
			t.Fatalf("sandbox did not run to completion for %q: %s", v, out)
		}
		if strings.Contains(out, "scope-secret") {
			t.Errorf("path variant %q leaked non-scoped content: %s", v, out)
		}
	}
}

// TestScope_DenyReadWinsInsideAllowedPath verifies deny_read still masks files
// living inside an allowed path.
func TestScope_DenyReadWinsInsideAllowedPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	skipWithoutBwrap(t)
	bin := buildBinary(t)
	tmpHome, workDir, env := scopeEnv(t)

	token := filepath.Join(tmpHome, ".cache", "token")
	if err := os.WriteFile(token, []byte("token-secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := "group: ai-agents\nuser: ai-runner\ndeny_read: [\"~/.cache/token\"]\ndeny_exec: []\nallow_net: []\nallowed_paths: [\"~/.cache\"]\n"
	if err := os.WriteFile(filepath.Join(tmpHome, ".aigate", "config.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	out, _ := runScoped(t, bin, workDir, env, fmt.Sprintf("cat %s; echo MARKER_DONE", token))
	if !strings.Contains(out, "MARKER_DONE") {
		t.Fatalf("sandbox did not run to completion: %s", out)
	}
	if strings.Contains(out, "token-secret") {
		t.Errorf("deny_read must win over allowed_paths, leaked: %s", out)
	}
}

// TestScope_RootStaysReadOnly verifies system paths cannot be written even
// with scope mode active.
func TestScope_RootStaysReadOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	skipWithoutBwrap(t)
	bin := buildBinary(t)
	_, workDir, env := scopeEnv(t)

	out, _ := runScoped(t, bin, workDir, env,
		"echo evil > /usr/aigate-scope-test 2>&1; echo EXIT:$?; echo MARKER_DONE")
	if !strings.Contains(out, "MARKER_DONE") {
		t.Fatalf("sandbox did not run to completion: %s", out)
	}
	if _, err := os.Stat("/usr/aigate-scope-test"); err == nil {
		t.Error("write to /usr reached the host filesystem")
	}
	if strings.Contains(out, "EXIT:0") {
		t.Errorf("write to /usr should fail inside the sandbox: %s", out)
	}
}

// TestScope_SessionAllowPathFlag verifies `run --allow-path` widens the scope
// for a single session only.
func TestScope_SessionAllowPathFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	skipWithoutBwrap(t)
	bin := buildBinary(t)
	tmpHome, workDir, env := scopeEnv(t)

	notes := filepath.Join(tmpHome, "notes")
	if err := os.MkdirAll(notes, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(notes, "n.txt"), []byte("note-content\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Without the flag: hidden.
	out, _ := runScoped(t, bin, workDir, env, fmt.Sprintf("cat %s/n.txt; echo MARKER_DONE", notes))
	if strings.Contains(out, "note-content") {
		t.Fatalf("notes dir should be hidden without --allow-path: %s", out)
	}

	// With the flag: readable.
	cmd := exec.Command(bin, "run", "--allow-path", notes, "--", "/bin/sh", "-c",
		fmt.Sprintf("cat %s/n.txt", notes))
	cmd.Env = env
	cmd.Dir = workDir
	out2, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run --allow-path failed: %v\n%s", err, out2)
	}
	if !strings.Contains(string(out2), "note-content") {
		t.Errorf("--allow-path should expose the path for this session: %s", out2)
	}
}

// TestCLI_AllowDenyPathRoundtrip verifies `allow path` / `deny path` persist
// scope changes in the global config.
func TestCLI_AllowDenyPathRoundtrip(t *testing.T) {
	bin := buildBinary(t)
	tmpHome := t.TempDir()
	env := append(os.Environ(), "HOME="+tmpHome)

	run := func(args ...string) string {
		cmd := exec.Command(bin, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v failed: %v\n%s", args, err, out)
		}
		return string(out)
	}

	run("init")
	run("allow", "path", "~/experiments")

	cfgData, err := os.ReadFile(filepath.Join(tmpHome, ".aigate", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfgData), "~/experiments") {
		t.Errorf("allow path should persist to config, got:\n%s", cfgData)
	}

	run("deny", "path", "~/experiments")
	cfgData, err = os.ReadFile(filepath.Join(tmpHome, ".aigate", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cfgData), "~/experiments") {
		t.Errorf("deny path should remove the entry from config, got:\n%s", cfgData)
	}

	// Status surfaces the scope section.
	statusOut := run("status")
	if !strings.Contains(statusOut, "allowed_paths") {
		t.Errorf("status should mention allowed_paths scope, got:\n%s", statusOut)
	}
}

// TestCLI_DoctorVerdict verifies doctor prints a verdict and exits zero on a
// healthy host.
func TestCLI_DoctorVerdict(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "doctor")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("doctor failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Verdict:") {
		t.Errorf("doctor should print a verdict, got:\n%s", out)
	}
}
