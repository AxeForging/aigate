package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	expect "github.com/Netflix/go-expect"
)

// sandboxEnv returns a tmpHome with a minimal aigate config and the env slice to use.
func sandboxEnv(t *testing.T) (tmpHome string, env []string) {
	t.Helper()
	tmpHome = t.TempDir()
	configDir := filepath.Join(tmpHome, ".aigate")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "group: ai-agents\nuser: ai-runner\ndeny_read: []\ndeny_exec: []\nallow_net: []\n"
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	env = append(os.Environ(), "HOME="+tmpHome)
	return
}

// runSandboxedShell starts `aigate run -- /bin/bash` under a PTY and returns the
// console + a cleanup func. The test is skipped if bwrap is not available.
func runSandboxedShell(t *testing.T, bin string, env []string) (*expect.Console, func()) {
	t.Helper()

	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not found, skipping sandbox PTY tests")
	}

	c, err := expect.NewConsole(expect.WithDefaultTimeout(10 * time.Second))
	if err != nil {
		t.Fatalf("expect.NewConsole: %v", err)
	}

	cmd := exec.Command(bin, "run", "--", "/bin/bash", "--norc", "--noprofile")
	cmd.Stdin = c.Tty()
	cmd.Stdout = c.Tty()
	cmd.Stderr = c.Tty()
	cmd.Env = env

	if err := cmd.Start(); err != nil {
		c.Close() //nolint:errcheck
		t.Fatalf("cmd.Start: %v", err)
	}

	cleanup := func() {
		c.Close()          //nolint:errcheck
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	}
	return c, cleanup
}

// sendLine writes a command and newline to the console.
func sendLine(t *testing.T, c *expect.Console, line string) {
	t.Helper()
	if _, err := c.SendLine(line); err != nil {
		t.Fatalf("SendLine(%q): %v", line, err)
	}
}

// TestSandbox_DenyRead starts an interactive bash session and verifies that a
// file added to deny_read is not readable from inside the sandbox.
func TestSandbox_DenyRead(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	// Create a secret file on the host
	secretFile := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secretFile, []byte("supersecret\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Add deny_read rule via CLI
	addDeny := exec.Command(bin, "deny", "read", secretFile)
	addDeny.Env = env
	if out, err := addDeny.CombinedOutput(); err != nil {
		t.Fatalf("deny read: %v\n%s", err, out)
	}

	c, cleanup := runSandboxedShell(t, bin, env)
	defer cleanup()

	// Send the read attempt and a sentinel
	sendLine(t, c, fmt.Sprintf("cat %s; echo EXIT_CODE:$?", secretFile))

	// Expect permission denied (ACL enforced) or file not found (bind-mount exclusion)
	out, err := c.ExpectString("EXIT_CODE:")
	if err != nil {
		t.Fatalf("ExpectString: %v", err)
	}
	if strings.Contains(out, "supersecret") {
		t.Error("sandbox leaked secret file contents")
	}
}

// TestSandbox_DenyExec verifies that a denied command is blocked inside the sandbox.
func TestSandbox_DenyExec(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	// Build a tiny wrapper that we'll deny
	blockedBin := filepath.Join(t.TempDir(), "blockedtool")
	src := `#!/bin/sh
echo "BLOCKED TOOL RAN"
exit 0`
	if err := os.WriteFile(blockedBin, []byte(src), 0o755); err != nil {
		t.Fatal(err)
	}

	addDeny := exec.Command(bin, "deny", "exec", blockedBin)
	addDeny.Env = env
	if out, err := addDeny.CombinedOutput(); err != nil {
		t.Fatalf("deny exec: %v\n%s", err, out)
	}

	c, cleanup := runSandboxedShell(t, bin, env)
	defer cleanup()

	sendLine(t, c, blockedBin+"; echo EXIT_CODE:$?")

	out, err := c.ExpectString("EXIT_CODE:")
	if err != nil {
		t.Fatalf("ExpectString: %v", err)
	}
	// Should not have executed successfully
	if strings.Contains(out, "BLOCKED TOOL RAN") {
		t.Error("denied command ran inside sandbox")
	}
}

// TestSandbox_ConfigDirHidden verifies that ~/.aigate is not visible inside the sandbox.
func TestSandbox_ConfigDirHidden(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	c, cleanup := runSandboxedShell(t, bin, env)
	defer cleanup()

	sendLine(t, c, fmt.Sprintf("ls %s/.aigate 2>&1; echo LS_DONE", tmpHome))

	out, err := c.ExpectString("LS_DONE")
	if err != nil {
		t.Fatalf("ExpectString: %v", err)
	}
	// config dir should not be accessible or should not contain config.yaml
	if strings.Contains(out, "config.yaml") {
		t.Error("sandbox exposed ~/.aigate/config.yaml to the sandboxed process")
	}
}

// TestSandbox_PlainCommand verifies that a basic command runs successfully
// inside the sandbox without network isolation (no --except flags).
func TestSandbox_PlainCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	cmd := exec.Command(bin, "run", "--", "/bin/echo", "hello-sandbox")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sandboxed echo failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "hello-sandbox") {
		t.Errorf("expected 'hello-sandbox' in output, got: %s", out)
	}
}

// TestSandbox_ExitCodePropagation verifies that the inner command's exit code is
// forwarded by aigate run so callers can rely on it for scripting/CI.
func TestSandbox_ExitCodePropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	for _, tc := range []struct {
		exitCode int
		args     []string
	}{
		{0, []string{"/bin/true"}},
		{1, []string{"/bin/false"}},
		{42, []string{"/bin/sh", "-c", "exit 42"}},
	} {
		cmd := exec.Command(bin, append([]string{"run", "--"}, tc.args...)...)
		cmd.Env = env
		err := cmd.Run()
		got := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				got = exitErr.ExitCode()
			} else {
				t.Errorf("exit code %d: unexpected error type: %v", tc.exitCode, err)
				continue
			}
		}
		if got != tc.exitCode {
			t.Errorf("expected exit code %d, got %d", tc.exitCode, got)
		}
	}
}

// TestSandbox_SandboxBanner verifies that aigate prints the sandbox active banner
// to stderr when running a command, so AI agents see what restrictions are active.
func TestSandbox_SandboxBanner(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	// Write config with a deny rule so the banner has content to show
	configPath := filepath.Join(tmpHome, ".aigate", "config.yaml")
	cfg := "group: ai-agents\nuser: ai-runner\ndeny_read: [.env]\ndeny_exec: [curl]\nallow_net: []\n"
	if err := os.WriteFile(configPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "run", "--", "/bin/true")
	cmd.Env = env
	out, _ := cmd.CombinedOutput()
	output := string(out)

	if !strings.Contains(output, "[aigate] sandbox active") {
		t.Errorf("expected sandbox banner in output, got: %s", output)
	}
	if !strings.Contains(output, "deny_read") {
		t.Errorf("expected deny_read in banner, got: %s", output)
	}
	if !strings.Contains(output, "deny_exec") {
		t.Errorf("expected deny_exec in banner, got: %s", output)
	}
}

// TestSandbox_MaskStdout verifies that secrets matching a preset are redacted
// from the sandboxed process output before reaching the terminal.
func TestSandbox_MaskStdout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	// Enable the anthropic preset in config
	configPath := filepath.Join(tmpHome, ".aigate", "config.yaml")
	cfg := "group: ai-agents\nuser: ai-runner\ndeny_read: []\ndeny_exec: []\nallow_net: []\nmask_stdout:\n  presets: [anthropic]\n"
	if err := os.WriteFile(configPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	fakeKey := "sk-ant-api03-thisisafakekeyfortesting1234567890"
	cmd := exec.Command(bin, "run", "--", "/bin/echo", fakeKey)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sandboxed echo failed: %v\n%s", err, out)
	}
	output := string(out)
	if strings.Contains(output, fakeKey) {
		t.Errorf("mask_stdout failed: full key visible in output: %s", output)
	}
	if !strings.Contains(output, "sk-ant-***") {
		t.Errorf("mask_stdout did not redact key (expected 'sk-ant-***'): %s", output)
	}
}

// TestSandbox_DenyExecSubcommand verifies that subcommand-level deny rules
// block the specific subcommand but not the base command with other arguments.
func TestSandbox_DenyExecSubcommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	// Write config with a subcommand deny rule
	configPath := filepath.Join(tmpHome, ".aigate", "config.yaml")
	cfg := "group: ai-agents\nuser: ai-runner\ndeny_read: []\ndeny_exec: [sh -c]\nallow_net: []\n"
	if err := os.WriteFile(configPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	// "sh -c" should be blocked
	blocked := exec.Command(bin, "run", "--", "sh", "-c", "echo blocked")
	blocked.Env = env
	out, err := blocked.CombinedOutput()
	if err == nil {
		t.Errorf("expected deny_exec subcommand to block 'sh -c', but it succeeded: %s", out)
	}
	if !strings.Contains(string(out), "deny_exec") && !strings.Contains(string(out), "blocked") {
		t.Errorf("expected block error in output, got: %s", out)
	}

	// "sh" with a different flag should pass through
	allowed := exec.Command(bin, "run", "--", "/bin/true")
	allowed.Env = env
	if out, err := allowed.CombinedOutput(); err != nil {
		t.Errorf("non-denied command failed unexpectedly: %v\n%s", err, out)
	}
}

// TestSandbox_ProjectConfig verifies that per-project .aigate.yaml rules are
// merged with and extend the global config when running from that directory.
func TestSandbox_ProjectConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	// Create a project dir with a .aigate.yaml that denies an extra exec
	projectDir := t.TempDir()
	projectCfg := "deny_exec: [cat]\n"
	if err := os.WriteFile(filepath.Join(projectDir, ".aigate.yaml"), []byte(projectCfg), 0o644); err != nil {
		t.Fatal(err)
	}

	// Running from the project dir should pick up the project deny rule
	cmd := exec.Command(bin, "run", "--", "cat", "/dev/null")
	cmd.Env = env
	cmd.Dir = projectDir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("expected project deny_exec to block 'cat', but it succeeded: %s", out)
	}

	// Running from a dir without .aigate.yaml should not block cat
	cmd = exec.Command(bin, "run", "--", "cat", "/dev/null")
	cmd.Env = env
	cmd.Dir = t.TempDir()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("cat should not be blocked without project config: %v\n%s", err, out)
	}
}

// TestSandbox_WorkdirAccessible verifies that the working directory (and files in it)
// are readable from inside the sandbox.
func TestSandbox_WorkdirAccessible(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	workDir := t.TempDir()
	testFile := filepath.Join(workDir, "hello.txt")
	if err := os.WriteFile(testFile, []byte("hello-from-workdir\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "run", "--", "cat", testFile)
	cmd.Env = env
	cmd.Dir = workDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("reading workdir file failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "hello-from-workdir") {
		t.Errorf("expected file content in output, got: %s", out)
	}
}
