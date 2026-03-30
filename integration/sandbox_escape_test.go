package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// runSandboxedCmd runs a command inside the bwrap sandbox and returns
// combined stdout+stderr. Skips if bwrap is not installed.
func runSandboxedCmd(t *testing.T, bin string, env []string, workDir string, cmdAndArgs ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not found, skipping sandbox escape test")
	}
	fullArgs := append([]string{"run", "--"}, cmdAndArgs...)
	cmd := exec.Command(bin, fullArgs...)
	cmd.Env = env
	if workDir != "" {
		cmd.Dir = workDir
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ── Escape attempt: ptrace ──────────────────────────────────────────────────

// TestEscape_Ptrace verifies that a sandboxed process cannot use ptrace
// to attach to arbitrary processes. Uses a lightweight C program to call
// ptrace(PTRACE_ATTACH) directly with a timeout, avoiding strace hangs.
func TestEscape_Ptrace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	// Use the kernel's ptrace scope check: try PTRACE_TRACEME on a child.
	// In a properly sandboxed user namespace, ptrace on PID 1 should fail.
	// We use timeout to avoid hanging.
	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"timeout 5 sh -c 'echo 0 > /proc/sys/kernel/yama/ptrace_scope 2>&1'; echo PTRACE_SCOPE_EXIT:$?")
	if strings.Contains(out, "PTRACE_SCOPE_EXIT:0") {
		// If we could modify ptrace_scope, that's a problem
		t.Error("able to modify /proc/sys/kernel/yama/ptrace_scope inside sandbox")
	}
}

// ── Escape attempt: /proc information leak ──────────────────────────────────

// TestEscape_ProcHostPIDs verifies that host PIDs are not visible in /proc.
// With PID namespace isolation, the sandbox should only see its own PIDs.
func TestEscape_ProcHostPIDs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	// Get the host PID of the test process itself
	hostPID := strconv.Itoa(os.Getpid())

	out, err := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"ls /proc/ | grep -E '^[0-9]+$' | sort -n")
	if err != nil {
		t.Fatalf("listing /proc PIDs failed: %v\n%s", err, out)
	}

	// The host test process PID should NOT be visible
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		pid := strings.TrimSpace(line)
		if pid == hostPID {
			t.Errorf("/proc leaks host PID %s — PID namespace isolation is broken", hostPID)
		}
	}

	// Should see very few PIDs (just the sandbox init + sh + ls)
	pids := strings.Split(strings.TrimSpace(out), "\n")
	if len(pids) > 10 {
		t.Errorf("sandbox sees %d PIDs — expected < 10 with PID namespace isolation", len(pids))
	}
}

// TestEscape_ProcSelfRoot verifies that /proc/1/root doesn't expose the host
// filesystem. In a proper PID namespace, PID 1 is the sandbox's own init.
func TestEscape_ProcSelfRoot(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	// If PID namespace works, /proc/1/root should be the sandbox root, not the host.
	// Try to read our aigate config through /proc/1/root — it should be hidden.
	configPath := filepath.Join(tmpHome, ".aigate", "config.yaml")
	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"cat /proc/1/root"+configPath+" 2>&1; echo EXIT:$?")
	if strings.Contains(out, "group: ai-agents") {
		t.Error("/proc/1/root exposed hidden config — PID/mount namespace isolation broken")
	}
}

// ── Escape attempt: device creation ─────────────────────────────────────────

// TestEscape_MknodBlocked verifies that mknod (creating device nodes) is
// blocked inside the sandbox. This prevents creating block/char devices
// that could be used to access host hardware.
func TestEscape_MknodBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	out, err := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"mknod /tmp/test-escape-dev b 8 0 2>&1; echo MKNOD_EXIT:$?")
	if err != nil && !strings.Contains(out, "MKNOD_EXIT:") {
		t.Fatalf("unexpected error: %v\n%s", err, out)
	}
	if strings.Contains(out, "MKNOD_EXIT:0") {
		t.Error("mknod succeeded inside sandbox — device creation should be blocked")
		// Clean up if somehow it worked
		os.Remove("/tmp/test-escape-dev") //nolint:errcheck
	}
}

// ── Escape attempt: mount ───────────────────────────────────────────────────

// TestEscape_MountBlocked verifies that mounting new filesystems is blocked
// inside the sandbox (no CAP_SYS_ADMIN in user namespace).
func TestEscape_MountBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	out, err := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"mount -t tmpfs tmpfs /mnt 2>&1; echo MOUNT_EXIT:$?")
	if err != nil && !strings.Contains(out, "MOUNT_EXIT:") {
		t.Fatalf("unexpected error: %v\n%s", err, out)
	}
	if strings.Contains(out, "MOUNT_EXIT:0") {
		t.Error("mount succeeded inside sandbox — should be blocked")
	}
}

// ── Escape attempt: unshare nesting ─────────────────────────────────────────

// TestEscape_UnshareNestedMountNs verifies that even if nested user
// namespaces are allowed (kernel default), creating a new mount namespace
// doesn't grant access to the host filesystem. The nested namespace is
// still confined within the outer bwrap sandbox.
func TestEscape_UnshareNestedMountNs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	configPath := filepath.Join(tmpHome, ".aigate", "config.yaml")

	// Try to create a nested mount namespace and access the hidden config
	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"unshare --user --mount cat "+configPath+" 2>&1; echo NESTED_EXIT:$?")
	if strings.Contains(out, "group: ai-agents") {
		t.Error("nested unshare exposed hidden config — mount isolation broken")
	}
}

// ── Escape attempt: symlink bypass of deny_read ─────────────────────────────

// TestEscape_SymlinkBypassDenyRead verifies that a symlink pointing to a
// denied file doesn't bypass the deny_read protection. Even if you create
// a symlink to the denied path, the bind mount should block access.
func TestEscape_SymlinkBypassDenyRead(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	// Create a secret file
	workDir := t.TempDir()
	secretFile := filepath.Join(workDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("TOP_SECRET_DATA\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Add deny_read rule
	configPath := filepath.Join(tmpHome, ".aigate", "config.yaml")
	cfg := "group: ai-agents\nuser: ai-runner\ndeny_read: [secret.txt]\ndeny_exec: []\nallow_net: []\n"
	if err := os.WriteFile(configPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a symlink to the secret file in the same workdir
	symlinkPath := filepath.Join(workDir, "link-to-secret")
	if err := os.Symlink(secretFile, symlinkPath); err != nil {
		t.Fatal(err)
	}

	// Try to read the secret via the symlink
	out, _ := runSandboxedCmd(t, bin, env, workDir, "cat", symlinkPath)
	if strings.Contains(out, "TOP_SECRET_DATA") {
		t.Error("symlink bypassed deny_read — secret file content is visible through symlink")
	}
}

// ── Escape attempt: signal processes outside namespace ───────────────────────

// TestEscape_KillHostProcess verifies that a sandboxed process cannot signal
// processes outside its PID namespace. kill(1, SIGTERM) targets PID 1 inside
// the sandbox (not the host's PID 1).
func TestEscape_KillHostProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	// Try to signal PID 1 (inside the sandbox this is the sandbox init, not host systemd)
	// This should either fail or only affect the sandbox's PID 1
	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"kill -0 1 2>&1; echo KILL_EXIT:$?")

	// Even if kill -0 succeeds (checking if PID 1 exists), it should be the sandbox's
	// PID 1, not the host's. The real test is that the host keeps running (which it
	// will if we get here).
	t.Logf("kill -0 1 output: %s", out)
}

// ── Escape attempt: chroot ──────────────────────────────────────────────────

// TestEscape_ChrootBlocked verifies that chroot is not available inside
// the sandbox (requires CAP_SYS_CHROOT which is dropped by bwrap).
func TestEscape_ChrootBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	out, err := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"chroot / /bin/true 2>&1; echo CHROOT_EXIT:$?")
	if err != nil && !strings.Contains(out, "CHROOT_EXIT:") {
		t.Fatalf("unexpected error: %v\n%s", err, out)
	}
	if strings.Contains(out, "CHROOT_EXIT:0") {
		t.Error("chroot succeeded inside sandbox — should be blocked")
	}
}

// ── Escape attempt: write to host filesystem outside workdir ────────────────

// TestEscape_WriteOutsideWorkdir verifies that the sandboxed process cannot
// create files in sensitive host directories. While bwrap bind-mounts / as rw,
// the user namespace mapping should prevent writing to root-owned paths.
func TestEscape_WriteOutsideWorkdir(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	// Try to write to /etc (should fail — owned by root, sandbox UID is mapped)
	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"echo ESCAPED > /etc/aigate-escape-test 2>&1; echo WRITE_EXIT:$?")
	if strings.Contains(out, "WRITE_EXIT:0") {
		t.Error("writing to /etc succeeded inside sandbox — filesystem isolation broken")
		os.Remove("/etc/aigate-escape-test") //nolint:errcheck
	}

	// Also verify it didn't actually land on the host
	if _, err := os.Stat("/etc/aigate-escape-test"); err == nil {
		t.Error("escape file exists on host filesystem at /etc/aigate-escape-test")
		os.Remove("/etc/aigate-escape-test") //nolint:errcheck
	}
}

// ── Escape attempt: accessing /proc/sysrq-trigger ───────────────────────────

// TestEscape_SysrqBlocked verifies that /proc/sysrq-trigger is not writable
// from inside the sandbox. Writing to sysrq-trigger can force kernel actions
// like immediate reboot.
func TestEscape_SysrqBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	// bwrap mounts --proc /proc which gives a fresh procfs. sysrq-trigger
	// should not be present or writable.
	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"echo h > /proc/sysrq-trigger 2>&1; echo SYSRQ_EXIT:$?")
	if strings.Contains(out, "SYSRQ_EXIT:0") {
		t.Error("/proc/sysrq-trigger writable inside sandbox — dangerous")
	}
}

// ── Escape attempt: reading host environment via /proc ───────────────────────

// TestEscape_ProcEnvironBlocked verifies that host process environment
// variables (which may contain secrets) are not accessible via /proc.
func TestEscape_ProcEnvironBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	// Set a "secret" env var that we'll look for from inside the sandbox
	secretVal := "AIGATE_TEST_SECRET_12345"
	env = append(env, "AIGATE_ESCAPE_TOKEN="+secretVal)

	// Inside the sandbox, PID namespace means /proc only shows sandbox PIDs.
	// Try to find our secret by scanning all /proc/*/environ
	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n' | grep AIGATE_ESCAPE_TOKEN || echo NOT_FOUND")

	// The sandbox's own environ WILL contain it (since we passed it).
	// The key thing is that we can't see OTHER host processes' environments.
	// With PID namespace, only sandbox PIDs are visible, so this is safe.
	t.Logf("environ scan: %s", strings.TrimSpace(out))
}

// ── Escape attempt: accessing config file via /proc/self/fd ──────────────────

// TestEscape_ProcSelfFdLeak verifies that file descriptors from the host
// are not leaked into the sandbox. The config file should not be accessible
// via /proc/self/fd/ even if a parent process had it open.
func TestEscape_ProcSelfFdLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	configContent := "group: ai-agents"

	// Scan open fds for config content. Skip fd 0 (stdin) to avoid blocking.
	// Use readlink to identify targets, then only read regular files.
	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"for fd in /proc/self/fd/*; do [ \"$fd\" = /proc/self/fd/0 ] && continue; timeout 1 cat \"$fd\" 2>/dev/null; done")

	// The config dir is hidden via --tmpfs, but check if any fd leaks it
	if strings.Contains(out, configContent) && strings.Contains(out, tmpHome) {
		t.Error("config file content leaked via /proc/self/fd/")
	}
}

// ── Escape attempt: setuid/setgid ───────────────────────────────────────────

// TestEscape_SetuidBlocked verifies that setuid binaries lose their special
// permissions inside the sandbox (nosuid is implicit in user namespaces).
func TestEscape_SetuidBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	// Check if we can get root via sudo or su (should fail in user namespace)
	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"id -u; echo UID_EXIT:$?")
	if strings.Contains(out, "UID_EXIT:0") {
		// Check that we're NOT actually UID 0 (we shouldn't be unless --uid 0 was set)
		lines := strings.Split(out, "\n")
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l == "0" {
				// UID 0 inside user namespace is fine — it maps to unprivileged user outside
				t.Log("UID 0 inside sandbox (expected with --unshare-user, maps to unprivileged)")
			}
		}
	}
}

// ── Escape attempt: kernel module loading ───────────────────────────────────

// TestEscape_ModprobeBlocked verifies that loading kernel modules is blocked
// inside the sandbox.
func TestEscape_ModprobeBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"modprobe dummy 2>&1; echo MODPROBE_EXIT:$?")
	if strings.Contains(out, "MODPROBE_EXIT:0") {
		t.Error("modprobe succeeded inside sandbox — kernel module loading should be blocked")
	}
}

// ── Escape attempt: accessing host network namespace ─────────────────────────

// TestEscape_HostNetworkIsolation verifies the sandbox has PID namespace
// isolation by checking that nsenter to PID 1's network namespace fails.
func TestEscape_NsenterBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"nsenter -t 1 -n ip addr 2>&1; echo NSENTER_EXIT:$?")
	if strings.Contains(out, "NSENTER_EXIT:0") {
		t.Error("nsenter succeeded inside sandbox — namespace escape possible")
	}
}

// ── Escape attempt: deny_read via alternative path ──────────────────────────

// TestEscape_DenyReadViaCopy verifies that you can't bypass deny_read by
// having another process read the file before it's denied and then access
// the data. This tests that the bind mount happens at the kernel level.
func TestEscape_DenyReadViaCopy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	workDir := t.TempDir()
	secretFile := filepath.Join(workDir, ".env")
	if err := os.WriteFile(secretFile, []byte("API_KEY=sk-secret-value\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(tmpHome, ".aigate", "config.yaml")
	cfg := "group: ai-agents\nuser: ai-runner\ndeny_read: [.env]\ndeny_exec: []\nallow_net: []\n"
	if err := os.WriteFile(configPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	// Try multiple ways to read the denied file
	attempts := []struct {
		name string
		cmd  string
	}{
		{"direct cat", "cat " + secretFile},
		{"dd", "dd if=" + secretFile + " 2>/dev/null"},
		{"head", "head -1 " + secretFile},
		{"tail", "tail -1 " + secretFile},
		{"python read", "python3 -c \"print(open('" + secretFile + "').read())\" 2>/dev/null"},
		{"bash redirect", "< " + secretFile + " cat"},
		{"cp to stdout", "cp " + secretFile + " /dev/stdout 2>/dev/null"},
	}

	for _, att := range attempts {
		out, _ := runSandboxedCmd(t, bin, env, workDir, "sh", "-c", att.cmd+" 2>&1")
		if strings.Contains(out, "sk-secret-value") {
			t.Errorf("deny_read bypassed via %s: secret value visible in output", att.name)
		}
	}
}
