//go:build linux

package services

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// SandboxExecArg is the hidden first argument that turns aigate into the last
// step of a sandbox: drop every capability, then exec the command. Sandbox
// setup (iptables, mounts) needs capabilities the command must never get, so
// setup scripts end with `exec <aigate> __sandbox-exec -- CMD ARGS…`.
const SandboxExecArg = "__sandbox-exec"

// SandboxExec drops all capabilities for good and replaces this process with
// args. It only returns on failure; the caller exits with the returned code
// (126 can't drop or exec, 127 not found), like a shell would.
//
// Before "--", `--unmount PATH` detaches a setup-only mount first (while the
// capability to do so still exists); failure there is reported, not fatal.
func SandboxExec(args []string) int {
	var unmount []string
	for len(args) > 1 && args[0] == "--unmount" {
		unmount, args = append(unmount, args[1]), args[2:]
	}
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "[aigate] "+SandboxExecArg+": no command")
		return 126
	}
	path, err := exec.LookPath(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: command not found\n", args[0])
		return 127
	}
	// Credentials are per thread: drop and exec from the same one.
	runtime.LockOSThread()
	for _, p := range unmount {
		if err := unix.Unmount(p, unix.MNT_DETACH); err != nil {
			fmt.Fprintf(os.Stderr, "[aigate] note: could not remove setup file %s: %v\n", p, err)
		}
	}
	if err := DropAllCapabilities(); err != nil {
		fmt.Fprintln(os.Stderr, "[aigate] refusing to run: "+err.Error())
		return 126
	}
	err = syscall.Exec(path, args, os.Environ())
	fmt.Fprintf(os.Stderr, "%s: %v\n", args[0], err)
	return 126
}

// DropAllCapabilities leaves the calling thread with no capabilities that any
// later exec could get back:
//   - no_new_privs: exec can't gain privileges (setuid files, file caps, or
//     uid 0's implicit full set — new caps are capped to the old, empty set);
//   - ambient and permitted/effective/inheritable sets cleared;
//   - bounding set emptied where allowed (needs CAP_SETPCAP; no_new_privs
//     already covers it when that's missing).
func DropAllCapabilities() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}
	for c := 0; c <= unix.CAP_LAST_CAP; c++ {
		_ = unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0) // best effort, see above
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("drop capabilities: %w", err)
	}
	return nil
}

// sandboxExecBinary is the aigate binary the sandbox execs as its last step.
func sandboxExecBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("find aigate binary: %w", err)
	}
	return CanonicalPath(exe), nil
}

// bwrapSandboxExec is where bwrap mounts the aigate binary (read-only) inside
// the sandbox; /tmp there is a private tmpfs.
const bwrapSandboxExec = "/tmp/.aigate-exec"

// bwrapSetupShell is the host's shell, bound for the setup script only.
const bwrapSetupShell = "/tmp/.aigate-setup-sh"

// hostShell is the real /bin/sh on the host (bwrap binds from the host side,
// before any deny_exec mount).
func hostShell() string {
	if p, err := filepath.EvalSymlinks("/bin/sh"); err == nil {
		return p
	}
	return "/bin/sh"
}

// sandboxExecStage is the aigate binary (src) bound read-only over an empty
// placeholder file (dst) for the unshare fallback, whose /tmp is the host's.
type sandboxExecStage struct{ src, dst string }

// stageSandboxExec creates the placeholder; cleanup removes it after the run.
func stageSandboxExec() (sandboxExecStage, func(), error) {
	src, err := sandboxExecBinary()
	if err != nil {
		return sandboxExecStage{}, func() {}, err
	}
	f, err := os.CreateTemp("", "aigate-exec-*")
	if err != nil {
		return sandboxExecStage{}, func() {}, fmt.Errorf("stage sandbox exec: %w", err)
	}
	_ = f.Close()
	return sandboxExecStage{src: src, dst: f.Name()}, func() { _ = os.Remove(f.Name()) }, nil
}

// bindScript mounts the binary over the placeholder read-only; it runs before
// scope hides $HOME (where aigate may live). Fail-closed: no helper, no run.
func (s sandboxExecStage) bindScript() string {
	return fmt.Sprintf("mount --bind %s %s && mount -o remount,bind,ro %s || { echo '[aigate] could not prepare the sandbox (mount aigate binary)' >&2; exit 126; }\n",
		shellQuote(s.src), shellQuote(s.dst), shellQuote(s.dst))
}

// execAsCommand is the last line of every setup script: back into the
// working dir (so relative paths go through the mounts made above, not the
// directory the shell started in), then drop capabilities and exec.
func execAsCommand(execBin, workDir string, unmount []string, cmd string, args []string) string {
	var sb strings.Builder
	if workDir != "" {
		fmt.Fprintf(&sb, "cd %s || exit 126\n", shellQuote(workDir))
	}
	helper := []string{SandboxExecArg}
	for _, p := range unmount {
		helper = append(helper, "--unmount", p)
	}
	sb.WriteString("exec ")
	sb.WriteString(shellEscape(execBin, append(append(helper, "--", cmd), args...)))
	sb.WriteString("\n")
	return sb.String()
}

// writeNetSetup brings up the sandbox's own network: wait for slirp4netns,
// point DNS at it, and with allow_net install the firewall. Without allow_net
// every host is reachable, but the host's loopback and abstract sockets
// still aren't (own namespace, --disable-host-loopback).
func writeNetSetup(sb *strings.Builder, allowNet []string, ipv6Enabled bool, ports []int) {
	writeWaitForTap0(sb)
	writeResolvConf(sb, ipv6Enabled)
	if len(allowNet) > 0 {
		writeIPv4Rules(sb, allowNet)
		if ipv6Enabled {
			writeIPv6Rules(sb, allowNet)
		}
	}
	writePortRedirects(sb, ports, len(allowNet) > 0)
}
