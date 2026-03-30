//go:build linux

package services

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/term"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/helpers"
)

// hasBwrap checks whether bwrap (Bubblewrap) is available on the system.
func hasBwrap() bool {
	_, err := exec.LookPath("bwrap")
	return err == nil
}

// runWithBwrap runs a command in a Bubblewrap sandbox.
//
// bwrap replaces the shell-script-based unshare approach:
//   - Mount namespace is set up declaratively via flags (no shell injection risk)
//   - deny_read: --bind deny-marker over files, --tmpfs over dirs
//   - deny_exec: --bind deny stub or wrapper over binary paths
//   - Config protection: --tmpfs over ~/.aigate
//   - cmd and args are passed directly after --, no shell escaping needed
//
// Falls back to runUnshare when bwrap is not installed.
func (p *LinuxPlatform) runWithBwrap(profile domain.SandboxProfile, cmd string, args []string, stdout, stderr io.Writer) error {
	var tmpFiles []string
	defer func() {
		for _, f := range tmpFiles {
			os.Remove(f) //nolint:errcheck
		}
	}()

	bwrapArgs, err := p.buildBwrapArgs(profile, &tmpFiles)
	if err != nil {
		return fmt.Errorf("failed to build bwrap args: %w", err)
	}

	bwrapArgs = append(bwrapArgs, "--")
	bwrapArgs = append(bwrapArgs, cmd)
	bwrapArgs = append(bwrapArgs, args...)

	return p.exec.RunPassthroughWith(stdout, stderr, "bwrap", bwrapArgs...)
}

// buildBwrapArgs constructs the bwrap argument list for the given profile.
// Paths of temp files created for bind mounts are appended to tmpFiles; the
// caller is responsible for removing them after bwrap exits.
func (p *LinuxPlatform) buildBwrapArgs(profile domain.SandboxProfile, tmpFiles *[]string) ([]string, error) {
	args := []string{
		"--ro-bind", "/", "/", // read-only root (prevents writes outside workdir)
		"--dev", "/dev", // minimal private /dev
		"--proc", "/proc", // fresh /proc for PID namespace
		"--tmpfs", "/tmp", // isolated writable /tmp (no host /tmp leaks)
		"--unshare-pid",  // new PID namespace
		"--unshare-user", // user namespace (current UID → root inside)
		"--die-with-parent",
	}

	// Writable workdir: the only host directory the sandbox can modify.
	if profile.WorkDir != "" {
		args = append(args, "--bind", profile.WorkDir, profile.WorkDir)
	}

	// Hide aigate config directory from the sandboxed process.
	if home, err := os.UserHomeDir(); err == nil {
		args = append(args, "--tmpfs", filepath.Join(home, ".aigate"))
	}

	// Write the policy file to a temp path, then bind it to /tmp/.aigate-policy
	// inside the sandbox so AI agents can read why access is restricted.
	policyPath, err := writeTmpFile("aigate-policy-*", policyFileContent(profile))
	if err != nil {
		return nil, fmt.Errorf("write policy file: %w", err)
	}
	*tmpFiles = append(*tmpFiles, policyPath)
	args = append(args, "--bind", policyPath, "/tmp/.aigate-policy")

	// deny_read: bind a deny marker over files, mount empty tmpfs over dirs.
	// For files with hardlinks, also deny all alternate paths in the workdir
	// that share the same inode (hardlinks bypass path-based bind mounts).
	denyMarkerPath := ""
	for _, pattern := range profile.Config.DenyRead {
		paths, _ := resolvePatterns([]string{pattern}, profile.WorkDir)
		for _, path := range paths {
			info, statErr := os.Stat(path)
			if statErr != nil {
				helpers.Log.Warn().Str("path", path).Msg("skipping (not found)")
				continue
			}
			if info.IsDir() {
				args = append(args, "--tmpfs", path)
			} else {
				if denyMarkerPath == "" {
					const denyMsg = "[aigate] access denied: this file is protected by sandbox policy. See /tmp/.aigate-policy for all active restrictions.\n"
					denyMarkerPath, err = writeTmpFile("aigate-denied-*", denyMsg)
					if err != nil {
						return nil, fmt.Errorf("write deny marker: %w", err)
					}
					*tmpFiles = append(*tmpFiles, denyMarkerPath)
				}
				args = append(args, "--bind", denyMarkerPath, path)

				// Deny hardlinks: find all paths in the workdir that share the
				// same inode and add deny bind mounts for each.
				hardlinks := findHardlinks(path, profile.WorkDir)
				for _, link := range hardlinks {
					args = append(args, "--bind", denyMarkerPath, link)
				}
			}
		}
	}

	// deny_exec: bind deny stubs / wrappers over binary paths.
	execArgs, execTmp, err := buildBwrapExecDenyArgs(profile)
	if err != nil {
		return nil, err
	}
	*tmpFiles = append(*tmpFiles, execTmp...)
	args = append(args, execArgs...)

	return args, nil
}

// policyFileContent returns the human-readable sandbox policy summary written
// to /tmp/.aigate-policy inside the sandbox.
func policyFileContent(profile domain.SandboxProfile) string {
	var sb strings.Builder
	sb.WriteString("[aigate] sandbox policy\n\n")
	if len(profile.Config.DenyRead) > 0 {
		fmt.Fprintf(&sb, "deny_read: %s\n", strings.Join(profile.Config.DenyRead, ", "))
		sb.WriteString("These files/directories appear empty or contain a deny marker inside the sandbox.\n\n")
	}
	if len(profile.Config.DenyExec) > 0 {
		fmt.Fprintf(&sb, "deny_exec: %s\n", strings.Join(profile.Config.DenyExec, ", "))
		sb.WriteString("These commands are blocked both before and inside the sandbox.\n\n")
	}
	if len(profile.Config.AllowNet) > 0 {
		fmt.Fprintf(&sb, "allow_net: %s\n", strings.Join(profile.Config.AllowNet, ", "))
		sb.WriteString("Only these hosts are reachable. All other outbound connections are rejected.\n\n")
	}
	return sb.String()
}

// writeTmpFile creates a named temp file with the given content and returns its path.
func writeTmpFile(pattern, content string) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck
	if _, err := f.WriteString(content); err != nil {
		os.Remove(f.Name()) //nolint:errcheck
		return "", err
	}
	return f.Name(), nil
}

// runWithBwrapNetFilter runs a network-filtered sandbox using bwrap + slirp4netns.
//
// Architecture (bwrap-native, no nested unshare):
//
//	bwrap [deny mounts] --unshare-net --info-fd 3 -- sh -c <net-setup+exec>
//	  └── slirp4netns --configure <child-PID> tap0   (launched from host)
//
// bwrap creates the network namespace natively via --unshare-net. The
// orchestration (two-process dance) is handled in Go:
//  1. bwrap writes {"child-pid": N} to info-fd once namespaces are ready.
//  2. Parent reads the PID and launches slirp4netns from host-side.
//  3. The inner script waits for tap0, sets up iptables, then execs the command.
//
// This avoids the nested `unshare --net` inside bwrap's user namespace, which
// fails with EPERM on systems where network-namespace creation requires
// CAP_SYS_ADMIN in the initial user namespace.
func (p *LinuxPlatform) runWithBwrapNetFilter(profile domain.SandboxProfile, cmd string, args []string, stdout, stderr io.Writer) error {
	dnsServers := getSystemDNS()
	helpers.Log.Info().
		Strs("allow_net", profile.Config.AllowNet).
		Strs("dns_servers", dnsServers).
		Msg("starting bwrap network-filtered sandbox")

	var tmpFiles []string
	defer func() {
		for _, f := range tmpFiles {
			os.Remove(f) //nolint:errcheck
		}
	}()

	bwrapArgs, err := p.buildBwrapArgs(profile, &tmpFiles)
	if err != nil {
		return fmt.Errorf("failed to build bwrap args: %w", err)
	}

	// Info pipe: bwrap writes {"child-pid": N} to fd 3 (ExtraFiles[0]) once
	// namespaces are ready, before exec'ing the inner command.
	infoR, infoW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create info pipe: %w", err)
	}
	defer infoR.Close() //nolint:errcheck

	bwrapArgs = appendBwrapNetArgs(bwrapArgs, profile.Config.AllowNet, dnsServers, cmd, args)

	bwrapCmd := exec.Command("bwrap", bwrapArgs...)
	bwrapCmd.ExtraFiles = []*os.File{infoW} // fd 3 in child

	// Start bwrap.
	// When stdout is a masking writer (not a raw *os.File) AND stdin is a TTY,
	// use a PTY so the child sees an interactive terminal. Otherwise connect
	// stdout/stderr directly so the masking writer receives the output.
	var ptm *os.File
	_, stdoutIsFile := stdout.(*os.File)
	if !stdoutIsFile && term.IsTerminal(int(os.Stdin.Fd())) {
		ptm, err = startBwrapWithPTY(bwrapCmd)
		if err != nil {
			// PTY unavailable — fall back to plain pipe so masking still applies.
			helpers.Log.Warn().Err(err).Msg("PTY setup failed, falling back to plain pipe")
			ptm = nil
			err = startBwrapPlain(bwrapCmd, stdout, stderr, infoW)
		}
	} else {
		err = startBwrapPlain(bwrapCmd, stdout, stderr, infoW)
	}
	infoW.Close() //nolint:errcheck // close write end in parent after Start (child has its own copy)
	if err != nil {
		infoR.Close() //nolint:errcheck
		return fmt.Errorf("start bwrap: %w", err)
	}

	// Read the child PID from info-fd (bwrap writes before exec'ing inner script).
	childPID, err := readBwrapInfoPID(infoR)
	infoR.Close() //nolint:errcheck
	if err != nil {
		bwrapCmd.Process.Kill() //nolint:errcheck
		bwrapCmd.Wait()         //nolint:errcheck
		if ptm != nil {
			ptm.Close() //nolint:errcheck
		}
		return fmt.Errorf("bwrap info-fd: %w", err)
	}

	// Launch slirp4netns from the host side targeting the child's net namespace.
	// Suppress stdout (verbose protocol debug), keep stderr for real errors.
	slirpCmd := exec.Command("slirp4netns", "--configure", strconv.Itoa(childPID), "tap0")
	slirpCmd.Stdout = nil
	slirpCmd.Stderr = os.Stderr
	if slirpErr := slirpCmd.Start(); slirpErr != nil {
		bwrapCmd.Process.Kill() //nolint:errcheck
		bwrapCmd.Wait()         //nolint:errcheck
		if ptm != nil {
			ptm.Close() //nolint:errcheck
		}
		return fmt.Errorf("start slirp4netns: %w", slirpErr)
	}

	// PTY: forward terminal I/O and propagate resize events.
	if ptm != nil {
		if ws, wsErr := pty.GetsizeFull(os.Stdin); wsErr == nil {
			pty.Setsize(ptm, ws) //nolint:errcheck
		}
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGWINCH)
		go func() {
			for range sigCh {
				if ws, wsErr := pty.GetsizeFull(os.Stdin); wsErr == nil {
					pty.Setsize(ptm, ws) //nolint:errcheck
				}
			}
		}()
		defer func() {
			signal.Stop(sigCh)
			close(sigCh)
		}()
		if oldState, rawErr := term.MakeRaw(int(os.Stdin.Fd())); rawErr == nil {
			defer term.Restore(int(os.Stdin.Fd()), oldState) //nolint:errcheck
		}
		go func() { io.Copy(ptm, os.Stdin) }() //nolint:errcheck
		go func() { io.Copy(stdout, ptm) }()   //nolint:errcheck
	}

	// Wait for bwrap to finish, then clean up slirp4netns.
	bwrapErr := bwrapCmd.Wait()
	if ptm != nil {
		ptm.Close() //nolint:errcheck
	}
	slirpCmd.Process.Kill() //nolint:errcheck
	slirpCmd.Wait()         //nolint:errcheck

	return bwrapErr
}

// appendBwrapNetArgs appends the network-sandbox-specific bwrap flags and the
// inner shell script to an existing bwrap arg slice. Separated for testability.
//
// The inner script needs to run iptables (CAP_NET_ADMIN) and bind-mount
// resolv.conf (CAP_SYS_ADMIN), so we set UID 0 and add the two caps.
// bwrap drops all capabilities by default even inside the user namespace;
// without --uid 0, the process is UID 1000 and nf_tables rejects it.
func appendBwrapNetArgs(args []string, allowNet, dnsServers []string, cmd string, cmdArgs []string) []string {
	// Set UID/GID to 0 inside the sandbox: nf_tables requires being root (UID 0)
	// in the user namespace, not just having CAP_NET_ADMIN.
	args = append(args, "--uid", "0", "--gid", "0")
	// CAP_NET_ADMIN: iptables / nf_tables rule manipulation.
	// CAP_SYS_ADMIN: mount --bind resolv.conf and mount --make-rprivate.
	args = append(args, "--cap-add", "cap_net_admin", "--cap-add", "cap_sys_admin")
	// bwrap creates the network namespace natively; info-fd 3 (ExtraFiles[0])
	// carries the child PID so the parent can launch slirp4netns.
	args = append(args, "--unshare-net", "--info-fd", "3")
	innerScript := buildNetOnlyScript(allowNet, dnsServers, cmd, cmdArgs)
	args = append(args, "--", "sh", "-c", innerScript)
	return args
}

// startBwrapPlain starts bwrap with direct stdout/stderr writers (no PTY).
// infoW is added as ExtraFiles[0] (fd 3 in the child) for --info-fd.
func startBwrapPlain(bwrapCmd *exec.Cmd, stdout, stderr io.Writer, infoW *os.File) error {
	bwrapCmd.Stdin = os.Stdin
	bwrapCmd.Stdout = stdout
	bwrapCmd.Stderr = stderr
	bwrapCmd.ExtraFiles = []*os.File{infoW}
	return bwrapCmd.Start()
}

// startBwrapWithPTY starts a bwrap command under a PTY so that child processes
// see a TTY on stdout. Only called when stdin is a terminal and stdout is a
// masking writer. Falls back to starting without a PTY if PTY creation fails.
// Returns the PTY master fd (or nil on fallback), and any error.
func startBwrapWithPTY(bwrapCmd *exec.Cmd) (*os.File, error) {
	// pty.Start sets cmd.Stdin/Stdout/Stderr to the tty and calls cmd.Start.
	// ExtraFiles (info pipe fd 3) are preserved across the fork.
	ptm, err := pty.Start(bwrapCmd)
	if err != nil {
		return nil, fmt.Errorf("pty.Start: %w", err)
	}
	return ptm, nil
}

// readBwrapInfoPID reads the {"child-pid": N} JSON that bwrap writes to its
// --info-fd once namespaces are set up and the child is ready to exec.
func readBwrapInfoPID(r io.Reader) (int, error) {
	var info struct {
		ChildPID int `json:"child-pid"`
	}
	if err := json.NewDecoder(r).Decode(&info); err != nil {
		return 0, fmt.Errorf("decode bwrap info JSON: %w", err)
	}
	if info.ChildPID == 0 {
		return 0, fmt.Errorf("bwrap info JSON: missing child-pid")
	}
	return info.ChildPID, nil
}

// buildNetOnlyScript builds the shell script that runs INSIDE the bwrap
// sandbox. bwrap has already applied isolation (user ns, mount ns, deny_read,
// deny_exec, config dir hide, /proc via --proc). This script handles only the
// network-specific setup: waiting for tap0, pointing resolv.conf at the
// slirp4netns DNS forwarder, configuring iptables, then exec'ing the command.
func buildNetOnlyScript(allowNetHosts, dnsServers []string, cmd string, args []string) string {
	var sb strings.Builder

	// Ensure mount propagation is private (bwrap sets this, but be defensive).
	sb.WriteString("mount --make-rprivate / 2>/dev/null || true\n")

	// Wait for tap0 (slirp4netns creates it after reading our PID from info-fd).
	sb.WriteString("for i in $(seq 1 100); do ip addr show tap0 2>/dev/null | grep -q inet && break; sleep 0.05; done\n")

	// Point resolv.conf at slirp4netns DNS forwarder.
	sb.WriteString("echo 'nameserver 10.0.2.3' > /tmp/.aigate-resolv\n")
	sb.WriteString("mount --bind /tmp/.aigate-resolv /etc/resolv.conf 2>/dev/null || ")
	sb.WriteString("mount --bind /tmp/.aigate-resolv $(readlink -f /etc/resolv.conf) 2>/dev/null || true\n")

	// iptables: loopback + DNS first, then allow_net hosts, then REJECT all.
	sb.WriteString("iptables -A OUTPUT -o lo -j ACCEPT\n")
	sb.WriteString("iptables -A OUTPUT -p udp --dport 53 -j ACCEPT\n")
	sb.WriteString("iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT\n")
	for _, dns := range dnsServers {
		fmt.Fprintf(&sb, "iptables -A OUTPUT -d %s -j ACCEPT\n", dns)
	}
	if len(allowNetHosts) > 0 {
		fmt.Fprintf(&sb, "for i in $(seq 1 50); do getent ahostsv4 %q >/dev/null 2>&1 && break; sleep 0.1; done\n", allowNetHosts[0])
	}
	for _, host := range allowNetHosts {
		fmt.Fprintf(&sb, "for _attempt in 1 2 3; do _ips=$(getent ahostsv4 %q 2>/dev/null | awk '{print $1}' | sort -u); [ -n \"$_ips\" ] && break; sleep 0.5; done; for _ip in $_ips; do iptables -A OUTPUT -d \"$_ip\" -j ACCEPT; done\n", host)
	}
	sb.WriteString("iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited\n")

	sb.WriteString("exec ")
	sb.WriteString(shellEscape(cmd, args))
	sb.WriteString("\n")

	return sb.String()
}

// findHardlinks scans searchDir for files that share the same device+inode as
// targetPath (i.e. hardlinks). Returns paths of hardlinks found, excluding
// targetPath itself. Only scans when the target has nlink > 1.
func findHardlinks(targetPath, searchDir string) []string {
	var targetStat syscall.Stat_t
	if err := syscall.Stat(targetPath, &targetStat); err != nil {
		return nil
	}
	if targetStat.Nlink <= 1 {
		return nil
	}

	var links []string
	walkForHardlinks(searchDir, targetPath, targetStat.Dev, targetStat.Ino, &links)
	return links
}

// walkForHardlinks recursively scans dir for files matching the given dev+ino.
// Uses os.ReadDir + syscall.Stat directly instead of filepath.WalkDir.
func walkForHardlinks(dir, excludePath string, dev uint64, ino uint64, links *[]string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if e.IsDir() {
			walkForHardlinks(path, excludePath, dev, ino, links)
			continue
		}
		if path == excludePath {
			continue
		}
		var st syscall.Stat_t
		if syscall.Stat(path, &st) == nil && st.Dev == dev && st.Ino == ino {
			*links = append(*links, path)
		}
	}
}

// resolveForBwrap resolves symlinks in path so it can be used as a bwrap bind
// destination. bwrap cannot bind-mount over a symlink — it requires an actual
// file/directory inode. Falls back to the original path if resolution fails.
func resolveForBwrap(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

const bwrapDenyExecScript = "#!/bin/sh\necho \"[aigate] blocked: this command is denied by sandbox policy\" >&2\nexit 126\n"

// buildBwrapExecDenyArgs generates bwrap bind-mount args for deny_exec rules.
//
// Full command blocks (e.g. "curl"): writes a deny stub and binds it over every
// instance of the binary found via LookPath.
//
// Subcommand blocks (e.g. "kubectl delete"): writes a wrapper script and binds:
//   - the original binary to /tmp/.aigate-orig-<cmd> (accessible by wrapper)
//   - the wrapper over the original binary path
//
// Returns the bwrap args to append and temp file paths to clean up.
func buildBwrapExecDenyArgs(profile domain.SandboxProfile) (bwrapArgs []string, tmpFiles []string, err error) {
	if len(profile.Config.DenyExec) == 0 {
		return nil, nil, nil
	}

	var fullBlocks []string
	subBlocks := make(map[string][]string) // base command → denied subcommands

	for _, entry := range profile.Config.DenyExec {
		parts := strings.SplitN(entry, " ", 2)
		if len(parts) == 2 {
			subBlocks[parts[0]] = append(subBlocks[parts[0]], parts[1])
		} else {
			fullBlocks = append(fullBlocks, entry)
		}
	}

	// Full command blocks: one shared deny stub, bound over each binary.
	// bwrap cannot bind-mount over symlinks as the destination — it needs a real
	// file. Resolve symlinks so the bind lands on the actual inode.
	if len(fullBlocks) > 0 {
		stubPath, stubErr := writeTmpFile("aigate-deny-exec-*", bwrapDenyExecScript)
		if stubErr != nil {
			return nil, tmpFiles, fmt.Errorf("write deny exec stub: %w", stubErr)
		}
		if chmodErr := os.Chmod(stubPath, 0o755); chmodErr != nil {
			os.Remove(stubPath) //nolint:errcheck
			return nil, tmpFiles, fmt.Errorf("chmod deny exec stub: %w", chmodErr)
		}
		tmpFiles = append(tmpFiles, stubPath)

		for _, cmd := range fullBlocks {
			var destPaths []string
			// Search $PATH for the binary.
			if binPath, lookErr := exec.LookPath(cmd); lookErr == nil {
				destPaths = append(destPaths, resolveForBwrap(binPath))
			}
			// Also search the workdir for local scripts/binaries.
			if profile.WorkDir != "" {
				wdPath := filepath.Join(profile.WorkDir, cmd)
				if info, statErr := os.Stat(wdPath); statErr == nil && !info.IsDir() {
					resolved := resolveForBwrap(wdPath)
					alreadyCovered := false
					for _, dp := range destPaths {
						if dp == resolved {
							alreadyCovered = true
							break
						}
					}
					if !alreadyCovered {
						destPaths = append(destPaths, resolved)
					}
				}
			}
			for _, destPath := range destPaths {
				bwrapArgs = append(bwrapArgs, "--bind", stubPath, destPath)
			}
		}
	}

	// Subcommand blocks: per-command wrapper that delegates to the original binary.
	// The original is exposed inside the sandbox at /tmp/.aigate-orig-<cmd> via a
	// bind mount from the host binary path — no copying of large binaries.
	// Symlinks are resolved for the wrapper destination (bwrap constraint).
	for baseCmd, subs := range subBlocks {
		origPath, lookErr := exec.LookPath(baseCmd)
		if lookErr != nil {
			helpers.Log.Warn().Str("cmd", baseCmd).Msg("deny_exec subcommand: binary not found in PATH, skipping")
			continue
		}

		// The resolved (non-symlink) path is used as the bwrap bind destination.
		resolvedPath := resolveForBwrap(origPath)
		origInSandbox := fmt.Sprintf("/tmp/.aigate-orig-%s", baseCmd)

		var caseArms strings.Builder
		for _, sub := range subs {
			fmt.Fprintf(&caseArms, "%s) echo \"[aigate] blocked: '%s %s' is denied by sandbox policy\" >&2; exit 126;; ", sub, baseCmd, sub)
		}
		wrapper := fmt.Sprintf("#!/bin/sh\nfor _a in \"$@\"; do case \"$_a\" in %s*) break;; esac; done\nexec %s \"$@\"\n",
			caseArms.String(), origInSandbox)

		wrapPath, wrapErr := writeTmpFile(fmt.Sprintf("aigate-wrap-%s-*", baseCmd), wrapper)
		if wrapErr != nil {
			return nil, tmpFiles, fmt.Errorf("write wrapper for %q: %w", baseCmd, wrapErr)
		}
		if chmodErr := os.Chmod(wrapPath, 0o755); chmodErr != nil {
			os.Remove(wrapPath) //nolint:errcheck
			return nil, tmpFiles, fmt.Errorf("chmod wrapper for %q: %w", baseCmd, chmodErr)
		}
		tmpFiles = append(tmpFiles, wrapPath)

		// Expose the original binary at origInSandbox (source may be a symlink —
		// bwrap follows symlinks for the source, only the destination must be real).
		bwrapArgs = append(bwrapArgs, "--bind", origPath, origInSandbox)
		// Shadow the resolved binary path with the wrapper.
		bwrapArgs = append(bwrapArgs, "--bind", wrapPath, resolvedPath)
	}

	return bwrapArgs, tmpFiles, nil
}
