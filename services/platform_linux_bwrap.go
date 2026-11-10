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
	"time"

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

// slirpArgs builds the slirp4netns CLI args for a given sandbox child PID.
// When ipv6Enabled is true, --enable-ipv6 is prepended so the inner namespace
// gets a v6 NAT path (forwarder at fd00::3, sandbox addr in fd00::/64).
// ipv6Enabled must only be true on hosts that also have ip6tables — otherwise
// the sandbox has v6 connectivity with no filter, which is worse than no v6.
func slirpArgs(childPID int, ipv6Enabled bool) []string {
	// --disable-host-loopback: 10.0.2.2 must not reach the host's 127.0.0.1.
	args := []string{"--disable-host-loopback", "--configure", strconv.Itoa(childPID), "tap0"}
	if ipv6Enabled {
		args = append([]string{"--enable-ipv6"}, args...)
	}
	return args
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
		"--ro-bind", "/", "/", // read-only root (system dirs protected)
		"--dev", "/dev", // minimal private /dev
		"--proc", "/proc", // fresh /proc for PID namespace
		"--tmpfs", "/tmp", // isolated writable /tmp (no host /tmp leaks)
		"--unshare-pid",  // new PID namespace
		"--unshare-user", // user namespace (current UID → root inside)
		"--die-with-parent",
	}

	// Home mount: without scope mode, tools (claude, git, npm, etc.) get a
	// writable $HOME for their config/cache dirs. With allowed_paths
	// configured, $HOME is replaced by an empty tmpfs — non-scoped files are
	// invisible, so both reads and writes fail to reach the host — and only
	// the workdir + allowed paths are bound back in read-write below. Writes
	// elsewhere under $HOME land in the ephemeral tmpfs and are discarded.
	scoped := len(profile.Config.AllowedPaths) > 0
	home, homeErr := os.UserHomeDir()
	if homeErr == nil {
		if scoped {
			args = append(args, "--tmpfs", home)
		} else {
			args = append(args, "--bind", home, home)
		}
	}

	// Workdir: always accessible read-write. Without scope mode it's already
	// covered when inside $HOME; with scope mode the bind must be explicit to
	// punch through the tmpfs hiding home.
	if profile.WorkDir != "" {
		if scoped || homeErr != nil || !strings.HasPrefix(profile.WorkDir, home+"/") && profile.WorkDir != home {
			args = append(args, "--bind", profile.WorkDir, profile.WorkDir)
		}
	}

	// allowed_paths: bound back in read-write on top of the home tmpfs (bwrap
	// creates the mount points inside the tmpfs automatically). Sensitive
	// dotfiles and deny mounts are applied after so they always win.
	var scopedPaths []string
	if scoped {
		// Drop a breadcrumb at the root of the hidden home so an agent that
		// lists or probes $HOME learns aigate scoped it (and why), instead of
		// only seeing bare "No such file" errors on non-scoped paths.
		if homeErr == nil {
			markerPath, mErr := writeTmpFile("aigate-scope-*", scopeMarkerContent(profile))
			if mErr != nil {
				return nil, fmt.Errorf("write scope marker: %w", mErr)
			}
			*tmpFiles = append(*tmpFiles, markerPath)
			args = append(args, "--ro-bind", markerPath, filepath.Join(home, ".aigate-scope-README"))
		}
		scopedPaths = resolveScopedPaths(profile)
		for _, path := range scopedPaths {
			args = append(args, "--bind", path, path)
		}
	}

	// Protect sensitive dotfiles from tampering by AI agents. Without scope
	// mode they are overlaid read-only on the writable $HOME bind. In scope
	// mode the home tmpfs already hides them — an ro-bind there would
	// re-expose content — so only re-protect ones reachable again through the
	// workdir or an allowed path.
	if homeErr == nil {
		exposedRoots := append([]string{}, scopedPaths...)
		if profile.WorkDir != "" {
			exposedRoots = append(exposedRoots, profile.WorkDir)
		}
		for _, sensitive := range []string{
			".ssh",
			".gnupg",
			".bashrc",
			".bash_profile",
			".profile",
			".zshrc",
			".gitconfig",
		} {
			path := filepath.Join(home, sensitive)
			if _, err := os.Stat(path); err != nil {
				continue
			}
			if scoped && !underAny(path, exposedRoots) {
				continue // already hidden by the home tmpfs
			}
			args = append(args, "--ro-bind", path, path)
		}
		// Hide aigate config directory completely.
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
	if len(profile.Config.DenyRead) > 0 {
		// Also at a fixed path: files that appear later are covered with it
		// from outside (see platform_linux_denywatch.go).
		if denyMarkerPath, err = writeTmpFile("aigate-denied-*", DenyReadMarker()); err != nil {
			return nil, fmt.Errorf("write deny marker: %w", err)
		}
		*tmpFiles = append(*tmpFiles, denyMarkerPath)
		args = append(args, "--ro-bind", denyMarkerPath, sandboxDenyMarker)
	}
	for _, pattern := range profile.Config.DenyRead {
		paths, _ := resolvePatterns([]string{pattern}, profile.WorkDir)
		for _, path := range paths {
			info, statErr := os.Stat(path)
			if statErr != nil {
				helpers.Log.Debug().Str("path", path).Msg("deny_read: nothing to hide (not found)")
				continue
			}
			if info.IsDir() {
				args = append(args, "--tmpfs", path)
			} else {
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

	// After deny mounts so the identity's ssh key survives the ~/.ssh/ deny.
	args = append(args, bwrapIdentityArgs(profile)...)

	// Last, so it wins over the home and allowed_paths binds above.
	args = append(args, bwrapAgentArgs()...)

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
	if len(profile.Config.AllowedPaths) > 0 {
		fmt.Fprintf(&sb, "allowed_paths: %s\n", strings.Join(profile.Config.AllowedPaths, ", "))
		sb.WriteString("Only the working directory and these paths are accessible. The rest of the home directory is hidden and the filesystem is read-only.\n\n")
	}
	return sb.String()
}

// scopeMarkerContent is the breadcrumb dropped at ~/.aigate-scope-README when
// scope mode is active, explaining why most of $HOME appears empty.
func scopeMarkerContent(profile domain.SandboxProfile) string {
	var sb strings.Builder
	sb.WriteString("[aigate] filesystem scope active\n\n")
	sb.WriteString("Most of this home directory is intentionally hidden by aigate sandbox policy.\n")
	sb.WriteString("Files outside the allowed scope are neither readable nor writable — a write\n")
	sb.WriteString("here goes to an ephemeral overlay and is discarded when the session ends.\n\n")
	if len(profile.Config.AllowedPaths) > 0 {
		fmt.Fprintf(&sb, "Accessible: the working directory plus %s\n\n", strings.Join(profile.Config.AllowedPaths, ", "))
	}
	sb.WriteString("See /tmp/.aigate-policy for the full active policy.\n")
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

// runWithBwrapNetFilter runs a sandbox with its own network: bwrap +
// slirp4netns, configured from the host side.
//
//		bwrap [mounts] --unshare-net --info-fd 3 --block-fd 4 -- CMD
//		  ├── slirp4netns --configure <child-PID> tap0   (host side, --ready-fd)
//		  └── nsenter … iptables-restore                 (host side, allow_net/ports)
//
//	 1. bwrap writes {"child-pid": N} to info-fd once namespaces exist, then
//	    waits on block-fd before running CMD.
//	 2. Go starts slirp4netns and waits until tap0 is up.
//	 3. Go installs the firewall / port redirects inside the namespace.
//	 4. Go releases block-fd: CMD starts, holding no capabilities.
func (p *LinuxPlatform) runWithBwrapNetFilter(profile domain.SandboxProfile, cmd string, args []string, stdout, stderr io.Writer) error {
	ipv6Enabled := ipv6SandboxSupported()
	helpers.Log.Debug().
		Strs("allow_net", profile.Config.AllowNet).
		Bool("ipv6", ipv6Enabled).
		Msg("starting bwrap sandbox with its own network namespace")

	var tmpFiles []string
	defer func() {
		for _, f := range tmpFiles {
			os.Remove(f) //nolint:errcheck
		}
	}()

	knownDenied := denyMatchesNow(profile) // before planning mounts: see startLateDenyGuard
	bwrapArgs, err := p.buildBwrapArgs(profile, &tmpFiles)
	if err != nil {
		return fmt.Errorf("failed to build bwrap args: %w", err)
	}
	resolvArgs, err := resolvConfArgs(ipv6Enabled, &tmpFiles)
	if err != nil {
		return err
	}
	bwrapArgs = append(bwrapArgs, resolvArgs...)
	bwrapArgs = appendBwrapNetArgs(bwrapArgs, cmd, args)

	// fd 3: bwrap reports the child PID. fd 4: bwrap waits for a byte here
	// before running the command.
	infoR, infoW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create info pipe: %w", err)
	}
	defer infoR.Close() //nolint:errcheck
	blockR, blockW, err := os.Pipe()
	if err != nil {
		infoW.Close() //nolint:errcheck
		return fmt.Errorf("create block pipe: %w", err)
	}
	defer blockW.Close() //nolint:errcheck

	bwrapCmd := exec.Command("bwrap", bwrapArgs...)
	bwrapCmd.ExtraFiles = []*os.File{infoW, blockR}

	// When stdout is a masking writer (not a raw *os.File) AND stdin is a TTY,
	// use a PTY so the child sees an interactive terminal. Otherwise connect
	// stdout/stderr directly so the masking writer receives the output.
	var ptm *os.File
	_, stdoutIsFile := stdout.(*os.File)
	if !stdoutIsFile && term.IsTerminal(int(os.Stdin.Fd())) {
		ptm, err = startBwrapWithPTY(bwrapCmd)
		if err != nil {
			helpers.Log.Warn().Err(err).Msg("PTY setup failed, falling back to plain pipe")
			ptm = nil
			err = startBwrapPlain(bwrapCmd, stdout, stderr)
		}
	} else {
		err = startBwrapPlain(bwrapCmd, stdout, stderr)
	}
	infoW.Close()  //nolint:errcheck // the child has its own copies
	blockR.Close() //nolint:errcheck
	if err != nil {
		return fmt.Errorf("start bwrap: %w", err)
	}
	// Never release block-fd on failure: bwrap reads EOF there as "go" and
	// would run the command without its network setup. Kill instead — the
	// waiting sandbox child too, which otherwise keeps the output pipes open.
	childPID := 0
	bwrapCmd.WaitDelay = 2 * time.Second
	abort := func(cause error) error {
		if childPID > 0 {
			syscall.Kill(childPID, syscall.SIGKILL) //nolint:errcheck
		}
		bwrapCmd.Process.Kill() //nolint:errcheck
		bwrapCmd.Wait()         //nolint:errcheck
		if ptm != nil {
			ptm.Close() //nolint:errcheck
		}
		return cause
	}

	childPID, err = readBwrapInfoPID(infoR)
	if err != nil {
		return abort(fmt.Errorf("bwrap info-fd: %w", err))
	}

	waitLoopback(childPID, 2*time.Second)
	sandboxNet, err := openSandboxNet(childPID)
	if err != nil {
		return abort(fmt.Errorf("sandbox network: %w", err))
	}
	defer sandboxNet.Close()

	slirp, apiSocket, cleanupSlirp, err := startSlirp(childPID, sandboxNet.userns, ipv6Enabled, len(profile.Ports) > 0)
	if err != nil {
		return abort(err)
	}
	defer cleanupSlirp()
	if err := configureSandboxNet(sandboxNet, profile.Config.AllowNet, ipv6Enabled, profile.Ports); err != nil {
		return abort(err)
	}
	if apiSocket != "" {
		publishPorts(apiSocket, profile.Ports)
	}
	stopGuard := startLateDenyGuard(childPID, profile, knownDenied)
	defer stopGuard()
	if _, err := blockW.Write([]byte{1}); err != nil { // network ready: run the command
		return abort(fmt.Errorf("start command: %w", err))
	}
	blockW.Close() //nolint:errcheck

	// PTY: forward terminal I/O and propagate resize events.
	var outDone chan struct{}
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
		// Stoppable: a leftover stdin reader would swallow the caller's next
		// input (e.g. the next prompt of aigate identity add).
		stopStdin := copyStdin(ptm)
		defer stopStdin()
		outDone = make(chan struct{})
		go func() { _, _ = io.Copy(stdout, ptm); close(outDone) }()
	}

	// Wait for bwrap to finish (and its output to drain); slirp stops after.
	bwrapErr := bwrapCmd.Wait()
	if ptm != nil {
		<-outDone   // EIO once the sandbox side of the PTY is closed
		ptm.Close() //nolint:errcheck
	}
	if bwrapErr != nil {
		helpers.Log.Debug().Str("slirp4netns", slirp.String()).Msg("network helper output")
	}
	return bwrapErr
}

// waitLoopback waits until bwrap has brought up the sandbox's loopback.
// slirp4netns --configure also brings lo up; both at once intermittently
// fails bwrap with "loopback: Failed RTM_NEWADDR" on slower machines.
// Gives up quietly after timeout: slirp's own setup still applies.
func waitLoopback(pid int, timeout time.Duration) {
	path := fmt.Sprintf("/proc/%d/net/fib_trie", pid)
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if b, err := os.ReadFile(path); err == nil && loopbackUp(string(b)) {
			return
		}
	}
	helpers.Log.Debug().Int("pid", pid).Msg("sandbox loopback not seen up; starting slirp4netns anyway")
}

// loopbackUp reports whether fib_trie has 127.0.0.1 as a local address,
// which the kernel adds once lo has the address and is up.
func loopbackUp(fibTrie string) bool {
	lines := strings.Split(fibTrie, "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) == "|-- 127.0.0.1" && i+1 < len(lines) && strings.Contains(lines[i+1], "/32 host LOCAL") {
			return true
		}
	}
	return false
}

// startSlirp attaches slirp4netns to the sandbox's network namespace and
// waits until tap0 is configured. userns is the user namespace that owns that
// network (bwrap nests the command one deeper; joining that one fails with
// EPERM). With api, it also opens the control socket used to publish ports.
// cleanup stops it.
func startSlirp(childPID int, userns *os.File, ipv6, api bool) (out *strings.Builder, apiSocket string, cleanup func(), err error) {
	out = &strings.Builder{}
	args := slirpArgs(childPID, ipv6)
	removeAPI := func() {}
	if api {
		if apiSocket, removeAPI, err = slirpAPISocket(); err != nil {
			return out, "", func() {}, fmt.Errorf("publish ports: %w", err)
		}
		args = append([]string{"--api-socket", apiSocket}, args...)
	}
	readyR, readyW, err := os.Pipe()
	if err != nil {
		removeAPI()
		return out, "", func() {}, err
	}
	defer readyR.Close() //nolint:errcheck
	args = append([]string{"--ready-fd", "3", "--userns-path", "/proc/self/fd/4"}, args...)
	cmd := exec.Command("slirp4netns", args...)
	cmd.Stdout, cmd.Stderr = out, out // protocol chatter; kept to explain a failure
	cmd.ExtraFiles = []*os.File{readyW, userns}
	if err := cmd.Start(); err != nil {
		readyW.Close() //nolint:errcheck
		removeAPI()
		return out, "", func() {}, fmt.Errorf("start slirp4netns: %w", err)
	}
	readyW.Close() //nolint:errcheck
	cleanup = func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
		removeAPI()
	}
	ready := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := readyR.Read(buf)
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			cleanup()
			return out, "", func() {}, fmt.Errorf("slirp4netns didn't start: %s", strings.TrimSpace(out.String()))
		}
	case <-time.After(10 * time.Second):
		cleanup()
		return out, "", func() {}, fmt.Errorf("slirp4netns didn't come up within 10s: %s", strings.TrimSpace(out.String()))
	}
	return out, apiSocket, cleanup, nil
}

// appendBwrapNetArgs adds the own-network flags and the command. bwrap runs
// the command itself (no setup shell, no extra capabilities); it waits on
// block-fd (fd 4) until the host side has configured the network.
func appendBwrapNetArgs(args []string, cmd string, cmdArgs []string) []string {
	args = append(args, "--unshare-net", "--info-fd", "3", "--block-fd", "4", "--", cmd)
	return append(args, cmdArgs...)
}

// startBwrapPlain starts bwrap with direct stdout/stderr writers (no PTY).
// The caller sets ExtraFiles (info-fd, block-fd).
func startBwrapPlain(bwrapCmd *exec.Cmd, stdout, stderr io.Writer) error {
	bwrapCmd.Stdin = os.Stdin
	bwrapCmd.Stdout = stdout
	bwrapCmd.Stderr = stderr
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

var bwrapDenyExecScript = "#!/bin/sh\necho \"" + DenyExecShellMessage(`$(basename "$0")`, `$(basename "$0")`) + "\" >&2\nexit 126\n"

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
		// Entries may be full paths (/opt/x/tool rm): only the name goes into
		// file names.
		safeName := filepath.Base(baseCmd)
		origInSandbox := fmt.Sprintf("/tmp/.aigate-orig-%s", safeName)

		var caseArms strings.Builder
		for _, sub := range subs {
			fmt.Fprintf(&caseArms, "%s) echo \"%s\" >&2; exit 126;; ", sub, DenyExecShellMessage(baseCmd+" "+sub, "'"+baseCmd+" "+sub+"'"))
		}
		wrapper := fmt.Sprintf("#!/bin/sh\nfor _a in \"$@\"; do case \"$_a\" in %s*) break;; esac; done\nexec %s \"$@\"\n",
			caseArms.String(), origInSandbox)

		wrapPath, wrapErr := writeTmpFile(fmt.Sprintf("aigate-wrap-%s-*", safeName), wrapper)
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
