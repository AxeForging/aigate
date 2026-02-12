//go:build linux

package services

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/helpers"
)

func newPlatform(exec Executor) Platform {
	return &LinuxPlatform{exec: exec}
}

// LinuxPlatform implements sandbox operations using Linux ACLs, namespaces, and cgroups.
type LinuxPlatform struct {
	exec Executor
}

func (p *LinuxPlatform) Name() string {
	return "linux"
}

func (p *LinuxPlatform) CreateGroup(name string) error {
	exists, err := p.GroupExists(name)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: group %q", helpers.ErrAlreadyInit, name)
	}
	out, err := p.exec.Run("groupadd", "--system", name)
	if err != nil {
		return fmt.Errorf("failed to create group %q: %s (%w)", name, string(out), err)
	}
	return nil
}

func (p *LinuxPlatform) CreateUser(name, group string) error {
	exists, err := p.UserExists(name)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: user %q", helpers.ErrAlreadyInit, name)
	}
	out, err := p.exec.Run("useradd", "--system", "--gid", group, "--shell", "/usr/sbin/nologin", "--no-create-home", name)
	if err != nil {
		return fmt.Errorf("failed to create user %q: %s (%w)", name, string(out), err)
	}
	return nil
}

func (p *LinuxPlatform) DeleteGroup(name string) error {
	exists, err := p.GroupExists(name)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	out, err := p.exec.Run("groupdel", name)
	if err != nil {
		return fmt.Errorf("failed to delete group %q: %s (%w)", name, string(out), err)
	}
	return nil
}

func (p *LinuxPlatform) DeleteUser(name string) error {
	exists, err := p.UserExists(name)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	out, err := p.exec.Run("userdel", name)
	if err != nil {
		return fmt.Errorf("failed to delete user %q: %s (%w)", name, string(out), err)
	}
	return nil
}

func (p *LinuxPlatform) GroupExists(name string) (bool, error) {
	_, err := p.exec.Run("getent", "group", name)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (p *LinuxPlatform) UserExists(name string) (bool, error) {
	_, err := p.exec.Run("getent", "passwd", name)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (p *LinuxPlatform) SetFileACLDeny(group string, patterns []string, workDir string) error {
	paths, err := resolvePatterns(patterns, workDir)
	if err != nil {
		return err
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			helpers.Log.Warn().Str("path", path).Msg("skipping (not found)")
			continue
		}
		aclEntry := fmt.Sprintf("g:%s:---", group)
		if info.IsDir() {
			// Set access ACL recursively + default ACL for inheritance
			out, err := p.exec.Run("setfacl", "-R", "-m", aclEntry, path)
			if err != nil {
				return fmt.Errorf("setfacl failed for %s: %s (%w)", path, string(out), err)
			}
			defaultEntry := fmt.Sprintf("d:g:%s:---", group)
			out, err = p.exec.Run("setfacl", "-R", "-m", defaultEntry, path)
			if err != nil {
				return fmt.Errorf("setfacl default failed for %s: %s (%w)", path, string(out), err)
			}
		} else {
			out, err := p.exec.Run("setfacl", "-m", aclEntry, path)
			if err != nil {
				return fmt.Errorf("setfacl failed for %s: %s (%w)", path, string(out), err)
			}
		}
		helpers.Log.Info().Str("path", path).Msg("ACL deny set")
	}
	return nil
}

func (p *LinuxPlatform) RemoveFileACL(group string, patterns []string, workDir string) error {
	paths, err := resolvePatterns(patterns, workDir)
	if err != nil {
		return err
	}
	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		aclEntry := fmt.Sprintf("g:%s", group)
		out, err := p.exec.Run("setfacl", "-R", "-x", aclEntry, path)
		if err != nil {
			helpers.Log.Warn().Str("path", path).Str("output", string(out)).Msg("failed to remove ACL")
		}
		defaultEntry := fmt.Sprintf("d:g:%s", group)
		p.exec.Run("setfacl", "-R", "-x", defaultEntry, path)
	}
	return nil
}

func (p *LinuxPlatform) ListACLs(workDir string) ([]string, error) {
	out, err := p.exec.Run("getfacl", "-R", "--absolute-names", workDir)
	if err != nil {
		return nil, fmt.Errorf("getfacl failed: %w", err)
	}
	var results []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "group:ai-agents") || strings.HasPrefix(line, "# file:") {
			results = append(results, line)
		}
	}
	return results, nil
}

func (p *LinuxPlatform) RunSandboxed(profile domain.SandboxProfile, cmd string, args []string) error {
	if len(profile.Config.AllowNet) > 0 {
		if hasSlirp4netns() {
			return p.runWithNetFilter(profile, cmd, args)
		}
		helpers.Log.Warn().Msg("slirp4netns not found; network filtering unavailable, running without network restrictions")
	}
	return p.runUnshare(profile, cmd, args)
}

// runUnshare runs a command in a user/mount/pid namespace without network filtering.
func (p *LinuxPlatform) runUnshare(profile domain.SandboxProfile, cmd string, args []string) error {
	unshareArgs := []string{
		"--mount",         // Mount namespace
		"--pid",           // PID namespace
		"--fork",          // Required for PID namespace
		"--map-root-user", // User namespace mapping
		"--",
	}

	shellCmd := buildMountOverrides(profile) + shellEscape(cmd, args)
	fullArgs := append(unshareArgs, "sh", "-c", shellCmd)
	return p.exec.RunPassthrough("unshare", fullArgs...)
}

// hasSlirp4netns checks whether slirp4netns is available on the system.
func hasSlirp4netns() bool {
	_, err := exec.LookPath("slirp4netns")
	return err == nil
}

// resolveAllowedIPs resolves a list of hostnames/IPs to deduplicated IPv4 addresses.
func resolveAllowedIPs(hosts []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			// It's already an IP address — keep only IPv4
			if ip.To4() != nil && !seen[host] {
				seen[host] = true
				result = append(result, host)
			}
			continue
		}
		// Resolve hostname
		addrs, err := net.LookupHost(host)
		if err != nil {
			helpers.Log.Warn().Str("host", host).Err(err).Msg("failed to resolve host, skipping")
			continue
		}
		for _, addr := range addrs {
			if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil && !seen[addr] {
				seen[addr] = true
				result = append(result, addr)
			}
		}
	}
	return result
}

// getSystemDNS reads upstream DNS servers from resolv.conf files.
func getSystemDNS() []string {
	// Try systemd-resolved upstream file first, then fall back to /etc/resolv.conf
	for _, path := range []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"} {
		servers := parseDNSFromFile(path)
		if len(servers) > 0 {
			return servers
		}
	}
	return []string{"8.8.8.8", "1.1.1.1"}
}

func parseDNSFromFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addr := fields[1]
		// Skip localhost/stub resolvers
		if strings.HasPrefix(addr, "127.") {
			continue
		}
		servers = append(servers, addr)
	}
	return servers
}

// runWithNetFilter runs a command in a network-filtered namespace using slirp4netns.
//
// Architecture (two-layer unshare):
//
//	Outer: unshare --user --map-root-user  (user namespace only, keeps host network)
//	  ├── Inner: unshare --net --mount --pid --fork  (sandbox, new net ns)
//	  │     └── sh -c <inner script>   (wait tap0 → iptables → exec cmd)
//	  └── slirp4netns --configure <inner_PID> tap0  (user ns caps, host network)
//
// slirp4netns must run INSIDE the user namespace to have CAP_SYS_ADMIN for
// setns(CLONE_NEWNET). Launching it from the host fails with EPERM because an
// unprivileged process lacks CAP_SYS_ADMIN in its own (init) user namespace.
func (p *LinuxPlatform) runWithNetFilter(profile domain.SandboxProfile, cmd string, args []string) error {
	dnsServers := getSystemDNS()
	helpers.Log.Info().
		Strs("allow_net", profile.Config.AllowNet).
		Strs("dns_servers", dnsServers).
		Msg("starting network-filtered sandbox")

	innerScript := buildNetFilterScript(profile.Config.AllowNet, dnsServers, profile, cmd, args)
	outerScript := buildOrchestrationScript(innerScript)

	return p.exec.RunPassthrough("unshare", "--user", "--map-root-user", "--", "sh", "-c", outerScript)
}

// buildOrchestrationScript wraps the inner sandbox script with the two-process
// orchestration that runs inside the user namespace.
//
// It backgrounds the sandbox (in a new net namespace) while preserving stdin
// via fd 3, then launches slirp4netns in the foreground (user ns + host network)
// to provide connectivity.
func buildOrchestrationScript(innerScript string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(innerScript))

	var sb strings.Builder

	// Save stdin so the backgrounded sandbox can still read the terminal.
	// POSIX non-interactive shells redirect background jobs' stdin from /dev/null.
	sb.WriteString("exec 3<&0\n")

	// Write the inner script to a temp file (avoids all quoting issues).
	sb.WriteString("_AIGATE_INNER=$(mktemp /tmp/.aigate-inner-XXXXXX)\n")
	sb.WriteString(fmt.Sprintf("printf '%%s' '%s' | base64 -d > \"$_AIGATE_INNER\"\n", encoded))

	// Start the sandbox in a new net/mount/pid namespace (background, stdin from fd 3).
	sb.WriteString("unshare --net --mount --pid --fork -- sh \"$_AIGATE_INNER\" <&3 &\n")
	sb.WriteString("_SANDBOX_PID=$!\n")
	sb.WriteString("exec 3<&-\n")

	// Wait until the sandbox has entered its new network namespace.
	sb.WriteString("_SELF_NS=$(readlink /proc/self/ns/net)\n")
	sb.WriteString("while [ -e \"/proc/$_SANDBOX_PID\" ] && [ \"$(readlink /proc/$_SANDBOX_PID/ns/net 2>/dev/null)\" = \"$_SELF_NS\" ]; do sleep 0.01; done\n")

	// Launch slirp4netns: runs in user ns (has CAP_SYS_ADMIN) + host network.
	// Suppress stdout (verbose protocol debug), keep stderr for real errors.
	sb.WriteString("slirp4netns --configure $_SANDBOX_PID tap0 >/dev/null &\n")
	sb.WriteString("_SLIRP_PID=$!\n")

	// Wait for the sandbox to exit, then clean up.
	sb.WriteString("wait $_SANDBOX_PID 2>/dev/null\n")
	sb.WriteString("_EXIT=$?\n")
	sb.WriteString("kill $_SLIRP_PID 2>/dev/null; wait $_SLIRP_PID 2>/dev/null\n")
	sb.WriteString("rm -f \"$_AIGATE_INNER\"\n")
	sb.WriteString("exit $_EXIT\n")

	return sb.String()
}

// buildNetFilterScript builds the shell script that runs inside the network namespace.
// allowNetHosts are the original hostnames/IPs from the config — resolution happens
// inside the namespace so the iptables rules match what the sandboxed process will see.
func buildNetFilterScript(allowNetHosts, dnsServers []string, profile domain.SandboxProfile, cmd string, args []string) string {
	var sb strings.Builder

	// Remount /proc so it reflects the new PID namespace.
	// Without this, /proc/self is stale and glibc's NSS/dlopen fails with
	// "fatal library error, lookup self".
	sb.WriteString("mount -t proc proc /proc\n")

	// Wait for tap0 interface to come up (slirp4netns creates it)
	sb.WriteString("for i in $(seq 1 100); do ip addr show tap0 2>/dev/null | grep -q inet && break; sleep 0.05; done\n")

	// Set up DNS: point resolv.conf at slirp4netns DNS forwarder (10.0.2.3)
	sb.WriteString("echo 'nameserver 10.0.2.3' > /tmp/.aigate-resolv\n")
	sb.WriteString("mount --bind /tmp/.aigate-resolv /etc/resolv.conf 2>/dev/null || ")
	sb.WriteString("mount --bind /tmp/.aigate-resolv $(readlink -f /etc/resolv.conf) 2>/dev/null || true\n")

	// iptables rules: allow loopback + DNS before anything else
	// (DNS must work for the host resolution below)
	sb.WriteString("iptables -A OUTPUT -o lo -j ACCEPT\n")
	sb.WriteString("iptables -A OUTPUT -p udp --dport 53 -j ACCEPT\n")
	sb.WriteString("iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT\n")

	// Allow traffic to upstream DNS servers (needed for slirp4netns forwarding)
	for _, dns := range dnsServers {
		sb.WriteString(fmt.Sprintf("iptables -A OUTPUT -d %s -j ACCEPT\n", dns))
	}

	// Wait for DNS to actually work by testing a REAL remote query.
	// Using localhost previously was wrong — it resolves from /etc/hosts,
	// not DNS, so it passed before slirp4netns DNS (10.0.2.3) was ready.
	if len(allowNetHosts) > 0 {
		sb.WriteString(fmt.Sprintf("for i in $(seq 1 50); do getent ahostsv4 %q >/dev/null 2>&1 && break; sleep 0.1; done\n", allowNetHosts[0]))
	}

	// Resolve each AllowNet entry INSIDE the namespace and add iptables rules.
	// This ensures the IPs match what the sandboxed process will get from DNS,
	// avoiding mismatches from CDN anycast / DNS load balancing.
	// Each host retries up to 3 times to handle transient DNS hiccups.
	for _, host := range allowNetHosts {
		sb.WriteString(fmt.Sprintf("for _attempt in 1 2 3; do _ips=$(getent ahostsv4 %q 2>/dev/null | awk '{print $1}' | sort -u); [ -n \"$_ips\" ] && break; sleep 0.5; done; for _ip in $_ips; do iptables -A OUTPUT -d \"$_ip\" -j ACCEPT; done\n", host))
	}

	sb.WriteString("iptables -A OUTPUT -j REJECT\n")

	// Mount overrides for deny_read
	sb.WriteString(buildMountOverrides(profile))

	// Execute the target command
	sb.WriteString("exec ")
	sb.WriteString(shellEscape(cmd, args))
	sb.WriteString("\n")

	return sb.String()
}

// buildMountOverrides generates shell commands to overmount denied paths.
func buildMountOverrides(profile domain.SandboxProfile) string {
	var mountCmds []string
	for _, pattern := range profile.Config.DenyRead {
		paths, _ := resolvePatterns([]string{pattern}, profile.WorkDir)
		for _, path := range paths {
			if info, err := os.Stat(path); err == nil {
				if info.IsDir() {
					mountCmds = append(mountCmds, fmt.Sprintf("mount -t tmpfs -o ro,size=0 tmpfs %s", path))
				} else {
					mountCmds = append(mountCmds, fmt.Sprintf("mount --bind /dev/null %s", path))
				}
			}
		}
	}
	if len(mountCmds) > 0 {
		return strings.Join(mountCmds, " && ") + " && "
	}
	return ""
}

// shellEscape builds a shell command string from a command and its arguments.
func shellEscape(cmd string, args []string) string {
	var sb strings.Builder
	sb.WriteString(cmd)
	for _, a := range args {
		sb.WriteString(" ")
		sb.WriteString(a)
	}
	return sb.String()
}
