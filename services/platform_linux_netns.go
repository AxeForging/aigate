//go:build linux

package services

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// The bwrap sandbox's network is configured from the host side, before the
// command starts (bwrap --block-fd): the command never holds a capability,
// and setup still works where AppArmor denies capabilities inside bwrap's
// user namespace (Ubuntu's bwrap-userns-restrict / unpriv_bwrap).
//
// aigate enters the network namespace together with the user namespace that
// owns it (bwrap nests the command one level deeper) through nsenter: Go
// itself can't setns into a user namespace, being multithreaded.

// firewallSpec is what the sandbox's own network must enforce.
type firewallSpec struct {
	allowIPs []string // resolved allow_net addresses of this family
	filter   bool     // allow_net set: reject everything else
	ports    []int    // published: DNAT tap0:PORT → 127.0.0.1:PORT
}

// firewallRules renders iptables-restore (v6: ip6tables-restore) input.
func firewallRules(v6 bool, spec firewallSpec) string {
	dns, reject := slirpDNSv4, "icmp-admin-prohibited"
	if v6 {
		dns, reject = slirpDNSv6, "icmp6-adm-prohibited"
	}
	var b strings.Builder
	if spec.filter {
		b.WriteString("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n")
		b.WriteString("-A OUTPUT -o lo -j ACCEPT\n")
		if len(spec.ports) > 0 {
			// Replies to connections forwarded in through a published port.
			b.WriteString("-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
		}
		fmt.Fprintf(&b, "-A OUTPUT -d %s -p udp --dport 53 -j ACCEPT\n", dns)
		fmt.Fprintf(&b, "-A OUTPUT -d %s -p tcp --dport 53 -j ACCEPT\n", dns)
		for _, ip := range spec.allowIPs {
			fmt.Fprintf(&b, "-A OUTPUT -d %s -j ACCEPT\n", ip)
		}
		fmt.Fprintf(&b, "-A OUTPUT -j REJECT --reject-with %s\n", reject)
		b.WriteString("COMMIT\n")
	}
	if len(spec.ports) > 0 && !v6 {
		b.WriteString("*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n")
		for _, p := range spec.ports {
			fmt.Fprintf(&b, "-A PREROUTING -i tap0 -p tcp --dport %d -j DNAT --to-destination 127.0.0.1:%d\n", p, p)
		}
		b.WriteString("COMMIT\n")
	}
	return b.String()
}

// resolveAllowNet resolves allow_net entries (hosts or IPs) into sorted,
// de-duplicated v4 and v6 address lists.
func resolveAllowNet(hosts []string, lookup func(string) ([]net.IP, error)) (v4, v6 []string) {
	seen := map[string]bool{}
	add := func(ip net.IP) {
		s := ip.String()
		if seen[s] {
			return
		}
		seen[s] = true
		if ip.To4() != nil {
			v4 = append(v4, s)
		} else {
			v6 = append(v6, s)
		}
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			add(ip)
			continue
		}
		ips, err := lookup(h)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[aigate] warning: allow_net host %s doesn't resolve (%v); it stays blocked\n", h, err)
			continue
		}
		for _, ip := range ips {
			add(ip)
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6
}

// iptablesTool finds an iptables program (tool "", "-restore"): the
// nf_tables variant first, because the legacy one needs kernel modules a
// normal user can't load (Fedora installs legacy as plain "iptables").
func iptablesTool(v6 bool, tool string) (string, error) {
	base := "iptables"
	if v6 {
		base = "ip6tables"
	}
	return FindTool(base+"-nft"+tool, base+tool)
}

// sandboxNet runs commands inside a sandbox's network namespace, with the
// rights of the user namespace that owns it.
type sandboxNet struct {
	pid    int
	userns *os.File
	lock   string // private xtables lock: the host's /run/xtables.lock isn't writable for us
}

func openSandboxNet(pid int) (*sandboxNet, error) {
	netf, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return nil, err
	}
	defer netf.Close() //nolint:errcheck
	fd, err := unix.IoctlRetInt(int(netf.Fd()), unix.NS_GET_USERNS)
	if err != nil {
		return nil, fmt.Errorf("find the sandbox network's owner: %w", err)
	}
	userns := os.NewFile(uintptr(fd), "userns")
	lock, err := os.CreateTemp("", "aigate-xtables-*.lock")
	if err != nil {
		_ = userns.Close()
		return nil, err
	}
	_ = lock.Close()
	return &sandboxNet{pid: pid, userns: userns, lock: lock.Name()}, nil
}

func (n *sandboxNet) Close() {
	_ = n.userns.Close()
	_ = os.Remove(n.lock)
}

// run executes name inside the namespace; stdin may be empty.
func (n *sandboxNet) run(stdin, name string, args ...string) error {
	nsArgs := append([]string{"--user=/proc/self/fd/3", fmt.Sprintf("--net=/proc/%d/ns/net", n.pid), "--preserve-credentials", "--", name}, args...)
	cmd := exec.Command("nsenter", nsArgs...)
	cmd.ExtraFiles = []*os.File{n.userns}
	cmd.Env = append(os.Environ(), "XTABLES_LOCKFILE="+n.lock)
	cmd.Stdin = strings.NewReader(stdin)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// configureSandboxNet installs allow_net's firewall and the published ports'
// redirects. A firewall that can't be installed is an error: allow_net must
// never silently go unenforced.
func configureSandboxNet(n *sandboxNet, allowNet []string, ipv6 bool, ports []int) error {
	firewallBlock := func(err error) error {
		return fmt.Errorf("%w (%v)", firewallSetupBlock(err), err)
	}
	v4, v6 := resolveAllowNet(allowNet, net.LookupIP)
	filter := len(allowNet) > 0
	restore4, err4 := iptablesTool(false, "-restore")
	check4, _ := iptablesTool(false, "")
	if filter && err4 != nil {
		return firewallBlock(fmt.Errorf("%w; install iptables", err4))
	}
	if filter || len(ports) > 0 {
		err := err4
		if err == nil {
			err = n.run(firewallRules(false, firewallSpec{allowIPs: v4, filter: filter, ports: ports}), restore4)
		}
		if err != nil {
			if filter {
				return firewallBlock(err)
			}
			fmt.Fprintf(os.Stderr, "[aigate] warning: published ports work only for servers listening on 0.0.0.0 (%v)\n", err)
		}
	}
	if filter && ipv6 {
		restore6, err := iptablesTool(true, "-restore")
		if err == nil {
			err = n.run(firewallRules(true, firewallSpec{allowIPs: v6, filter: true, ports: ports}), restore6)
		}
		if err != nil {
			return firewallBlock(err)
		}
	}
	if filter {
		// Belt and braces: the final REJECT must really be there.
		if err := n.run("", check4, "-C", "OUTPUT", "-j", "REJECT", "--reject-with", "icmp-admin-prohibited"); err != nil {
			return firewallBlock(err)
		}
	}
	if len(ports) > 0 {
		// DNAT to 127.0.0.1 needs route_localnet on the incoming interface.
		script := "echo 1 > /proc/sys/net/ipv4/conf/all/route_localnet && echo 1 > /proc/sys/net/ipv4/conf/tap0/route_localnet"
		if err := n.run("", "sh", "-c", script); err != nil {
			fmt.Fprintf(os.Stderr, "[aigate] warning: published ports work only for servers listening on 0.0.0.0 (%v)\n", err)
		}
	}
	return nil
}

// resolvConfArgs points the sandbox's DNS at slirp4netns' forwarder: a file
// bound over the host's resolv.conf (or what its symlink points to).
func resolvConfArgs(ipv6 bool, tmpFiles *[]string) ([]string, error) {
	target, err := filepath.EvalSymlinks("/etc/resolv.conf")
	if err != nil {
		return nil, nil // no resolv.conf: nothing to replace
	}
	content := "nameserver " + slirpDNSv4 + "\n"
	if ipv6 {
		content += "nameserver " + slirpDNSv6 + "\n"
	}
	path, err := writeTmpFile("aigate-resolv-*", content)
	if err != nil {
		return nil, fmt.Errorf("write resolv.conf: %w", err)
	}
	*tmpFiles = append(*tmpFiles, path)
	return []string{"--ro-bind", path, target}, nil
}

// firewallSetupBlock explains a firewall that couldn't be installed, with
// the specific fix when the cause is known.
func firewallSetupBlock(err error) Block {
	fix := "run aigate doctor to see what's missing"
	if msg := err.Error(); strings.Contains(msg, "(legacy)") || strings.Contains(msg, "modprobe") {
		// Legacy iptables needs kernel modules a normal user can't load.
		fix = "install the nf_tables iptables: sudo dnf install iptables-nft (Debian/Ubuntu: sudo apt install iptables)"
	}
	return Block{
		What: "this run", Layer: LayerSandbox,
		Reason: "the allow_net firewall could not be set up inside the sandbox",
		Fix:    fix,
	}
}
