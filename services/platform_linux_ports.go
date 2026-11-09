//go:build linux

package services

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Published ports (aigate run --port): slirp4netns forwards the host's
// 127.0.0.1:PORT to the sandbox's tap0, and a DNAT rule inside sends it on to
// 127.0.0.1:PORT there, so dev servers that only listen on localhost (the
// usual default) are reachable too.

// writePortRedirects runs during setup, while the script still has
// capabilities. Replies to forwarded connections are allowed through an
// allow_net firewall by connection state only (no new outbound by port).
func writePortRedirects(sb *strings.Builder, ports []int, firewall bool) {
	if len(ports) == 0 {
		return
	}
	sb.WriteString("echo 1 > /proc/sys/net/ipv4/conf/all/route_localnet\n")
	sb.WriteString("echo 1 > /proc/sys/net/ipv4/conf/tap0/route_localnet\n")
	for _, p := range ports {
		fmt.Fprintf(sb, "iptables -t nat -A PREROUTING -i tap0 -p tcp --dport %d -j DNAT --to-destination 127.0.0.1:%d\n", p, p)
	}
	if firewall {
		sb.WriteString("iptables -I OUTPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	}
}

// slirpAPISocket returns a private path for slirp4netns' control socket.
func slirpAPISocket() (path string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "aigate-slirp-")
	if err != nil {
		return "", func() {}, err
	}
	return filepath.Join(dir, "api.sock"), func() { _ = os.RemoveAll(dir) }, nil
}

// publishPorts asks slirp4netns to forward 127.0.0.1:PORT on the host into
// the sandbox. A port that can't be published (already in use) is reported
// and skipped; the session still runs.
func publishPorts(apiSocket string, ports []int) {
	for _, p := range ports {
		if err := slirpHostFwd(apiSocket, p); err != nil {
			fmt.Fprintf(os.Stderr, "[aigate] warning: port %d not published: %v\n", p, err)
		}
	}
}

func slirpHostFwd(apiSocket string, port int) error {
	var conn net.Conn
	var err error
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if conn, err = net.Dial("unix", apiSocket); err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("network helper not ready: %w", err)
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	req := map[string]any{"execute": "add_hostfwd", "arguments": map[string]any{
		"proto": "tcp", "host_addr": "127.0.0.1", "host_port": port, "guest_port": port,
	}}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}
	var resp struct {
		Error *struct {
			Desc string `json:"desc"`
		} `json:"error"`
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("network helper: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("%s (is something on your machine already using it?)", resp.Error.Desc)
	}
	return nil
}

// portsNeedBwrap: the unshare fallback runs slirp4netns inside a shell where
// aigate can't reach its control socket.
func portsNeedBwrap() Block {
	return Block{
		What: "--port", Layer: LayerSandbox,
		Reason: "publishing ports needs bubblewrap, which isn't installed",
		Fix:    "install bubblewrap (sudo apt install bubblewrap, or sudo dnf install bubblewrap)",
	}
}
