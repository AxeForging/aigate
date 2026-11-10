package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// sandboxMode is one way `aigate run` can build its sandbox on Linux. Every
// mode must give the same guarantees, so the privilege tests run against all.
type sandboxMode struct {
	name     string
	noBwrap  bool // hide bwrap from PATH: the unshare fallback runs
	allowNet bool // allow_net set: network-filter path (slirp4netns)
}

var sandboxModes = []sandboxMode{
	{name: "bwrap"},
	{name: "bwrap+allow_net", allowNet: true},
	{name: "unshare", noBwrap: true},
	{name: "unshare+allow_net", noBwrap: true, allowNet: true},
}

// modeEnv builds a throwaway HOME + workdir for mode with deny_read .env and
// a .env file holding a canary. Scope is on (allowed_paths), as in real configs. It skips when the mode can't run here.
func modeEnv(t *testing.T, m sandboxMode) (env []string, work string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("linux sandbox modes")
	}
	for _, tool := range []string{"bwrap", "unshare", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found", tool)
		}
	}
	if m.noBwrap && exec.Command("unshare", "--user", "--map-root-user", "true").Run() != nil {
		t.Skip("plain unshare can't create user namespaces here (e.g. Ubuntu's AppArmor allows only bwrap)")
	}
	if m.allowNet {
		if _, err := exec.LookPath("slirp4netns"); err != nil {
			t.Skip("slirp4netns not found, network-filter path unavailable")
		}
	}
	home, env := sandboxEnv(t)
	allow := "[]"
	if m.allowNet {
		allow = "[example.com]"
	}
	cfg := "group: ai-agents\nuser: ai-runner\ndeny_read: [.env]\ndeny_exec: []\nallowed_paths: [~/.cache]\nallow_net: " + allow + "\n"
	if err := os.WriteFile(filepath.Join(home, ".aigate", "config.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	work = filepath.Join(home, "proj")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, ".env"), []byte("CANARY_SECRET_ENV\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if m.noBwrap {
		env = append(env, "PATH="+pathWithout(t, "bwrap"))
	}
	return env, work
}

// pathWithout returns a PATH holding symlinks to every program on the current
// PATH except the named ones, so aigate takes its fallback code path.
func pathWithout(t *testing.T, hide ...string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "path")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		entries, _ := os.ReadDir(d)
		for _, e := range entries {
			name := e.Name()
			if contains(hide, name) {
				continue
			}
			_ = os.Symlink(filepath.Join(d, name), filepath.Join(dir, name)) // first one on PATH wins
		}
	}
	return dir
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func forEachMode(t *testing.T, fn func(t *testing.T, bin string, env []string, work string)) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	for _, m := range sandboxModes {
		t.Run(m.name, func(t *testing.T) {
			env, work := modeEnv(t, m)
			fn(t, bin, env, work)
		})
	}
}

// TestEscape_NoCapabilitiesInside: the command must hold no capabilities in
// any mode. Setup needs some (iptables, mounts); they must be gone by the
// time the user's command runs.
func TestEscape_NoCapabilitiesInside(t *testing.T) {
	forEachMode(t, func(t *testing.T, bin string, env []string, work string) {
		out, err := runSandboxedCmd(t, bin, env, work, "sh", "-c", "grep -E '^Cap(Inh|Prm|Eff|Amb)' /proc/self/status; echo MARKER_DONE")
		if err != nil || !strings.Contains(out, "MARKER_DONE") {
			t.Fatalf("sandbox did not run: %v\n%s", err, out)
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "Cap") && !strings.HasSuffix(strings.TrimSpace(line), "0000000000000000") {
				t.Errorf("capability left to the sandboxed command: %s", line)
			}
		}
	})
}

// TestEscape_UmountRevealsDenyRead: unmounting the deny_read overlay must not
// reveal the file underneath — directly, or from a nested user namespace
// (which grants fresh capabilities, but over locked mounts).
func TestEscape_UmountRevealsDenyRead(t *testing.T) {
	forEachMode(t, func(t *testing.T, bin string, env []string, work string) {
		out, _ := runSandboxedCmd(t, bin, env, work, "sh", "-c",
			`umount -l "$PWD/.env" 2>/dev/null; umount -l .env 2>/dev/null; cat "$PWD/.env"
unshare -Urm sh -c 'umount -l "$0/.env" 2>/dev/null; cat "$0/.env"' "$PWD" 2>/dev/null
echo MARKER_DONE`)
		if !strings.Contains(out, "MARKER_DONE") {
			t.Fatalf("sandbox did not run: %s", out)
		}
		if strings.Contains(out, "CANARY_SECRET_ENV") {
			t.Errorf("umount revealed a deny_read file:\n%s", out)
		}
	})
}

// TestEscape_RelativePathDenyRead: a relative path from the working directory
// must hit the same deny_read overlay as the absolute one.
func TestEscape_RelativePathDenyRead(t *testing.T) {
	forEachMode(t, func(t *testing.T, bin string, env []string, work string) {
		out, _ := runSandboxedCmd(t, bin, env, work, "sh", "-c", "cat .env; cat ./.env; echo MARKER_DONE")
		if !strings.Contains(out, "MARKER_DONE") {
			t.Fatalf("sandbox did not run: %s", out)
		}
		if strings.Contains(out, "CANARY_SECRET_ENV") {
			t.Errorf("relative path read a deny_read file:\n%s", out)
		}
	})
}

// TestEscape_FlushAllowNet: the command must not be able to remove the
// allow_net firewall it runs behind.
func TestEscape_FlushAllowNet(t *testing.T) {
	forEachMode(t, func(t *testing.T, bin string, env []string, work string) {
		out, _ := runSandboxedCmd(t, bin, env, work, "sh", "-c",
			"iptables -F OUTPUT 2>/dev/null && echo FLUSHED; ip6tables -F OUTPUT 2>/dev/null && echo FLUSHED6; echo MARKER_DONE")
		if !strings.Contains(out, "MARKER_DONE") {
			t.Fatalf("sandbox did not run: %s", out)
		}
		if strings.Contains(out, "FLUSHED") {
			t.Errorf("sandboxed command flushed the firewall:\n%s", out)
		}
	})
}

// TestEscape_HostLocalServicesUnreachable: services that listen only on the
// host's loopback (debuggers, dev databases) and abstract unix sockets (X11,
// session helpers) must not be reachable, with or without allow_net.
func TestEscape_HostLocalServicesUnreachable(t *testing.T) {
	forEachMode(t, func(t *testing.T, bin string, env []string, work string) {
		if _, err := exec.LookPath("slirp4netns"); err != nil {
			t.Skip("slirp4netns not found: without it the sandbox shares the host network (doctor warns)")
		}
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer tcp.Close() //nolint:errcheck
		abstract := fmt.Sprintf("@aigate-test-%d", os.Getpid())
		unix, err := net.Listen("unix", abstract)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close() //nolint:errcheck
		port := tcp.Addr().(*net.TCPAddr).Port

		probe := fmt.Sprintf(`import socket
for fam, addr, label in [(socket.AF_INET, ("127.0.0.1", %d), "TCP"), (socket.AF_UNIX, "\0%s", "ABSTRACT")]:
    s = socket.socket(fam)
    s.settimeout(2)
    try:
        s.connect(addr); print(label + "_CONNECTED")
    except OSError:
        pass
print("MARKER_DONE")`, port, strings.TrimPrefix(abstract, "@"))
		out, _ := runSandboxedCmd(t, bin, env, work, "python3", "-I", "-c", probe)
		if !strings.Contains(out, "MARKER_DONE") {
			t.Fatalf("sandbox did not run: %s", out)
		}
		for _, leak := range []string{"TCP_CONNECTED", "ABSTRACT_CONNECTED"} {
			if strings.Contains(out, leak) {
				t.Errorf("host-local service reachable from the sandbox (%s):\n%s", leak, out)
			}
		}
	})
}

// TestRun_PortPublishedToHost: `aigate run --port P` makes a server the agent
// starts on 127.0.0.1:P (the usual dev-server default) reachable from the
// host at localhost:P, with or without allow_net.
func TestRun_PortPublishedToHost(t *testing.T) {
	forEachMode(t, func(t *testing.T, bin string, env []string, work string) {
		if _, err := exec.LookPath("slirp4netns"); err != nil {
			t.Skip("slirp4netns not found: the sandbox shares the host network, nothing to publish")
		}
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
		if err := os.WriteFile(filepath.Join(work, "index.html"), []byte("SERVED_FROM_SANDBOX"), 0o644); err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), escapeTestTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, "run", "--port", strconv.Itoa(port), "--",
			"python3", "-I", "-m", "http.server", strconv.Itoa(port), "--bind", "127.0.0.1")
		cmd.Env, cmd.Dir = env, work
		var out strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

		if strings.HasPrefix(t.Name(), "TestRun_PortPublishedToHost/unshare") {
			_ = cmd.Wait()
			if !strings.Contains(out.String(), "publishing ports needs bubblewrap") {
				t.Errorf("unshare fallback should refuse --port with the fix, got:\n%s", out.String())
			}
			return
		}
		body := ""
		for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			body = string(b)
			break
		}
		if !strings.Contains(body, "SERVED_FROM_SANDBOX") {
			t.Errorf("server inside the sandbox not reachable at localhost:%d (body %q)\n%s", port, body, out.String())
		}
	})
}

// TestEscape_AllowNetBlocksOtherHosts: with allow_net set, a host that isn't
// listed is unreachable — by IP too, so DNS isn't what stops it. (Without a
// working firewall this connects whenever the machine is online.)
func TestEscape_AllowNetBlocksOtherHosts(t *testing.T) {
	forEachMode(t, func(t *testing.T, bin string, env []string, work string) {
		if !strings.HasSuffix(t.Name(), "allow_net") {
			t.Skip("no allow_net in this mode")
		}
		probe := `import socket
for ip in ["1.1.1.1", "8.8.8.8"]:
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect((ip, 443)); print("CONNECTED " + ip)
    except OSError:
        pass
print("MARKER_DONE")`
		out, _ := runSandboxedCmd(t, bin, env, work, "python3", "-I", "-c", probe)
		if !strings.Contains(out, "MARKER_DONE") {
			t.Fatalf("sandbox did not run: %s", out)
		}
		if strings.Contains(out, "CONNECTED") {
			t.Errorf("a host outside allow_net was reachable:\n%s", out)
		}
		if strings.Contains(out, "iptables") || strings.Contains(out, "Permission denied") {
			t.Errorf("firewall setup reported errors:\n%s", out)
		}
	})
}

// TestEscape_AllowNetFailsClosedWithoutFirewall: if the firewall can't be
// installed (here: every iptables program fails), the command must not run
// unfiltered.
func TestEscape_AllowNetFailsClosedWithoutFirewall(t *testing.T) {
	forEachMode(t, func(t *testing.T, bin string, env []string, work string) {
		if !strings.HasSuffix(t.Name(), "allow_net") {
			t.Skip("no allow_net in this mode")
		}
		broken := t.TempDir()
		for _, n := range []string{"iptables", "iptables-nft", "iptables-restore", "iptables-nft-restore",
			"ip6tables", "ip6tables-nft", "ip6tables-restore", "ip6tables-nft-restore"} {
			if err := os.WriteFile(filepath.Join(broken, n), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		path := os.Getenv("PATH")
		for _, kv := range env {
			if strings.HasPrefix(kv, "PATH=") {
				path = strings.TrimPrefix(kv, "PATH=")
			}
		}
		env = append(env, "PATH="+broken+":"+path)
		out, err := runSandboxedCmd(t, bin, env, work, "sh", "-c", "echo COMMAND_RAN")
		if strings.Contains(out, "AppArmor is blocking") {
			t.Skip("AppArmor allows bwrap only at its installed path; can't hide iptables here")
		}
		if err == nil || strings.Contains(out, "COMMAND_RAN") {
			t.Errorf("command ran without its allow_net firewall: %v\n%s", err, out)
		}
		if !strings.Contains(out, "allow_net firewall could not be set up") {
			t.Errorf("want a block message naming the firewall, got:\n%s", out)
		}
	})
}
