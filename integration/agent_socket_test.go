package integration

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// listenCanarySocket opens a fake agent socket on the host and reports whether
// anything connected to it. It never touches a real agent.
func listenCanarySocket(t *testing.T, path string) (connected func() bool) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("cannot create canary socket at %s: %v", path, err)
	}
	t.Cleanup(func() { ln.Close(); os.Remove(path) }) //nolint:errcheck

	hits := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close() //nolint:errcheck
		hits <- struct{}{}
	}()
	return func() bool {
		select {
		case <-hits:
			return true
		case <-time.After(300 * time.Millisecond):
			return false
		}
	}
}

// probeSocketScript checks, from inside the sandbox, whether a socket path is
// visible and connectable, and prints the agent/bus env vars it inherited.
func probeSocketScript(path string) string {
	return fmt.Sprintf(`[ -S %[1]q ] && echo SOCK_VISIBLE
python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); print("SOCK_CONNECTED")' %[1]q 2>/dev/null
echo "ENV_SSH=${SSH_AUTH_SOCK:-}"
echo "ENV_DBUS=${DBUS_SESSION_BUS_ADDRESS:-}"
echo MARKER_DONE`, path)
}

func assertSocketSealed(t *testing.T, out string, connected func() bool) {
	t.Helper()
	if !strings.Contains(out, "MARKER_DONE") {
		t.Fatalf("sandbox did not run to completion: %s", out)
	}
	for _, leak := range []string{"SOCK_VISIBLE", "SOCK_CONNECTED"} {
		if strings.Contains(out, leak) {
			t.Errorf("agent socket reachable inside sandbox (%s): %s", leak, out)
		}
	}
	if connected() {
		t.Error("host canary socket accepted a connection from inside the sandbox")
	}
	for _, line := range strings.Split(out, "\n") {
		if (strings.HasPrefix(line, "ENV_SSH=") || strings.HasPrefix(line, "ENV_DBUS=")) &&
			!strings.HasSuffix(strings.TrimSpace(line), "=") {
			t.Errorf("agent/bus env var leaked into sandbox: %s", line)
		}
	}
}

// TestEscape_AgentSocketInHomeSealed: an ssh-agent socket that lives in $HOME
// (bound read-write in non-scoped mode) must not be reachable, and the env
// vars that advertise agents/buses must not be inherited.
func TestEscape_AgentSocketInHomeSealed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)

	sock := filepath.Join(tmpHome, "agent.sock")
	connected := listenCanarySocket(t, sock)
	env = append(env,
		"SSH_AUTH_SOCK="+sock,
		"DBUS_SESSION_BUS_ADDRESS=unix:path="+sock,
	)

	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c", probeSocketScript(sock))
	assertSocketSealed(t, out, connected)
}

// TestEscape_AgentSocketSealedWithNetFilter: the allow_net path builds its
// sandbox separately (bwrap + slirp4netns); it must seal agents the same way.
func TestEscape_AgentSocketSealedWithNetFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	if _, err := exec.LookPath("slirp4netns"); err != nil {
		t.Skip("slirp4netns not found, network-filter path unavailable")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)
	cfg := "group: ai-agents\nuser: ai-runner\ndeny_read: []\ndeny_exec: []\nallow_net: [example.com]\n"
	if err := os.WriteFile(filepath.Join(tmpHome, ".aigate", "config.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	sock := filepath.Join(tmpHome, "agent.sock")
	connected := listenCanarySocket(t, sock)
	env = append(env, "SSH_AUTH_SOCK="+sock)

	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c", probeSocketScript(sock))
	assertSocketSealed(t, out, connected)
}

// TestEscape_RuntimeDirSealed: sockets in the user runtime dir (session bus,
// keyring and agent sockets) must not be visible or connectable, even when
// nothing points at them through the environment.
func TestEscape_RuntimeDirSealed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox escape test in short mode")
	}
	runtimeDir := fmt.Sprintf("/run/user/%d", os.Getuid())
	if fi, err := os.Stat(runtimeDir); err != nil || !fi.IsDir() {
		t.Skipf("no user runtime dir at %s", runtimeDir)
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)

	sock := filepath.Join(runtimeDir, fmt.Sprintf("aigate-test-%d.sock", os.Getpid()))
	connected := listenCanarySocket(t, sock)

	out, _ := runSandboxedCmd(t, bin, env, "", "sh", "-c", probeSocketScript(sock))
	assertSocketSealed(t, out, connected)
}

// TestRuntimeDir_UsableInsideSandbox: hiding the runtime dir must not break
// tools that write to $XDG_RUNTIME_DIR — it is an empty, writable dir.
func TestRuntimeDir_UsableInsideSandbox(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	runtimeDir := fmt.Sprintf("/run/user/%d", os.Getuid())
	if _, err := os.Stat(runtimeDir); err != nil {
		t.Skipf("no user runtime dir at %s", runtimeDir)
	}
	bin := buildBinary(t)
	_, env := sandboxEnv(t)
	env = append(env, "XDG_RUNTIME_DIR="+runtimeDir)

	out, err := runSandboxedCmd(t, bin, env, "", "sh", "-c",
		`touch "$XDG_RUNTIME_DIR/probe" && echo WRITE_OK; echo MARKER_DONE`)
	if err != nil || !strings.Contains(out, "WRITE_OK") {
		t.Errorf("runtime dir not writable inside sandbox: %v\n%s", err, out)
	}
}
