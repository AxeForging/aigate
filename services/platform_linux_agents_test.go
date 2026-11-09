//go:build linux

package services

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/AxeForging/aigate/domain"
)

func TestDbusSocketPaths(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want []string
	}{
		{"empty", "", nil},
		{"single path", "unix:path=/run/user/1000/bus", []string{"/run/user/1000/bus"}},
		{"path with guid", "unix:path=/tmp/bus,guid=abc", []string{"/tmp/bus"}},
		{"abstract only", "unix:abstract=/tmp/dbus-x", nil},
		{"list", "unix:abstract=/x;unix:path=/a/bus", []string{"/a/bus"}},
		{"garbage", "nonsense", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dbusSocketPaths(tt.addr); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("dbusSocketPaths(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func listenUnix(t *testing.T, path string) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck
}

func TestAgentSocketPaths_OnlyExistingSocketsOutsideRuntimeDirs(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	listenUnix(t, sock)
	regular := filepath.Join(dir, "not-a-socket")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		ssh, dbus   string
		runtimeDirs []string
		want        []string
	}{
		{"socket in home is hidden", sock, "", nil, []string{sock}},
		{"same socket via both vars listed once", sock, "unix:path=" + sock, nil, []string{sock}},
		{"covered by runtime dir tmpfs", sock, "", []string{dir}, nil},
		{"regular file ignored", regular, "", nil, nil},
		{"missing path ignored", filepath.Join(dir, "gone"), "", nil, nil},
		{"relative path ignored", "agent.sock", "", nil, nil},
		{"unset", "", "", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SSH_AUTH_SOCK", tt.ssh)
			t.Setenv("DBUS_SESSION_BUS_ADDRESS", tt.dbus)
			if got := agentSocketPaths(tt.runtimeDirs); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("agentSocketPaths() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserRuntimeDirs_IgnoresUnsafeXDGValues(t *testing.T) {
	for _, v := range []string{"", "relative/dir", "/", "/tmp", "/does/not/exist"} {
		t.Setenv("XDG_RUNTIME_DIR", v)
		for _, d := range userRuntimeDirs() {
			if d == "/" || d == "/tmp" || !filepath.IsAbs(d) || d == "/does/not/exist" {
				t.Errorf("XDG_RUNTIME_DIR=%q produced unsafe runtime dir %q", v, d)
			}
		}
	}
}

func TestUserRuntimeDirs_IncludesCustomXDG(t *testing.T) {
	custom := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", custom)
	if dirs := userRuntimeDirs(); !containsString(dirs, custom) {
		t.Errorf("userRuntimeDirs() = %v, want it to include %q", dirs, custom)
	}
}

func TestBuildBwrapArgs_SealsAgentsAfterHomeBind(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	sock := filepath.Join(tmpHome, "agent.sock")
	listenUnix(t, sock)
	t.Setenv("SSH_AUTH_SOCK", sock)

	profile := domain.SandboxProfile{Config: domain.Config{}, WorkDir: tmpHome + "/project"}
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	for _, v := range agentEnvVars {
		if !containsPair(args, "--unsetenv", v) {
			t.Errorf("args should unset %s, got: %v", v, args)
		}
	}
	homeIdx, sockIdx := -1, -1
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--bind" && args[i+1] == tmpHome && args[i+2] == tmpHome {
			homeIdx = i
		}
		if args[i] == "--ro-bind" && args[i+1] == "/dev/null" && args[i+2] == sock {
			sockIdx = i
		}
	}
	if sockIdx == -1 {
		t.Fatalf("agent socket in home not hidden, got: %v", args)
	}
	if homeIdx > sockIdx {
		t.Errorf("socket hide (%d) must come after home bind (%d) or the bind re-exposes it", sockIdx, homeIdx)
	}
}

func TestBuildAgentOverrides_FailsClosedAndUnsets(t *testing.T) {
	custom := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", custom)
	script := buildAgentOverrides()

	if !strings.Contains(script, "mount -t tmpfs tmpfs \""+custom+"\" || {") || !strings.Contains(script, "exit 125") {
		t.Errorf("runtime dir hide must abort on failure, got:\n%s", script)
	}
	if !strings.Contains(script, "unset "+strings.Join(agentEnvVars, " ")) {
		t.Errorf("script must unset agent env vars, got:\n%s", script)
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
