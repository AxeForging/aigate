//go:build linux

package services

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Host sockets such as the ssh-agent, the desktop session bus and keyring
// daemons hand out credentials to anyone who can connect. Read-only mounts do
// not stop connect(), so the sandbox hides these sockets and drops the env
// vars that advertise them.

// agentEnvVars are unset inside the sandbox.
var agentEnvVars = []string{
	"SSH_AUTH_SOCK",
	"SSH_AGENT_PID",
	"DBUS_SESSION_BUS_ADDRESS",
	"GPG_AGENT_INFO",
	"GNOME_KEYRING_CONTROL",
}

// userRuntimeDirs returns the existing per-user runtime dirs to replace with an
// empty tmpfs: /run/user/<uid> and $XDG_RUNTIME_DIR when it differs.
func userRuntimeDirs() []string {
	var dirs []string
	seen := map[string]bool{}
	for _, d := range []string{fmt.Sprintf("/run/user/%d", os.Getuid()), os.Getenv("XDG_RUNTIME_DIR")} {
		if d == "" || !filepath.IsAbs(d) {
			continue
		}
		d = filepath.Clean(d)
		if seen[d] || d == "/" || d == "/tmp" {
			continue
		}
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			continue
		}
		seen[d] = true
		dirs = append(dirs, d)
	}
	return dirs
}

// agentSocketPaths returns advertised agent/bus sockets that exist and are not
// already hidden by a runtime-dir tmpfs, e.g. an ssh-agent socket in $HOME.
func agentSocketPaths(runtimeDirs []string) []string {
	candidates := []string{os.Getenv("SSH_AUTH_SOCK")}
	candidates = append(candidates, dbusSocketPaths(os.Getenv("DBUS_SESSION_BUS_ADDRESS"))...)

	var paths []string
	seen := map[string]bool{}
	for _, p := range candidates {
		if p == "" || !filepath.IsAbs(p) {
			continue
		}
		p = filepath.Clean(p)
		if seen[p] || underAny(p, runtimeDirs) {
			continue
		}
		if fi, err := os.Stat(p); err != nil || fi.Mode()&os.ModeSocket == 0 {
			continue
		}
		seen[p] = true
		paths = append(paths, p)
	}
	return paths
}

// dbusSocketPaths extracts unix:path= entries from a D-Bus address list
// ("unix:path=/run/user/1000/bus;unix:abstract=..."). Abstract sockets have
// no filesystem path and are out of scope here.
func dbusSocketPaths(addr string) []string {
	var paths []string
	for _, entry := range strings.Split(addr, ";") {
		_, params, ok := strings.Cut(entry, ":")
		if !ok {
			continue
		}
		for _, kv := range strings.Split(params, ",") {
			if v, ok := strings.CutPrefix(kv, "path="); ok {
				paths = append(paths, v)
			}
		}
	}
	return paths
}

// bwrapAgentArgs hides runtime dirs and agent sockets and drops agent env
// vars. Append it after all other mounts so it wins over home/scope binds.
func bwrapAgentArgs() []string {
	runtimeDirs := userRuntimeDirs()
	var args []string
	for _, d := range runtimeDirs {
		args = append(args, "--tmpfs", d)
	}
	for _, p := range agentSocketPaths(runtimeDirs) {
		args = append(args, "--ro-bind", "/dev/null", p)
	}
	for _, v := range agentEnvVars {
		args = append(args, "--unsetenv", v)
	}
	return args
}

// buildAgentOverrides is the unshare-fallback equivalent of bwrapAgentArgs.
// Failing to hide a runtime dir aborts the run instead of leaving it exposed.
func buildAgentOverrides() string {
	runtimeDirs := userRuntimeDirs()
	var sb strings.Builder
	for _, d := range runtimeDirs {
		fmt.Fprintf(&sb,
			"mount -t tmpfs tmpfs %q || { echo '[aigate] failed to hide user runtime dir' >&2; exit 125; }\n", d)
	}
	for _, p := range agentSocketPaths(runtimeDirs) {
		fmt.Fprintf(&sb,
			"mount --bind /dev/null %q || { echo '[aigate] failed to hide agent socket' >&2; exit 125; }\n", p)
	}
	fmt.Fprintf(&sb, "unset %s\n", strings.Join(agentEnvVars, " "))
	return sb.String()
}
