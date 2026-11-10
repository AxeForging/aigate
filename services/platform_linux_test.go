//go:build linux

package services

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/AxeForging/aigate/domain"
)

type mockExecutor struct {
	calls   []mockCall
	results map[string]mockResult
}

type mockCall struct {
	Name string
	Args []string
}

type mockResult struct {
	Output []byte
	Err    error
}

func newMockExecutor() *mockExecutor {
	return &mockExecutor{
		results: make(map[string]mockResult),
	}
}

func (m *mockExecutor) Run(name string, args ...string) ([]byte, error) {
	m.calls = append(m.calls, mockCall{Name: name, Args: args})
	key := name
	if len(args) > 0 {
		key = fmt.Sprintf("%s %s", name, args[0])
	}
	if r, ok := m.results[key]; ok {
		return r.Output, r.Err
	}
	return nil, nil
}

func (m *mockExecutor) RunPassthrough(name string, args ...string) error {
	return m.RunPassthroughWith(os.Stdout, os.Stderr, name, args...)
}

func (m *mockExecutor) RunPassthroughWith(_ io.Writer, _ io.Writer, name string, args ...string) error {
	m.calls = append(m.calls, mockCall{Name: name, Args: args})
	key := name
	if len(args) > 0 {
		key = fmt.Sprintf("%s %s", name, args[0])
	}
	if r, ok := m.results[key]; ok {
		return r.Err
	}
	return nil
}

func (m *mockExecutor) setResult(key string, output []byte, err error) {
	m.results[key] = mockResult{Output: output, Err: err}
}

func (m *mockExecutor) lastCall() mockCall {
	if len(m.calls) == 0 {
		return mockCall{}
	}
	return m.calls[len(m.calls)-1]
}

func (m *mockExecutor) callCount() int {
	return len(m.calls)
}

func TestLinuxPlatform_Name(t *testing.T) {
	p := &LinuxPlatform{exec: newMockExecutor()}
	if p.Name() != "linux" {
		t.Errorf("Name() = %q, want %q", p.Name(), "linux")
	}
}

func TestLinuxPlatform_GroupExists(t *testing.T) {
	exec := newMockExecutor()
	p := &LinuxPlatform{exec: exec}

	// Group does not exist
	exec.setResult("getent group", nil, fmt.Errorf("not found"))
	exists, err := p.GroupExists("ai-agents")
	if err != nil {
		t.Fatalf("GroupExists() error = %v", err)
	}
	if exists {
		t.Error("GroupExists() should return false")
	}
}

func TestLinuxPlatform_GroupExistsTrue(t *testing.T) {
	exec := newMockExecutor()
	p := &LinuxPlatform{exec: exec}

	// Group exists
	exists, err := p.GroupExists("ai-agents")
	if err != nil {
		t.Fatalf("GroupExists() error = %v", err)
	}
	if !exists {
		t.Error("GroupExists() should return true")
	}
}

func TestLinuxPlatform_CreateGroup(t *testing.T) {
	exec := newMockExecutor()
	p := &LinuxPlatform{exec: exec}

	// Group doesn't exist yet
	exec.setResult("getent group", nil, fmt.Errorf("not found"))
	err := p.CreateGroup("ai-agents")
	if err != nil {
		t.Fatalf("CreateGroup() error = %v", err)
	}
	// Should have called groupadd
	found := false
	for _, c := range exec.calls {
		if c.Name == "groupadd" {
			found = true
			break
		}
	}
	if !found {
		t.Error("CreateGroup() should call groupadd")
	}
}

func TestLinuxPlatform_CreateGroupAlreadyExists(t *testing.T) {
	exec := newMockExecutor()
	p := &LinuxPlatform{exec: exec}

	// Group already exists (getent succeeds)
	err := p.CreateGroup("ai-agents")
	if err == nil {
		t.Error("CreateGroup() should error when group already exists")
	}
}

func TestLinuxPlatform_UserExists(t *testing.T) {
	exec := newMockExecutor()
	p := &LinuxPlatform{exec: exec}

	exec.setResult("getent passwd", nil, fmt.Errorf("not found"))
	exists, err := p.UserExists("ai-runner")
	if err != nil {
		t.Fatalf("UserExists() error = %v", err)
	}
	if exists {
		t.Error("UserExists() should return false")
	}
}

func TestLinuxPlatform_CreateUser(t *testing.T) {
	exec := newMockExecutor()
	p := &LinuxPlatform{exec: exec}

	exec.setResult("getent passwd", nil, fmt.Errorf("not found"))
	err := p.CreateUser("ai-runner", "ai-agents")
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	found := false
	for _, c := range exec.calls {
		if c.Name == "useradd" {
			found = true
			break
		}
	}
	if !found {
		t.Error("CreateUser() should call useradd")
	}
}

func TestLinuxPlatform_DeleteGroupNotExists(t *testing.T) {
	exec := newMockExecutor()
	p := &LinuxPlatform{exec: exec}

	exec.setResult("getent group", nil, fmt.Errorf("not found"))
	err := p.DeleteGroup("ai-agents")
	if err != nil {
		t.Fatalf("DeleteGroup() error = %v (should be nil for non-existent)", err)
	}
}

func TestLinuxPlatform_DeleteUserNotExists(t *testing.T) {
	exec := newMockExecutor()
	p := &LinuxPlatform{exec: exec}

	exec.setResult("getent passwd", nil, fmt.Errorf("not found"))
	err := p.DeleteUser("ai-runner")
	if err != nil {
		t.Fatalf("DeleteUser() error = %v (should be nil for non-existent)", err)
	}
}

func TestLinuxPlatform_SetFileACLDeny(t *testing.T) {
	tmpDir := t.TempDir()
	exec := newMockExecutor()
	p := &LinuxPlatform{exec: exec}

	// Create a test file
	testFile := tmpDir + "/test.env"
	writeTestFile(t, testFile, "SECRET=foo")

	err := p.SetFileACLDeny("ai-agents", []string{"test.env"}, tmpDir)
	if err != nil {
		t.Fatalf("SetFileACLDeny() error = %v", err)
	}
	// Should have called setfacl
	found := false
	for _, c := range exec.calls {
		if c.Name == "setfacl" {
			found = true
			break
		}
	}
	if !found {
		t.Error("SetFileACLDeny() should call setfacl")
	}
}

func TestLinuxPlatform_RemoveFileACL(t *testing.T) {
	tmpDir := t.TempDir()
	exec := newMockExecutor()
	p := &LinuxPlatform{exec: exec}

	testFile := tmpDir + "/test.env"
	writeTestFile(t, testFile, "SECRET=foo")

	err := p.RemoveFileACL("ai-agents", []string{"test.env"}, tmpDir)
	if err != nil {
		t.Fatalf("RemoveFileACL() error = %v", err)
	}
}

func TestResolvePatterns(t *testing.T) {
	tmpDir := t.TempDir()
	writeTestFile(t, tmpDir+"/test.env", "foo")
	writeTestFile(t, tmpDir+"/prod.env", "bar")

	paths, err := resolvePatterns([]string{"*.env"}, tmpDir)
	if err != nil {
		t.Fatalf("resolvePatterns() error = %v", err)
	}
	if len(paths) != 2 {
		t.Errorf("resolvePatterns() len = %d, want 2", len(paths))
	}
}

func TestResolvePatterns_NonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	paths, err := resolvePatterns([]string{"nonexistent.txt"}, tmpDir)
	if err != nil {
		t.Fatalf("resolvePatterns() error = %v", err)
	}
	if len(paths) != 1 {
		t.Errorf("resolvePatterns() should keep non-existent paths, got len = %d", len(paths))
	}
}

func TestResolvePatterns_Absolute(t *testing.T) {
	paths, err := resolvePatterns([]string{"/tmp/some-file"}, "/irrelevant")
	if err != nil {
		t.Fatalf("resolvePatterns() error = %v", err)
	}
	if len(paths) != 1 || paths[0] != "/tmp/some-file" {
		t.Errorf("resolvePatterns() absolute path = %v, want [/tmp/some-file]", paths)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writeFile(%s) error = %v", path, err)
	}
}

func TestResolveAllowedIPs(t *testing.T) {
	t.Run("raw IPv4 passes through", func(t *testing.T) {
		ips := resolveAllowedIPs([]string{"1.2.3.4", "5.6.7.8"})
		if len(ips) != 2 {
			t.Fatalf("expected 2 IPs, got %d: %v", len(ips), ips)
		}
		if ips[0] != "1.2.3.4" || ips[1] != "5.6.7.8" {
			t.Errorf("unexpected IPs: %v", ips)
		}
	})

	t.Run("deduplicates IPs", func(t *testing.T) {
		ips := resolveAllowedIPs([]string{"1.2.3.4", "1.2.3.4"})
		if len(ips) != 1 {
			t.Fatalf("expected 1 IP after dedup, got %d: %v", len(ips), ips)
		}
	})

	t.Run("filters out IPv6", func(t *testing.T) {
		ips := resolveAllowedIPs([]string{"::1"})
		if len(ips) != 0 {
			t.Errorf("expected 0 IPs for IPv6, got %d: %v", len(ips), ips)
		}
	})

	t.Run("unresolvable host skipped", func(t *testing.T) {
		ips := resolveAllowedIPs([]string{"this-domain-does-not-exist.invalid"})
		if len(ips) != 0 {
			t.Errorf("expected 0 IPs for unresolvable host, got %d: %v", len(ips), ips)
		}
	})

	t.Run("resolves real hostname", func(t *testing.T) {
		ips := resolveAllowedIPs([]string{"localhost"})
		// localhost should resolve to 127.0.0.1 on any system
		found := false
		for _, ip := range ips {
			if ip == "127.0.0.1" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected 127.0.0.1 from localhost, got %v", ips)
		}
	})
}

// testStage is a staged aigate binary for script-building tests.
var testStage = sandboxExecStage{src: "/opt/aigate", dst: "/tmp/aigate-exec-test"}

func TestBuildNetFilterScript(t *testing.T) {
	profile := domain.SandboxProfile{
		Config: domain.Config{
			DenyRead: []string{"/nonexistent/path/for/test"},
		},
		WorkDir: "/tmp",
	}

	t.Run("resolves hosts inside namespace via getent", func(t *testing.T) {
		script := buildNetFilterScript([]string{"api.anthropic.com", "1.2.3.4"}, false, profile, testStage, "echo", []string{"hello"})
		// Hostnames and raw IPs both go through getent inside the namespace.
		for _, want := range []string{`getent ahostsv4 "api.anthropic.com"`, `getent ahostsv4 "1.2.3.4"`, "iptables -A OUTPUT -j REJECT"} {
			if !strings.Contains(script, want) {
				t.Errorf("script should contain %q", want)
			}
		}
	})

	// DNS goes only to slirp4netns' forwarder. Allowing the host's DNS servers
	// (all ports) or port 53 to any address let traffic around allow_net —
	// e.g. 1.1.1.1:443 was reachable when the host used 1.1.1.1 for DNS.
	t.Run("DNS only to the slirp forwarder", func(t *testing.T) {
		script := buildNetFilterScript([]string{"example.com"}, true, profile, testStage, "echo", nil)
		for _, want := range []string{
			"iptables -A OUTPUT -d 10.0.2.3 -p udp --dport 53 -j ACCEPT",
			"iptables -A OUTPUT -d 10.0.2.3 -p tcp --dport 53 -j ACCEPT",
			"ip6tables -A OUTPUT -d fd00::3 -p udp --dport 53 -j ACCEPT",
			"ip6tables -A OUTPUT -d fd00::3 -p tcp --dport 53 -j ACCEPT",
		} {
			if !strings.Contains(script, want) {
				t.Errorf("script should contain %q, got:\n%s", want, script)
			}
		}
		for _, line := range strings.Split(script, "\n") {
			if strings.Contains(line, "--dport 53") && !strings.Contains(line, "-d 10.0.2.3 ") && !strings.Contains(line, "-d fd00::3 ") {
				t.Errorf("DNS port open beyond the forwarder: %s", line)
			}
		}
	})

	t.Run("stops the run when the firewall isn't in place", func(t *testing.T) {
		script := buildNetFilterScript([]string{"example.com"}, true, profile, testStage, "echo", nil)
		for _, want := range []string{
			"iptables -C OUTPUT -j REJECT --reject-with icmp-admin-prohibited 2>/dev/null || {",
			"ip6tables -C OUTPUT -j REJECT --reject-with icmp6-adm-prohibited 2>/dev/null || {",
			"the allow_net firewall could not be set up",
		} {
			if !strings.Contains(script, want) {
				t.Errorf("script should contain %q, got:\n%s", want, script)
			}
		}
		guard := strings.Index(script, "iptables -C OUTPUT")
		if guard == -1 || guard > strings.Index(script, "__sandbox-exec") {
			t.Error("the guard must run before the command")
		}
	})

	t.Run("contains resolv.conf fix", func(t *testing.T) {
		script := buildNetFilterScript(nil, false, profile, testStage, "echo", nil)
		if !strings.Contains(script, "nameserver 10.0.2.3") {
			t.Error("script should set resolv.conf to slirp4netns DNS")
		}
	})

	t.Run("contains wait for tap0", func(t *testing.T) {
		script := buildNetFilterScript(nil, false, profile, testStage, "echo", nil)
		if !strings.Contains(script, "ip addr show tap0") {
			t.Error("script should wait for tap0 interface")
		}
	})

	t.Run("waits for real DNS before resolving hosts", func(t *testing.T) {
		script := buildNetFilterScript([]string{"example.com", "other.com"}, false, profile, testStage, "echo", nil)
		// DNS readiness check should use the FIRST AllowNet host, not localhost
		dnsWaitIdx := strings.Index(script, "getent ahostsv4 \"example.com\" >/dev/null")
		if dnsWaitIdx == -1 {
			t.Fatal("script should check DNS readiness with first AllowNet host")
		}
		if strings.Contains(script, "getent ahostsv4 localhost") {
			t.Error("should NOT use localhost for DNS readiness (resolves from /etc/hosts, not DNS)")
		}
	})

	t.Run("retries host resolution on failure", func(t *testing.T) {
		script := buildNetFilterScript([]string{"example.com"}, false, profile, testStage, "echo", nil)
		if !strings.Contains(script, "_attempt in 1 2 3") {
			t.Error("should retry getent resolution")
		}
	})

	t.Run("contains target command", func(t *testing.T) {
		script := buildNetFilterScript(nil, false, profile, testStage, "mycommand", []string{"--flag", "value"})
		if !strings.Contains(script, "exec /tmp/aigate-exec-test __sandbox-exec -- mycommand --flag value") {
			t.Errorf("script should exec the command through the capability drop, got:\n%s", script)
		}
	})

	t.Run("goes back into the workdir before exec", func(t *testing.T) {
		// The shell starts in the workdir as it was before the mounts; without
		// the cd, relative paths would skip deny_read and scope.
		script := buildNetFilterScript(nil, false, profile, testStage, "echo", nil)
		cd := strings.LastIndex(script, "cd /tmp ||")
		exec := strings.LastIndex(script, "exec /tmp/aigate-exec-test")
		if cd == -1 || exec == -1 || cd > exec {
			t.Errorf("script should cd into the workdir right before exec, got:\n%s", script)
		}
	})

	t.Run("binds the aigate binary read-only before anything hides it", func(t *testing.T) {
		script := buildNetFilterScript(nil, false, profile, testStage, "echo", nil)
		bind := strings.Index(script, "mount --bind /opt/aigate /tmp/aigate-exec-test && mount -o remount,bind,ro /tmp/aigate-exec-test")
		if bind == -1 || bind > strings.Index(script, "aigate-policy") {
			t.Errorf("script should bind the binary read-only first, got:\n%s", script)
		}
	})

	t.Run("no firewall without allow_net", func(t *testing.T) {
		// Own namespace (host loopback unreachable) but every host allowed.
		script := buildNetFilterScript(nil, false, profile, testStage, "echo", nil)
		if strings.Contains(script, "iptables") {
			t.Errorf("no allow_net should mean no firewall rules, got:\n%s", script)
		}
		if !strings.Contains(script, "nameserver 10.0.2.3") {
			t.Error("DNS must still point at slirp4netns")
		}
	})

	// IPv6 path: when ipv6Enabled=true, the script must also emit ip6tables
	// rules, a v6 DNS forwarder, and AAAA resolution for allow_net hosts.
	t.Run("emits ip6tables rules when ipv6Enabled", func(t *testing.T) {
		script := buildNetFilterScript([]string{"example.com"}, true, profile, testStage, "echo", nil)
		for _, want := range []string{
			"ip6tables -A OUTPUT -o lo -j ACCEPT",
			"getent ahostsv6 \"example.com\"",
			"ip6tables -A OUTPUT -j REJECT --reject-with icmp6-adm-prohibited",
			"nameserver fd00::3",
		} {
			if !strings.Contains(script, want) {
				t.Errorf("script should contain %q, got:\n%s", want, script)
			}
		}
		// v4 rules must still be present.
		if !strings.Contains(script, "getent ahostsv4 \"example.com\"") {
			t.Error("v4 rules must still be emitted when ipv6Enabled=true")
		}
	})

	t.Run("omits ip6tables and fd00::3 when ipv6Enabled=false", func(t *testing.T) {
		script := buildNetFilterScript([]string{"example.com"}, false, profile, testStage, "echo", nil)
		if strings.Contains(script, "ip6tables") {
			t.Errorf("script must not contain ip6tables when ipv6Enabled=false, got:\n%s", script)
		}
		if strings.Contains(script, "fd00::3") {
			t.Errorf("script must not include v6 forwarder when ipv6Enabled=false")
		}
		if strings.Contains(script, "getent ahostsv6") {
			t.Errorf("script must not resolve AAAA when ipv6Enabled=false")
		}
	})
}

func TestRunSandboxedDispatch(t *testing.T) {
	t.Run("AllowNet set without slirp4netns falls back (no --net)", func(t *testing.T) {
		if hasSlirp4netns() {
			t.Skip("slirp4netns is installed; this test covers the no-slirp fallback path only")
		}
		mock := newMockExecutor()
		p := &LinuxPlatform{exec: mock}
		profile := domain.SandboxProfile{
			Config:  domain.Config{AllowNet: []string{"example.com"}},
			WorkDir: "/tmp",
		}
		_ = p.RunSandboxed(profile, "echo", []string{"hello"}, os.Stdout, os.Stderr)
		if mock.callCount() == 0 {
			t.Fatal("expected executor to be called via fallback")
		}
		// Should use bwrap or unshare — never the net-filter path.
		last := mock.lastCall()
		if last.Name != "bwrap" && last.Name != "unshare" {
			t.Errorf("expected bwrap or unshare fallback, got %q", last.Name)
		}
		for _, arg := range last.Args {
			if arg == "--net" {
				t.Error("no-slirp fallback should not pass --net flag")
			}
		}
	})
}

func TestBuildOrchestrationScript(t *testing.T) {
	inner := "echo hello world\n"

	t.Run("embeds inner script via base64", func(t *testing.T) {
		script := buildOrchestrationScript(inner, false)
		encoded := base64.StdEncoding.EncodeToString([]byte(inner))
		if !strings.Contains(script, encoded) {
			t.Error("orchestration script should contain base64-encoded inner script")
		}
	})

	t.Run("preserves stdin via fd 3", func(t *testing.T) {
		script := buildOrchestrationScript(inner, false)
		if !strings.Contains(script, "exec 3<&0") {
			t.Error("should save stdin to fd 3")
		}
		if !strings.Contains(script, "<&3") {
			t.Error("should redirect fd 3 to sandbox stdin")
		}
	})

	t.Run("uses two-layer unshare", func(t *testing.T) {
		script := buildOrchestrationScript(inner, false)
		// Inner unshare should create net namespace (outer only creates user ns)
		if !strings.Contains(script, "unshare --net --mount --pid --fork") {
			t.Error("inner unshare should create net/mount/pid namespaces")
		}
	})

	t.Run("runs slirp4netns inside user namespace", func(t *testing.T) {
		script := buildOrchestrationScript(inner, false)
		if !strings.Contains(script, "slirp4netns --disable-host-loopback --configure $_SANDBOX_PID tap0") {
			t.Error("should launch slirp4netns with sandbox PID")
		}
		if strings.Contains(script, "--enable-ipv6") {
			t.Error("ipv6Enabled=false should not enable v6 on slirp4netns")
		}
	})

	t.Run("passes --enable-ipv6 to slirp4netns when ipv6Enabled=true", func(t *testing.T) {
		script := buildOrchestrationScript(inner, true)
		if !strings.Contains(script, "slirp4netns --disable-host-loopback --enable-ipv6 --configure $_SANDBOX_PID tap0") {
			t.Errorf("ipv6Enabled=true should pass --enable-ipv6 to slirp4netns, got:\n%s", script)
		}
	})

	t.Run("waits for namespace and cleans up", func(t *testing.T) {
		script := buildOrchestrationScript(inner, false)
		if !strings.Contains(script, "readlink /proc/$_SANDBOX_PID/ns/net") {
			t.Error("should wait for net namespace to differ from host")
		}
		if !strings.Contains(script, "wait $_SANDBOX_PID") {
			t.Error("should wait for sandbox to finish")
		}
		if !strings.Contains(script, "kill $_SLIRP_PID") {
			t.Error("should kill slirp4netns on cleanup")
		}
	})
}

func TestResolvePatterns_TildeExpansion(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// Create a file at ~/testfile
	writeTestFile(t, tmpDir+"/testfile", "content")

	paths, err := resolvePatterns([]string{"~/testfile"}, "/irrelevant")
	if err != nil {
		t.Fatalf("resolvePatterns() error = %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("resolvePatterns() len = %d, want 1", len(paths))
	}
	if paths[0] != tmpDir+"/testfile" {
		t.Errorf("resolvePatterns() = %q, want %q", paths[0], tmpDir+"/testfile")
	}
}

func TestResolvePatterns_TildeDir(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// Create ~/.ssh/ directory
	_ = os.MkdirAll(tmpDir+"/.ssh", 0o755)

	paths, err := resolvePatterns([]string{"~/.ssh/"}, "/irrelevant")
	if err != nil {
		t.Fatalf("resolvePatterns() error = %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("resolvePatterns() len = %d, want 1", len(paths))
	}
	expected := tmpDir + "/.ssh"
	if paths[0] != expected {
		t.Errorf("resolvePatterns() = %q, want %q", paths[0], expected)
	}
}

func TestBuildExecDenyOverrides_Empty(t *testing.T) {
	profile := domain.SandboxProfile{
		Config:  domain.Config{DenyExec: nil},
		WorkDir: "/tmp",
	}
	result := buildExecDenyOverrides(profile)
	if result != "" {
		t.Errorf("buildExecDenyOverrides() with empty deny list should return empty, got %q", result)
	}
}

func TestBuildExecDenyOverrides_FullCommand(t *testing.T) {
	profile := domain.SandboxProfile{
		Config: domain.Config{
			DenyExec: []string{"curl", "wget"},
		},
		WorkDir: "/tmp",
	}
	result := buildExecDenyOverrides(profile)

	// Should create the deny script
	if !strings.Contains(result, "/tmp/.aigate-deny-exec") {
		t.Error("should create deny script at /tmp/.aigate-deny-exec")
	}
	// Should iterate PATH for each denied command
	if !strings.Contains(result, "\"$_d/curl\"") {
		t.Error("should search PATH for curl")
	}
	if !strings.Contains(result, "\"$_d/wget\"") {
		t.Error("should search PATH for wget")
	}
	// Should mount --bind the deny script
	if !strings.Contains(result, "mount --bind /tmp/.aigate-deny-exec") {
		t.Error("should mount --bind deny script over binaries")
	}
}

func TestBuildExecDenyOverrides_Subcommand(t *testing.T) {
	profile := domain.SandboxProfile{
		Config: domain.Config{
			DenyExec: []string{"kubectl delete", "kubectl exec"},
		},
		WorkDir: "/tmp",
	}
	result := buildExecDenyOverrides(profile)

	// Should NOT create the full-deny script (no full blocks)
	if strings.Contains(result, "/tmp/.aigate-deny-exec") {
		t.Error("should not create full deny script for subcommand-only rules")
	}
	// Should create wrapper and original copy
	if !strings.Contains(result, "/tmp/.aigate-orig-kubectl") {
		t.Error("should copy original binary to /tmp/.aigate-orig-kubectl")
	}
	if !strings.Contains(result, "/tmp/.aigate-wrap-kubectl") {
		t.Error("should create wrapper at /tmp/.aigate-wrap-kubectl")
	}
	// Should contain base64-encoded wrapper
	if !strings.Contains(result, "base64 -d") {
		t.Error("should decode wrapper from base64")
	}
	// Decode and verify the wrapper script content
	// Extract the base64 portion
	idx := strings.Index(result, "printf '%s' '")
	if idx == -1 {
		t.Fatal("could not find base64 content in script")
	}
	start := idx + len("printf '%s' '")
	end := strings.Index(result[start:], "'")
	encoded := result[start : start+end]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("failed to decode wrapper: %v", err)
	}
	wrapper := string(decoded)
	if !strings.Contains(wrapper, "delete)") {
		t.Error("wrapper should contain case arm for 'delete'")
	}
	if !strings.Contains(wrapper, "exec)") {
		t.Error("wrapper should contain case arm for 'exec'")
	}
	if !strings.Contains(wrapper, "/tmp/.aigate-orig-kubectl") {
		t.Error("wrapper should exec the original binary from /tmp/.aigate-orig-kubectl")
	}
}

func TestBuildExecDenyOverrides_Mixed(t *testing.T) {
	profile := domain.SandboxProfile{
		Config: domain.Config{
			DenyExec: []string{"curl", "kubectl delete"},
		},
		WorkDir: "/tmp",
	}
	result := buildExecDenyOverrides(profile)

	// Should have both full-deny and subcommand wrappers
	if !strings.Contains(result, "/tmp/.aigate-deny-exec") {
		t.Error("should create deny script for full command block")
	}
	if !strings.Contains(result, "/tmp/.aigate-orig-kubectl") {
		t.Error("should create wrapper for subcommand block")
	}
}

func TestBuildConfigDirOverride(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	result := buildConfigDirOverride()
	expected := tmpDir + "/.aigate"
	if !strings.Contains(result, "mount -t tmpfs") {
		t.Error("should mount tmpfs")
	}
	if !strings.Contains(result, expected) {
		t.Errorf("should mount over %s, got: %s", expected, result)
	}
}

func TestBuildNetFilterScript_MountMakeRprivate(t *testing.T) {
	profile := domain.SandboxProfile{
		Config:  domain.Config{},
		WorkDir: "/tmp",
	}
	script := buildNetFilterScript(nil, false, profile, testStage, "echo", nil)
	if !strings.Contains(script, "mount --make-rprivate /") {
		t.Error("net filter script should start with mount --make-rprivate /")
	}
	// Verify rprivate comes BEFORE any bind mounts
	rprivateIdx := strings.Index(script, "mount --make-rprivate /")
	procIdx := strings.Index(script, "mount -t proc proc /proc")
	if rprivateIdx > procIdx {
		t.Error("mount --make-rprivate should come before mount -t proc")
	}
}

func TestBuildMountOverrides_IndependentMounts(t *testing.T) {
	tmpDir := t.TempDir()
	writeTestFile(t, tmpDir+"/secret1.txt", "secret")
	writeTestFile(t, tmpDir+"/secret2.txt", "secret")

	profile := domain.SandboxProfile{
		Config: domain.Config{
			DenyRead: []string{"secret1.txt", "secret2.txt"},
		},
		WorkDir: tmpDir,
	}
	result := buildMountOverrides(profile)

	// Each mount should be on its own line (not joined with &&)
	lines := strings.Split(strings.TrimSpace(result), "\n")
	mountCount := 0
	for _, line := range lines {
		if strings.Contains(line, "mount --bind") {
			mountCount++
			// Each mount should have || true for resilience
			if !strings.Contains(line, "|| true") {
				t.Errorf("mount line should have || true: %s", line)
			}
		}
	}
	if mountCount != 2 {
		t.Errorf("expected 2 independent mount commands, got %d", mountCount)
	}

	// Should NOT contain && between mount commands (cascading failure risk)
	if strings.Contains(result, "mount --bind /tmp/.aigate-denied") &&
		strings.Contains(result, "&& mount --bind") {
		t.Error("mount commands should NOT be joined with && (cascading failure)")
	}
}

func TestBuildMountOverrides_QuotesPaths(t *testing.T) {
	tmpDir := t.TempDir()
	writeTestFile(t, tmpDir+"/secret.txt", "secret")

	profile := domain.SandboxProfile{
		Config: domain.Config{
			DenyRead: []string{"secret.txt"},
		},
		WorkDir: tmpDir,
	}
	result := buildMountOverrides(profile)
	// Path should be quoted
	expected := fmt.Sprintf("mount --bind /tmp/.aigate-denied \"%s/secret.txt\"", tmpDir)
	if !strings.Contains(result, expected) {
		t.Errorf("mount should quote path, got:\n%s", result)
	}
}

func TestBuildMountOverrides_DirMount(t *testing.T) {
	tmpDir := t.TempDir()
	_ = os.MkdirAll(tmpDir+"/secrets", 0o755)

	profile := domain.SandboxProfile{
		Config: domain.Config{
			DenyRead: []string{"secrets/"},
		},
		WorkDir: tmpDir,
	}
	result := buildMountOverrides(profile)

	// Dir mount should use tmpfs and have || true
	if !strings.Contains(result, "mount -t tmpfs") {
		t.Error("dir mount should use tmpfs")
	}
	if !strings.Contains(result, "|| true") {
		t.Error("dir mount should have || true for resilience")
	}
	// Should NOT create the file deny marker (no file mounts)
	if strings.Contains(result, "printf '[aigate]") && strings.Contains(result, "/tmp/.aigate-denied\n") {
		t.Error("file deny marker should not be created when there are only directory mounts")
	}
}

func TestRunUnshare_MountMakeRprivate(t *testing.T) {
	mock := newMockExecutor()
	p := &LinuxPlatform{exec: mock}
	profile := domain.SandboxProfile{
		Config:  domain.Config{},
		WorkDir: "/tmp",
	}
	// Call runUnshare directly: RunSandboxed prefers bwrap when available.
	_ = p.runUnshare(profile, "echo", []string{"hello"}, os.Stdout, os.Stderr)

	if mock.callCount() == 0 {
		t.Fatal("expected executor to be called")
	}
	last := mock.lastCall()
	// The shell command is the last argument
	shellCmd := last.Args[len(last.Args)-1]
	if !strings.Contains(shellCmd, "mount --make-rprivate /") {
		t.Error("runUnshare should include mount --make-rprivate /")
	}
	// Verify rprivate comes first (before any other commands)
	if !strings.HasPrefix(shellCmd, "mount --make-rprivate /") {
		t.Error("mount --make-rprivate should be the first command in the script")
	}
	// Verify exec is used before the command
	if !strings.Contains(shellCmd, "__sandbox-exec -- echo hello") {
		t.Error("runUnshare should exec the target command through the capability drop")
	}
}

func TestBuildNetFilterScript_IncludesExecDeny(t *testing.T) {
	profile := domain.SandboxProfile{
		Config: domain.Config{
			DenyExec: []string{"curl", "wget"},
			DenyRead: []string{"/nonexistent/path/for/test"},
		},
		WorkDir: "/tmp",
	}

	script := buildNetFilterScript(nil, false, profile, testStage, "echo", []string{"hello"})
	if !strings.Contains(script, "/tmp/.aigate-deny-exec") {
		t.Error("net filter script should include exec deny overrides")
	}
	if !strings.Contains(script, ".aigate") {
		t.Error("net filter script should include config dir override")
	}
}

// ── shellQuote / shellEscape ─────────────────────────────────────────────────

func TestShellQuote_SafeStrings(t *testing.T) {
	cases := []string{"echo", "--flag", "value", "/usr/bin/sh", "123"}
	for _, s := range cases {
		got := shellQuote(s)
		if got != s {
			t.Errorf("shellQuote(%q) = %q; safe string should be unchanged", s, got)
		}
	}
}

func TestShellQuote_StringWithSpaces(t *testing.T) {
	got := shellQuote("hello world")
	if got != "'hello world'" {
		t.Errorf("shellQuote(%q) = %q, want %q", "hello world", got, "'hello world'")
	}
}

func TestShellQuote_StringWithSingleQuote(t *testing.T) {
	got := shellQuote("it's fine")
	// Expected: 'it'\''s fine'
	want := `'it'\''s fine'`
	if got != want {
		t.Errorf("shellQuote(%q) = %q, want %q", "it's fine", got, want)
	}
}

func TestShellQuote_DollarSign(t *testing.T) {
	got := shellQuote("$SECRET")
	if got != "'$SECRET'" {
		t.Errorf("shellQuote(%q) = %q, want %q", "$SECRET", got, "'$SECRET'")
	}
}

func TestShellEscape_PreservesArgOrder(t *testing.T) {
	got := shellEscape("echo", []string{"a", "b c", "d"})
	// "a" and "d" are safe, "b c" gets quoted
	want := "echo a 'b c' d"
	if got != want {
		t.Errorf("shellEscape = %q, want %q", got, want)
	}
}
