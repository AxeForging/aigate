//go:build linux

package services

import (
	"encoding/base64"
	"fmt"
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

func TestBuildNetFilterScript(t *testing.T) {
	profile := domain.SandboxProfile{
		Config: domain.Config{
			DenyRead: []string{"/nonexistent/path/for/test"},
		},
		WorkDir: "/tmp",
	}

	t.Run("resolves hosts inside namespace via getent", func(t *testing.T) {
		script := buildNetFilterScript(
			[]string{"api.anthropic.com", "1.2.3.4"},
			[]string{"8.8.8.8"},
			profile, "echo", []string{"hello"},
		)
		// Hostnames should be resolved inside the namespace via getent ahostsv4
		if !strings.Contains(script, "getent ahostsv4 \"api.anthropic.com\"") {
			t.Error("script should resolve api.anthropic.com inside namespace")
		}
		// Raw IPs are also passed through getent (getent handles IPs fine)
		if !strings.Contains(script, "getent ahostsv4 \"1.2.3.4\"") {
			t.Error("script should include raw IP 1.2.3.4 via getent")
		}
		if !strings.Contains(script, "iptables -A OUTPUT -j REJECT") {
			t.Error("script should contain final REJECT rule")
		}
	})

	t.Run("contains DNS rules", func(t *testing.T) {
		script := buildNetFilterScript(
			[]string{"example.com"},
			[]string{"8.8.8.8", "1.1.1.1"},
			profile, "echo", []string{"hello"},
		)
		if !strings.Contains(script, "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT") {
			t.Error("script should allow UDP DNS")
		}
		if !strings.Contains(script, "iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT") {
			t.Error("script should allow TCP DNS")
		}
		if !strings.Contains(script, "iptables -A OUTPUT -d 8.8.8.8 -j ACCEPT") {
			t.Error("script should allow DNS server 8.8.8.8")
		}
		if !strings.Contains(script, "iptables -A OUTPUT -d 1.1.1.1 -j ACCEPT") {
			t.Error("script should allow DNS server 1.1.1.1")
		}
	})

	t.Run("contains resolv.conf fix", func(t *testing.T) {
		script := buildNetFilterScript(nil, nil, profile, "echo", nil)
		if !strings.Contains(script, "nameserver 10.0.2.3") {
			t.Error("script should set resolv.conf to slirp4netns DNS")
		}
	})

	t.Run("contains wait for tap0", func(t *testing.T) {
		script := buildNetFilterScript(nil, nil, profile, "echo", nil)
		if !strings.Contains(script, "ip addr show tap0") {
			t.Error("script should wait for tap0 interface")
		}
	})

	t.Run("waits for real DNS before resolving hosts", func(t *testing.T) {
		script := buildNetFilterScript([]string{"example.com", "other.com"}, nil, profile, "echo", nil)
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
		script := buildNetFilterScript([]string{"example.com"}, nil, profile, "echo", nil)
		if !strings.Contains(script, "_attempt in 1 2 3") {
			t.Error("should retry getent resolution")
		}
	})

	t.Run("contains target command", func(t *testing.T) {
		script := buildNetFilterScript(nil, nil, profile, "mycommand", []string{"--flag", "value"})
		if !strings.Contains(script, "exec mycommand --flag value") {
			t.Errorf("script should contain exec of target command, got:\n%s", script)
		}
	})
}

func TestRunSandboxedDispatch(t *testing.T) {
	t.Run("empty AllowNet uses runUnshare", func(t *testing.T) {
		mock := newMockExecutor()
		p := &LinuxPlatform{exec: mock}
		profile := domain.SandboxProfile{
			Config:  domain.Config{AllowNet: nil},
			WorkDir: "/tmp",
		}
		_ = p.RunSandboxed(profile, "echo", []string{"hello"})
		if mock.callCount() == 0 {
			t.Fatal("expected executor to be called")
		}
		last := mock.lastCall()
		if last.Name != "unshare" {
			t.Errorf("expected unshare call, got %q", last.Name)
		}
		// Verify no --net flag (runUnshare doesn't add it)
		for _, arg := range last.Args {
			if arg == "--net" {
				t.Error("runUnshare should not pass --net flag")
			}
		}
	})

	t.Run("AllowNet set without slirp4netns warns and falls back to runUnshare", func(t *testing.T) {
		// This test works because slirp4netns may or may not be installed.
		// If it IS installed, it will try runWithNetFilter which won't use the mock executor.
		// We test the warning path by checking that when the mock executor is called,
		// --net is not passed (meaning runUnshare was used).
		// In CI without slirp4netns, this tests the fallback path.
		if hasSlirp4netns() {
			t.Skip("slirp4netns is installed; this test covers the fallback path only")
		}
		mock := newMockExecutor()
		p := &LinuxPlatform{exec: mock}
		profile := domain.SandboxProfile{
			Config:  domain.Config{AllowNet: []string{"example.com"}},
			WorkDir: "/tmp",
		}
		_ = p.RunSandboxed(profile, "echo", []string{"hello"})
		if mock.callCount() == 0 {
			t.Fatal("expected executor to be called via runUnshare fallback")
		}
		last := mock.lastCall()
		if last.Name != "unshare" {
			t.Errorf("expected unshare call, got %q", last.Name)
		}
		for _, arg := range last.Args {
			if arg == "--net" {
				t.Error("fallback runUnshare should not pass --net flag")
			}
		}
	})
}

func TestBuildOrchestrationScript(t *testing.T) {
	inner := "echo hello world\n"

	t.Run("embeds inner script via base64", func(t *testing.T) {
		script := buildOrchestrationScript(inner)
		encoded := base64.StdEncoding.EncodeToString([]byte(inner))
		if !strings.Contains(script, encoded) {
			t.Error("orchestration script should contain base64-encoded inner script")
		}
	})

	t.Run("preserves stdin via fd 3", func(t *testing.T) {
		script := buildOrchestrationScript(inner)
		if !strings.Contains(script, "exec 3<&0") {
			t.Error("should save stdin to fd 3")
		}
		if !strings.Contains(script, "<&3") {
			t.Error("should redirect fd 3 to sandbox stdin")
		}
	})

	t.Run("uses two-layer unshare", func(t *testing.T) {
		script := buildOrchestrationScript(inner)
		// Inner unshare should create net namespace (outer only creates user ns)
		if !strings.Contains(script, "unshare --net --mount --pid --fork") {
			t.Error("inner unshare should create net/mount/pid namespaces")
		}
	})

	t.Run("runs slirp4netns inside user namespace", func(t *testing.T) {
		script := buildOrchestrationScript(inner)
		if !strings.Contains(script, "slirp4netns --configure $_SANDBOX_PID tap0") {
			t.Error("should launch slirp4netns with sandbox PID")
		}
	})

	t.Run("waits for namespace and cleans up", func(t *testing.T) {
		script := buildOrchestrationScript(inner)
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

func TestGetSystemDNS(t *testing.T) {
	servers := getSystemDNS()
	if len(servers) == 0 {
		t.Fatal("getSystemDNS() should return at least one server")
	}
	// Should not contain localhost addresses
	for _, s := range servers {
		if strings.HasPrefix(s, "127.") {
			t.Errorf("getSystemDNS() should not return localhost address %q", s)
		}
	}
}

func TestParseDNSFromFile(t *testing.T) {
	tmpFile := t.TempDir() + "/resolv.conf"

	t.Run("parses nameserver lines", func(t *testing.T) {
		writeTestFile(t, tmpFile, "nameserver 8.8.8.8\nnameserver 1.1.1.1\n")
		servers := parseDNSFromFile(tmpFile)
		if len(servers) != 2 {
			t.Fatalf("expected 2 servers, got %d: %v", len(servers), servers)
		}
		if servers[0] != "8.8.8.8" || servers[1] != "1.1.1.1" {
			t.Errorf("unexpected servers: %v", servers)
		}
	})

	t.Run("skips 127.x addresses", func(t *testing.T) {
		writeTestFile(t, tmpFile, "nameserver 127.0.0.53\nnameserver 8.8.4.4\n")
		servers := parseDNSFromFile(tmpFile)
		if len(servers) != 1 || servers[0] != "8.8.4.4" {
			t.Errorf("expected [8.8.4.4], got %v", servers)
		}
	})

	t.Run("returns nil for missing file", func(t *testing.T) {
		servers := parseDNSFromFile("/nonexistent/resolv.conf")
		if servers != nil {
			t.Errorf("expected nil for missing file, got %v", servers)
		}
	})

	t.Run("skips comments and blank lines", func(t *testing.T) {
		writeTestFile(t, tmpFile, "# comment\n\nnameserver 9.9.9.9\nsearch example.com\n")
		servers := parseDNSFromFile(tmpFile)
		if len(servers) != 1 || servers[0] != "9.9.9.9" {
			t.Errorf("expected [9.9.9.9], got %v", servers)
		}
	})
}
