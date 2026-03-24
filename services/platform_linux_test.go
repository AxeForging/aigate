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
	script := buildNetFilterScript(nil, nil, profile, "echo", nil)
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
	if !strings.Contains(shellCmd, "exec echo hello") {
		t.Error("runUnshare should exec the target command")
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

	script := buildNetFilterScript(nil, nil, profile, "echo", []string{"hello"})
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
