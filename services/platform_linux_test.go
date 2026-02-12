//go:build linux

package services

import (
	"fmt"
	"os"
	"testing"
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
