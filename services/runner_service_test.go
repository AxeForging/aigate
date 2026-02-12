package services

import (
	"errors"
	"testing"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/helpers"
)

type mockPlatform struct {
	runSandboxedCalled bool
	runSandboxedCmd    string
	runSandboxedArgs   []string
	runSandboxedErr    error
}

func (m *mockPlatform) Name() string                                  { return "mock" }
func (m *mockPlatform) CreateGroup(string) error                      { return nil }
func (m *mockPlatform) CreateUser(string, string) error               { return nil }
func (m *mockPlatform) DeleteGroup(string) error                      { return nil }
func (m *mockPlatform) DeleteUser(string) error                       { return nil }
func (m *mockPlatform) GroupExists(string) (bool, error)              { return false, nil }
func (m *mockPlatform) UserExists(string) (bool, error)               { return false, nil }
func (m *mockPlatform) SetFileACLDeny(string, []string, string) error { return nil }
func (m *mockPlatform) RemoveFileACL(string, []string, string) error  { return nil }
func (m *mockPlatform) ListACLs(string) ([]string, error)             { return nil, nil }
func (m *mockPlatform) RunSandboxed(_ domain.SandboxProfile, cmd string, args []string) error {
	m.runSandboxedCalled = true
	m.runSandboxedCmd = cmd
	m.runSandboxedArgs = args
	return m.runSandboxedErr
}

func TestRunnerService_BlockedCommand(t *testing.T) {
	mock := &mockPlatform{}
	svc := NewRunnerService(mock)
	profile := domain.SandboxProfile{
		Config: domain.Config{
			DenyExec: []string{"curl", "wget"},
		},
	}

	err := svc.Run(profile, "curl", []string{"-s", "http://example.com"})
	if err == nil {
		t.Fatal("Run() should error for blocked command")
	}
	if !errors.Is(err, helpers.ErrCommandBlocked) {
		t.Errorf("Run() error = %v, want ErrCommandBlocked", err)
	}
	if mock.runSandboxedCalled {
		t.Error("RunSandboxed should not be called for blocked command")
	}
}

func TestRunnerService_AllowedCommand(t *testing.T) {
	mock := &mockPlatform{}
	svc := NewRunnerService(mock)
	profile := domain.SandboxProfile{
		Config: domain.Config{
			DenyExec: []string{"curl", "wget"},
		},
	}

	err := svc.Run(profile, "go", []string{"build", "."})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !mock.runSandboxedCalled {
		t.Error("RunSandboxed should be called for allowed command")
	}
	if mock.runSandboxedCmd != "go" {
		t.Errorf("RunSandboxed cmd = %q, want %q", mock.runSandboxedCmd, "go")
	}
}

func TestRunnerService_BlockedByPath(t *testing.T) {
	mock := &mockPlatform{}
	svc := NewRunnerService(mock)
	profile := domain.SandboxProfile{
		Config: domain.Config{
			DenyExec: []string{"curl"},
		},
	}

	err := svc.Run(profile, "/usr/bin/curl", []string{"-s", "http://example.com"})
	if err == nil {
		t.Fatal("Run() should block /usr/bin/curl when 'curl' is denied")
	}
}

func TestRunnerService_SandboxError(t *testing.T) {
	mock := &mockPlatform{runSandboxedErr: errors.New("sandbox failed")}
	svc := NewRunnerService(mock)
	profile := domain.SandboxProfile{
		Config: domain.Config{},
	}

	err := svc.Run(profile, "echo", []string{"hello"})
	if err == nil {
		t.Fatal("Run() should propagate sandbox errors")
	}
}

func TestRunnerService_BlockedSubcommand(t *testing.T) {
	mock := &mockPlatform{}
	svc := NewRunnerService(mock)
	profile := domain.SandboxProfile{
		Config: domain.Config{
			DenyExec: []string{"kubectl delete"},
		},
	}

	err := svc.Run(profile, "kubectl", []string{"delete", "pod", "my-pod"})
	if err == nil {
		t.Fatal("Run() should block kubectl delete")
	}
	if !errors.Is(err, helpers.ErrCommandBlocked) {
		t.Errorf("Run() error = %v, want ErrCommandBlocked", err)
	}
	if mock.runSandboxedCalled {
		t.Error("RunSandboxed should not be called for blocked subcommand")
	}
}

func TestRunnerService_AllowedSubcommand(t *testing.T) {
	mock := &mockPlatform{}
	svc := NewRunnerService(mock)
	profile := domain.SandboxProfile{
		Config: domain.Config{
			DenyExec: []string{"kubectl delete"},
		},
	}

	err := svc.Run(profile, "kubectl", []string{"get", "pods"})
	if err != nil {
		t.Fatalf("Run() error = %v, want nil for allowed subcommand", err)
	}
	if !mock.runSandboxedCalled {
		t.Error("RunSandboxed should be called for allowed subcommand")
	}
}

func TestRunnerService_SubcommandInMiddleOfArgs(t *testing.T) {
	mock := &mockPlatform{}
	svc := NewRunnerService(mock)
	profile := domain.SandboxProfile{
		Config: domain.Config{
			DenyExec: []string{"kubectl delete"},
		},
	}

	err := svc.Run(profile, "kubectl", []string{"-n", "default", "delete", "pod", "my-pod"})
	if err == nil {
		t.Fatal("Run() should block kubectl delete even when subcommand is in middle of args")
	}
	if !errors.Is(err, helpers.ErrCommandBlocked) {
		t.Errorf("Run() error = %v, want ErrCommandBlocked", err)
	}
}

func TestRunnerService_FullCommandBlockStillWorks(t *testing.T) {
	mock := &mockPlatform{}
	svc := NewRunnerService(mock)
	profile := domain.SandboxProfile{
		Config: domain.Config{
			DenyExec: []string{"kubectl"},
		},
	}

	err := svc.Run(profile, "kubectl", []string{"get", "pods"})
	if err == nil {
		t.Fatal("Run() should block all kubectl usage when full command is denied")
	}
	if !errors.Is(err, helpers.ErrCommandBlocked) {
		t.Errorf("Run() error = %v, want ErrCommandBlocked", err)
	}
}
