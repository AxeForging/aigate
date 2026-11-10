package services

import (
	"errors"
	"io"
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
func (m *mockPlatform) RunSandboxed(_ domain.SandboxProfile, cmd string, args []string, _, _ io.Writer) error {
	m.runSandboxedCalled = true
	m.runSandboxedCmd = cmd
	m.runSandboxedArgs = args
	return m.runSandboxedErr
}

// TestRunnerService_DenyExec: deny_exec stops a command before any sandbox
// starts — by name, by full path, or by subcommand anywhere in the args —
// and lets everything else through to the sandbox unchanged.
func TestRunnerService_DenyExec(t *testing.T) {
	cases := []struct {
		name    string
		deny    []string
		cmd     string
		args    []string
		blocked bool
	}{
		{"denied command", []string{"curl", "wget"}, "curl", []string{"-s", "http://example.com"}, true},
		{"denied command by full path", []string{"curl"}, "/usr/bin/curl", []string{"-s", "http://example.com"}, true},
		{"other command allowed", []string{"curl", "wget"}, "go", []string{"build", "."}, false},
		{"denied subcommand", []string{"kubectl delete"}, "kubectl", []string{"delete", "pod", "my-pod"}, true},
		{"denied subcommand after flags", []string{"kubectl delete"}, "kubectl", []string{"-n", "default", "delete", "pod", "my-pod"}, true},
		{"other subcommand allowed", []string{"kubectl delete"}, "kubectl", []string{"get", "pods"}, false},
		{"whole command denied covers every subcommand", []string{"kubectl"}, "kubectl", []string{"get", "pods"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mock := &mockPlatform{}
			err := NewRunnerService(mock).Run(domain.SandboxProfile{Config: domain.Config{DenyExec: c.deny}}, c.cmd, c.args)
			if c.blocked {
				if !errors.Is(err, helpers.ErrCommandBlocked) {
					t.Errorf("Run() error = %v, want ErrCommandBlocked", err)
				}
				if mock.runSandboxedCalled {
					t.Error("a blocked command must not reach the sandbox")
				}
				return
			}
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if !mock.runSandboxedCalled || mock.runSandboxedCmd != c.cmd {
				t.Errorf("sandbox should run %q, got called=%v cmd=%q", c.cmd, mock.runSandboxedCalled, mock.runSandboxedCmd)
			}
		})
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
