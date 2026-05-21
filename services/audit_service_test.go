package services

import (
	"path/filepath"
	"testing"

	"github.com/AxeForging/aigate/domain"
)

func TestAuditService_LogAndRecent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	configSvc := NewConfigService()
	auditSvc := NewAuditService(configSvc)

	profile := domain.SandboxProfile{WorkDir: "/tmp/project"}
	auditSvc.LogRunStarted(profile, "echo", []string{"hello"})
	auditSvc.LogBlocked(profile, "curl", []string{"example.test"}, "deny_exec", "preflight", "curl is blocked")

	events, err := auditSvc.Recent(10)
	if err != nil {
		t.Fatalf("Recent() error = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("Recent() returned %d events, want 2", len(events))
	}
	if events[0].Kind != "blocked" {
		t.Fatalf("newest event kind = %q, want blocked", events[0].Kind)
	}
	if events[0].Command != "curl example.test" {
		t.Fatalf("blocked command = %q", events[0].Command)
	}

	path, err := auditSvc.Path()
	if err != nil {
		t.Fatalf("Path() error = %v", err)
	}
	wantSuffix := filepath.Join(".aigate", "audit.jsonl")
	if len(path) < len(wantSuffix) || filepath.ToSlash(path[len(path)-len(wantSuffix):]) != filepath.ToSlash(wantSuffix) {
		t.Fatalf("Path() = %q, want suffix %q", path, wantSuffix)
	}
}
