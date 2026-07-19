package services

import (
	"testing"

	"github.com/AxeForging/aigate/domain"
)

func TestAddDenyRule_Read(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{}

	err := svc.AddDenyRule(cfg, domain.RuleTypeRead, []string{".env", "secrets/"})
	if err != nil {
		t.Fatalf("AddDenyRule() error = %v", err)
	}
	if len(cfg.DenyRead) != 2 {
		t.Errorf("DenyRead len = %d, want 2", len(cfg.DenyRead))
	}
}

func TestAddDenyRule_Exec(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{}

	err := svc.AddDenyRule(cfg, domain.RuleTypeExec, []string{"curl", "wget"})
	if err != nil {
		t.Fatalf("AddDenyRule() error = %v", err)
	}
	if len(cfg.DenyExec) != 2 {
		t.Errorf("DenyExec len = %d, want 2", len(cfg.DenyExec))
	}
}

func TestAddDenyRule_Net(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{}

	err := svc.AddDenyRule(cfg, domain.RuleTypeNet, []string{"api.anthropic.com"})
	if err != nil {
		t.Fatalf("AddDenyRule() error = %v", err)
	}
	if len(cfg.AllowNet) != 1 {
		t.Errorf("AllowNet len = %d, want 1", len(cfg.AllowNet))
	}
}

func TestAddDenyRule_NoDuplicates(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{DenyRead: []string{".env"}}

	_ = svc.AddDenyRule(cfg, domain.RuleTypeRead, []string{".env", "secrets/"})
	if len(cfg.DenyRead) != 2 {
		t.Errorf("DenyRead len = %d, want 2 (no duplicates)", len(cfg.DenyRead))
	}
}

func TestAddAllowedPaths(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{}

	if err := svc.AddAllowedPaths(cfg, []string{"~/.cache", "~/.config"}); err != nil {
		t.Fatalf("AddAllowedPaths() error = %v", err)
	}
	if len(cfg.AllowedPaths) != 2 {
		t.Errorf("AllowedPaths len = %d, want 2", len(cfg.AllowedPaths))
	}

	// Duplicates are not added twice.
	if err := svc.AddAllowedPaths(cfg, []string{"~/.cache"}); err != nil {
		t.Fatalf("AddAllowedPaths() duplicate error = %v", err)
	}
	if len(cfg.AllowedPaths) != 2 {
		t.Errorf("AllowedPaths len = %d after duplicate add, want 2", len(cfg.AllowedPaths))
	}
}

func TestAddAllowedPaths_Empty(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{}
	if err := svc.AddAllowedPaths(cfg, nil); err == nil {
		t.Error("AddAllowedPaths() with no paths should error")
	}
}

func TestRemoveAllowedPaths(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{AllowedPaths: []string{"~/.cache", "~/.config"}}

	if err := svc.RemoveAllowedPaths(cfg, []string{"~/.config"}); err != nil {
		t.Fatalf("RemoveAllowedPaths() error = %v", err)
	}
	if len(cfg.AllowedPaths) != 1 || cfg.AllowedPaths[0] != "~/.cache" {
		t.Errorf("AllowedPaths = %v, want [~/.cache]", cfg.AllowedPaths)
	}

	// Removing the last entry turns scope mode off (empty list).
	if err := svc.RemoveAllowedPaths(cfg, []string{"~/.cache"}); err != nil {
		t.Fatalf("RemoveAllowedPaths() error = %v", err)
	}
	if len(cfg.AllowedPaths) != 0 {
		t.Errorf("AllowedPaths = %v, want empty", cfg.AllowedPaths)
	}
}

func TestRemoveAllowedPaths_Empty(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{}
	if err := svc.RemoveAllowedPaths(cfg, nil); err == nil {
		t.Error("RemoveAllowedPaths() with no paths should error")
	}
}

func TestListRules_IncludesAllowedPaths(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{AllowedPaths: []string{"~/.cache"}}

	rules := svc.ListRules(cfg)
	found := false
	for _, r := range rules {
		if r.Type == domain.RuleTypePath && len(r.Patterns) == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("ListRules() should include a path rule, got: %v", rules)
	}
}

func TestAddDenyRule_EmptyPatterns(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{}

	err := svc.AddDenyRule(cfg, domain.RuleTypeRead, []string{})
	if err == nil {
		t.Error("AddDenyRule() should error on empty patterns")
	}
}

func TestAddDenyRule_InvalidType(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{}

	err := svc.AddDenyRule(cfg, domain.RuleType("invalid"), []string{"foo"})
	if err == nil {
		t.Error("AddDenyRule() should error on invalid type")
	}
}

func TestRemoveRule(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{
		DenyRead: []string{".env", "secrets/", "*.pem"},
	}

	err := svc.RemoveRule(cfg, domain.RuleTypeRead, []string{".env", "*.pem"})
	if err != nil {
		t.Fatalf("RemoveRule() error = %v", err)
	}
	if len(cfg.DenyRead) != 1 {
		t.Errorf("DenyRead len = %d, want 1", len(cfg.DenyRead))
	}
	if cfg.DenyRead[0] != "secrets/" {
		t.Errorf("DenyRead[0] = %q, want %q", cfg.DenyRead[0], "secrets/")
	}
}

func TestRemoveRule_EmptyPatterns(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{}

	err := svc.RemoveRule(cfg, domain.RuleTypeRead, []string{})
	if err == nil {
		t.Error("RemoveRule() should error on empty patterns")
	}
}

func TestListRules(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{
		DenyRead: []string{".env"},
		DenyExec: []string{"curl"},
		AllowNet: []string{"api.anthropic.com"},
	}

	rules := svc.ListRules(cfg)
	if len(rules) != 3 {
		t.Errorf("ListRules() len = %d, want 3", len(rules))
	}
}

func TestListRules_Empty(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{}

	rules := svc.ListRules(cfg)
	if len(rules) != 0 {
		t.Errorf("ListRules() len = %d, want 0", len(rules))
	}
}

func TestIsCommandBlocked(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{
		DenyExec: []string{"curl", "wget", "nc"},
	}

	if !svc.IsCommandBlocked(cfg, "curl", nil) {
		t.Error("IsCommandBlocked(curl) should be true")
	}
	if svc.IsCommandBlocked(cfg, "go", nil) {
		t.Error("IsCommandBlocked(go) should be false")
	}
}

func TestIsCommandBlocked_Subcommand(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{
		DenyExec: []string{"kubectl delete", "kubectl create"},
	}

	if !svc.IsCommandBlocked(cfg, "kubectl", []string{"delete", "pod"}) {
		t.Error("IsCommandBlocked should block kubectl delete")
	}
	if !svc.IsCommandBlocked(cfg, "kubectl", []string{"-n", "default", "delete", "pod"}) {
		t.Error("IsCommandBlocked should block kubectl delete in middle of args")
	}
	if !svc.IsCommandBlocked(cfg, "kubectl", []string{"create", "deployment"}) {
		t.Error("IsCommandBlocked should block kubectl create")
	}
}

func TestIsCommandBlocked_SubcommandNotMatched(t *testing.T) {
	svc := NewRuleService()
	cfg := &domain.Config{
		DenyExec: []string{"kubectl delete"},
	}

	if svc.IsCommandBlocked(cfg, "kubectl", []string{"get", "pods"}) {
		t.Error("IsCommandBlocked should allow kubectl get when only delete is denied")
	}
	if svc.IsCommandBlocked(cfg, "kubectl", []string{"describe", "pod", "my-pod"}) {
		t.Error("IsCommandBlocked should allow kubectl describe when only delete is denied")
	}
}

func TestRemovePatterns(t *testing.T) {
	result := removePatterns([]string{"a", "b", "c", "d"}, []string{"b", "d"})
	if len(result) != 2 {
		t.Errorf("removePatterns len = %d, want 2", len(result))
	}
}

func TestRemovePatterns_NotFound(t *testing.T) {
	result := removePatterns([]string{"a", "b"}, []string{"x", "y"})
	if len(result) != 2 {
		t.Errorf("removePatterns len = %d, want 2 (nothing removed)", len(result))
	}
}
