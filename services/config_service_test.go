package services

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AxeForging/aigate/domain"
	"gopkg.in/yaml.v3"
)

func TestInitDefaultConfig(t *testing.T) {
	svc := NewConfigService()
	cfg := svc.InitDefaultConfig()

	if cfg.Group != "ai-agents" {
		t.Errorf("Group = %q, want %q", cfg.Group, "ai-agents")
	}
	if cfg.User != "ai-runner" {
		t.Errorf("User = %q, want %q", cfg.User, "ai-runner")
	}
	if len(cfg.DenyRead) == 0 {
		t.Error("DenyRead should have default entries")
	}
	if len(cfg.DenyExec) == 0 {
		t.Error("DenyExec should have default entries")
	}
	if len(cfg.AllowNet) == 0 {
		t.Error("AllowNet should have default entries")
	}
	if cfg.ResourceLimits.MaxMemory != "4G" {
		t.Errorf("MaxMemory = %q, want %q", cfg.ResourceLimits.MaxMemory, "4G")
	}
}

func TestSaveAndLoadGlobal(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	svc := NewConfigService()
	cfg := svc.InitDefaultConfig()

	if err := svc.SaveGlobal(cfg); err != nil {
		t.Fatalf("SaveGlobal() error = %v", err)
	}

	loaded, err := svc.LoadGlobal()
	if err != nil {
		t.Fatalf("LoadGlobal() error = %v", err)
	}

	if loaded.Group != cfg.Group {
		t.Errorf("Group = %q, want %q", loaded.Group, cfg.Group)
	}
	if len(loaded.DenyRead) != len(cfg.DenyRead) {
		t.Errorf("DenyRead len = %d, want %d", len(loaded.DenyRead), len(cfg.DenyRead))
	}
}

func TestLoadProject(t *testing.T) {
	tmpDir := t.TempDir()
	projectCfg := domain.Config{
		DenyRead: []string{"terraform.tfstate", "vault-token"},
		AllowNet: []string{"registry.terraform.io"},
	}
	data, _ := yaml.Marshal(&projectCfg)
	_ = os.WriteFile(filepath.Join(tmpDir, ".aigate.yaml"), data, 0o644)

	svc := NewConfigService()
	loaded, err := svc.LoadProject(tmpDir)
	if err != nil {
		t.Fatalf("LoadProject() error = %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadProject() returned nil")
	}
	if len(loaded.DenyRead) != 2 {
		t.Errorf("DenyRead len = %d, want 2", len(loaded.DenyRead))
	}
}

func TestLoadProjectMissing(t *testing.T) {
	tmpDir := t.TempDir()
	svc := NewConfigService()
	loaded, err := svc.LoadProject(tmpDir)
	if err != nil {
		t.Fatalf("LoadProject() error = %v", err)
	}
	if loaded != nil {
		t.Error("LoadProject() should return nil for missing project config")
	}
}

func TestMerge(t *testing.T) {
	svc := NewConfigService()
	global := &domain.Config{
		Group:    "ai-agents",
		User:     "ai-runner",
		DenyRead: []string{".env", ".ssh/"},
		DenyExec: []string{"curl"},
		AllowNet: []string{"api.anthropic.com"},
		ResourceLimits: domain.ResourceLimits{
			MaxMemory: "4G",
		},
	}
	project := &domain.Config{
		DenyRead: []string{"terraform.tfstate", ".env"}, // .env is duplicate
		AllowNet: []string{"registry.terraform.io"},
		ResourceLimits: domain.ResourceLimits{
			MaxMemory: "8G",
		},
	}

	merged := svc.Merge(global, project)

	// Should have global + project unique entries
	if len(merged.DenyRead) != 3 {
		t.Errorf("DenyRead len = %d, want 3 (.env, .ssh/, terraform.tfstate)", len(merged.DenyRead))
	}
	if merged.ResourceLimits.MaxMemory != "8G" {
		t.Errorf("MaxMemory = %q, want %q (project override)", merged.ResourceLimits.MaxMemory, "8G")
	}
	// Global should not be mutated
	if global.ResourceLimits.MaxMemory != "4G" {
		t.Error("Merge should not mutate the global config")
	}
}

func TestMergeNilProject(t *testing.T) {
	svc := NewConfigService()
	global := &domain.Config{
		Group: "ai-agents",
		User:  "ai-runner",
	}
	merged := svc.Merge(global, nil)
	if merged.Group != "ai-agents" {
		t.Error("Merge with nil project should return global")
	}
}

func TestConfigExists(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	svc := NewConfigService()
	if svc.ConfigExists() {
		t.Error("ConfigExists() should return false before init")
	}

	cfg := svc.InitDefaultConfig()
	_ = svc.SaveGlobal(cfg)

	if !svc.ConfigExists() {
		t.Error("ConfigExists() should return true after save")
	}
}

func TestAppendUnique(t *testing.T) {
	base := []string{"a", "b", "c"}
	extra := []string{"b", "c", "d", "e"}
	result := appendUnique(base, extra)
	if len(result) != 5 {
		t.Errorf("appendUnique len = %d, want 5", len(result))
	}
}

func TestInitDefaultConfig_TildePrefixes(t *testing.T) {
	svc := NewConfigService()
	cfg := svc.InitDefaultConfig()

	tildePatterns := []string{"~/.ssh/", "~/.aws/", "~/.gcloud/", "~/.kube/config", "~/.npmrc", "~/.pypirc"}
	for _, want := range tildePatterns {
		found := false
		for _, got := range cfg.DenyRead {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DenyRead missing %q", want)
		}
	}

	// These should NOT have tilde prefix (they are project-relative)
	projectPatterns := []string{".env", ".env.*", "secrets/", "credentials/"}
	for _, want := range projectPatterns {
		found := false
		for _, got := range cfg.DenyRead {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DenyRead missing project-relative pattern %q", want)
		}
	}
}

func TestInitDefaultConfig_SubcommandExamples(t *testing.T) {
	svc := NewConfigService()
	cfg := svc.InitDefaultConfig()

	subcommandExamples := []string{"kubectl delete", "kubectl exec"}
	for _, want := range subcommandExamples {
		found := false
		for _, got := range cfg.DenyExec {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DenyExec missing subcommand example %q", want)
		}
	}

	// Also check that full command blocks are still present
	fullCommands := []string{"curl", "wget", "nc", "ssh", "scp"}
	for _, want := range fullCommands {
		found := false
		for _, got := range cfg.DenyExec {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DenyExec missing full command %q", want)
		}
	}
}
