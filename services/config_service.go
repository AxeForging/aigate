package services

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/helpers"
	"gopkg.in/yaml.v3"
)

const (
	globalConfigDir   = ".aigate"
	globalConfigFile  = "config.yaml"
	projectConfigFile = ".aigate.yaml"
)

type ConfigService struct{}

func NewConfigService() *ConfigService {
	return &ConfigService{}
}

func (s *ConfigService) GlobalConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(home, globalConfigDir, globalConfigFile), nil
}

func (s *ConfigService) GlobalConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(home, globalConfigDir), nil
}

func (s *ConfigService) LoadGlobal() (*domain.Config, error) {
	path, err := s.GlobalConfigPath()
	if err != nil {
		return nil, err
	}
	return s.loadFromFile(path)
}

func (s *ConfigService) LoadProject(workDir string) (*domain.Config, error) {
	path := filepath.Join(workDir, projectConfigFile)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	return s.loadFromFile(path)
}

func (s *ConfigService) loadFromFile(path string) (*domain.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, helpers.ErrConfigNotFound
		}
		return nil, fmt.Errorf("failed to read config %s: %w", path, err)
	}
	var cfg domain.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config %s: %w", path, err)
	}
	return &cfg, nil
}

func (s *ConfigService) SaveGlobal(cfg *domain.Config) error {
	dir, err := s.GlobalConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	path := filepath.Join(dir, globalConfigFile)
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	return nil
}

func (s *ConfigService) Merge(global, project *domain.Config) *domain.Config {
	if project == nil {
		return global
	}
	merged := *global
	if len(project.DenyRead) > 0 {
		merged.DenyRead = appendUnique(merged.DenyRead, project.DenyRead)
	}
	if len(project.DenyExec) > 0 {
		merged.DenyExec = appendUnique(merged.DenyExec, project.DenyExec)
	}
	if len(project.AllowNet) > 0 {
		merged.AllowNet = appendUnique(merged.AllowNet, project.AllowNet)
	}
	if project.ResourceLimits.MaxMemory != "" {
		merged.ResourceLimits.MaxMemory = project.ResourceLimits.MaxMemory
	}
	if project.ResourceLimits.MaxCPUPercent > 0 {
		merged.ResourceLimits.MaxCPUPercent = project.ResourceLimits.MaxCPUPercent
	}
	if project.ResourceLimits.MaxPIDs > 0 {
		merged.ResourceLimits.MaxPIDs = project.ResourceLimits.MaxPIDs
	}
	return &merged
}

func (s *ConfigService) InitDefaultConfig() *domain.Config {
	return &domain.Config{
		Group: "ai-agents",
		User:  "ai-runner",
		DenyRead: []string{
			".env",
			".env.*",
			"secrets/",
			"credentials/",
			"~/.ssh/",
			"*.pem",
			"*.key",
			"*.p12",
			"~/.aws/",
			"~/.gcloud/",
			"~/.kube/config",
			"~/.npmrc",
			"~/.pypirc",
			"terraform.tfstate",
			"*.tfvars",
		},
		DenyExec: []string{
			"curl",
			"wget",
			"nc",
			"ncat",
			"netcat",
			"ssh",
			"scp",
			"rsync",
			"ftp",
			"kubectl delete",
			"kubectl exec",
		},
		AllowNet: []string{
			"api.anthropic.com",
			"api.openai.com",
			"api.github.com",
			"registry.npmjs.org",
			"proxy.golang.org",
		},
		ResourceLimits: domain.ResourceLimits{
			MaxMemory:     "4G",
			MaxCPUPercent: 80,
			MaxPIDs:       1000,
		},
	}
}

func (s *ConfigService) ConfigExists() bool {
	path, err := s.GlobalConfigPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

func (s *ConfigService) RemoveConfig() error {
	dir, err := s.GlobalConfigDir()
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

func appendUnique(base, extra []string) []string {
	seen := make(map[string]bool, len(base))
	for _, v := range base {
		seen[v] = true
	}
	for _, v := range extra {
		if !seen[v] {
			base = append(base, v)
			seen[v] = true
		}
	}
	return base
}
