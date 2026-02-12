package domain

// RuleType identifies the category of sandbox rule.
type RuleType string

const (
	RuleTypeRead RuleType = "read"
	RuleTypeExec RuleType = "exec"
	RuleTypeNet  RuleType = "net"
)

// Rule represents a single sandbox restriction.
type Rule struct {
	Type     RuleType `yaml:"type"`
	Patterns []string `yaml:"patterns"`
}

// ResourceLimits defines cgroup-enforced resource constraints.
type ResourceLimits struct {
	MaxMemory     string `yaml:"max_memory"`
	MaxCPUPercent int    `yaml:"max_cpu_percent"`
	MaxPIDs       int    `yaml:"max_pids"`
}

// Config represents the aigate configuration file.
type Config struct {
	Group          string         `yaml:"group"`
	User           string         `yaml:"user"`
	DenyRead       []string       `yaml:"deny_read"`
	DenyExec       []string       `yaml:"deny_exec"`
	AllowNet       []string       `yaml:"allow_net"`
	ResourceLimits ResourceLimits `yaml:"resource_limits"`
}

// SandboxProfile is the fully resolved configuration used to launch a sandboxed process.
type SandboxProfile struct {
	Config  Config
	WorkDir string
}
