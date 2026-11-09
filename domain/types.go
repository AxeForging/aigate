package domain

// RuleType identifies the category of sandbox rule.
type RuleType string

const (
	RuleTypeRead RuleType = "read"
	RuleTypeExec RuleType = "exec"
	RuleTypeNet  RuleType = "net"
	RuleTypePath RuleType = "path"
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

// MaskPattern defines a single custom output masking rule.
type MaskPattern struct {
	Regex           string `yaml:"regex"`
	ShowPrefix      int    `yaml:"show_prefix"`
	CaseInsensitive bool   `yaml:"case_insensitive"`
}

// MaskStdout configures output redaction applied to sandboxed process stdout/stderr.
// Presets are named built-in patterns for common secret formats.
// Patterns are additional user-defined regexes.
type MaskStdout struct {
	Presets  []string      `yaml:"presets"`
	Patterns []MaskPattern `yaml:"patterns"`
}

// Config represents the aigate configuration file.
// AllowedPaths, when non-empty, activates scope mode: inside the sandbox only
// the working directory and the listed paths are accessible (read + write)
// under $HOME — everything else in $HOME is hidden entirely. System paths
// outside $HOME stay read-only (required to execute anything). Empty means
// legacy behavior (home fully accessible).
type Config struct {
	Group          string         `yaml:"group"`
	User           string         `yaml:"user"`
	DenyRead       []string       `yaml:"deny_read"`
	DenyExec       []string       `yaml:"deny_exec"`
	AllowNet       []string       `yaml:"allow_net"`
	AllowedPaths   []string       `yaml:"allowed_paths"`
	ResourceLimits ResourceLimits `yaml:"resource_limits"`
	MaskStdout     MaskStdout     `yaml:"mask_stdout"`

	// Identities are only read from the global config; a project
	// .aigate.yaml may not set them (a cloned repo must not pick one).
	DefaultIdentity  string              `yaml:"default_identity,omitempty"`
	Identities       map[string]Identity `yaml:"identities,omitempty"`
	IdentityBindings map[string]string   `yaml:"identity_bindings,omitempty"`

	// Judge is an optional decision gate on agent tool calls. Global config
	// only: a project config must not be able to switch it off.
	Judge JudgeConfig `yaml:"judge,omitempty"`
}

// JudgeConfig configures the optional decision gate. It can only block or
// ask, never allow anything the sandbox would not.
type JudgeConfig struct {
	Enabled       bool           `yaml:"enabled"`
	Chain         []string       `yaml:"chain,omitempty"`
	EscalateBelow float64        `yaml:"escalate_below,omitempty"`
	DenyAbove     float64        `yaml:"deny_above,omitempty"`
	AskAbove      float64        `yaml:"ask_above,omitempty"`
	Timeout       string         `yaml:"timeout,omitempty"`
	ExcerptBytes  int            `yaml:"excerpt_bytes,omitempty"`
	Providers     JudgeProviders `yaml:"providers,omitempty"`
}

// JudgeProviders names the env vars holding provider credentials; values
// are never stored in config.
type JudgeProviders struct {
	Cloudflare CloudflareProvider `yaml:"cloudflare,omitempty"`
	Jev        JevProvider        `yaml:"jev,omitempty"`
}

type CloudflareProvider struct {
	AccountEnv string `yaml:"account_env,omitempty"`
	TokenEnv   string `yaml:"token_env,omitempty"`
}

type JevProvider struct {
	TokenEnv string `yaml:"token_env,omitempty"`
}

// GitAuthor is the commit author/committer used inside an identity's sandbox.
type GitAuthor struct {
	Name  string `yaml:"name"`
	Email string `yaml:"email"`
}

// Identity is one account set: Claude login, gh login, git author, ssh key.
// Only its own dirs are mounted when a sandbox runs under it.
type Identity struct {
	ClaudeDir    string    `yaml:"claude_dir"`
	GhDir        string    `yaml:"gh_dir"`
	Git          GitAuthor `yaml:"git"`
	SSHKey       string    `yaml:"ssh_key,omitempty"`
	AllowedPaths []string  `yaml:"allowed_paths,omitempty"`
	PassEnv      []string  `yaml:"pass_env,omitempty"`
}

// ResolvedIdentity is the identity selected for a run, with paths expanded
// to absolute form and the reason it was chosen (shown to the user).
type ResolvedIdentity struct {
	Name   string
	Reason string
	Identity
}

// SandboxProfile is the fully resolved configuration used to launch a sandboxed process.
type SandboxProfile struct {
	Config   Config
	WorkDir  string
	Identity *ResolvedIdentity // nil when no identity is active
}
