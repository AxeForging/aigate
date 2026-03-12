package actions

import (
	"fmt"

	"github.com/urfave/cli"
)

type HelpAIAction struct{}

func NewHelpAIAction() *HelpAIAction {
	return &HelpAIAction{}
}

func (a *HelpAIAction) Execute(c *cli.Context) error {
	fmt.Print(helpAIText)
	return nil
}

const helpAIText = `aigate — AI Agent Usage Examples
=================================

SETUP (one-time)
  sudo aigate setup              # Create OS group "ai-agents" and user "ai-runner"
  aigate init                    # Create default config at ~/.aigate/config.yaml
  aigate init --force            # Re-create config (overwrites existing)

FILE RESTRICTIONS (deny read)
  aigate deny read .env                    # Block a single file
  aigate deny read .env secrets/ *.pem     # Block multiple files/dirs/globs
  aigate deny read .aws/ .gcloud/ .kube/   # Block cloud credential dirs
  aigate deny read terraform.tfstate *.tfvars  # Block Terraform state/secrets
  aigate allow read .env                   # Remove a deny rule

COMMAND RESTRICTIONS (deny exec)
  aigate deny exec curl wget               # Block network tools
  aigate deny exec ssh scp rsync           # Block remote access tools
  aigate deny exec nc ncat netcat          # Block raw socket tools
  aigate allow exec curl                   # Remove a deny rule

NETWORK RESTRICTIONS (deny net)
  aigate deny net --except api.anthropic.com --except api.github.com
      # Block all outbound except listed domains
  aigate allow net api.github.com          # Remove a domain from allow list

RUNNING SANDBOXED
  aigate run -- claude                     # Run Claude in sandbox
  aigate run -- aider                      # Run any AI tool
  aigate run -- bash -c "npm test"         # Run arbitrary commands
  aigate run --config ./project.yaml -- claude  # Use project-specific config
  aigate run --verbose -- claude           # Show debug logging

CHECKING STATUS
  aigate status                            # Show all rules, group/user, limits

CONFIGURATION
  Global config:   ~/.aigate/config.yaml
  Project config:  .aigate.yaml (in project root, merged with global)

  Project configs add to global rules (deny_read, deny_exec, allow_net are
  unioned). Resource limits in project config override global values.

  Example ~/.aigate/config.yaml:
    group: ai-agents
    user: ai-runner
    deny_read:
      - .env
      - .env.*
      - secrets/
      - credentials/
      - .ssh/
      - "*.pem"
      - "*.key"
    deny_exec:
      - curl
      - wget
      - ssh
    allow_net:
      - api.anthropic.com
      - api.openai.com
      - api.github.com
      - registry.npmjs.org
      - proxy.golang.org
    resource_limits:
      max_memory: 4G
      max_cpu_percent: 80
      max_pids: 1000
    mask_stdout:
      presets:
        - openai
        - anthropic
        - aws_key
        - github
        - bearer

  Example .aigate.yaml (project-level, adds to global):
    deny_read:
      - .stripe-key
      - production.env
    allow_net:
      - api.stripe.com
    mask_stdout:
      presets:
        - openai
        - bearer
      patterns:
        - regex: "myapp-secret-[a-z0-9]+"
          show_prefix: 0
          case_insensitive: false
        - regex: "(?:db_pass|database_password)\\s*[=:]\\s*\\S+"
          show_prefix: 0
          case_insensitive: true

OUTPUT MASKING (mask_stdout)
  Redacts secrets from stdout/stderr before they reach the terminal. Applied in
  addition to kernel-level sandbox protections (defense-in-depth).

  Built-in presets:
    openai     sk-... / sk-proj-...           → sk-***
    anthropic  sk-ant-...                     → sk-ant-***
    aws_key    AKIA... (access key ID)        → AKIA***
    github     ghp_, gho_, ghu_, ghs_, ghr_  → ghp_***
    bearer     Bearer <token>                 → Bearer ***

  All 5 presets are enabled by default (aigate init).

  Pattern options:
    regex            RE2-compatible regular expression (required)
    show_prefix      bytes to preserve before *** (default: 0, fully masked)
    case_insensitive match regardless of letter case (default: false)

  Custom pattern examples:
    mask_stdout:
      patterns:
        - regex: "mysecret-[a-z0-9]+"
          show_prefix: 0                   # → ***
        - regex: "token-[a-zA-Z0-9]{16}"
          show_prefix: 6                   # → token-***
        - regex: "(?:password|secret)\\s*[=:]\\s*\\S+"
          show_prefix: 0
          case_insensitive: true           # catches PASSWORD=, Password=, etc.

WHAT THE AI AGENT SEES INSIDE THE SANDBOX
  Startup banner on stderr:
    [aigate] sandbox active
    [aigate] deny_read: .env, secrets/, *.pem
    [aigate] deny_exec: curl, wget, ssh
    [aigate] allow_net: api.anthropic.com (all other outbound connections will be blocked)
    [aigate] mask_stdout: openai, anthropic, aws_key, github, bearer

  Denied files contain a marker instead of their content:
    [aigate] access denied: this file is protected by sandbox policy. See /tmp/.aigate-policy for all active restrictions.

  Denied directories contain a .aigate-denied marker file:
    [aigate] access denied: this directory is protected by sandbox policy. Run 'cat /tmp/.aigate-policy' to see all active restrictions.

  Policy summary file at /tmp/.aigate-policy lists all active restrictions.

  Network connections to non-allowed hosts are rejected (connection refused).

COMMON PATTERNS
  Node.js project:
    aigate deny read .env .npmrc
    aigate deny net --except registry.npmjs.org --except api.anthropic.com
    aigate run -- claude

  Python project:
    aigate deny read .env .pypirc secrets/
    aigate deny net --except pypi.org --except api.anthropic.com
    aigate run -- claude

  Go project:
    aigate deny read .env *.key
    aigate deny net --except proxy.golang.org --except api.anthropic.com
    aigate run -- claude

  Terraform project:
    aigate deny read terraform.tfstate *.tfvars .aws/
    aigate deny exec curl wget ssh
    aigate run -- claude

  Full lockdown:
    aigate deny read .env .env.* secrets/ credentials/ .ssh/ .aws/ .gcloud/ *.pem *.key
    aigate deny exec curl wget nc ncat netcat ssh scp rsync ftp
    aigate deny net --except api.anthropic.com
    aigate run -- claude
`
