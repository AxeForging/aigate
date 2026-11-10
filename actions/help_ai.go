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
  aigate init --upgrade          # Add newer default protections, keep your rules
  aigate doctor                  # Check prerequisites and active isolation mode

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

FILESYSTEM SCOPE (allowed_paths)
  When allowed_paths is non-empty, scope mode is ON: inside the sandbox only
  the working directory and the listed paths are accessible (read AND write).
  The rest of $HOME is hidden — non-scoped files are invisible, and writes to
  them land in an ephemeral overlay that is discarded. System paths outside
  $HOME stay read-only. deny_read/deny_exec rules always win over the scope.

  aigate allow path ~/experiments          # Add a path to the scope (persists)
  aigate deny path ~/experiments           # Remove it (empty list = scope off)
  aigate run --allow-path ~/notes -- claude  # Extra scope path, one session only
  aigate run --port 3000 -- claude           # Open the agent's dev server at localhost:3000

  'aigate init' enables scope mode by default with the dirs agent tools need:
  ~/.cache ~/.config ~/.local ~/.claude ~/.claude.json ~/.npm

  Caveat: running from $HOME itself disables enforcement (the working
  directory is always accessible) — aigate warns loudly when this happens.

IDENTITIES (several accounts on one machine)
  Each identity has its own Claude login, gh login, git author and optional ssh
  key. A session only sees the active identity's logins; other identities'
  folders are hidden by the kernel.

  aigate identity add work                 # Guided setup: folders, git author, ssh key, logins
  aigate identity use work                 # This folder (and inside it) runs as work
  aigate identity use none                 # Unbind this folder
  aigate whoami                            # Which identity runs here, and why
  aigate identity list                     # All identities (* = active here)
  aigate run --identity personal -- claude # Pick one for a single run

  A repo's .aigate.yaml can't choose an identity (a cloned repo could pick
  your work logins); bind folders with 'aigate identity use' instead.
  Inside the sandbox: $AIGATE_IDENTITY names the active identity.

JUDGE (optional; Claude Code hooks)
  An extra check on tool calls: local rules, then Clef/Jev models. It can only
  deny or ask, never allow; the sandbox stays the boundary.

  aigate judge install                     # Add hooks to Claude Code, turn the judge on
  aigate judge uninstall                   # Remove exactly what install added
  aigate judge --dry-run < payload.json    # What a model would receive (masked); sends nothing
  aigate judge eval                        # Precision/recall/latency of rules, models, chain
  aigate judge allow-once ID               # Let one blocked call through (human, in a terminal)
  aigate run --judge=off -- claude         # One session without the judge (audited)

  If a call is denied by the judge, don't retry it in another form: ask the
  user, who can allow it once.

RUNNING SANDBOXED
  aigate run -- claude                     # Run Claude in sandbox
  aigate run -- aider                      # Run any AI tool
  aigate run -- bash -c "npm test"         # Run arbitrary commands
  aigate run --config ./project.yaml -- claude  # Use project-specific config
  aigate run --verbose -- claude           # Show debug logging

CHECKING STATUS
  aigate status                            # Show all rules, group/user, limits
  aigate doctor                            # Verdict + fix for every problem (exit 1 if blocked)
  aigate doctor --json | --report          # For scripts | safe to paste in an issue
  aigate explain ~/.ssh/id_ed25519         # Would this be readable here? Which layer decides?
  aigate explain -- curl https://x.com     # Would this command run? (runs nothing; exit 1 if not)

BLOCK MESSAGES (same format from every layer)
  [aigate] blocked <what> — <layer>: <reason>. To allow: <command>
  Layers: sandbox, rule, identity, judge. Inside the sandbox only a person can
  run the "To allow" command — tell the user instead of retrying.

DASHBOARD & AUDIT LOG
  Every run, block, judge verdict, override and fallback is appended to
  ~/.aigate/audit.jsonl (JSON Lines). Kinds: run_started, blocked,
  judge_decision, judge_override, judge_fallback.

  tail -f ~/.aigate/audit.jsonl            # Follow events as plain text
  aigate serve                             # Dashboard: decisions timeline + identities → http://127.0.0.1:8080
  aigate serve --addr 127.0.0.1:9000       # Custom address (or AIGATE_ADDR env var)

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
    allowed_paths:
      - ~/.cache
      - ~/.config
      - ~/.local
      - ~/.claude
      - ~/.claude.json
      - ~/.npm
    resource_limits:
      max_memory: 4G
      max_cpu_percent: 80
      max_pids: 1000
    mask_stdout:
      presets:
        - openai
        - anthropic
        - aws_key
        - aws_secret
        - github
        - bearer
        - cloudflare
        - gitlab
        - slack
        - stripe
        - google
        - npm
        - huggingface

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
    openai      sk-... / sk-proj-...           → sk-***
    anthropic   sk-ant-...                     → sk-ant-***
    aws_key     AKIA... (access key ID)        → AKIA***
    aws_secret  AWS_SECRET_ACCESS_KEY=...      → AWS_SECRET_ACCESS_KEY=***
    github      ghp_/gho_/ghu_/ghs_/ghr_, github_pat_ → ghp_***
    bearer      Bearer <token>                 → Bearer ***
    cloudflare  cfut_/cfat_ tokens, cfk_ keys  → cfut***
    gitlab      glpat-...                      → glpat-***
    slack       xoxb-/xoxp-/xoxa-/xoxr-/xoxs-  → xoxb-***
    stripe      sk_live_/rk_live_...           → sk_live_***
    google      AIza... API keys               → AIza***
    npm         npm_...                        → npm_***
    huggingface hf_...                         → hf_***

  All 13 presets are enabled by default for new configs (aigate init). Older
  configs keep their list: aigate init --upgrade adds the missing ones.

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
    [aigate] allowed_paths: ~/.cache, ~/.config (plus the working directory; the rest of $HOME is hidden)
    [aigate] mask_stdout: openai, anthropic, aws_key, aws_secret, github, bearer, cloudflare, …

  With scope mode on, non-scoped home files are invisible (plain "No such
  file"), and ~/.aigate-scope-README inside the sandbox explains the scope
  and points to /tmp/.aigate-policy for the full policy.

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
