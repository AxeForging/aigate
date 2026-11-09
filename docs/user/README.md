# aigate User Guide

## What is aigate?

aigate creates an OS-level sandbox for AI coding agents. When you use Claude Code, Cursor, Copilot, or any AI tool, aigate ensures they cannot:

- **Read** your secrets (.env, credentials, SSH keys, cloud configs)
- **Execute** dangerous commands (curl, wget, ssh)
- **Access** unauthorized network endpoints

Unlike application-level restrictions that can be bypassed, aigate uses kernel-enforced isolation (Linux namespaces + iptables/ip6tables, macOS sandbox-exec). The AI tool physically cannot access what you deny.

## Prerequisites

| | Linux | macOS |
|---|---|---|
| **Recommended** | `bwrap` (Bubblewrap) | None (uses built-in sandbox-exec) |
| **For network filtering** | `slirp4netns` | None (uses built-in Seatbelt) |
| **For IPv6 filtering** | `ip6tables` (optional — sandbox is v4-only without it) | None |
| **For persistent ACLs** | `setfacl` (usually pre-installed) | None |

### Install Bubblewrap (recommended, Linux)

`bwrap` provides stronger isolation than the fallback `unshare` path. When present, aigate uses it for all sandbox modes.

```sh
# Fedora / RHEL
sudo dnf install bubblewrap

# Ubuntu / Debian
sudo apt install bubblewrap

# Arch
sudo pacman -S bubblewrap
```

Without `bwrap`, aigate falls back to `unshare`-based namespaces (still functional, but shell-script-based overrides instead of declarative bind mounts).

### Install slirp4netns (required for `allow_net`, Linux)

```sh
# Fedora / RHEL
sudo dnf install slirp4netns

# Ubuntu / Debian
sudo apt install slirp4netns

# Arch
sudo pacman -S slirp4netns
```

If `slirp4netns` is not installed, aigate logs a warning and runs without network filtering.

IPv6 egress is filtered when `ip6tables` is installed (usually shipped with the `iptables` package) and the kernel has IPv6 enabled. Otherwise the sandbox runs IPv4-only and IPv6 traffic is unreachable from inside.

### Verify your setup

```sh
aigate doctor
```

Shows which tools are available and the isolation mode that will be used.

## Install

### Linux/macOS (AMD64)
```sh
curl -L https://github.com/AxeForging/aigate/releases/latest/download/aigate-linux-amd64.tar.gz | tar xz
chmod +x aigate-linux-amd64
sudo mv aigate-linux-amd64 /usr/local/bin/aigate
```

### Linux/macOS (ARM64 / Apple Silicon)
```sh
# Linux
curl -L https://github.com/AxeForging/aigate/releases/latest/download/aigate-linux-arm64.tar.gz | tar xz
sudo mv aigate-linux-arm64 /usr/local/bin/aigate

# macOS
curl -L https://github.com/AxeForging/aigate/releases/latest/download/aigate-darwin-arm64.tar.gz | tar xz
sudo mv aigate-darwin-arm64 /usr/local/bin/aigate
```

### From Source (Go 1.25+)
```sh
go install github.com/AxeForging/aigate@latest
```

## Quick Start

```sh
# 1. System setup (creates OS group + user, requires sudo)
sudo aigate setup

# 2. Create default config
aigate init

# 3. Add custom restrictions
aigate deny read .env secrets/ terraform.tfstate
aigate deny exec curl wget ssh

# 4. Run your AI tool inside the sandbox
aigate run -- claude
aigate run -- cursor
aigate run -- aider

# 5. (Optional) several accounts: one identity each
aigate identity add work
```

See [Identities](#identities-several-accounts-on-one-machine) for multiple accounts.

## Commands

### setup

Creates the OS group (`ai-agents`) and user (`ai-runner`). Requires `sudo`. Safe to re-run (skips existing group/user).

```sh
sudo aigate setup                                # Default group/user
sudo aigate setup --group mygroup --user myuser  # Custom names
```

### init

Creates default config at `~/.aigate/config.yaml`. Does not require sudo.

```sh
aigate init                    # Create default config
aigate init --force            # Re-create config (overwrites existing)
```

### deny

Add restrictions. Three sub-commands:

```sh
# Block file/directory access
aigate deny read .env secrets/ *.pem .aws/

# Block command execution
aigate deny exec curl wget nc ssh scp

# Block specific subcommands (allow other uses of the command)
aigate deny exec "kubectl delete" "kubectl create" "docker rm"

# Restrict network (only allow specific domains)
aigate deny net --except api.anthropic.com --except api.openai.com

# Narrow the filesystem scope (remove an allowed path; empty list = scope off)
aigate deny path ~/experiments
```

### allow

Remove restrictions / widen the filesystem scope:

```sh
aigate allow read .env          # Remove .env from deny list
aigate allow exec curl          # Allow curl again
aigate allow exec "kubectl delete"  # Allow kubectl delete again
aigate allow net example.com    # Add allowed domain
aigate allow path ~/experiments # Add a path to the filesystem scope
```

### run

Execute any command inside the sandbox:

```sh
aigate run -- claude                       # Claude Code
aigate run -- cursor                       # Cursor AI
aigate run -- aider --model claude-3       # Aider
aigate run -- echo "test"                  # Any command
aigate run --allow-path ~/notes -- claude  # Session-only scope addition
```

### status

Show current sandbox configuration:

```sh
aigate status
```

### doctor

Check your setup (config, OS accounts, sandbox tooling) and show which
isolation mode will be active. Ends with a verdict — `READY`, `DEGRADED`, or
`BLOCKED` — plus copy-pasteable next steps, and exits non-zero when the
sandbox cannot run so scripts/CI can gate on it:

```sh
aigate doctor
```

Example output:
```
aigate doctor — environment checks (linux/amd64)

Setup
  ok    config           ~/.aigate/config.yaml
          15 deny_read, 11 deny_exec, 5 allow_net, 6 allowed_paths (scope ON)
  ok    os accounts      group "ai-agents" and user "ai-runner" exist

Tools
  ok    bwrap            v0.10.0 (/usr/bin/bwrap)
  ok    slirp4netns      v1.3.1 (/usr/bin/slirp4netns)
  ok    user namespaces  enabled

Isolation mode:
  bwrap + slirp4netns  (full isolation)

Verdict: READY — full isolation available. Try: aigate run -- claude
```

### serve

Run a local web dashboard over the audit log. Read-only, binds to loopback by default — nothing is exposed off-host.

```sh
aigate serve                          # http://127.0.0.1:8080
aigate serve --addr 127.0.0.1:9000    # custom address (or AIGATE_ADDR env var)
```

The dashboard shows live counters and a timeline of `run_started` and `blocked` events drawn from `~/.aigate/audit.jsonl` (see [Audit log](#audit-log)).

### reset

Remove everything (group, user, config):

```sh
sudo aigate reset --force
```

## Configuration

### Global Config (~/.aigate/config.yaml)

Created automatically by `aigate init` with sensible defaults:

```yaml
group: ai-agents
user: ai-runner
deny_read:
  - ".env"
  - ".env.*"
  - "secrets/"
  - "credentials/"
  - "~/.ssh/"
  - "*.pem"
  - "*.key"
  - "*.p12"
  - "~/.aws/"
  - "~/.gcloud/"
  - "~/.kube/config"
  - "~/.npmrc"
  - "~/.pypirc"
  - "terraform.tfstate"
  - "*.tfvars"
deny_exec:
  - "curl"
  - "wget"
  - "nc"
  - "ncat"
  - "netcat"
  - "ssh"
  - "scp"
  - "rsync"
  - "ftp"
  - "kubectl delete"
  - "kubectl exec"
allow_net:
  - "api.anthropic.com"
  - "api.openai.com"
  - "api.github.com"
  - "registry.npmjs.org"
  - "proxy.golang.org"
allowed_paths:
  - "~/.cache"
  - "~/.config"
  - "~/.local"
  - "~/.claude"
  - "~/.claude.json"
  - "~/.npm"
resource_limits:
  max_memory: "4G"
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
  patterns:
    # Generic key=value / key: value assignments for common secret names
    - regex: "(?:api_?key|secret|password|passwd|token|credential)\\s*[=:]\\s*\\S+"
      show_prefix: 0
      case_insensitive: true
```

### Output Masking (mask_stdout)

`mask_stdout` intercepts stdout and stderr from the sandboxed process and redacts secrets before they reach your terminal. This is an **application-layer** protection on top of the kernel-level sandbox — it prevents secrets from appearing in logs, CI output, or terminal recordings.

**Built-in presets:**

| Preset | Matches | Example output |
|--------|---------|----------------|
| `openai` | `sk-...` / `sk-proj-...` | `sk-***` |
| `anthropic` | `sk-ant-...` | `sk-ant-***` |
| `aws_key` | `AKIA...` (access key ID) | `AKIA***` |
| `aws_secret` | `AWS_SECRET_ACCESS_KEY=...` assignment | `AWS_SECRET_ACCESS_KEY=***` |
| `github` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` | `ghp_***` |
| `bearer` | `Bearer <token>` in headers/logs | `Bearer ***` |

Enable presets in your config:

```yaml
# ~/.aigate/config.yaml or .aigate.yaml
mask_stdout:
  presets:
    - openai
    - anthropic
    - aws_key
    - github
    - bearer
```

**Custom patterns** with options:

```yaml
mask_stdout:
  presets:
    - openai
  patterns:
    # Fully mask a custom secret format
    - regex: "myapp-secret-[a-z0-9]+"
      show_prefix: 0
    # Show first 8 chars, mask the rest (e.g. "token-AB***")
    - regex: "token-[a-zA-Z0-9]{16}"
      show_prefix: 8
    # Case-insensitive match (catches PASSWORD=, password=, Password=)
    - regex: "(?:password|secret|token)\\s*[=:]\\s*\\S+"
      show_prefix: 0
      case_insensitive: true
```

**Pattern options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `regex` | string | — | RE2-compatible regular expression |
| `show_prefix` | int | `0` | Bytes to preserve before `***` (0 = fully masked) |
| `case_insensitive` | bool | `false` | Match regardless of letter case |

`show_prefix: N` preserves the first N bytes so you can identify which secret was present without exposing the value.

> **Note:** Masking is line-buffered. Secrets spanning chunk boundaries on the same line are still caught. Binary output streams should not use `mask_stdout`.

### Filesystem Scope (allowed_paths)

When `allowed_paths` is non-empty, **scope mode** is on. Inside the sandbox:

- The **working directory** is always fully accessible (read + write).
- Each listed path is fully accessible. Entries support `~/` expansion,
  absolute paths, and workdir-relative paths — same as `deny_read`.
- **Everything else in `$HOME` is hidden.** Non-scoped files are invisible:
  reads fail with "No such file", directory listings don't leak names, and
  writes land in an ephemeral overlay that is discarded when the session ends.
- System paths outside `$HOME` (`/usr`, `/etc`, ...) stay readable (anything
  else would break running programs) but read-only.
- `deny_read` / `deny_exec` always win, even inside allowed paths.

`aigate init` enables scope mode by default with the config/cache dirs common
agent tools need (`~/.cache`, `~/.config`, `~/.local`, `~/.claude`,
`~/.claude.json`, `~/.npm`), so `aigate run -- claude` works out of the box
while the rest of your home stays invisible.

Manage the scope:

```sh
aigate allow path ~/experiments            # persist a new scope path
aigate deny path ~/experiments             # remove it (empty list = scope off)
aigate run --allow-path ~/notes -- claude  # one session only
```

Inside the sandbox, `~/.aigate-scope-README` explains the active scope and
`/tmp/.aigate-policy` lists the full policy, so agents understand why paths
are missing instead of chasing phantom errors.

> **Caveat:** running `aigate run` from `$HOME` itself makes the scope
> unenforceable (the working directory is always accessible). aigate prints a
> loud warning when this happens — `cd` into a project directory to get
> enforcement.

### Identities (several accounts on one machine)

Use identities when you have more than one account — work, personal, a client
— each with its own Claude Code login, GitHub CLI login, git author and ssh
key. A session under one identity **can't see the others**: their folders are
hidden by the kernel, not just pointed elsewhere.

**Start in one command:**

```sh
aigate identity add personal   # first one: offers to reuse your current ~/.claude and ~/.config/gh
aigate identity add work       # asks for folders, git author, ssh key, then logs in to Claude and gh
cd ~/work && aigate identity use work
aigate whoami                  # identity: work … why: folder ~/work
aigate run -- claude           # [aigate] identity: work (folder ~/work)
```

**Everyday commands**

| Command | What it does |
|---|---|
| `aigate identity add NAME` | Guided setup; `--yes` for scripts, plus `--claude-dir`, `--gh-dir`, `--git-name`, `--git-email`, `--ssh-key`, `--default`, `--use`, `--login` |
| `aigate identity use NAME [FOLDER]` | Bind a folder (and everything inside it); `use none` unbinds |
| `aigate whoami` | Which identity runs here and why |
| `aigate identity list` / `show NAME` | Overview / details with problems and their fixes |
| `aigate identity remove NAME` | Remove from config (login folders are kept) |
| `aigate run --identity NAME -- …` | Pick an identity for one run |

**Which identity runs:** `--identity` flag → the deepest bound folder → `default_identity` → none (today's behavior). The first line of every run says which one and why.

**Config** (`~/.aigate/config.yaml`, written for you by the commands above):

```yaml
default_identity: personal
identities:
  personal:
    claude_dir: ~/.claude          # your existing login, kept as-is
    gh_dir: ~/.config/gh
    git: { name: Jane, email: jane@home.example }
  work:
    claude_dir: ~/.claude-work
    gh_dir: ~/.config/gh-work
    git: { name: Jane Doe, email: jane@work.example }
    ssh_key: ~/.ssh/id_work        # optional; mounted read-only, used via GIT_SSH_COMMAND
    allowed_paths: [~/work-notes]  # optional extra paths for this identity
    pass_env: []                   # host credential vars to keep (unset by default)
identity_bindings:
  ~/work: work
```

**What a session gets:** only its identity's folders (plus caches and installed
tools such as `~/.cache`, `~/.npm`, `~/.local/bin`), `CLAUDE_CONFIG_DIR`,
`GH_CONFIG_DIR`, the git author/committer, `GIT_SSH_COMMAND` for its key (never
an ssh-agent), and `AIGATE_IDENTITY`. Host credential variables such as
`ANTHROPIC_API_KEY`, `GH_TOKEN` and `GITHUB_TOKEN` are removed unless listed in
`pass_env`. The identity on `~/.claude` leaves `CLAUDE_CONFIG_DIR` unset so
Claude Code keeps using `~/.claude.json` and (on macOS) the same Keychain item
as before.

**Safety rules**

- A project `.aigate.yaml` can't select or widen an identity — a cloned repo
  could otherwise pick your work logins. Bind folders with `aigate identity use`.
- If any allowed path would expose another identity (e.g. `~/.config` while
  another identity uses `~/.config/gh`), the run stops and names both.
- Two identities can't share or nest their folders.

**Platforms**

| | Linux (bwrap) | macOS (Seatbelt) |
|---|---|---|
| Other identities' files, gh login, ssh keys | hidden | hidden |
| Git author per identity | yes | yes |
| Claude login | separate folder, hidden | separate Keychain item, **not** access-isolated — `aigate doctor` explains |

Tested on Fedora 43/44, Ubuntu 22.04/24.04, Debian 12/13, Arch, Rocky 9 and
macOS (`make test-vm DISTRO=all` runs the Linux matrix in throwaway VMs).

**Common messages**

| You see | Do |
|---|---|
| `identity: none (pick one with --identity NAME …)` | `aigate identity use NAME` in the project folder |
| `allowed path … exposes identity "x"` | Remove that path from `allowed_paths`, or list a narrower one |
| `… sets "identity", but a project config can't choose your identity` | Delete the key from `.aigate.yaml`; run `aigate identity use NAME` |
| `claude_dir … does not exist` | Run the printed `mkdir -p …`, then log in: `aigate run --identity NAME -- claude` |
| `AppArmor is blocking the user namespaces bubblewrap needs` (Ubuntu 23.10+) | Run the printed AppArmor profile commands |

### Project Config (.aigate.yaml)

Place in your project root to extend global rules (identity keys are not
allowed here — see [Identities](#identities-several-accounts-on-one-machine)):

```yaml
deny_read:
  - "terraform.tfstate"
  - "vault-token"
allow_net:
  - "registry.terraform.io"
resource_limits:
  max_memory: "8G"
mask_stdout:
  presets:
    - openai
    - github
  patterns:
    - regex: "stripe_key\\s*[=:]\\s*\\S+"
      show_prefix: 0
      case_insensitive: true
```

Project config merges with global (extends, does not replace).

## How It Works

Architecture diagrams are in [`docs/diagrams/`](../diagrams/).

### File isolation

Two layers working together for defense-in-depth:

1. **Persistent ACLs** (applied when you run `aigate deny read`):
   - **Linux**: POSIX ACLs via `setfacl` deny the `ai-agents` group read access
   - **macOS**: Extended ACLs via `chmod +a` with explicit deny entries
2. **Runtime overrides** (applied when you run `aigate run`):
   - **Linux**: Mount namespaces overmount directories with empty tmpfs, files with `/dev/null`
   - **macOS**: Seatbelt `file-read*` deny rules in the sandbox profile

![File Isolation](../diagrams/file-isolation.png)

### Network isolation

Restricts outbound connections to domains listed in `allow_net`:

- **Linux (bwrap path)**: bwrap creates a network namespace via `--unshare-net`. Go reads bwrap's `--info-fd` to get the child PID, then launches `slirp4netns --configure` from host-side to attach user-mode networking. Inside the sandbox, `iptables` OUTPUT rules resolve each `allow_net` hostname and restrict egress. When `ip6tables` is available and the kernel has IPv6 enabled, slirp4netns is launched with `--enable-ipv6` and a parallel `ip6tables` filter is installed. No root needed.
- **Linux (unshare fallback)**: Two-layer `unshare` — outer creates user namespace, inner creates network namespace. `slirp4netns` runs inside the user namespace. Same `iptables`/`ip6tables` filtering.
- **macOS**: `sandbox-exec` Seatbelt profiles with `(deny network-outbound)` and per-host `(allow network-outbound (remote ip ...))` rules. Kernel-enforced via Sandbox.kext.

**Linux**:

![Linux Network Isolation](../diagrams/linux-network.png)

**macOS**:

![macOS Network Isolation](../diagrams/macos-network.png)

### Process isolation (Linux)

When `bwrap` is installed (recommended):

- **User namespace** (`--unshare-user`): Maps calling user to a root-equivalent UID inside the namespace. Required for mount/net operations without real root.
- **PID namespace** (`--unshare-pid`): Sandboxed process sees itself as PID 1, cannot see or signal host processes. `/proc` is remounted fresh.
- **Mount namespace**: bwrap declaratively applies deny_read bind mounts, config-dir hiding, and deny_exec stubs before exec — no shell-based overrides.

Without `bwrap`, aigate falls back to `unshare --user --map-root-user` + shell scripts for the same effects.

![Linux Process Isolation](../diagrams/linux-process.png)

### Command blocking

`deny_exec` rules are enforced at two layers for defense-in-depth:

1. **Pre-sandbox check**: Before entering the sandbox, aigate checks the command (and subcommands like `kubectl delete`) against the deny list and refuses to launch blocked commands.
2. **Kernel-level enforcement inside the sandbox**:
   - **Linux**: Full command blocks use `mount --bind` to overlay denied binaries with a deny script. Subcommand blocks use wrapper scripts that check arguments before forwarding to the original binary.
   - **macOS**: Full command blocks use Seatbelt `(deny process-exec)` rules enforced by Sandbox.kext. Subcommand blocks rely on the pre-sandbox check.

### Resource limits *(coming soon)*

Resource limits (`max_memory`, `max_cpu_percent`, `max_pids`) are defined in the config but **not yet enforced**. Enforcement via cgroups v2 controllers is planned for a future release.

## Audit log

Each sandboxed run appends a line to `~/.aigate/audit.jsonl` (JSON Lines). Two kinds of events are recorded:

- `run_started` — a sandbox launched, with the command and a count of active `deny_read` / `deny_exec` / `allow_net` / masking rules
- `blocked` — a command was refused by the `deny_exec` preflight check, with the matched rule

```json
{"time":"2026-06-08T17:00:00Z","kind":"run_started","command":"claude","work_dir":"/home/me/proj","counts":{"deny_read":15,"deny_exec":11,"allow_net":5,"masking":7}}
{"time":"2026-06-08T17:01:12Z","kind":"blocked","rule":"curl","command":"curl ifconfig.me","source":"preflight"}
```

The file is plain text — `tail -f ~/.aigate/audit.jsonl` works, or run [`aigate serve`](#serve) for a live dashboard.

## Troubleshooting

### "operation requires elevated privileges"
`setup` and `reset` need `sudo` to create/delete OS users and groups. `init`, `deny`, `allow`, `run`, and `status` do not.

### ACL warnings on deny/allow
If you see "Failed to apply ACLs", the AI agent group may not exist yet. Run `sudo aigate setup` first.

### "aigate not initialized"
Run `sudo aigate setup` to create the sandbox group and user, then `aigate init` to create the default config.

### "slirp4netns not found" warning
Install `slirp4netns` for network filtering on Linux (see [Prerequisites](#prerequisites)). Without it, `allow_net` rules are ignored and the sandboxed process has unrestricted network access.

### Allowed hosts still blocked
If hosts in `allow_net` are being rejected, DNS inside the sandbox may not have been ready in time. Check that `slirp4netns` is installed and working. Run `aigate doctor` to verify your setup, or use `AIGATE_LOG_LEVEL=debug` for detailed output.

### bwrap not found
Install `bubblewrap` for stronger isolation (see [Prerequisites](#prerequisites)). Without it, aigate falls back to the `unshare`-based sandbox which is still functional but uses shell-script-based mount overrides.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (invalid args, missing config, blocked command, etc.) |
