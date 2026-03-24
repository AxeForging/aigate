# aigate User Guide

## What is aigate?

aigate creates an OS-level sandbox for AI coding agents. When you use Claude Code, Cursor, Copilot, or any AI tool, aigate ensures they cannot:

- **Read** your secrets (.env, credentials, SSH keys, cloud configs)
- **Execute** dangerous commands (curl, wget, ssh)
- **Access** unauthorized network endpoints

Unlike application-level restrictions that can be bypassed, aigate uses kernel-enforced isolation (Linux namespaces + iptables, macOS sandbox-exec). The AI tool physically cannot access what you deny.

## Prerequisites

| | Linux | macOS |
|---|---|---|
| **Recommended** | `bwrap` (Bubblewrap) | None (uses built-in sandbox-exec) |
| **For network filtering** | `slirp4netns` | None (uses built-in Seatbelt) |
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

### From Source (Go 1.24+)
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
```

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
```

### allow

Remove restrictions:

```sh
aigate allow read .env          # Remove .env from deny list
aigate allow exec curl          # Allow curl again
aigate allow exec "kubectl delete"  # Allow kubectl delete again
aigate allow net example.com    # Add allowed domain
```

### run

Execute any command inside the sandbox:

```sh
aigate run -- claude                       # Claude Code
aigate run -- cursor                       # Cursor AI
aigate run -- aider --model claude-3       # Aider
aigate run -- echo "test"                  # Any command
```

### status

Show current sandbox configuration:

```sh
aigate status
```

### doctor

Check sandbox prerequisites and show which isolation mode will be active:

```sh
aigate doctor
```

Example output:
```
  ok    bwrap            v0.10.0  — sandbox isolation (mount/pid/user namespaces)
  ok    slirp4netns      v1.3.1   — network filtering (allow_net rules)
  ok    setfacl          v2.3.2   — persistent ACLs
  ok    user namespaces  enabled

Isolation mode: bwrap + slirp4netns (full isolation)
```

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
  - "~/.aws/"
  - "~/.gcloud/"
  - "~/.kube/config"
  - "~/.npmrc"
  - "~/.pypirc"
deny_exec:
  - "curl"
  - "wget"
  - "nc"
  - "ssh"
  - "scp"
  - "kubectl delete"
  - "kubectl exec"
allow_net:
  - "api.anthropic.com"
  - "api.openai.com"
  - "api.github.com"
resource_limits:
  max_memory: "4G"
  max_cpu_percent: 80
  max_pids: 1000
```

### Output Masking (mask_stdout)

`mask_stdout` intercepts stdout and stderr from the sandboxed process and redacts secrets before they reach your terminal. This is an **application-layer** protection on top of the kernel-level sandbox — it prevents secrets from appearing in logs, CI output, or terminal recordings.

**Built-in presets:**

| Preset | Matches | Example output |
|--------|---------|----------------|
| `openai` | `sk-...` / `sk-proj-...` | `sk-***` |
| `anthropic` | `sk-ant-...` | `sk-ant-***` |
| `aws_key` | `AKIA...` (access key ID) | `AKIA***` |
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

### Project Config (.aigate.yaml)

Place in your project root to extend global rules:

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

- **Linux (bwrap path)**: bwrap creates a network namespace via `--unshare-net`. Go reads bwrap's `--info-fd` to get the child PID, then launches `slirp4netns --configure` from host-side to attach user-mode networking. Inside the sandbox, `iptables` OUTPUT rules resolve each `allow_net` hostname and restrict egress. No root needed.
- **Linux (unshare fallback)**: Two-layer `unshare` — outer creates user namespace, inner creates network namespace. `slirp4netns` runs inside the user namespace. Same `iptables` filtering.
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
