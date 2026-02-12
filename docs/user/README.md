# aigate User Guide

## What is aigate?

aigate creates an OS-level sandbox for AI coding agents. When you use Claude Code, Cursor, Copilot, or any AI tool, aigate ensures they cannot:

- **Read** your secrets (.env, credentials, SSH keys, cloud configs)
- **Execute** dangerous commands (curl, wget, ssh)
- **Access** unauthorized network endpoints

Unlike application-level restrictions that can be bypassed, aigate uses kernel-enforced isolation (Linux ACLs + namespaces, macOS ACLs + sandbox-exec). The AI tool physically cannot access what you deny.

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
# 1. Initialize (creates OS group + user + default config)
sudo aigate init

# 2. Add custom restrictions
aigate deny read .env secrets/ terraform.tfstate
aigate deny exec curl wget ssh

# 3. Run your AI tool inside the sandbox
aigate run -- claude
aigate run -- cursor
aigate run -- aider
```

## Commands

### init

Creates the sandbox group (`ai-agents`), user (`ai-runner`), and default config.

```sh
sudo aigate init                           # Default setup
sudo aigate init --group mygroup --user myuser  # Custom names
sudo aigate init --force                   # Reinitialize
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
  - ".ssh/"
  - "*.pem"
  - "*.key"
  - ".aws/"
  - ".gcloud/"
deny_exec:
  - "curl"
  - "wget"
  - "nc"
  - "ssh"
  - "scp"
  - "kubectl delete"
  - "kubectl create"
  - "docker rm"
allow_net:
  - "api.anthropic.com"
  - "api.openai.com"
  - "api.github.com"
resource_limits:
  max_memory: "4G"
  max_cpu_percent: 80
  max_pids: 1000
```

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
```

Project config merges with global (extends, does not replace).

## How It Works

### Linux
- **File isolation**: POSIX ACLs via `setfacl` deny the `ai-agents` group read access
- **Process isolation**: Mount namespaces overmount sensitive directories with empty tmpfs
- **Network isolation**: Network namespaces + iptables restrict egress to allowed domains. Requires `slirp4netns` (`dnf install slirp4netns` / `apt install slirp4netns`). Falls back to unrestricted networking if not installed.
- **PID isolation**: PID namespaces hide host processes
- **Resource limits**: cgroups v2 enforce memory, CPU, and PID limits

### macOS
- **File isolation**: macOS ACLs via `chmod +a` with explicit deny entries
- **Process sandboxing**: `sandbox-exec` Seatbelt profiles restrict file and network access

## Troubleshooting

### "operation requires elevated privileges"
`init` and `reset` need `sudo` to create/delete OS users and groups. `deny`, `allow`, `run`, and `status` do not.

### ACL warnings on deny/allow
If you see "Failed to apply ACLs", the AI agent group may not exist yet. Run `sudo aigate init` first.

### "aigate not initialized"
Run `sudo aigate init` to create the sandbox group, user, and default config.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (invalid args, missing config, blocked command, etc.) |
