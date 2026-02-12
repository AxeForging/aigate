# aigate - AI Assistant Reference

## Overview

aigate is a Go CLI tool that creates OS-level sandboxes for AI coding agents (Claude Code, Cursor, Copilot, etc.). It uses kernel-enforced isolation (ACLs, namespaces, cgroups) to restrict what AI tools can read, execute, and access on the network. Think of it as a Python venv but for AI permissions.

## Architecture

```
main.go          Entry point, service wiring, CLI commands
flags.go         All CLI flag definitions

domain/          Pure data structures
  types.go       Rule, Config, SandboxProfile, ResourceLimits

services/        Core business logic
  platform.go           Platform interface + Executor interface + resolvePatterns
  platform_linux.go     Linux: setfacl, groupadd/useradd, unshare (namespaces)
  platform_darwin.go    macOS: chmod +a, dscl, sandbox-exec
  config_service.go     Config load/save/merge (global + project)
  rule_service.go       Rule CRUD (add/remove/list deny rules)
  runner_service.go     Sandboxed process launcher

actions/         CLI command handlers
  init.go        Create group, user, default config
  deny.go        Add deny rules (read, exec, net subcommands)
  allow.go       Remove deny rules
  run.go         Run command inside sandbox
  status.go      Show current sandbox state
  reset.go       Remove group, user, config

helpers/         Logging and error types
  logger.go      zerolog console logger
  errors.go      Sentinel errors

integration/     End-to-end CLI tests
  cli_test.go    Build binary, run real commands
```

## Key Design Decisions

- **Platform interface**: Linux and macOS use completely different OS mechanisms. The `Platform` interface abstracts this with `newPlatform()` factory via build tags.
- **Executor interface**: All `exec.Command` calls go through `Executor`, enabling unit tests without root.
- **No CGO**: All platform operations use `exec.Command` to call system utilities (setfacl, groupadd, dscl, chmod).
- **Config merging**: Global config (`~/.aigate/config.yaml`) + project config (`.aigate.yaml`) merge with project extending global.

## Testing

```bash
# All tests
go test ./... -v

# Unit tests only (services)
go test ./services -v

# Integration tests only (builds binary)
go test ./integration -v
```

## Adding a New Command

1. Create `actions/mycommand.go` with struct + constructor + Execute method
2. Add flags to `flags.go` if needed
3. Register in `main.go` under `app.Commands`
4. Add integration test in `integration/cli_test.go`

## Adding a New Platform

1. Create `services/platform_newos.go` with `//go:build newos` constraint
2. Implement `newPlatform()` factory and all `Platform` interface methods
3. Add test file `services/platform_newos_test.go`

## Dependencies

- `github.com/urfave/cli` v1 - CLI framework
- `github.com/rs/zerolog` - Structured logging
- `gopkg.in/yaml.v3` - Config file parsing
