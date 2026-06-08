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
  platform.go                 Platform interface + Executor interface + resolvePatterns
  platform_linux.go           Linux: setfacl, groupadd/useradd, RunSandboxed dispatch, splitDNSByFamily
  platform_linux_bwrap.go     Linux bwrap path: buildBwrapArgs, runWithBwrap, runWithBwrapNetFilter
  platform_darwin.go          macOS: chmod +a, dscl, sandbox-exec
  config_service.go           Config load/save/merge (global + project), InitDefaultConfig
  rule_service.go             Rule CRUD (add/remove/list deny rules)
  runner_service.go           Sandboxed process launcher
  masker.go                   MaskingWriter + builtin mask_stdout presets
  audit_service.go            Append/read ~/.aigate/audit.jsonl; AuditWriter wraps run output

internal/web/    Local dashboard (aigate serve)
  server.go      HTTP server (loopback by default)
  handlers.go    JSON API + page handlers over the audit log
  static/, templates/   Embedded JS/CSS/HTML assets

actions/         CLI command handlers
  setup.go       Create OS group + user (sudo)
  init.go        Write default config
  deny.go        Add deny rules (read, exec, net subcommands)
  allow.go       Remove deny rules
  run.go         Run command inside sandbox
  status.go      Show current sandbox state
  reset.go       Remove group, user, config
  doctor.go      Check prerequisites and active isolation mode
  help_ai.go     Print AI-friendly usage reference
  (serve is defined inline in main.go)

helpers/         Logging and error types
  logger.go      zerolog console logger
  errors.go      Sentinel errors

integration/     End-to-end CLI tests
  cli_test.go             Build binary, run real commands
  sandbox_test.go         Sandbox behaviour end-to-end
  sandbox_escape_test.go  Adversarial escape tests (-short skips them)
```

## Key Design Decisions

- **Platform interface**: Linux and macOS use completely different OS mechanisms. The `Platform` interface abstracts this with `newPlatform()` factory via build tags.
- **Executor interface**: All `exec.Command` calls go through `Executor`, enabling unit tests without root. Exception: `runWithBwrapNetFilter` uses `exec.Command` directly because it needs `cmd.Start()` + `ExtraFiles` for the info-fd pipe, which the Executor interface does not expose.
- **bwrap-first on Linux**: `RunSandboxed` prefers bwrap when available; falls back to `unshare`-based shell scripts. bwrap uses declarative bind mounts (no shell injection risk), resolves symlinks for bind destinations, and handles capabilities via `--uid 0 --cap-add` for the network path.
- **No CGO**: All platform operations use `exec.Command` to call system utilities (setfacl, groupadd, dscl, chmod, bwrap, slirp4netns, iptables/ip6tables).
- **IPv6 sandbox is opt-in by capability detection**: `ipv6SandboxSupported()` requires both kernel v6 enabled and `ip6tables` on PATH. Either missing → sandbox runs IPv4-only. Partial v6 (NAT but no filter) is refused — it would silently bypass `allow_net`.
- **Config merging**: Global config (`~/.aigate/config.yaml`) + project config (`.aigate.yaml`) merge with project extending global.
- **Audit log is append-only JSON Lines**: `AuditService` writes `run_started` / `blocked` events to `~/.aigate/audit.jsonl` under a mutex. `aigate serve` (`internal/web`) is a read-only dashboard over that file; it never mutates sandbox state. Keep the dashboard out of the sandbox enforcement path.

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
