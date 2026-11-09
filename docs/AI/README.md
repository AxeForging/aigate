# aigate - AI Assistant Reference

## Overview

aigate is a Go CLI tool that creates OS-level sandboxes for AI coding agents (Claude Code, Cursor, Copilot, etc.). It uses kernel-enforced isolation (ACLs, namespaces, cgroups) to restrict what AI tools can read, execute, and access on the network. Think of it as a Python venv but for AI permissions.

## Architecture

```
main.go          Entry point, service wiring, CLI commands
flags.go         All CLI flag definitions

domain/          Pure data structures
  types.go       Rule, Config, SandboxProfile, ResourceLimits, Identity, ResolvedIdentity

services/        Core business logic
  platform.go                 Platform interface + Executor interface + resolvePatterns
  platform_linux.go           Linux: setfacl, groupadd/useradd, RunSandboxed dispatch, splitDNSByFamily
  platform_linux_bwrap.go     Linux bwrap path: buildBwrapArgs, runWithBwrap, runWithBwrapNetFilter
  platform_linux_agents.go    Hide user runtime dir, agent/bus sockets, their env vars
  platform_linux_identity.go  Linux identity mounts (ssh key) + env; unshare fallback limits
  platform_darwin.go          macOS: chmod +a, dscl, sandbox-exec (Seatbelt rules use resolved paths)
  identity_service.go         Identity validate / resolve (flag → folder → default) / per-identity allowlist
  identity_env.go             Env set/unset per identity (shared by Linux + macOS)
  block_message.go            One "[aigate] blocked … — layer: … To allow: …" format, used by deny_read
                              markers, deny_exec stubs/wrappers, pre-run refusals and the judge
  doctor_checks.go            Doctor check units {id, group, name, status, detail, fix}, verdict,
                              identity + judge checks, --report redaction
  explain_service.go          aigate explain: path/command → access, layer, rule, fix
  audit_query.go              Dashboard rows (decisions) and identity cards, masked
  userns_check.go             Detect Ubuntu AppArmor user-namespace block + printed fix
  pty.go                      PTY passthrough; stoppable stdin copy
  judge_config.go             judge: settings, defaults, validation (env var names only)
  judge_service.go            Judge port, Chain (rules → models, strictest wins, fallback), adapter registry
  judge_rules.go              Local rules (keyword prefilters, µs per call)
  judge_clef.go               Clef / Clef-flash / Jev adapters (typed questions aigate-judge-v1)
  judge_payload.go            What may leave the machine: masked with every preset, capped
  judge_hook.go               Claude Code hook payload ↔ Call; hook output (never "allow")
  judge_broker.go             Socket broker for hooks inside the sandbox; audit; warnings
  judge_install.go            settings.json hook install/uninstall with exact restore
  judge_override.go           allow-once grants (single use, 10 min)
  judge_eval.go, judge_corpus.json   Labeled synthetic corpus + scoring
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
  run.go         Run command inside sandbox (resolves identity, prints why)
  identity.go    identity list/show/use/remove
  identity_add.go, identity_prompt.go   Guided identity add (logins run inside its sandbox)
  whoami.go      Which identity runs here and why
  status.go      Show current sandbox state
  reset.go       Remove group, user, config
  doctor.go      Runs checks (incl. a real sandbox probe for agent sockets); text / --json / --report
  explain.go     aigate explain; shares buildRunProfile with run.go so they can't disagree
  help_ai.go     Print AI-friendly usage reference
  (serve is defined inline in main.go)

helpers/         Logging and error types
  logger.go      zerolog console logger
  errors.go      Sentinel errors

integration/     End-to-end CLI tests
  cli_test.go             Build binary, run real commands
  sandbox_test.go         Sandbox behaviour end-to-end
  sandbox_escape_test.go  Adversarial escape tests (-short skips them)
  scope_test.go           allowed_paths scope + bypass attempts (-short skips)
  agent_socket_test.go    Runtime dir / agent socket / env hardening
  identity*_test.go       Identity isolation, CLI, guided add (stub claude/gh, never real logins)

scripts/test-vm.sh  Run the suite in throwaway VMs per distro (make test-vm DISTRO=…|all)
```

## Key Design Decisions

- **Platform interface**: Linux and macOS use completely different OS mechanisms. The `Platform` interface abstracts this with `newPlatform()` factory via build tags.
- **Executor interface**: All `exec.Command` calls go through `Executor`, enabling unit tests without root. Exception: `runWithBwrapNetFilter` uses `exec.Command` directly because it needs `cmd.Start()` + `ExtraFiles` for the info-fd pipe, which the Executor interface does not expose.
- **bwrap-first on Linux**: `RunSandboxed` prefers bwrap when available; falls back to `unshare`-based shell scripts. bwrap uses declarative bind mounts (no shell injection risk), resolves symlinks for bind destinations, and handles capabilities via `--uid 0 --cap-add` for the network path.
- **No CGO**: All platform operations use `exec.Command` to call system utilities (setfacl, groupadd, dscl, chmod, bwrap, slirp4netns, iptables/ip6tables).
- **IPv6 sandbox is opt-in by capability detection**: `ipv6SandboxSupported()` requires both kernel v6 enabled and `ip6tables` on PATH. Either missing → sandbox runs IPv4-only. Partial v6 (NAT but no filter) is refused — it would silently bypass `allow_net`.
- **Config merging**: Global config (`~/.aigate/config.yaml`) + project config (`.aigate.yaml`) merge with project extending global.
- **Filesystem scope (`allowed_paths`)**: when non-empty, `$HOME` is replaced by an empty tmpfs (bwrap `--tmpfs`; rbind-stage + tmpfs in the unshare fallback; Seatbelt read+write denies on macOS) and only the workdir + allowed paths are bound back read-write. Non-scoped home files are invisible — reads AND writes blocked; deny rules are mounted after scope binds so they always win. Fallback fails closed (`exit 125`) if the hide cannot be established. `~/.aigate-scope-README` inside the sandbox + `/tmp/.aigate-policy` explain the policy to agents. Empty list = legacy behavior (home fully accessible).
- **Identities**: only read from the global config (project `.aigate.yaml` identity keys are rejected). Under an identity, scope mode is forced: broad defaults (`~/.config`, `~/.local`, `~/.claude*`) are dropped, the identity's dirs are allowed, and any path touching another identity is a hard error. Env sets `CLAUDE_CONFIG_DIR`/`GH_CONFIG_DIR`/git author/`GIT_SSH_COMMAND` and unsets host credential vars. The identity on `~/.claude` leaves `CLAUDE_CONFIG_DIR` unset (Claude Code changes settings file + macOS Keychain item when it is set). Paths are compared resolved (`CanonicalPath`) because of symlinked homes.
- **Judge is stricter-only**: outcomes are deny / ask / no-objection; no-objection prints nothing so Claude Code's own permissions apply. Hooks inside `aigate run` forward to a host-side broker socket, so config, provider credentials and audit stay outside the sandbox; judge credential env vars are removed from every sandbox. allow-once needs a TTY and lives in `~/.aigate` (hidden inside), so an agent can't approve itself.
- **Audit log is append-only JSON Lines**: `AuditService` writes `run_started` / `blocked` events to `~/.aigate/audit.jsonl` under a mutex. `aigate serve` (`internal/web`) is a read-only dashboard over that file; it never mutates sandbox state. Keep the dashboard out of the sandbox enforcement path.

## Testing

```bash
# All tests
go test ./... -v

# Unit tests only (services)
go test ./services -v

# Integration tests only (builds binary; AIGATE_TEST_BIN uses a prebuilt one)
go test ./integration -v

# Other distros in throwaway VMs (qemu + KVM, no root)
make test-vm DISTRO=ubuntu-24.04   # or DISTRO=all

# macOS (manual): gh workflow run macos.yml --ref <branch>
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

## Doctor, explain, dashboard

- **Doctor** checks are data (`services.Check`); renderers only print. Add a check by returning one more `Check` with a `Fix` the user can paste. `note` never changes the verdict; `warn` → DEGRADED; `fail` → BLOCKED (exit 1).
- **Explain** must agree with `run`: both build the profile with `actions.buildRunProfile`, and `TestExplain_AgreesWithRun` reads each case in a real sandbox. When adding a sandbox rule, add its case to `ExplainPath`/`ExplainCommand` *and* that table.
- **Dashboard** data comes from `/api/overview`, `/api/decisions`, `/api/identities`; every text field is masked server-side, and `TestDashboard_NeverShowsSecrets` plants an unmasked canary in the audit log. UI changes are validated in a browser on data from `scripts/dash-seed.sh`.
