# 001 — Filesystem scope (`allowed_paths`), doctor/help UX, dashboard polish

Status: reviewed-in-session (implementation in same PR)

## Problem

1. **Write scope.** Inside the sandbox the filesystem root is read-only (bwrap
   `--ro-bind / /`), but `$HOME` is bind-mounted read-write so agent tools can
   write their caches/configs. That means `aigate run -- claude` can modify
   *anything* under the user's home directory — dotfiles, other projects,
   documents. There is no way to say "this session may only touch these paths".
2. **Doctor UX.** `aigate doctor` prints checks but no verdict, no config/setup
   checks, and always exits 0 — a newcomer can't tell if they are ready to run,
   and scripts can't gate on it.
3. **Help UX.** `aigate --help` lists commands with one-liners only; there are
   no examples in per-command help. New users must find the README.
4. **Dashboard.** The `aigate serve` dashboard doesn’t show the filesystem scope and
   could look/feel more polished (motion, live feedback).

## Requirements

- New config key `allowed_paths: []string` (global + project, merged by union).
  - Empty/absent → legacy behavior (home fully accessible). Backwards compatible.
  - Non-empty → **scope mode**: the scope controls *access in general*, not
    just writes. Only the working directory (always) and the listed paths are
    accessible under `$HOME`; every other home path is **hidden** — reads fail,
    listings don't leak names, and writes land in an ephemeral overlay that is
    discarded. System paths outside `$HOME` stay read-only (required to
    execute anything). `/tmp` stays a writable private tmpfs. Deny rules
    always win over `allowed_paths`.
  - Paths support `~/` expansion, absolute, and workdir-relative forms (same
    resolution as `deny_read`). Non-existent paths are skipped.
- `aigate run --allow-path <path>` adds session-only scope paths.
- `aigate allow path <path...>` / `aigate deny path <path...>` add/remove
  `allowed_paths` entries in the global config.
- `aigate init` default config ships a practical scope: common agent tool dirs
  (`~/.cache`, `~/.config`, `~/.local`, `~/.claude`, `~/.claude.json`,
  `~/.npm`) so `aigate run -- claude` works out of the box while the rest of
  `$HOME` is invisible.
- Enforcement per platform:
  - **Linux / bwrap**: `--tmpfs $HOME` (hides everything) + rw `--bind` for
    workdir and each allowed path; sensitive-dotfile ro-binds only where
    re-exposed through the scope; deny mounts stay on top.
  - **Linux / unshare fallback**: rbind `$HOME` to a staging dir, tmpfs over
    `$HOME`, bind workdir/allowed paths back from the stage, lazy-unmount the
    stage. Fails closed (exit 125) if the hide cannot be established.
  - **macOS / Seatbelt**: `(deny file-write*)` + `(deny file-read* (subpath
    $HOME))` with read+write allows for workdir, allowed paths, and system
    temp/dev locations; placed before the specific deny rules so those win.
- Visibility: startup banner line, `/tmp/.aigate-policy` section, an
  `~/.aigate-scope-README` breadcrumb inside the hidden home, `status`
  output, dashboard "session scope" panel, `help-ai` docs.
- Adversarial tests: symlink escape (pre-planted and created in-sandbox),
  hardlink escape, `..` traversal, absolute-path normalization variants,
  write-persistence probes, deny-over-scope precedence.
- Doctor: adds config/setup checks, per-check status, actionable next-steps
  summary, and a final verdict; exits non-zero when the sandbox cannot run.
- Edge case: when the working directory *is* `$HOME`, the scope cannot be
  enforced meaningfully (workdir is always accessible); warn loudly on run.

## Test plan

- Unit (services): config merge/defaults for `allowed_paths`; rule service
  add/remove path; bwrap arg construction (home hidden, workdir rw, allowed rw,
  sensitive dotfiles still ro, deny wins); unshare script generation; policy
  file content; Seatbelt profile generation is covered on darwin hosts only.
- Integration (built binary, bwrap-gated): write outside scope fails, write to
  workdir and to an allowed path succeeds; `allow path`/`deny path`
  round-trip persists config; doctor prints verdict and exits 0 on a healthy
  host.

## Out of scope

- Per-run interactive approval of writes; audit events for blocked writes
  (kernel returns EROFS/EPERM directly, no user-space hook to log).
- Windows.
