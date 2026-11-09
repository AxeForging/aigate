package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/AxeForging/aigate/domain"
)

// Check statuses, from good to bad. Note = optional thing missing; it never
// changes the verdict.
const (
	StatusOK   = "ok"
	StatusNote = "note"
	StatusWarn = "warn"
	StatusFail = "fail"
)

// DoctorSchemaVersion versions `aigate doctor --json`.
const DoctorSchemaVersion = 1

// Check is one doctor result. Fix is a copy-pasteable command (or empty).
type Check struct {
	ID     string `json:"id"`
	Group  string `json:"group"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

// Verdicts.
const (
	VerdictReady    = "ready"
	VerdictDegraded = "degraded"
	VerdictBlocked  = "blocked"
)

// DoctorVerdict is blocked if any check failed, degraded if any warned, else ready.
func DoctorVerdict(checks []Check) string {
	v := VerdictReady
	for _, c := range checks {
		switch c.Status {
		case StatusFail:
			return VerdictBlocked
		case StatusWarn:
			v = VerdictDegraded
		}
	}
	return v
}

// IdentityChecks reports per-identity setup: folders, logins present (file
// presence only — tokens are never read), git author, and allowed paths that
// would expose another identity.
func IdentityChecks(cfg *domain.Config) []Check {
	if cfg == nil || len(cfg.Identities) == 0 {
		return []Check{{ID: "identities", Group: "Identities", Name: "identities", Status: StatusNote,
			Detail: "none configured; sessions use your normal logins",
			Fix:    "aigate identity add work   # optional: separate logins per account"}}
	}
	svc := NewIdentityService()
	problems := svc.Validate(cfg)
	var out []Check
	for _, name := range sortedIdentityNames(cfg) {
		c := Check{ID: "identity." + name, Group: "Identities", Name: "identity " + name, Status: StatusOK}
		var notes []string
		for _, p := range problems {
			if p.Identity != name && p.Identity != "" {
				continue
			}
			if p.Fatal {
				c.Status, c.Fix = StatusFail, p.Fix
			} else if c.Status == StatusOK {
				c.Status, c.Fix = StatusWarn, p.Fix
			}
			notes = append(notes, p.Message)
		}
		if c.Status != StatusFail {
			if id, err := svc.Resolve(cfg, name, ""); err == nil {
				if _, err := svc.EffectiveAllowedPaths(cfg, id, filepath.Join(os.TempDir(), "aigate-doctor")); err != nil {
					c.Status, c.Fix = StatusFail, "remove the path from allowed_paths in ~/.aigate/config.yaml"
					notes = append(notes, err.Error())
				}
				notes = append(notes, loginNotes(name, id, &c)...)
			}
		}
		if len(notes) == 0 {
			notes = append(notes, "folders, logins and git author set")
		}
		c.Detail = strings.Join(notes, "; ")
		out = append(out, c)
	}
	return out
}

// loginNotes checks login files exist (never reads them). A missing login is
// a warning: the session works, the tool will just ask to log in.
func loginNotes(name string, id *domain.ResolvedIdentity, c *Check) []string {
	var notes []string
	missing := func(what, fix string) {
		notes = append(notes, what+" not logged in yet")
		if c.Status == StatusOK {
			c.Status, c.Fix = StatusWarn, fix
		}
	}
	// macOS keeps the Claude login in the Keychain; only the file is checkable here.
	if runtime.GOOS == "linux" && !exists(filepath.Join(id.ClaudeDir, ".credentials.json")) {
		missing("Claude", "aigate run --identity "+name+" -- claude")
	}
	if !exists(filepath.Join(id.GhDir, "hosts.yml")) {
		missing("GitHub CLI", "aigate run --identity "+name+" -- gh auth login")
	}
	return notes
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// JudgeChecks reports whether the judge is on, its hook installed in the
// Claude settings that apply here, each model's credentials, and (when
// online) a real round trip with its latency.
func JudgeChecks(cfg *domain.Config, settingsJSON string, hookCommand func(string) bool, online bool) []Check {
	var jc domain.JudgeConfig
	if cfg != nil {
		jc = cfg.Judge
	}
	s, err := ResolveJudgeSettings(jc)
	if err != nil {
		return []Check{{ID: "judge", Group: "Judge", Name: "judge config", Status: StatusWarn,
			Detail: err.Error() + " — the judge stays silent until fixed", Fix: "edit judge: in ~/.aigate/config.yaml"}}
	}
	if !s.Enabled {
		return []Check{{ID: "judge", Group: "Judge", Name: "judge", Status: StatusNote,
			Detail: "off (optional extra check on Claude Code tool calls)", Fix: "aigate judge install"}}
	}
	out := []Check{{ID: "judge", Group: "Judge", Name: "judge", Status: StatusOK, Detail: "on, chain " + strings.Join(s.Chain, " → ")}}
	hook := Check{ID: "judge.hook", Group: "Judge", Name: "judge hook", Status: StatusOK, Detail: "installed in " + TildePath(settingsJSON)}
	if !hookCommand(settingsJSON) {
		hook.Status, hook.Detail, hook.Fix = StatusWarn, "not installed in "+TildePath(settingsJSON)+"; Claude Code won't call the judge", "aigate judge install"
	}
	out = append(out, hook)

	chain := BuildJudgeChain(s)
	for _, skipped := range chain.Skipped {
		name, why, _ := strings.Cut(skipped, ": ")
		out = append(out, Check{ID: "judge." + name, Group: "Judge", Name: name, Status: StatusWarn,
			Detail: "skipped: " + why + " (only local rules run for it)", Fix: "export " + envNamesIn(why)})
	}
	for _, m := range chain.Models {
		c := Check{ID: "judge." + m.Name(), Group: "Judge", Name: m.Name(), Status: StatusOK, Detail: "credentials set"}
		if online {
			ctx, cancel := context.WithTimeout(context.Background(), s.Timeout+2*time.Second)
			start := time.Now()
			_, err := m.Judge(ctx, Call{Event: EventPreTool, Tool: "Bash", Target: "ls"})
			cancel()
			if err != nil {
				c.Status, c.Detail, c.Fix = StatusWarn, "unreachable: "+maskSecrets(err.Error())+" (calls fall back to local rules)", "check network and credentials"
			} else {
				c.Detail = fmt.Sprintf("reachable, %s round trip", time.Since(start).Round(time.Millisecond))
			}
		}
		out = append(out, c)
	}
	return out
}

var envNameIn = regexp.MustCompile(`\b[A-Z][A-Z0-9_]{2,}\b`)

// envNamesIn turns "set A and B" into "A=… B=…" for a fix line.
func envNamesIn(s string) string {
	var parts []string
	for _, n := range envNameIn.FindAllString(s, -1) {
		parts = append(parts, n+"=…")
	}
	return strings.Join(parts, " ")
}

var absHomePath = regexp.MustCompile(`(/home|/Users|/var/home)/[^/\s"']+`)

// RedactForReport makes text safe to paste in a public issue: paths under
// $HOME become ~, other home-looking paths lose the user name, secrets are
// masked.
func RedactForReport(s string) string {
	if home, err := os.UserHomeDir(); err == nil && home != "/" {
		s = strings.ReplaceAll(s, CanonicalPath(home), "~")
		s = strings.ReplaceAll(s, home, "~")
	}
	s = absHomePath.ReplaceAllString(s, "$1/USER")
	return maskSecrets(s)
}
