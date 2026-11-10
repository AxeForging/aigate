package services

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/AxeForging/aigate/domain"
)

// Decision is one dashboard row: something aigate blocked, judged, let
// through on override, or fell back on. Every text field is masked.
type Decision struct {
	Time       time.Time         `json:"time"`
	Kind       string            `json:"kind"`  // blocked | judge_decision | judge_fallback | judge_override
	Layer      string            `json:"layer"` // sandbox | rule | identity | judge
	Identity   string            `json:"identity,omitempty"`
	WorkDir    string            `json:"work_dir,omitempty"`
	What       string            `json:"what,omitempty"`
	By         string            `json:"by,omitempty"` // rule name or judge name
	Outcome    string            `json:"outcome,omitempty"`
	Reason     string            `json:"reason,omitempty"`
	Scores     map[string]string `json:"scores,omitempty"`
	Confidence string            `json:"confidence,omitempty"`
	OSUser     string            `json:"os_user,omitempty"`
	CallID     string            `json:"call_id,omitempty"`
}

// DecisionFilter narrows decisions; empty fields match everything.
type DecisionFilter struct {
	Identity string
	Layer    string
	Kind     string
	Since    time.Time
}

var decisionKinds = map[string]bool{"blocked": true, "judge_decision": true, "judge_fallback": true, "judge_override": true}

// LayerOf says which part of aigate an event came from. Older log lines
// without judge kinds are rule or sandbox blocks.
func LayerOf(e AuditEvent) string {
	switch {
	case strings.HasPrefix(e.Kind, "judge_"):
		return LayerJudge
	case e.Rule == "identity":
		return LayerIdentity
	case e.Source == "preflight" || e.Rule == "deny_exec":
		return LayerRule
	default:
		return LayerSandbox
	}
}

// Decisions turns audit events into masked, newest-first dashboard rows.
func Decisions(events []AuditEvent, f DecisionFilter) []Decision {
	var out []Decision
	for _, e := range events {
		if !decisionKinds[e.Kind] {
			continue
		}
		d := Decision{
			Time: e.Time, Kind: e.Kind, Layer: LayerOf(e), Identity: e.Identity,
			WorkDir: TildePath(e.WorkDir), What: maskSecrets(CleanAuditText(e.Command)), By: e.Rule,
			Reason: maskSecrets(CleanAuditText(e.Detail)), Outcome: e.Meta["outcome"], Confidence: e.Meta["confidence"],
			OSUser: e.Meta["os_user"], CallID: e.Meta["call_id"],
		}
		if e.Kind == "blocked" {
			d.Outcome = "deny"
		}
		for k, v := range e.Meta {
			if score, ok := strings.CutPrefix(k, "score_"); ok {
				if d.Scores == nil {
					d.Scores = map[string]string{}
				}
				d.Scores[score] = v
			}
		}
		if (f.Identity != "" && d.Identity != f.Identity) || (f.Layer != "" && d.Layer != f.Layer) ||
			(f.Kind != "" && d.Kind != f.Kind) || (!f.Since.IsZero() && d.Time.Before(f.Since)) {
			continue
		}
		out = append(out, d)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

// IdentitySummary is one identity card on the dashboard. Paths are shown as
// ~/…; nothing here reads login files.
type IdentitySummary struct {
	Name     string            `json:"name"`
	Default  bool              `json:"default"`
	Git      string            `json:"git,omitempty"`
	Claude   string            `json:"claude_dir"`
	GitHub   string            `json:"gh_dir"`
	SSHKey   string            `json:"ssh_key,omitempty"`
	Folders  []string          `json:"folders"`
	Reach    []string          `json:"reach"`
	LastUsed *time.Time        `json:"last_used,omitempty"`
	Problems []IdentityProblem `json:"problems"`
	Fixes    []string          `json:"fixes"`
}

// SummarizeIdentities builds the identity cards from config and the audit log.
func SummarizeIdentities(cfg *domain.Config, events []AuditEvent) []IdentitySummary {
	svc := NewIdentityService()
	problems := svc.Validate(cfg)
	home, _ := os.UserHomeDir()
	var out []IdentitySummary
	for _, name := range sortedIdentityNames(cfg) {
		id, err := svc.Resolve(cfg, name, home)
		if err != nil {
			continue
		}
		s := IdentitySummary{Name: name, Default: cfg.DefaultIdentity == name, Claude: TildePath(id.ClaudeDir),
			GitHub: TildePath(id.GhDir), SSHKey: TildePath(id.SSHKey), Folders: []string{}, Reach: []string{},
			Problems: []IdentityProblem{}, Fixes: []string{"aigate identity show " + name, "aigate identity use " + name}}
		if id.Git.Email != "" {
			s.Git = strings.TrimSpace(id.Git.Name + " <" + id.Git.Email + ">")
		}
		for dir, n := range cfg.IdentityBindings {
			if n == name {
				s.Folders = append(s.Folders, dir)
			}
		}
		sort.Strings(s.Folders)
		if reach, err := svc.EffectiveAllowedPaths(cfg, id, filepath.Join(home, ".aigate-dashboard-probe")); err == nil {
			for _, p := range reach {
				s.Reach = append(s.Reach, TildePath(p))
			}
		} else {
			s.Problems = append(s.Problems, IdentityProblem{Identity: name, Message: err.Error(), Fatal: true})
		}
		for _, p := range problems {
			if p.Identity == name || p.Identity == "" {
				s.Problems = append(s.Problems, p)
			}
		}
		for i := range events {
			e := events[i]
			if e.Identity == name && (s.LastUsed == nil || e.Time.After(*s.LastUsed)) {
				t := e.Time
				s.LastUsed = &t
			}
		}
		out = append(out, s)
	}
	return out
}

// TildePath shows paths under $HOME as ~/… (resolving symlinks so /var/home
// and /home, or /private/var and /var, compare equal).
func TildePath(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || p == "" {
		return p
	}
	if rp, rh := CanonicalPath(p), CanonicalPath(home); rp == rh || strings.HasPrefix(rp, rh+"/") {
		p, home = rp, rh
	}
	if p == home {
		return "~"
	}
	if rest, ok := strings.CutPrefix(p, home+"/"); ok {
		return "~/" + rest
	}
	return p
}

// MaskEvent returns e with its free-text fields masked, for display.
func MaskEvent(e AuditEvent) AuditEvent {
	e.Command = maskSecrets(CleanAuditText(e.Command))
	e.Detail = maskSecrets(CleanAuditText(e.Detail))
	return e
}
