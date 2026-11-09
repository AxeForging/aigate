package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AxeForging/aigate/domain"
)

func mixedEvents(now time.Time, secret string) []AuditEvent {
	return []AuditEvent{
		{Time: now.Add(-48 * time.Hour), Kind: "blocked", Rule: "deny_exec", Source: "preflight", Command: "curl x"}, // old line: no identity
		{Time: now.Add(-3 * time.Hour), Kind: "run_started", Identity: "work"},
		{Time: now.Add(-2 * time.Hour), Kind: "blocked", Rule: "deny_read", Source: "stderr", Identity: "work", Command: "cat .env"},
		{Time: now.Add(-90 * time.Minute), Kind: "judge_decision", Identity: "work", Rule: "clef", Command: "Bash echo " + secret,
			Detail: "clef judged this unsafe", Meta: map[string]string{"outcome": "deny", "score_unsafe": "0.970", "confidence": "0.900"}},
		{Time: now.Add(-1 * time.Hour), Kind: "judge_fallback", Identity: "personal", Rule: "rules", Detail: "clef-flash unavailable"},
		{Time: now.Add(-30 * time.Minute), Kind: "judge_override", Identity: "work", Rule: "rules", Detail: "allowed once by the user: reviewed",
			Meta: map[string]string{"outcome": "deny", "os_user": "dev", "call_id": "3f9c2a1b7d04"}},
	}
}

func TestDecisions_LayersFiltersAndMasking(t *testing.T) {
	now := time.Now()
	secret := "gh" + "p_" + strings.Repeat("S", 36)
	all := Decisions(mixedEvents(now, secret), DecisionFilter{})
	if len(all) != 5 {
		t.Fatalf("run_started must be excluded, want 5 decisions, got %d", len(all))
	}
	if all[0].Kind != "judge_override" || all[len(all)-1].Kind != "blocked" {
		t.Errorf("want newest first: %v … %v", all[0].Kind, all[len(all)-1].Kind)
	}
	layers := map[string]string{}
	for _, d := range all {
		layers[d.Kind+"/"+d.By] = d.Layer
		if strings.Contains(d.What+d.Reason, secret) {
			t.Errorf("unmasked secret in decision: %+v", d)
		}
	}
	want := map[string]string{"blocked/deny_exec": LayerRule, "blocked/deny_read": LayerSandbox,
		"judge_decision/clef": LayerJudge, "judge_override/rules": LayerJudge}
	for k, v := range want {
		if layers[k] != v {
			t.Errorf("%s layer = %q, want %q", k, layers[k], v)
		}
	}
	judged := Decisions(mixedEvents(now, secret), DecisionFilter{Kind: "judge_decision"})
	if len(judged) != 1 || judged[0].Scores["unsafe"] != "0.970" || judged[0].Confidence != "0.900" || judged[0].Outcome != "deny" {
		t.Errorf("scores/confidence/outcome not carried: %+v", judged)
	}
	if got := Decisions(mixedEvents(now, secret), DecisionFilter{Identity: "work", Layer: LayerJudge}); len(got) != 2 {
		t.Errorf("identity+layer filter: want 2, got %d", len(got))
	}
	if got := Decisions(mixedEvents(now, secret), DecisionFilter{Since: now.Add(-24 * time.Hour)}); len(got) != 4 {
		t.Errorf("since filter: want 4, got %d", len(got))
	}
	ov := Decisions(mixedEvents(now, secret), DecisionFilter{Kind: "judge_override"})
	if ov[0].OSUser != "dev" || ov[0].CallID != "3f9c2a1b7d04" || !strings.Contains(ov[0].Reason, "reviewed") {
		t.Errorf("override who/why missing: %+v", ov[0])
	}
}

func TestSummarizeIdentities(t *testing.T) {
	home, cfg := identityHome(t)
	if err := os.RemoveAll(filepath.Join(home, ".config", "gh")); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sums := SummarizeIdentities(cfg, mixedEvents(now, "x"))
	if len(sums) != 2 || sums[0].Name != "personal" || sums[1].Name != "work" {
		t.Fatalf("want personal, work: %+v", sums)
	}
	personal, work := sums[0], sums[1]
	if !personal.Default || work.Default {
		t.Error("default flag wrong")
	}
	if strings.Join(work.Folders, ",") != "~/work" || work.Claude != "~/.claude-work" || work.SSHKey != "~/.ssh/id_work" {
		t.Errorf("work card wrong: %+v", work)
	}
	if work.LastUsed == nil || !work.LastUsed.Equal(now.Add(-30*time.Minute)) {
		t.Errorf("last used should be the newest work event: %v", work.LastUsed)
	}
	for _, r := range work.Reach {
		if r == "~/.claude" || r == "~/.config/gh" {
			t.Errorf("work's reach must not include personal's dirs: %v", work.Reach)
		}
	}
	found := false
	for _, p := range personal.Problems {
		found = found || (strings.Contains(p.Message, "does not exist") && strings.Contains(p.Fix, "mkdir -p"))
	}
	if !found {
		t.Errorf("missing gh dir should show as a problem with its fix: %+v", personal.Problems)
	}
	if sums := SummarizeIdentities(&domain.Config{}, nil); len(sums) != 0 {
		t.Error("no identities → no cards")
	}
}
