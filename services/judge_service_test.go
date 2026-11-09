package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/AxeForging/aigate/domain"
)

// fakeJudge returns a fixed verdict (or error) and records calls.
type fakeJudge struct {
	name  string
	v     Verdict
	err   error
	sleep time.Duration
	calls int
}

func (f *fakeJudge) Name() string { return f.name }
func (f *fakeJudge) Judge(ctx context.Context, _ Call) (Verdict, error) {
	f.calls++
	if f.sleep > 0 {
		select {
		case <-time.After(f.sleep):
		case <-ctx.Done():
			return Verdict{}, ctx.Err()
		}
	}
	v := f.v
	v.Judge = f.name
	return v, f.err
}

func newChain(rules Judge, models ...Judge) *Chain {
	return &Chain{Rules: rules, Models: models, EscalateBelow: 0.6, Timeout: 200 * time.Millisecond}
}

func TestChain_RulesDenyShortCircuitsModels(t *testing.T) {
	fast := &fakeJudge{name: "fast", v: Verdict{Outcome: NoObjection, Confidence: 0.9}}
	c := newChain(&fakeJudge{name: "rules", v: Verdict{Outcome: Deny, Reason: "pipe"}}, fast)
	v := c.Decide(context.Background(), Call{Event: EventPreTool})
	if v.Outcome != Deny || v.Judge != "rules" || fast.calls != 0 {
		t.Errorf("rules deny must be final without calling models: %+v calls=%d", v, fast.calls)
	}
}

func TestChain_EscalatesOnlyWhenUnsure(t *testing.T) {
	tests := []struct {
		name          string
		fastConf      float64
		wantPrecise   int
		wantJudge     string
		wantOutcome   Outcome
		preciseVerdct Outcome
	}{
		{"confident fast model decides", 0.9, 0, "fast", Ask, Deny},
		{"unsure fast model escalates", 0.3, 1, "precise", Deny, Deny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fast := &fakeJudge{name: "fast", v: Verdict{Outcome: Ask, Confidence: tt.fastConf}}
			precise := &fakeJudge{name: "precise", v: Verdict{Outcome: tt.preciseVerdct, Confidence: 0.95}}
			v := newChain(RulesJudge{}, fast, precise).Decide(context.Background(), Call{Event: EventPreTool, Target: "ls"})
			if precise.calls != tt.wantPrecise || v.Judge != tt.wantJudge || v.Outcome != tt.wantOutcome {
				t.Errorf("got %+v precise.calls=%d", v, precise.calls)
			}
		})
	}
}

func TestChain_StrictestWins_ModelCannotLoosenRules(t *testing.T) {
	model := &fakeJudge{name: "model", v: Verdict{Outcome: NoObjection, Confidence: 0.99}}
	c := newChain(&fakeJudge{name: "rules", v: Verdict{Outcome: Ask, Reason: ".env"}}, model)
	if v := c.Decide(context.Background(), Call{}); v.Outcome != Ask || v.Judge != "rules" {
		t.Errorf("a confident 'no objection' must not override a rules ask: %+v", v)
	}
}

func TestChain_ModelFailureFallsBackToRules(t *testing.T) {
	tests := []struct {
		name  string
		model *fakeJudge
	}{
		{"error", &fakeJudge{name: "clef", err: errors.New("503")}},
		{"timeout", &fakeJudge{name: "clef", sleep: time.Second}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			// A call the rules let through, so the model is consulted.
			v := newChain(RulesJudge{}, tt.model).Decide(context.Background(),
				Call{Event: EventPreTool, Tool: "Bash", Target: "ls -la"})
			if v.Outcome != NoObjection || v.Judge != JudgeRules || !strings.Contains(v.Fallback, "clef unavailable") {
				t.Errorf("want rules verdict marked as fallback, got %+v", v)
			}
			if time.Since(start) > 900*time.Millisecond {
				t.Errorf("timeout not enforced: took %s", time.Since(start))
			}
		})
	}
}

func TestChain_NoJudgesMeansNoObjection(t *testing.T) {
	if v := (&Chain{}).Decide(context.Background(), Call{}); v.Outcome != NoObjection {
		t.Errorf("empty chain must stay out of the way, got %+v", v)
	}
}

func TestResolveJudgeSettings(t *testing.T) {
	s, err := ResolveJudgeSettings(domain.JudgeConfig{})
	if err != nil || s.Enabled || s.Timeout != 1500*time.Millisecond || s.ExcerptBytes != 4096 ||
		strings.Join(s.Chain, ",") != "rules,clef-flash,clef" || s.CFTokenEnv != "AIGATE_CF_TOKEN" {
		t.Fatalf("defaults wrong: %+v err=%v", s, err)
	}
	bad := []struct {
		name string
		cfg  domain.JudgeConfig
		want string
	}{
		{"unknown judge", domain.JudgeConfig{Chain: []string{"rules", "gpt"}}, `unknown judge "gpt"`},
		{"threshold range", domain.JudgeConfig{DenyAbove: 1.5}, "deny_above must be between 0 and 1"},
		{"ask above deny", domain.JudgeConfig{AskAbove: 0.9, DenyAbove: 0.7}, "must not be higher than"},
		{"bad timeout", domain.JudgeConfig{Timeout: "soon"}, "is not a duration"},
		{"huge timeout", domain.JudgeConfig{Timeout: "5m"}, "between 0 and 30s"},
		{"excerpt range", domain.JudgeConfig{ExcerptBytes: 10}, "excerpt_bytes"},
		{"secret pasted as env name", domain.JudgeConfig{Providers: domain.JudgeProviders{
			Cloudflare: domain.CloudflareProvider{TokenEnv: "fake-secret-value-123"}}}, "must name an environment variable"},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ResolveJudgeSettings(tt.cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("want error containing %q, got %v", tt.want, err)
			}
			if err != nil && strings.Contains(err.Error(), "fake-secret-value-123") {
				t.Errorf("error must not echo a pasted secret: %v", err)
			}
		})
	}
}
