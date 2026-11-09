package services

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// clefFake is a local stand-in for the Cloudflare API. It records the last
// request so tests can check what left the machine.
type clefFake struct {
	status   int
	answers  string
	delay    time.Duration
	lastAuth string
	lastPath string
	lastBody string
}

func (f *clefFake) serve(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.lastAuth, f.lastPath, f.lastBody = r.Header.Get("Authorization"), r.URL.Path, string(b)
		if f.delay > 0 {
			time.Sleep(f.delay)
		}
		if f.status != 0 && f.status != 200 {
			w.WriteHeader(f.status)
			return
		}
		_, _ = io.WriteString(w, `{"success":true,"result":{"answers":`+f.answers+`},"errors":[]}`)
	}))
	t.Cleanup(srv.Close)
	old := cloudflareAPIBase
	cloudflareAPIBase = srv.URL
	t.Cleanup(func() { cloudflareAPIBase = old })
}

func answers(unsafe, injection float64, choice string, conf float64) string {
	b, _ := json.Marshal(map[string]any{
		"unsafe":    map[string]any{"type": "noul", "noul": unsafe},
		"injection": map[string]any{"type": "noul", "noul": injection},
		"action": map[string]any{"type": "choice", "choice": choice, "confidence": conf,
			"probabilities": map[string]float64{"allow": 0.1, "ask": 0.1, choice: 0.8}},
	})
	return string(b)
}

func clefWithEnv(t *testing.T) *ClefJudge {
	t.Helper()
	t.Setenv("AIGATE_CF_ACCOUNT", "acct-for-tests")
	t.Setenv("AIGATE_CF_TOKEN", "canary-token-for-tests")
	return NewClefJudge(JudgeClefFlash, DefaultJudgeSettings())
}

func TestClefJudge_MapsProbabilitiesToOutcome(t *testing.T) {
	tests := []struct {
		name    string
		event   string
		answers string
		want    Outcome
		conf    float64
	}{
		{"confident deny", EventPreTool, answers(0.98, 0.05, "deny", 0.9), Deny, 0.9},
		{"deny choice but risk below deny_above asks", EventPreTool, answers(0.6, 0.1, "deny", 0.3), Ask, 0.3},
		{"risk above ask_above asks", EventPreTool, answers(0.55, 0.1, "allow", 0.4), Ask, 0.4},
		{"benign", EventPreTool, answers(0.03, 0.02, "allow", 0.92), NoObjection, 0.92},
		{"injection in output", EventPostTool, answers(0.2, 0.97, "deny", 0.9), Deny, 0.9},
		{"post ignores unsafe score", EventPostTool, answers(0.9, 0.05, "allow", 0.8), NoObjection, 0.8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &clefFake{answers: tt.answers}
			f.serve(t)
			v, err := clefWithEnv(t).Judge(context.Background(), Call{Event: tt.event, Tool: "Bash", Target: "x"})
			if err != nil {
				t.Fatal(err)
			}
			if v.Outcome != tt.want || v.Confidence != tt.conf || v.Judge != JudgeClefFlash {
				t.Errorf("got %+v", v)
			}
			if tt.want != NoObjection && !strings.Contains(v.Reason, "clef-flash judged") {
				t.Errorf("reason should explain the model's call: %q", v.Reason)
			}
			if _, ok := v.Scores["unsafe"]; !ok {
				t.Error("scores must be recorded for the audit log")
			}
		})
	}
}

func TestClefJudge_RequestCarriesOnlyMaskedPayload(t *testing.T) {
	f := &clefFake{answers: answers(0.1, 0.1, "allow", 0.9)}
	f.serve(t)
	secret := "sk-" + "ant-" + strings.Repeat("z", 30)
	_, err := clefWithEnv(t).Judge(context.Background(), Call{Event: EventPreTool, Tool: "Bash", Target: "export K=" + secret})
	if err != nil {
		t.Fatal(err)
	}
	if f.lastAuth != "Bearer canary-token-for-tests" || f.lastPath != "/accounts/acct-for-tests/ai/run/@cf/cloudflare/clef-flash" {
		t.Errorf("auth/path wrong: %q %q", f.lastAuth, f.lastPath)
	}
	if strings.Contains(f.lastBody, secret) || !strings.Contains(f.lastBody, judgeQuestionsVersion) {
		t.Errorf("body must be masked and versioned: %s", f.lastBody)
	}
	if strings.Contains(f.lastBody, "canary-token-for-tests") {
		t.Error("the API token must never appear in the request body")
	}
}

func TestClefJudge_Errors(t *testing.T) {
	t.Run("missing env names the variables, not values", func(t *testing.T) {
		t.Setenv("AIGATE_CF_ACCOUNT", "")
		t.Setenv("AIGATE_CF_TOKEN", "")
		_, err := NewClefJudge(JudgeClef, DefaultJudgeSettings()).Judge(context.Background(), Call{})
		if err == nil || !strings.Contains(err.Error(), "AIGATE_CF_TOKEN") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("http error", func(t *testing.T) {
		(&clefFake{status: 503}).serve(t)
		if _, err := clefWithEnv(t).Judge(context.Background(), Call{}); err == nil || !strings.Contains(err.Error(), "503") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("garbage response", func(t *testing.T) {
		(&clefFake{answers: `null`}).serve(t)
		if _, err := clefWithEnv(t).Judge(context.Background(), Call{}); err == nil {
			t.Error("want error on empty answers")
		}
	})
	t.Run("timeout via chain falls back to rules", func(t *testing.T) {
		(&clefFake{answers: answers(0.1, 0.1, "allow", 0.9), delay: 500 * time.Millisecond}).serve(t)
		c := &Chain{Rules: RulesJudge{}, Models: []Judge{clefWithEnv(t)}, EscalateBelow: 0.6, Timeout: 100 * time.Millisecond}
		v := c.Decide(context.Background(), Call{Event: EventPreTool, Target: "ls"})
		if v.Judge != JudgeRules || !strings.Contains(v.Fallback, "deadline exceeded") {
			t.Errorf("want rules fallback on timeout, got %+v", v)
		}
	})
}

func TestBuildJudgeChain_RegistersClef(t *testing.T) {
	clefWithEnv(t) // credentials set
	c := BuildJudgeChain(DefaultJudgeSettings())
	if c.Rules == nil || len(c.Models) != 2 || c.Models[0].Name() != JudgeClefFlash || c.Models[1].Name() != JudgeClef {
		t.Errorf("default chain should be rules → clef-flash → clef, got %+v", c)
	}
	off := DefaultJudgeSettings()
	off.Chain = []string{JudgeRules, JudgeOff}
	if c := BuildJudgeChain(off); c.Rules != nil || len(c.Models) != 0 {
		t.Error("off must disable the whole chain")
	}
}

func TestBuildJudgeChain_SkipsModelsWithoutCredentials(t *testing.T) {
	t.Setenv("AIGATE_CF_ACCOUNT", "")
	t.Setenv("AIGATE_CF_TOKEN", "")
	c := BuildJudgeChain(DefaultJudgeSettings())
	if c.Rules == nil || len(c.Models) != 0 || len(c.Skipped) != 2 || !strings.Contains(c.Skipped[0], "set AIGATE_CF_ACCOUNT") {
		t.Errorf("models without credentials must be skipped with a reason, got %+v", c)
	}
	s := DefaultJudgeSettings()
	s.Chain = []string{JudgeRules, JudgeJev}
	if c := BuildJudgeChain(s); len(c.Skipped) != 1 || !strings.Contains(c.Skipped[0], "jev: not available yet") {
		t.Errorf("unregistered adapters must be listed as skipped: %+v", c.Skipped)
	}
}
