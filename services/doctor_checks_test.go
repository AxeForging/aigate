package services

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/AxeForging/aigate/domain"
)

func TestDoctorVerdict(t *testing.T) {
	c := func(s string) Check { return Check{Status: s} }
	tests := []struct {
		checks []Check
		want   string
	}{
		{nil, VerdictReady},
		{[]Check{c(StatusOK), c(StatusNote)}, VerdictReady},
		{[]Check{c(StatusOK), c(StatusWarn), c(StatusNote)}, VerdictDegraded},
		{[]Check{c(StatusWarn), c(StatusFail), c(StatusOK)}, VerdictBlocked},
	}
	for _, tt := range tests {
		if got := DoctorVerdict(tt.checks); got != tt.want {
			t.Errorf("%v: got %s, want %s", tt.checks, got, tt.want)
		}
	}
}

func findCheck(t *testing.T, checks []Check, id string) Check {
	t.Helper()
	for _, c := range checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %q in %+v", id, checks)
	return Check{}
}

func TestIdentityChecks(t *testing.T) {
	t.Run("none configured is a note", func(t *testing.T) {
		c := findCheck(t, IdentityChecks(&domain.Config{}), "identities")
		if c.Status != StatusNote || !strings.Contains(c.Fix, "aigate identity add") {
			t.Errorf("got %+v", c)
		}
	})
	t.Run("logged in identity is ok, missing login warns with the login command", func(t *testing.T) {
		home, cfg := identityHome(t)
		writeFile := func(rel string) {
			if err := os.WriteFile(filepath.Join(home, rel), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		writeFile(".claude-work/.credentials.json")
		writeFile(".config/gh-work/hosts.yml")
		checks := IdentityChecks(cfg)
		if c := findCheck(t, checks, "identity.work"); c.Status != StatusOK {
			t.Errorf("work should be ok: %+v", c)
		}
		p := findCheck(t, checks, "identity.personal")
		want := "aigate run --identity personal -- claude"
		if runtime.GOOS != "linux" {
			want = "aigate run --identity personal -- gh auth login"
		}
		if p.Status != StatusWarn || p.Fix != want {
			t.Errorf("personal should warn with %q: %+v", want, p)
		}
	})
	t.Run("missing folder fails with mkdir fix", func(t *testing.T) {
		home, cfg := identityHome(t)
		if err := os.RemoveAll(filepath.Join(home, ".config/gh-work")); err != nil {
			t.Fatal(err)
		}
		c := findCheck(t, IdentityChecks(cfg), "identity.work")
		if c.Status != StatusFail || !strings.HasPrefix(c.Fix, "mkdir -p ") {
			t.Errorf("got %+v", c)
		}
	})
	t.Run("allowed path exposing another identity fails", func(t *testing.T) {
		_, cfg := identityHome(t)
		cfg.AllowedPaths = []string{"~/.config/gh"}
		c := findCheck(t, IdentityChecks(cfg), "identity.work")
		if c.Status != StatusFail || !strings.Contains(c.Detail, `exposes identity "personal"`) {
			t.Errorf("got %+v", c)
		}
	})
}

func TestJudgeChecks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	noHook := func(string) bool { return false }
	hook := func(string) bool { return true }
	on := &domain.Config{Judge: domain.JudgeConfig{Enabled: true}}

	if c := JudgeChecks(&domain.Config{}, "s.json", hook, false); len(c) != 1 || c[0].Status != StatusNote || c[0].Fix != "aigate judge install" {
		t.Errorf("off judge should be one note pointing at install: %+v", c)
	}
	bad := &domain.Config{Judge: domain.JudgeConfig{Enabled: true, Timeout: "soon"}}
	if c := JudgeChecks(bad, "s.json", hook, false); c[0].Status != StatusWarn || !strings.Contains(c[0].Detail, "not a duration") {
		t.Errorf("invalid config should warn: %+v", c)
	}

	t.Setenv("AIGATE_CF_ACCOUNT", "")
	t.Setenv("AIGATE_CF_TOKEN", "")
	checks := JudgeChecks(on, "s.json", noHook, false)
	if h := findCheck(t, checks, "judge.hook"); h.Status != StatusWarn || h.Fix != "aigate judge install" {
		t.Errorf("missing hook should warn: %+v", h)
	}
	if m := findCheck(t, checks, "judge.clef-flash"); m.Status != StatusWarn || m.Fix != "export AIGATE_CF_ACCOUNT=… AIGATE_CF_TOKEN=…" {
		t.Errorf("model without credentials should warn with export fix: %+v", m)
	}

	t.Setenv("AIGATE_CF_ACCOUNT", "acct")
	t.Setenv("AIGATE_CF_TOKEN", "canary-doctor-token")
	(&clefFake{status: 503}).serve(t)
	checks = JudgeChecks(on, "s.json", hook, true)
	m := findCheck(t, checks, "judge.clef")
	if m.Status != StatusWarn || !strings.Contains(m.Detail, "unreachable") || strings.Contains(m.Detail, "canary-doctor-token") {
		t.Errorf("unreachable model should warn without leaking the token: %+v", m)
	}
	(&clefFake{answers: answers(0.1, 0.1, "allow", 0.9)}).serve(t)
	if m := findCheck(t, JudgeChecks(on, "s.json", hook, true), "judge.clef"); m.Status != StatusOK || !strings.Contains(m.Detail, "round trip") {
		t.Errorf("reachable model should report latency: %+v", m)
	}
	if m := findCheck(t, JudgeChecks(on, "s.json", hook, false), "judge.clef"); strings.Contains(m.Detail, "round trip") {
		t.Errorf("offline must not contact the provider: %+v", m)
	}
}

func TestRedactForReport(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	secret := "gh" + "p_" + strings.Repeat("R", 36)
	in := "config " + home + "/.aigate/config.yaml; other /home/alice/x and /Users/bob/y; token " + secret
	out := RedactForReport(in)
	for _, leak := range []string{home, "alice", "bob", secret} {
		if strings.Contains(out, leak) {
			t.Errorf("report leaks %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, "~/.aigate/config.yaml") || !strings.Contains(out, "/home/USER/x") {
		t.Errorf("paths should stay readable: %s", out)
	}
}

func TestHasJudgeHookAndClaudeSettingsFor(t *testing.T) {
	home, cfg := identityHome(t)
	settings, who, err := ClaudeSettingsFor(cfg, "", home+"/work/api")
	if err != nil || settings != home+"/.claude-work/settings.json" || who != "identity work" {
		t.Fatalf("got %q %q %v", settings, who, err)
	}
	if HasJudgeHook(settings) {
		t.Error("no file → no hook")
	}
	for cmd, want := range map[string]bool{"/usr/local/bin/aigate judge": true, "'/opt/my tools/aigate' judge": true, "/usr/bin/other judge": false, "aigate judge eval": false} {
		b := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":` + jsonString(cmd) + `}]}]}}`
		if err := os.WriteFile(settings, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := HasJudgeHook(settings); got != want {
			t.Errorf("%q: got %v want %v", cmd, got, want)
		}
	}
}

func jsonString(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
