package services

import (
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/AxeForging/aigate/domain"
)

func TestAuditService_LogAndRecent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	configSvc := NewConfigService()
	auditSvc := NewAuditService(configSvc)

	profile := domain.SandboxProfile{WorkDir: "/tmp/project"}
	auditSvc.LogRunStarted(profile, "echo", []string{"hello"})
	auditSvc.LogBlocked(profile, "curl", []string{"example.test"}, "deny_exec", "preflight", "curl is blocked")

	events, err := auditSvc.Recent(10)
	if err != nil {
		t.Fatalf("Recent() error = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("Recent() returned %d events, want 2", len(events))
	}
	if events[0].Kind != "blocked" {
		t.Fatalf("newest event kind = %q, want blocked", events[0].Kind)
	}
	if events[0].Command != "curl example.test" {
		t.Fatalf("blocked command = %q", events[0].Command)
	}

	path, err := auditSvc.Path()
	if err != nil {
		t.Fatalf("Path() error = %v", err)
	}
	wantSuffix := filepath.Join(".aigate", "audit.jsonl")
	if len(path) < len(wantSuffix) || filepath.ToSlash(path[len(path)-len(wantSuffix):]) != filepath.ToSlash(wantSuffix) {
		t.Fatalf("Path() = %q, want suffix %q", path, wantSuffix)
	}
}

// TestAuditWriter_TUIOutput: a TUI redraws without newlines and wraps text in
// escape codes. Captured blocks must be one clean, short message each; the
// judge's own messages are skipped (the judge logs its decisions itself).
func TestAuditWriter_TUIOutput(t *testing.T) {
	esc := func(s string) string { return "\x1b[1C\x1b[38;5;246m" + s + "\x1b[39m\x1b[50;1H" }
	judgeMsg := `[aigate] blocked Bash git push --force — judge: clef judged this unsafe (risk 0.39, model chose ask) (clef). To allow: aigate judge allow-once 903c`
	execMsg := `[aigate] blocked exec curl — rule: it is in deny_exec. To allow: a person runs, outside the sandbox: aigate allow exec curl`
	readMsg := `[aigate] blocked read of this file — rule: it matches a deny_read rule. To allow: aigate allow read PATTERN`
	cases := []struct {
		name   string
		output string
		want   []AuditEvent // Rule and Detail only
	}{
		{"judge message in a redraw", strings.Repeat(esc("●"), 200) + esc(judgeMsg) + strings.Repeat(esc("●"), 200), nil},
		{"exec block redrawn many times", strings.Repeat(esc(execMsg)+esc("✻ thinking"), 30),
			[]AuditEvent{{Rule: "deny_exec", Detail: execMsg}}},
		{"read block is deny_read", readMsg + "\n", []AuditEvent{{Rule: "deny_read", Detail: readMsg}}},
		{"plain output", "hello\nworld\n", nil},
		{"judge ask and status lines", esc("[aigate] judge wants your OK: Bash rm -rf build — network access to an unknown host (clef). Answer Yes to run it this once, or No to stop it.") +
			"\n[aigate] judge: clef-flash unavailable (request failed); used local rules\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			svc := NewAuditService(NewConfigService())
			w := NewAuditWriter(io.Discard, svc, domain.SandboxProfile{WorkDir: "/w"}, "claude", nil, "stdout")
			for chunk := range slices.Chunk([]byte(tc.output), 512) {
				if _, err := w.Write(chunk); err != nil {
					t.Fatal(err)
				}
			}
			if f, ok := w.(interface{ Flush() }); ok {
				f.Flush()
			}
			events, err := svc.Recent(0)
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != len(tc.want) {
				t.Fatalf("got %d events, want %d: %+v", len(events), len(tc.want), events)
			}
			for i, e := range events {
				if e.Rule != tc.want[i].Rule || e.Detail != tc.want[i].Detail {
					t.Errorf("event %d = %q %q, want %q %q", i, e.Rule, e.Detail, tc.want[i].Rule, tc.want[i].Detail)
				}
			}
		})
	}
}

// TestCleanAuditText: stored details from older versions (raw TUI capture)
// display as the one aigate message they contain, capped in length.
func TestCleanAuditText(t *testing.T) {
	raw := "\x1b[1C\x1b[1B\x1b[39mrtk\x1b[6Ggit ��\x1b[38;5;246m[aigate] blocked Bash git push — judge: clef judged this unsafe\x1b[39m\x1b[50;1H" + strings.Repeat("\x1b[31B●\x1b[39m", 300)
	got := CleanAuditText(raw)
	if !strings.HasPrefix(got, "[aigate] blocked Bash git push — judge: clef judged this unsafe") {
		t.Errorf("want the aigate message first, got %q", got)
	}
	if strings.ContainsAny(got, "\x1b�") {
		t.Errorf("escape codes or broken bytes left: %q", got)
	}
	if n := len([]rune(got)); n > maxDisplayText {
		t.Errorf("len %d > %d", n, maxDisplayText)
	}
	if got := CleanAuditText("curl example.test"); got != "curl example.test" {
		t.Errorf("plain text changed: %q", got)
	}
}

// TestAuditService_RecentDropsJudgeEchoes: a judge message captured from the
// session output by older versions isn't counted as a second block.
func TestAuditService_RecentDropsJudgeEchoes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	svc := NewAuditService(NewConfigService())
	p := domain.SandboxProfile{WorkDir: "/w"}
	svc.LogBlocked(p, "claude", nil, "deny_exec", "stdout", "[aigate] blocked Bash git push — judge: clef judged this unsafe")
	svc.LogBlocked(p, "claude", nil, "deny_exec", "stdout", "[aigate] blocked exec curl — rule: it is in deny_exec")
	svc.LogBlocked(p, "git", []string{"push"}, "judge", "preflight", "— judge: kept: preflight sources are real blocks")
	events, err := svc.Recent(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events (echo dropped), got %d: %+v", len(events), events)
	}
	for _, e := range events {
		if isJudgeEcho(e) {
			t.Errorf("echo kept: %+v", e)
		}
	}
}
