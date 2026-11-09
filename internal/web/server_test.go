package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// webHome is a temp HOME with two identities and an audit log that holds an
// unmasked canary token, as an old log line might.
func webHome(t *testing.T) (srv *httptest.Server, canary string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	canary = "gh" + "p_" + strings.Repeat("C", 36)
	for _, d := range []string{".claude-work", ".config/gh-work", ".claude", ".config/gh", "work"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := `group: ai-agents
user: ai-runner
default_identity: personal
identities:
  work: { claude_dir: ~/.claude-work, gh_dir: ~/.config/gh-work, git: { name: W, email: w@example.test } }
  personal: { claude_dir: ~/.claude, gh_dir: ~/.config/gh, git: { name: P, email: p@example.test } }
identity_bindings:
  ~/work: work
`
	now := time.Now().UTC()
	line := func(m map[string]any) string { b, _ := json.Marshal(m); return string(b) + "\n" }
	audit := line(map[string]any{"time": now.Add(-48 * time.Hour), "kind": "blocked", "rule": "deny_exec", "source": "preflight", "command": "curl x"}) +
		line(map[string]any{"time": now.Add(-time.Hour), "kind": "judge_decision", "identity": "work", "rule": "rules",
			"command": "Bash export T=" + canary, "detail": "token " + canary, "meta": map[string]string{"outcome": "deny"}}) +
		line(map[string]any{"time": now.Add(-time.Minute), "kind": "judge_override", "identity": "work", "rule": "rules",
			"detail": "allowed once by the user: ok", "meta": map[string]string{"os_user": "dev", "call_id": "abcdef123456"}})
	for name, content := range map[string]string{".aigate/config.yaml": cfg, ".aigate/audit.jsonl": audit} {
		p := filepath.Join(home, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv = httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, canary
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAPI_Decisions(t *testing.T) {
	srv, _ := webHome(t)
	code, body := get(t, srv.URL+"/api/decisions")
	var got struct {
		Decisions []struct{ Kind, Layer, Identity, OSUser string } `json:"decisions"`
	}
	if code != 200 || json.Unmarshal([]byte(body), &got) != nil || len(got.Decisions) != 3 {
		t.Fatalf("want 3 decisions: %d %s", code, body)
	}
	if got.Decisions[0].Kind != "judge_override" {
		t.Errorf("newest first: %+v", got.Decisions[0])
	}
	_, body = get(t, srv.URL+"/api/decisions?layer=judge&identity=work")
	if strings.Count(body, `"kind"`) != 2 {
		t.Errorf("layer+identity filter: %s", body)
	}
	_, body = get(t, srv.URL+"/api/decisions?since=24h")
	if strings.Contains(body, "deny_exec") {
		t.Errorf("since=24h must drop the 2-day-old block: %s", body)
	}
	if code, _ := get(t, srv.URL+"/api/decisions?since=yesterday"); code != 400 {
		t.Errorf("bad since must be 400, got %d", code)
	}
	_, body = get(t, srv.URL+"/api/decisions?kind=nothing")
	if !strings.Contains(body, `"decisions":[]`) {
		t.Errorf("empty result must be an empty list, not null: %s", body)
	}
}

func TestAPI_Identities(t *testing.T) {
	srv, _ := webHome(t)
	_, body := get(t, srv.URL+"/api/identities")
	for _, want := range []string{`"name":"personal"`, `"default":true`, `"name":"work"`, `"folders":["~/work"]`, `"claude_dir":"~/.claude-work"`, `"last_used"`, "aigate identity use work"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s in %s", want, body)
		}
	}
}

// TestDashboard_NeverShowsSecrets (R8): a raw token in the audit log is
// masked in every page and API response.
func TestDashboard_NeverShowsSecrets(t *testing.T) {
	srv, canary := webHome(t)
	for _, path := range []string{"/", "/api/overview", "/api/decisions", "/api/identities"} {
		code, body := get(t, srv.URL+path)
		if code != 200 {
			t.Errorf("%s: status %d", path, code)
		}
		if strings.Contains(body, canary) {
			t.Errorf("%s leaks the canary token", path)
		}
	}
}

func TestServer_DefaultsToLocalhost(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	s, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s.Addr(), "127.0.0.1:") {
		t.Errorf("default address must be loopback, got %s", s.Addr())
	}
}

// TestAPI_Overview_EmptyRuleListsAreArrays: a config without rules must give
// [] (not null) so the page script can read .length; null blanked the page.
func TestAPI_Overview_EmptyRuleListsAreArrays(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".aigate"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".aigate", "config.yaml"), []byte("group: ai-agents\nuser: ai-runner\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	_, body := get(t, srv.URL+"/api/overview")
	for _, k := range []string{"deny_read", "deny_exec", "allow_net", "allowed_paths"} {
		if strings.Contains(body, `"`+k+`":null`) {
			t.Errorf("%s is null in /api/overview: %s", k, body)
		}
	}
}

// TestDashboard_PageShowsSectionsAndHomeRelativePaths: the page renders its
// four sections and shows config/audit paths as ~/… (short, and no user name
// on screen when sharing it).
func TestDashboard_PageShowsSectionsAndHomeRelativePaths(t *testing.T) {
	srv, _ := webHome(t)
	_, body := get(t, srv.URL+"/")
	for _, want := range []string{`id="overview"`, `id="decisions"`, `id="identities"`, `id="policy"`, "<code>~/.aigate/config.yaml</code>", "<code>~/.aigate/audit.jsonl</code>"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %s", want)
		}
	}
	if home, _ := os.UserHomeDir(); strings.Contains(body, home) {
		t.Errorf("page shows the absolute home path %s", home)
	}
}
