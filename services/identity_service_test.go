package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AxeForging/aigate/domain"
)

// identityHome builds a temp HOME with two identities whose dirs exist.
func identityHome(t *testing.T) (home string, cfg *domain.Config) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	for _, d := range []string{".claude-work", ".config/gh-work", ".claude", ".config/gh", "work/api", "oss"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_work"), []byte("fake-key-for-tests"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = &domain.Config{
		DefaultIdentity: "personal",
		Identities: map[string]domain.Identity{
			"work": {
				ClaudeDir: "~/.claude-work", GhDir: "~/.config/gh-work",
				Git:    domain.GitAuthor{Name: "Test Work", Email: "work@example.test"},
				SSHKey: "~/.ssh/id_work",
			},
			"personal": {
				ClaudeDir: "~/.claude", GhDir: "~/.config/gh",
				Git: domain.GitAuthor{Name: "Test Me", Email: "me@example.test"},
			},
		},
		IdentityBindings: map[string]string{"~/work": "work", "~/oss": "personal"},
	}
	return home, cfg
}

func fatalProblems(ps []IdentityProblem) []string {
	var out []string
	for _, p := range ps {
		if p.Fatal {
			out = append(out, p.Message)
		}
	}
	return out
}

func TestValidate_ValidConfigHasNoFatalProblems(t *testing.T) {
	_, cfg := identityHome(t)
	if f := fatalProblems(NewIdentityService().Validate(cfg)); len(f) != 0 {
		t.Errorf("valid config reported fatal problems: %v", f)
	}
}

func TestValidate_NoIdentitiesIsValid(t *testing.T) {
	if ps := NewIdentityService().Validate(&domain.Config{}); len(ps) != 0 {
		t.Errorf("empty config should have no problems, got %v", ps)
	}
}

func TestValidate_Problems(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(c *domain.Config)
		wantFatal bool
		wantInMsg string
		wantFix   string
	}{
		{"bad name", func(c *domain.Config) { c.Identities["Bad Name!"] = c.Identities["work"] }, true, "invalid identity name", ""},
		{"missing claude_dir", func(c *domain.Config) {
			w := c.Identities["work"]
			w.ClaudeDir = ""
			c.Identities["work"] = w
		}, true, "claude_dir is required", ""},
		{"relative dir", func(c *domain.Config) {
			w := c.Identities["work"]
			w.GhDir = "gh-work"
			c.Identities["work"] = w
		}, true, "must be absolute or start with ~/", ""},
		{"dir does not exist", func(c *domain.Config) {
			w := c.Identities["work"]
			w.ClaudeDir = "~/.claude-new"
			c.Identities["work"] = w
		}, true, "does not exist", "mkdir -p"},
		{"ssh key missing", func(c *domain.Config) {
			w := c.Identities["work"]
			w.SSHKey = "~/.ssh/nope"
			c.Identities["work"] = w
		}, true, "ssh_key", ""},
		{"shared dir between identities", func(c *domain.Config) {
			p := c.Identities["personal"]
			p.GhDir = "~/.config/gh-work"
			c.Identities["personal"] = p
		}, true, "overlaps", ""},
		{"nested dir between identities", func(c *domain.Config) {
			p := c.Identities["personal"]
			p.ClaudeDir = "~/.config"
			c.Identities["personal"] = p
		}, true, "overlaps", ""},
		{"unknown default", func(c *domain.Config) { c.DefaultIdentity = "ghost" }, true, "default_identity", "aigate identity add ghost"},
		{"binding to unknown", func(c *domain.Config) { c.IdentityBindings["~/x"] = "ghost" }, true, "ghost", ""},
		{"bad pass_env name", func(c *domain.Config) {
			w := c.Identities["work"]
			w.PassEnv = []string{"NOT VALID"}
			c.Identities["work"] = w
		}, true, "pass_env", ""},
		{"missing git email is a warning", func(c *domain.Config) {
			w := c.Identities["work"]
			w.Git.Email = ""
			c.Identities["work"] = w
		}, false, "git.email", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, cfg := identityHome(t)
			tt.mutate(cfg)
			var hit *IdentityProblem
			for _, p := range NewIdentityService().Validate(cfg) {
				if strings.Contains(p.Message, tt.wantInMsg) {
					hit = &p
					break
				}
			}
			if hit == nil {
				t.Fatalf("no problem containing %q", tt.wantInMsg)
			}
			if hit.Fatal != tt.wantFatal {
				t.Errorf("Fatal = %v, want %v (%s)", hit.Fatal, tt.wantFatal, hit.Message)
			}
			if tt.wantFix != "" && !strings.Contains(hit.Fix, tt.wantFix) {
				t.Errorf("Fix = %q, want it to contain %q", hit.Fix, tt.wantFix)
			}
		})
	}
}

func TestResolve_Precedence(t *testing.T) {
	home, cfg := identityHome(t)
	tests := []struct {
		name       string
		flag       string
		workDir    string
		noDefault  bool
		wantName   string
		wantReason string
	}{
		{"flag wins over binding", "personal", home + "/work/api", false, "personal", "--identity flag"},
		{"nearest binding", "", home + "/work/api", false, "work", "folder ~/work"},
		{"binding exact dir", "", home + "/oss", false, "personal", "folder ~/oss"},
		{"default when unbound", "", home, false, "personal", "default_identity"},
		{"none without default", "", home, true, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := *cfg
			if tt.noDefault {
				c.DefaultIdentity = ""
			}
			got, err := NewIdentityService().Resolve(&c, tt.flag, tt.workDir)
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}
			if tt.wantName == "" {
				if got != nil {
					t.Fatalf("want no identity, got %q", got.Name)
				}
				return
			}
			if got == nil || got.Name != tt.wantName || got.Reason != tt.wantReason {
				t.Fatalf("got %+v, want %s (%s)", got, tt.wantName, tt.wantReason)
			}
			if !filepath.IsAbs(got.ClaudeDir) || !filepath.IsAbs(got.GhDir) {
				t.Errorf("paths not expanded: %+v", got.Identity)
			}
		})
	}
}

func TestResolve_NestedBindingPicksDeepest(t *testing.T) {
	home, cfg := identityHome(t)
	cfg.IdentityBindings["~/work/api"] = "personal"
	got, err := NewIdentityService().Resolve(cfg, "", home+"/work/api/sub")
	if err != nil || got == nil || got.Name != "personal" {
		t.Fatalf("want deepest binding personal, got %+v err=%v", got, err)
	}
}

func TestResolve_BindingPrefixIsNotPathPrefix(t *testing.T) {
	home, cfg := identityHome(t)
	cfg.DefaultIdentity = ""
	got, err := NewIdentityService().Resolve(cfg, "", home+"/workshop")
	if err != nil || got != nil {
		t.Fatalf("~/work must not match ~/workshop, got %+v err=%v", got, err)
	}
}

func TestResolve_Errors(t *testing.T) {
	home, cfg := identityHome(t)
	_, err := NewIdentityService().Resolve(cfg, "ghost", home)
	if err == nil || !strings.Contains(err.Error(), "personal, work") || !strings.Contains(err.Error(), "aigate identity add ghost") {
		t.Errorf("unknown flag error should list identities and the add command, got %v", err)
	}
	_, err = NewIdentityService().Resolve(&domain.Config{}, "work", home)
	if err == nil || !strings.Contains(err.Error(), "aigate identity add") {
		t.Errorf("flag without identities should point to identity add, got %v", err)
	}
	got, err := NewIdentityService().Resolve(&domain.Config{}, "", home)
	if err != nil || got != nil {
		t.Errorf("no identities and no flag must resolve to none, got %+v err=%v", got, err)
	}
}

func TestEffectiveAllowedPaths_DropsBroadDefaultsAndAddsIdentityDirs(t *testing.T) {
	home, cfg := identityHome(t)
	cfg.AllowedPaths = NewConfigService().InitDefaultConfig().AllowedPaths
	svc := NewIdentityService()
	id, err := svc.Resolve(cfg, "work", home)
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.EffectiveAllowedPaths(cfg, id, home+"/work/api")
	if err != nil {
		t.Fatalf("EffectiveAllowedPaths() error = %v", err)
	}
	for _, broad := range []string{"/.config", "/.local", "/.claude", "/.claude.json"} {
		if containsString(got, home+broad) {
			t.Errorf("broad default %s must be dropped under an identity: %v", broad, got)
		}
	}
	for _, want := range []string{home + "/.claude-work", home + "/.config/gh-work", home + "/.cache"} {
		if !containsString(got, want) {
			t.Errorf("want %s in %v", want, got)
		}
	}
	for _, p := range got {
		if underAny(p, []string{home + "/.claude", home + "/.config/gh"}) || p == home+"/.claude" {
			t.Errorf("other identity's dir reachable via %s", p)
		}
	}
}

func TestEffectiveAllowedPaths_ConflictNamesPathAndIdentity(t *testing.T) {
	home, cfg := identityHome(t)
	tests := []struct{ name, allowed string }{
		{"parent of other identity dir", "~/.config"},
		{"equal to other identity dir", "~/.claude"},
		{"inside other identity dir", "~/.config/gh/hosts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := *cfg
			c.AllowedPaths = nil
			w := c.Identities["work"]
			w.AllowedPaths = []string{tt.allowed}
			c.Identities = map[string]domain.Identity{"work": w, "personal": cfg.Identities["personal"]}
			svc := NewIdentityService()
			id, err := svc.Resolve(&c, "work", home)
			if err != nil {
				t.Fatal(err)
			}
			_, err = svc.EffectiveAllowedPaths(&c, id, home)
			if err == nil || !strings.Contains(err.Error(), `"personal"`) || !strings.Contains(err.Error(), "allowed path") {
				t.Errorf("want conflict error naming personal, got %v", err)
			}
		})
	}
}

func TestEffectiveAllowedPaths_NoIdentityKeepsConfig(t *testing.T) {
	_, cfg := identityHome(t)
	cfg.AllowedPaths = []string{"~/.config"}
	got, err := NewIdentityService().EffectiveAllowedPaths(cfg, nil, "/tmp")
	if err != nil || len(got) != 1 || got[0] != "~/.config" {
		t.Errorf("without identity allowed_paths must be unchanged, got %v err=%v", got, err)
	}
}

func TestLoadProject_RejectsIdentityKeys(t *testing.T) {
	for _, key := range []string{"identity: work", "default_identity: work", "identities: {}", "identity_bindings: {}"} {
		t.Run(key, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ".aigate.yaml"), []byte("deny_read: [x]\n"+key+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := NewConfigService().LoadProject(dir)
			if err == nil || !strings.Contains(err.Error(), "aigate identity use") {
				t.Errorf("project config with %q must be refused with the bind command, got %v", key, err)
			}
		})
	}
}

func TestLoadProject_WithoutIdentityKeysStillLoads(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".aigate.yaml"), []byte("deny_read: [secret.txt]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := NewConfigService().LoadProject(dir)
	if err != nil || cfg == nil || len(cfg.DenyRead) != 1 {
		t.Errorf("plain project config should load, got %+v err=%v", cfg, err)
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
