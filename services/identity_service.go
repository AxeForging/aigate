package services

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/AxeForging/aigate/domain"
)

var (
	identityNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	envNameRe      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// broadAllowedPaths are default allowed_paths entries that can hold any
// identity's credentials. They are dropped when an identity is active.
var broadAllowedPaths = []string{"~", "~/.config", "~/.local", "~/.local/share", "~/.claude", "~/.claude.json"}

// identityBaseAllowedPaths replace them: what agent tools need to run
// (caches, installed binaries) without exposing anyone's logins.
var identityBaseAllowedPaths = []string{"~/.cache", "~/.npm", "~/.local/bin", "~/.local/share/claude"}

// IdentityProblem is a config issue, with the command that fixes it when
// there is one. Fatal problems stop a run.
type IdentityProblem struct {
	Identity string
	Message  string
	Fix      string
	Fatal    bool
}

type IdentityService struct{}

func NewIdentityService() *IdentityService {
	return &IdentityService{}
}

// Validate reports every identity problem in cfg. No identities → none.
func (s *IdentityService) Validate(cfg *domain.Config) []IdentityProblem {
	var ps []IdentityProblem
	owners := map[string]string{} // expanded dir → identity
	for _, name := range sortedIdentityNames(cfg) {
		ps = append(ps, s.validateOne(name, cfg.Identities[name], owners)...)
	}
	if cfg.DefaultIdentity != "" {
		if _, ok := cfg.Identities[cfg.DefaultIdentity]; !ok {
			ps = append(ps, IdentityProblem{
				Message: fmt.Sprintf("default_identity %q is not defined", cfg.DefaultIdentity),
				Fix:     "aigate identity add " + cfg.DefaultIdentity, Fatal: true,
			})
		}
	}
	for dir, name := range cfg.IdentityBindings {
		if _, ok := cfg.Identities[name]; !ok {
			ps = append(ps, IdentityProblem{
				Message: fmt.Sprintf("folder %s is bound to undefined identity %q", dir, name),
				Fix:     "aigate identity add " + name, Fatal: true,
			})
		}
		if _, err := expandHome(dir); err != nil {
			ps = append(ps, IdentityProblem{Message: fmt.Sprintf("identity_bindings: %v", err), Fatal: true})
		}
	}
	return ps
}

func (s *IdentityService) validateOne(name string, id domain.Identity, owners map[string]string) []IdentityProblem {
	var ps []IdentityProblem
	bad := func(msg, fix string) {
		ps = append(ps, IdentityProblem{Identity: name, Message: fmt.Sprintf("identity %q: %s", name, msg), Fix: fix, Fatal: true})
	}
	if !identityNameRe.MatchString(name) {
		bad("invalid identity name (use lowercase letters, digits, - or _)", "")
	}
	for _, d := range []struct{ key, val string }{{"claude_dir", id.ClaudeDir}, {"gh_dir", id.GhDir}} {
		if d.val == "" {
			bad(d.key+" is required", "aigate identity add "+name)
			continue
		}
		p, err := expandHome(d.val)
		if err != nil {
			bad(fmt.Sprintf("%s: %v", d.key, err), "")
			continue
		}
		if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
			bad(fmt.Sprintf("%s %s does not exist", d.key, d.val), "mkdir -p "+p)
		}
		for other, owner := range owners {
			if owner != name && (p == other || underAny(p, []string{other}) || underAny(other, []string{p})) {
				// Global: it concerns two identities, so it blocks every run.
				ps = append(ps, IdentityProblem{Fatal: true, Message: fmt.Sprintf(
					"identity %q: %s %s overlaps identity %q (%s); each identity needs its own dirs", name, d.key, d.val, owner, other)})
			}
		}
		owners[p] = name
	}
	if id.SSHKey != "" {
		p, err := expandHome(id.SSHKey)
		if err != nil {
			bad(fmt.Sprintf("ssh_key: %v", err), "")
		} else if fi, err := os.Stat(p); err != nil || fi.IsDir() {
			bad(fmt.Sprintf("ssh_key %s is not a readable file", id.SSHKey), "ls -l "+p)
		}
	}
	for _, v := range id.PassEnv {
		if !envNameRe.MatchString(v) {
			bad(fmt.Sprintf("pass_env entry %q is not a valid variable name", v), "")
		}
	}
	if id.Git.Email == "" {
		ps = append(ps, IdentityProblem{
			Identity: name,
			Message:  fmt.Sprintf("identity %q: git.email is empty; commits will use your global git author", name),
			Fix:      fmt.Sprintf("set identities.%s.git.email in ~/.aigate/config.yaml", name),
		})
	}
	return ps
}

// Resolve picks the identity for a run: --identity flag, then the deepest
// bound folder containing workDir, then default_identity, then none (nil).
func (s *IdentityService) Resolve(cfg *domain.Config, flag, workDir string) (*domain.ResolvedIdentity, error) {
	if flag != "" {
		if _, ok := cfg.Identities[flag]; !ok {
			if len(cfg.Identities) == 0 {
				return nil, fmt.Errorf("no identities configured yet. Create one: aigate identity add %s", flag)
			}
			return nil, fmt.Errorf("unknown identity %q. Available: %s. Create it: aigate identity add %s",
				flag, strings.Join(sortedIdentityNames(cfg), ", "), flag)
		}
		return s.expand(cfg, flag, "--identity flag")
	}
	if name, dir := deepestBinding(cfg.IdentityBindings, workDir); name != "" {
		if _, ok := cfg.Identities[name]; !ok {
			return nil, fmt.Errorf("folder %s is bound to undefined identity %q. Fix: aigate identity add %s", dir, name, name)
		}
		return s.expand(cfg, name, "folder "+dir)
	}
	if cfg.DefaultIdentity != "" {
		if _, ok := cfg.Identities[cfg.DefaultIdentity]; !ok {
			return nil, fmt.Errorf("default_identity %q is not defined. Fix: aigate identity add %s", cfg.DefaultIdentity, cfg.DefaultIdentity)
		}
		return s.expand(cfg, cfg.DefaultIdentity, "default_identity")
	}
	return nil, nil
}

func (s *IdentityService) expand(cfg *domain.Config, name, reason string) (*domain.ResolvedIdentity, error) {
	id := cfg.Identities[name]
	out := &domain.ResolvedIdentity{Name: name, Reason: reason, Identity: id}
	var err error
	if out.ClaudeDir, err = expandHome(id.ClaudeDir); err != nil {
		return nil, fmt.Errorf("identity %q claude_dir: %w", name, err)
	}
	if out.GhDir, err = expandHome(id.GhDir); err != nil {
		return nil, fmt.Errorf("identity %q gh_dir: %w", name, err)
	}
	if id.SSHKey != "" {
		if out.SSHKey, err = expandHome(id.SSHKey); err != nil {
			return nil, fmt.Errorf("identity %q ssh_key: %w", name, err)
		}
	}
	return out, nil
}

// EffectiveAllowedPaths returns the allowed_paths for a run. Without an
// identity, cfg.AllowedPaths is returned unchanged. With one, broad defaults
// are replaced by narrow ones plus the identity's dirs, and any path that
// would expose another identity is an error naming both.
func (s *IdentityService) EffectiveAllowedPaths(cfg *domain.Config, id *domain.ResolvedIdentity, workDir string) ([]string, error) {
	if id == nil {
		return cfg.AllowedPaths, nil
	}
	broad, err := resolvePatterns(broadAllowedPaths, workDir)
	if err != nil {
		return nil, err
	}
	// Global entries (often the init defaults) lose their broad paths quietly;
	// paths the identity lists itself are kept and conflict-checked below.
	global, err := resolvePatterns(append(append([]string{}, identityBaseAllowedPaths...), cfg.AllowedPaths...), workDir)
	if err != nil {
		return nil, err
	}
	own, err := resolvePatterns(id.AllowedPaths, workDir)
	if err != nil {
		return nil, err
	}
	paths := []string{id.ClaudeDir, id.GhDir}
	add := func(p string) {
		if p = filepath.Clean(p); !containsPath(paths, p) {
			paths = append(paths, p)
		}
	}
	for _, p := range global {
		if !containsPath(broad, filepath.Clean(p)) {
			add(p)
		}
	}
	for _, p := range own {
		add(p)
	}

	for _, other := range sortedIdentityNames(cfg) {
		if other == id.Name {
			continue
		}
		o, err := s.expand(cfg, other, "")
		if err != nil {
			return nil, err
		}
		for _, protected := range []string{o.ClaudeDir, o.GhDir, o.SSHKey} {
			if protected == "" {
				continue
			}
			for _, p := range paths {
				if p == protected || underAny(p, []string{protected}) || underAny(protected, []string{p}) {
					return nil, fmt.Errorf("allowed path %s exposes identity %q (%s). Remove it from allowed_paths, or run without --identity", p, other, protected)
				}
			}
		}
	}
	return paths, nil
}

// expandHome turns "~" / "~/x" into absolute paths; other values must
// already be absolute.
func expandHome(p string) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home for %q: %w", p, err)
		}
		return filepath.Join(home, strings.TrimPrefix(p, "~")), nil
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("%q must be absolute or start with ~/", p)
	}
	return filepath.Clean(p), nil
}

// deepestBinding returns the identity bound to the deepest folder that
// contains workDir, and that folder as written in config.
func deepestBinding(bindings map[string]string, workDir string) (name, dir string) {
	wd := filepath.Clean(workDir)
	best := -1
	for raw, n := range bindings {
		p, err := expandHome(raw)
		if err != nil || !underAny(wd, []string{p}) {
			continue
		}
		if len(p) > best || (len(p) == best && raw < dir) {
			best, name, dir = len(p), n, raw
		}
	}
	return name, dir
}

func sortedIdentityNames(cfg *domain.Config) []string {
	names := make([]string, 0, len(cfg.Identities))
	for n := range cfg.Identities {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func containsPath(list []string, p string) bool {
	for _, v := range list {
		if v == p {
			return true
		}
	}
	return false
}
