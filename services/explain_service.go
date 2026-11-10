package services

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/AxeForging/aigate/domain"
)

// Access levels a sandboxed session gets.
const (
	AccessReadWrite = "read-write"
	AccessReadOnly  = "read-only"
	AccessHidden    = "hidden"
	AccessBlocked   = "blocked"
	AccessAllowed   = "allowed"  // commands
	AccessAsk       = "asks you" // judge
)

// Explanation says what aigate would do with a path or command, which layer
// decides and how to change it. Nothing is run to find out.
type Explanation struct {
	Subject string        `json:"subject"`
	Kind    string        `json:"kind"` // path | command
	Access  string        `json:"access"`
	Allowed bool          `json:"allowed"`
	Layer   string        `json:"layer,omitempty"`
	Rule    string        `json:"rule,omitempty"`
	Reason  string        `json:"reason"`
	Fix     string        `json:"fix,omitempty"`
	Parts   []Explanation `json:"parts,omitempty"` // paths and judge verdict inside a command
}

// ExplainPath mirrors the sandbox's mount order: aigate's config, deny_read
// (except the identity's own ssh key), other identities, then scope.
func ExplainPath(profile domain.SandboxProfile, global *domain.Config, raw string) Explanation {
	p := absPath(raw, profile.WorkDir)
	e := Explanation{Subject: TildePath(p), Kind: "path"}
	home, _ := os.UserHomeDir()
	home = CanonicalPath(home)

	if underAny(p, []string{filepath.Join(home, ".aigate")}) {
		return e.set(AccessHidden, LayerSandbox, "aigate config", "aigate's own config and audit log are always hidden from agents", "")
	}
	if id := profile.Identity; id != nil && id.SSHKey != "" && p == CanonicalPath(id.SSHKey) {
		return e.set(AccessReadOnly, LayerIdentity, "ssh_key", fmt.Sprintf("identity %q's ssh key, mounted read-only", id.Name), "")
	}
	for _, pattern := range profile.Config.DenyRead {
		paths, _ := resolvePatterns([]string{pattern}, profile.WorkDir)
		for _, d := range paths {
			if d = CanonicalPath(d); p == d || underAny(p, []string{d}) {
				return e.set(AccessBlocked, LayerRule, "deny_read "+pattern, fmt.Sprintf("matches deny_read %q", pattern),
					"aigate allow read "+shellArg(pattern)+"   # or remove it from .aigate.yaml if the project set it")
			}
		}
	}
	if id := profile.Identity; id != nil && global != nil {
		for _, other := range sortedIdentityNames(global) {
			if other == id.Name {
				continue
			}
			o, err := NewIdentityService().Resolve(global, other, "")
			if err != nil {
				continue
			}
			for _, dir := range []string{o.ClaudeDir, o.GhDir, o.SSHKey} {
				if dir != "" && (p == CanonicalPath(dir) || underAny(p, []string{CanonicalPath(dir)})) {
					return e.set(AccessHidden, LayerIdentity, "identity "+other,
						fmt.Sprintf("belongs to identity %q; sessions as %q can't see it", other, id.Name), "aigate run --identity "+other+" -- …")
				}
			}
		}
	}
	if runtimeDirs := userRuntimeDirsAll(); underAny(p, runtimeDirs) {
		return e.set(AccessHidden, LayerSandbox, "runtime dir", "agent and keyring sockets live here; always hidden", "")
	}
	wd := CanonicalPath(profile.WorkDir)
	if p == wd || underAny(p, []string{wd}) {
		return e.set(AccessReadWrite, LayerSandbox, "working dir", "inside the working directory", "")
	}
	if !underAny(p, []string{home}) {
		if p == "/tmp" || underAny(p, []string{"/tmp"}) {
			return e.set(AccessReadWrite, LayerSandbox, "private /tmp", "the sandbox gets its own empty /tmp; the host's /tmp isn't visible", "")
		}
		return e.set(AccessReadOnly, LayerSandbox, "system", "outside $HOME: readable, never writable", "")
	}
	if len(profile.Config.AllowedPaths) == 0 {
		return e.set(AccessReadWrite, LayerSandbox, "scope off",
			"filesystem scope is off, so all of $HOME is reachable", DefaultScopeFix())
	}
	if wd == home {
		return e.set(AccessReadWrite, LayerSandbox, "scope unenforced", "running from $HOME itself makes all of $HOME the working dir", "cd into a project folder first")
	}
	for _, s := range resolveScopedPaths(profile) {
		if s = CanonicalPath(s); p == s || underAny(p, []string{s}) {
			return e.set(AccessReadWrite, LayerSandbox, "allowed_paths", "inside allowed path "+TildePath(s), "")
		}
	}
	dir := TildePath(nearestDir(p))
	return e.set(AccessHidden, LayerSandbox, "scope", "outside the working dir and allowed_paths",
		"aigate run --allow-path "+shellArg(dir)+" -- …   # this session only; or: aigate allow path "+shellArg(dir))
}

// ExplainCommand checks deny_exec, the network allow-list, any paths in the
// arguments and (when the judge is on) the local rules — or the full judge
// chain when withModels is set.
func ExplainCommand(profile domain.SandboxProfile, global *domain.Config, args []string, withModels bool) Explanation {
	e := Explanation{Subject: strings.Join(args, " "), Kind: "command"}
	base := filepath.Base(args[0])
	for _, entry := range profile.Config.DenyExec {
		name, sub, hasSub := strings.Cut(entry, " ")
		if name != base && name != args[0] {
			continue
		}
		if !hasSub || containsPath(args[1:], sub) {
			return e.set(AccessBlocked, LayerRule, "deny_exec "+entry, fmt.Sprintf("%q is in deny_exec", entry), "aigate allow exec "+shellArg(entry))
		}
	}
	if allow := profile.Config.AllowNet; len(allow) > 0 {
		for _, a := range args[1:] {
			u, err := url.Parse(a)
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				continue
			}
			if host := u.Hostname(); !containsPath(allow, host) {
				return e.set(AccessBlocked, LayerSandbox, "allow_net", host+" is not in allow_net (all other outbound traffic is dropped)", "aigate allow net "+host)
			}
		}
	}
	worst := e.set(AccessAllowed, LayerSandbox, "", "no rule blocks this command", "")
	for _, a := range args[1:] {
		if !looksLikePath(a, profile.WorkDir) {
			continue
		}
		pe := ExplainPath(profile, global, a)
		worst.Parts = append(worst.Parts, pe)
		if !pe.Allowed && worst.Allowed {
			worst.Access, worst.Allowed, worst.Layer, worst.Rule = pe.Access, false, pe.Layer, pe.Rule
			worst.Reason, worst.Fix = "it reads "+pe.Subject+", which is "+pe.Access+": "+pe.Reason, pe.Fix
		}
	}
	if global != nil && global.Judge.Enabled {
		s, err := ResolveJudgeSettings(global.Judge)
		if err == nil {
			call := Call{Event: EventPreTool, Tool: "Bash", Target: e.Subject}
			chain := &Chain{Rules: RulesJudge{}}
			if withModels {
				chain = BuildJudgeChain(s)
			}
			v := chain.Decide(context.Background(), call)
			if v.Outcome != NoObjection {
				je := Explanation{Subject: "judge (" + v.Judge + ")", Kind: "judge", Layer: LayerJudge, Rule: v.Judge, Reason: v.Reason, Fix: JudgeFix(call)}
				je.Access, je.Allowed = AccessAsk, v.Outcome == Ask
				if v.Outcome == Deny {
					je.Access = AccessBlocked
				}
				worst.Parts = append(worst.Parts, je)
				switch {
				case worst.Allowed && v.Outcome == Deny:
					worst.Access, worst.Allowed, worst.Layer, worst.Rule, worst.Reason, worst.Fix = AccessBlocked, false, LayerJudge, v.Judge, v.Reason, je.Fix
				case worst.Allowed && worst.Access == AccessAllowed:
					worst.Access, worst.Layer, worst.Rule, worst.Reason, worst.Fix = AccessAsk, LayerJudge, v.Judge, v.Reason, je.Fix
				}
			}
		}
	}
	return worst
}

func (e Explanation) set(access, layer, rule, reason, fix string) Explanation {
	e.Access, e.Layer, e.Rule, e.Reason, e.Fix = access, layer, rule, reason, fix
	e.Allowed = access == AccessReadWrite || access == AccessReadOnly || access == AccessAllowed
	return e
}

func absPath(raw, workDir string) string {
	p, err := expandHome(raw)
	if err != nil {
		p = filepath.Join(workDir, raw)
	}
	return CanonicalPath(p)
}

// looksLikePath: ~/x, /x, ./x, ../x, or an existing file in the workdir.
func looksLikePath(a, workDir string) bool {
	if strings.HasPrefix(a, "-") || strings.Contains(a, "://") {
		return false
	}
	if strings.HasPrefix(a, "~") || strings.HasPrefix(a, "/") || strings.HasPrefix(a, "./") || strings.HasPrefix(a, "../") {
		return true
	}
	return exists(filepath.Join(workDir, a))
}

// nearestDir is p if it is a folder, else its parent.
func nearestDir(p string) string {
	if fi, err := os.Stat(p); err == nil && fi.IsDir() {
		return p
	}
	return filepath.Dir(p)
}

func shellArg(s string) string {
	if strings.ContainsAny(s, " *?'\"$\\") {
		return singleQuote(s)
	}
	return s
}

// userRuntimeDirsAll lists runtime dirs hidden on this OS (none on macOS).
func userRuntimeDirsAll() []string {
	var out []string
	for _, d := range []string{fmt.Sprintf("/run/user/%d", os.Getuid()), os.Getenv("XDG_RUNTIME_DIR")} {
		if d != "" && d != "/" && d != "/tmp" && filepath.IsAbs(d) && exists(d) {
			out = append(out, CanonicalPath(d))
		}
	}
	return out
}
