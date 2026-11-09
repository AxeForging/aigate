package actions

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/services"
	"github.com/urfave/cli"
)

// Add creates an identity: dirs, config entry, optional folder binding, and
// (interactively, or with --login) Claude + gh logins inside its sandbox.
func (a *IdentityAction) Add(c *cli.Context) error {
	cfg, err := a.load()
	if err != nil {
		return err
	}
	name := c.Args().First()
	if name == "" {
		return fmt.Errorf("usage: aigate identity add NAME   (e.g. aigate identity add work)")
	}
	if _, exists := cfg.Identities[name]; exists {
		return fmt.Errorf("identity %q already exists. See: aigate identity show %s", name, name)
	}
	p := newPrompter(c.Bool("yes"))
	first := len(cfg.Identities) == 0

	id := domain.Identity{
		ClaudeDir: c.String("claude-dir"),
		GhDir:     c.String("gh-dir"),
		Git:       domain.GitAuthor{Name: c.String("git-name"), Email: c.String("git-email")},
		SSHKey:    c.String("ssh-key"),
	}
	if id.ClaudeDir == "" && id.GhDir == "" && first && existingLogins() &&
		p.confirm(fmt.Sprintf("Found your current logins in ~/.claude and ~/.config/gh. Use them for %q (nothing is moved)?", name), true) {
		id.ClaudeDir, id.GhDir = "~/.claude", "~/.config/gh"
	}
	if id.ClaudeDir == "" {
		id.ClaudeDir = p.ask("Claude folder", "~/.claude-"+name)
	}
	if id.GhDir == "" {
		id.GhDir = p.ask("GitHub CLI folder", "~/.config/gh-"+name)
	}
	if id.Git.Name == "" {
		id.Git.Name = p.ask("Git author name", gitGlobal("user.name"))
	}
	if id.Git.Email == "" {
		id.Git.Email = p.ask("Git author email", gitGlobal("user.email"))
	}
	if id.SSHKey == "" && !c.Bool("yes") {
		id.SSHKey = p.choose("SSH key for git (Enter = none)", sshKeyCandidates())
	}

	for _, d := range []string{id.ClaudeDir, id.GhDir} {
		if err := os.MkdirAll(expand(d), 0o700); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
	}
	if cfg.Identities == nil {
		cfg.Identities = map[string]domain.Identity{}
	}
	cfg.Identities[name] = id
	if first || c.Bool("default") {
		cfg.DefaultIdentity = name
	}
	if err := firstFatal(services.NewIdentityService().Validate(cfg), name); err != nil {
		return err // nothing saved yet
	}
	bound := ""
	if c.Bool("use") {
		wd, _ := os.Getwd()
		bound = tildePath(wd)
		if cfg.IdentityBindings == nil {
			cfg.IdentityBindings = map[string]string{}
		}
		cfg.IdentityBindings[bound] = name
	}
	if err := a.configSvc.SaveGlobal(cfg); err != nil {
		return err
	}

	fmt.Printf("\nCreated identity %q", name)
	if cfg.DefaultIdentity == name {
		fmt.Print(" (default)")
	}
	fmt.Println(".")
	if bound != "" {
		fmt.Printf("%s now uses it.\n", bound)
	}

	login := c.Bool("login") || (!c.Bool("yes") && p.interactive)
	for _, l := range []struct{ bin, label string }{{"claude", "Claude"}, {"gh", "GitHub CLI"}} {
		args := map[string][]string{"claude": nil, "gh": {"auth", "login"}}[l.bin]
		later := fmt.Sprintf("aigate run --identity %s -- %s", name, strings.TrimSpace(l.bin+" "+strings.Join(args, " ")))
		if _, err := exec.LookPath(l.bin); err != nil {
			fmt.Printf("%s (%s) is not installed. Log in later with: %s\n", l.label, l.bin, later)
			continue
		}
		if !login || !p.confirm(fmt.Sprintf("Log in to %s for %q now?", l.label, name), true) {
			fmt.Printf("Log in to %s later with: %s\n", l.label, later)
			continue
		}
		if err := a.runLogin(cfg, name, l.bin, args); err != nil {
			fmt.Printf("%s login didn't finish (%v). Retry with: %s\n", l.label, err, later)
		}
	}
	fmt.Printf("\nNext: cd into a project and run `aigate identity use %s`, or `aigate run --identity %s -- claude`.\n", name, name)
	return nil
}

// runLogin runs a login command inside the identity's sandbox: only its own
// files are visible, but the network allowlist is skipped so browser/device
// login flows can reach their sites.
func (a *IdentityAction) runLogin(global *domain.Config, name, bin string, args []string) error {
	merged := *global
	workDir := expand(global.Identities[name].ClaudeDir)
	id, err := resolveRunIdentity(global, &merged, name, workDir)
	if err != nil {
		return err
	}
	merged.AllowNet = nil
	return a.runner.Run(domain.SandboxProfile{Config: merged, WorkDir: workDir, Identity: id}, bin, args)
}

func firstFatal(ps []services.IdentityProblem, name string) error {
	for _, p := range ps {
		if p.Fatal && (p.Identity == "" || p.Identity == name) {
			if p.Fix != "" {
				return fmt.Errorf("%s. Fix: %s", p.Message, p.Fix)
			}
			return fmt.Errorf("%s", p.Message)
		}
	}
	return nil
}

func existingLogins() bool {
	for _, d := range []string{"~/.claude", "~/.config/gh"} {
		if fi, err := os.Stat(expand(d)); err == nil && fi.IsDir() {
			return true
		}
	}
	return false
}

func gitGlobal(key string) string {
	out, err := exec.Command("git", "config", "--global", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// sshKeyCandidates lists private keys in ~/.ssh as ~/… paths.
func sshKeyCandidates() []string {
	matches, _ := filepath.Glob(expand("~/.ssh/id_*"))
	var keys []string
	for _, m := range matches {
		if !strings.HasSuffix(m, ".pub") {
			keys = append(keys, tildePath(m))
		}
	}
	return keys
}
