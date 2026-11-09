package actions

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/helpers"
	"github.com/AxeForging/aigate/services"
	"github.com/urfave/cli"
)

// noneIdentity is the reserved name that unbinds a folder.
const noneIdentity = "none"

type IdentityAction struct {
	configSvc *services.ConfigService
	idSvc     *services.IdentityService
	runner    *services.RunnerService // runs logins inside the identity's sandbox
}

func NewIdentityAction(c *services.ConfigService, r *services.RunnerService) *IdentityAction {
	return &IdentityAction{configSvc: c, idSvc: services.NewIdentityService(), runner: r}
}

func (a *IdentityAction) load() (*domain.Config, error) {
	cfg, err := a.configSvc.LoadGlobal()
	if err != nil {
		return nil, helpers.ErrNotInitialized
	}
	return cfg, nil
}

// List prints every identity; "*" marks the one active in this folder.
func (a *IdentityAction) List(c *cli.Context) error {
	cfg, err := a.load()
	if err != nil {
		return err
	}
	if len(cfg.Identities) == 0 {
		fmt.Println("No identities yet. Create one: aigate identity add NAME")
		return nil
	}
	workDir, _ := os.Getwd()
	active, _ := a.idSvc.Resolve(cfg, "", workDir)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "\tNAME\tGIT\tCLAUDE\tGH\tFOLDERS")
	for _, name := range sortedNames(cfg) {
		id := cfg.Identities[name]
		mark := ""
		if active != nil && active.Name == name {
			mark = "*"
		}
		label := name
		if cfg.DefaultIdentity == name {
			label += " (default)"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", mark, label, gitLabel(id.Git), id.ClaudeDir, id.GhDir,
			orDash(strings.Join(boundFolders(cfg, name), ", ")))
	}
	_ = w.Flush()
	if active != nil {
		fmt.Printf("\n* active here (%s)\n", active.Reason)
	}
	return nil
}

// Show prints one identity, what a session under it can see, and problems.
func (a *IdentityAction) Show(c *cli.Context) error {
	cfg, err := a.load()
	if err != nil {
		return err
	}
	name := c.Args().First()
	if name == "" {
		return fmt.Errorf("usage: aigate identity show NAME (see: aigate identity list)")
	}
	id, err := a.idSvc.Resolve(cfg, name, "")
	if err != nil {
		return err
	}
	printIdentity(cfg, id)
	printProblems(a.idSvc.Validate(cfg), name)
	return nil
}

// Use binds a folder (default: current) to an identity; "none" unbinds it.
func (a *IdentityAction) Use(c *cli.Context) error {
	cfg, err := a.load()
	if err != nil {
		return err
	}
	name := c.Args().First()
	if name == "" {
		return fmt.Errorf("usage: aigate identity use NAME [FOLDER]  (NAME \"none\" unbinds the folder)")
	}
	dir := c.Args().Get(1)
	if dir == "" {
		dir, _ = os.Getwd()
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if fi, err := os.Stat(abs); err != nil || !fi.IsDir() {
		return fmt.Errorf("%s is not a folder", dir)
	}
	key := tildePath(abs)

	if name == noneIdentity {
		removed := false
		for k := range cfg.IdentityBindings {
			if tildePath(expand(k)) == key {
				delete(cfg.IdentityBindings, k)
				removed = true
			}
		}
		if !removed {
			fmt.Printf("%s has no identity binding. Nothing to do.\n", key)
			return nil
		}
		if err := a.configSvc.SaveGlobal(cfg); err != nil {
			return err
		}
		fmt.Printf("%s is no longer bound to an identity. Check: aigate whoami\n", key)
		return nil
	}

	if _, ok := cfg.Identities[name]; !ok {
		_, err := a.idSvc.Resolve(cfg, name, "") // reuses the "unknown identity" message
		return err
	}
	if cfg.IdentityBindings == nil {
		cfg.IdentityBindings = map[string]string{}
	}
	for k := range cfg.IdentityBindings {
		if tildePath(expand(k)) == key {
			delete(cfg.IdentityBindings, k)
		}
	}
	cfg.IdentityBindings[key] = name
	if err := a.configSvc.SaveGlobal(cfg); err != nil {
		return err
	}
	fmt.Printf("%s (and folders inside it) now use identity %q. Check: aigate whoami\n", key, name)
	return nil
}

// Remove deletes an identity from config, with its bindings. Login dirs are
// never deleted.
func (a *IdentityAction) Remove(c *cli.Context) error {
	cfg, err := a.load()
	if err != nil {
		return err
	}
	name := c.Args().First()
	id, ok := cfg.Identities[name]
	if name == "" || !ok {
		return fmt.Errorf("usage: aigate identity remove NAME (identities: %s)", orDash(strings.Join(sortedNames(cfg), ", ")))
	}
	folders := boundFolders(cfg, name)
	delete(cfg.Identities, name)
	for k, v := range cfg.IdentityBindings {
		if v == name {
			delete(cfg.IdentityBindings, k)
		}
	}
	if cfg.DefaultIdentity == name {
		cfg.DefaultIdentity = ""
	}
	if err := a.configSvc.SaveGlobal(cfg); err != nil {
		return err
	}
	fmt.Printf("Removed identity %q", name)
	if len(folders) > 0 {
		fmt.Printf(" and its folder bindings (%s)", strings.Join(folders, ", "))
	}
	fmt.Printf(".\nIts logins were kept: %s, %s. Delete them yourself if you no longer need them.\n", id.ClaudeDir, id.GhDir)
	return nil
}

func printIdentity(cfg *domain.Config, id *domain.ResolvedIdentity) {
	fmt.Printf("identity: %s", id.Name)
	if cfg.DefaultIdentity == id.Name {
		fmt.Print(" (default)")
	}
	fmt.Println()
	fmt.Printf("  claude:   %s\n", tildePath(id.ClaudeDir))
	fmt.Printf("  gh:       %s\n", tildePath(id.GhDir))
	fmt.Printf("  git:      %s\n", gitLabel(id.Git))
	fmt.Printf("  ssh key:  %s\n", orDash(tildePath(id.SSHKey)))
	if len(id.AllowedPaths) > 0 {
		fmt.Printf("  extra paths: %s\n", strings.Join(id.AllowedPaths, ", "))
	}
	if len(id.PassEnv) > 0 {
		fmt.Printf("  passes env:  %s\n", strings.Join(id.PassEnv, ", "))
	}
	fmt.Printf("  folders:  %s\n", orDash(strings.Join(boundFolders(cfg, id.Name), ", ")))
}

func printProblems(ps []services.IdentityProblem, name string) {
	for _, p := range ps {
		if p.Identity != "" && p.Identity != name {
			continue
		}
		kind := "warning"
		if p.Fatal {
			kind = "problem"
		}
		fmt.Printf("  %s: %s\n", kind, p.Message)
		if p.Fix != "" {
			fmt.Printf("    fix: %s\n", p.Fix)
		}
	}
}

func sortedNames(cfg *domain.Config) []string {
	var names []string
	for n := range cfg.Identities {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func boundFolders(cfg *domain.Config, name string) []string {
	var out []string
	for dir, n := range cfg.IdentityBindings {
		if n == name {
			out = append(out, dir)
		}
	}
	sort.Strings(out)
	return out
}

func gitLabel(g domain.GitAuthor) string {
	switch {
	case g.Name != "" && g.Email != "":
		return fmt.Sprintf("%s <%s>", g.Name, g.Email)
	case g.Email != "":
		return g.Email
	case g.Name != "":
		return g.Name
	}
	return "-"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// tildePath shows paths under $HOME as ~/… so output and config stay readable.
func tildePath(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || p == "" {
		return p
	}
	if p == home {
		return "~"
	}
	if strings.HasPrefix(p, home+"/") {
		return "~/" + strings.TrimPrefix(p, home+"/")
	}
	return p
}

func expand(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return filepath.Clean(p)
}
