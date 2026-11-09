package actions

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/services"
	"github.com/urfave/cli"
)

type ExplainAction struct {
	configSvc *services.ConfigService
}

func NewExplainAction(c *services.ConfigService) *ExplainAction {
	return &ExplainAction{configSvc: c}
}

// Execute says whether a path or command would be allowed under `aigate run`
// here, which layer decides, and how to change it. It runs nothing and only
// contacts judge models with --judge. Exit 1 when it would be blocked.
func (a *ExplainAction) Execute(c *cli.Context) error {
	args := []string(c.Args())
	if len(args) == 0 {
		return fmt.Errorf("usage: aigate explain PATH   or   aigate explain -- COMMAND [ARGS…]\n  e.g. aigate explain ~/.ssh/id_ed25519\n       aigate explain -- curl https://example.com")
	}
	wd, _ := os.Getwd()
	global, profile, err := buildRunProfile(a.configSvc, wd, c.String("identity"), c.StringSlice("allow-path"))
	if err != nil {
		return err
	}
	var e services.Explanation
	if len(args) == 1 && !c.Bool("command") && (c.Bool("path") || isPathArg(args[0], wd)) {
		e = services.ExplainPath(profile, global, args[0])
	} else {
		e = services.ExplainCommand(profile, global, args, c.Bool("judge"))
	}
	if c.Bool("json") {
		out, _ := json.MarshalIndent(map[string]any{"identity": identityLabel(profile.Identity), "explanation": e}, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Print(renderExplanation(e, profile.Identity))
	}
	if !e.Allowed {
		return cli.NewExitError("", 1)
	}
	return nil
}

// isPathArg: a single argument is a path unless it names a program on PATH
// (use --path / --command to force either).
func isPathArg(a, wd string) bool {
	if strings.ContainsAny(a, " \t") {
		return false
	}
	if strings.ContainsAny(a, "/~") || strings.HasPrefix(a, ".") {
		return true
	}
	if _, err := os.Stat(filepath.Join(wd, a)); err == nil {
		return true
	}
	_, err := exec.LookPath(a)
	return err != nil
}

func identityLabel(id *domain.ResolvedIdentity) string {
	if id == nil {
		return "none"
	}
	return id.Name + " (" + id.Reason + ")"
}

func renderExplanation(e services.Explanation, id *domain.ResolvedIdentity) string {
	var b strings.Builder
	verdict := map[bool]string{true: "allowed", false: "BLOCKED"}[e.Allowed]
	if e.Kind == "path" {
		verdict = e.Access
		if !e.Allowed {
			verdict = strings.ToUpper(e.Access)
		}
	} else if e.Access == services.AccessAsk {
		verdict = "allowed, but the judge would ask you first"
	}
	fmt.Fprintf(&b, "%s → %s\n", e.Subject, verdict)
	fmt.Fprintf(&b, "  why:      %s\n", e.Reason)
	if e.Layer != "" {
		layer := e.Layer
		if e.Rule != "" {
			layer += " (" + e.Rule + ")"
		}
		fmt.Fprintf(&b, "  layer:    %s\n", layer)
	}
	if e.Fix != "" && (!e.Allowed || e.Access == services.AccessAsk) {
		fmt.Fprintf(&b, "  to allow: %s\n", e.Fix)
	}
	for _, p := range e.Parts {
		mark := "✓"
		if !p.Allowed {
			mark = "✗"
		} else if p.Access == services.AccessAsk {
			mark = "?"
		}
		fmt.Fprintf(&b, "  %s %s: %s — %s\n", mark, p.Subject, p.Access, p.Reason)
	}
	fmt.Fprintf(&b, "  identity: %s\n", identityLabel(id))
	return b.String()
}
