package actions

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/services"
	"github.com/urfave/cli"
	"golang.org/x/term"
)

var callIDRe = regexp.MustCompile(`^[0-9a-f]{12}$`)

func allowOnceStore(configSvc *services.ConfigService) *services.AllowOnceStore {
	dir, _ := configSvc.GlobalConfigDir()
	return &services.AllowOnceStore{Path: filepath.Join(dir, "judge-allow-once.json")}
}

// AllowOnce lets one blocked call through. It must be typed by a person in
// a terminal: an agent's tool calls have no terminal, and inside the sandbox
// ~/.aigate is hidden, so an agent can't approve its own calls.
func (a *JudgeAction) AllowOnce(c *cli.Context) error {
	id := c.Args().First()
	if !callIDRe.MatchString(id) {
		return fmt.Errorf("usage: aigate judge allow-once ID   (the 12-character ID from the block message)")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("allow-once must be run by you in your own terminal, not by a tool or script")
	}
	if err := allowOnceStore(a.configSvc).Grant(id, c.String("reason")); err != nil {
		return err
	}
	_ = services.NewAuditService(a.configSvc).Log(services.AuditEvent{Kind: "judge_override",
		Detail: "allow-once granted: " + orDash(c.String("reason")),
		Meta:   map[string]string{"call_id": id, "os_user": services.OSUser()}})
	fmt.Printf("Call %s may run once within %s. Ask the agent to retry it.\n", id, services.AllowOnceTTL)
	return nil
}

// judgeOffForRun handles `aigate run --judge=off`: no broker, hooks inside
// stay silent, and the choice is audited.
func judgeOffForRun(configSvc *services.ConfigService, mode string, profile *domain.SandboxProfile) (off bool, err error) {
	switch mode {
	case "", "on":
		return false, nil
	case "off":
		profile.JudgeOff = true
		_ = services.NewAuditService(configSvc).Log(services.AuditEvent{Kind: "judge_override",
			Identity: identityNameOf(profile), WorkDir: profile.WorkDir, Detail: "session started with --judge=off",
			Meta: map[string]string{"os_user": services.OSUser()}})
		fmt.Fprintln(os.Stderr, "[aigate] judge: off for this session (audited); the sandbox still applies")
		return true, nil
	default:
		return false, fmt.Errorf("--judge must be on or off, got %q", mode)
	}
}

func identityNameOf(p *domain.SandboxProfile) string {
	if p.Identity == nil {
		return ""
	}
	return p.Identity.Name
}
