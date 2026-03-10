package actions

import (
	"fmt"
	"os"
	"strings"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/helpers"
	"github.com/AxeForging/aigate/services"
	"github.com/urfave/cli"
)

type RunAction struct {
	runner    *services.RunnerService
	configSvc *services.ConfigService
	platform  services.Platform
}

func NewRunAction(r *services.RunnerService, c *services.ConfigService, p services.Platform) *RunAction {
	return &RunAction{runner: r, configSvc: c, platform: p}
}

func (a *RunAction) Execute(c *cli.Context) error {
	if c.Bool("verbose") {
		helpers.SetupLogger("debug")
	}

	args := c.Args()
	if len(args) == 0 {
		return fmt.Errorf("usage: aigate run -- <command> [args...]")
	}

	cmd := args[0]
	var cmdArgs []string
	if len(args) > 1 {
		cmdArgs = args[1:]
	}

	// Load and merge configs
	globalCfg, err := a.configSvc.LoadGlobal()
	if err != nil {
		return fmt.Errorf("%w", helpers.ErrNotInitialized)
	}

	workDir, _ := os.Getwd()
	projectCfg, _ := a.configSvc.LoadProject(workDir)
	merged := a.configSvc.Merge(globalCfg, projectCfg)

	profile := domain.SandboxProfile{
		Config:  *merged,
		WorkDir: workDir,
	}

	helpers.Log.Debug().
		Str("command", cmd).
		Strs("args", cmdArgs).
		Str("platform", a.platform.Name()).
		Int("deny_read", len(merged.DenyRead)).
		Int("deny_exec", len(merged.DenyExec)).
		Int("allow_net", len(merged.AllowNet)).
		Msg("Running sandboxed command")

	printSandboxBanner(merged)

	return a.runner.Run(profile, cmd, cmdArgs)
}

// printSandboxBanner prints active restrictions to stderr so AI agents
// (and users) can see exactly what is enforced inside the sandbox.
func printSandboxBanner(cfg *domain.Config) {
	fmt.Fprintln(os.Stderr, "[aigate] sandbox active")
	if len(cfg.DenyRead) > 0 {
		fmt.Fprintf(os.Stderr, "[aigate] deny_read: %s\n", strings.Join(cfg.DenyRead, ", "))
	}
	if len(cfg.DenyExec) > 0 {
		fmt.Fprintf(os.Stderr, "[aigate] deny_exec: %s\n", strings.Join(cfg.DenyExec, ", "))
	}
	if len(cfg.AllowNet) > 0 {
		fmt.Fprintf(os.Stderr, "[aigate] allow_net: %s (all other outbound connections will be blocked)\n", strings.Join(cfg.AllowNet, ", "))
	}
	if len(cfg.MaskStdout.Presets) > 0 || len(cfg.MaskStdout.Patterns) > 0 {
		var parts []string
		if len(cfg.MaskStdout.Presets) > 0 {
			parts = append(parts, strings.Join(cfg.MaskStdout.Presets, ", "))
		}
		if len(cfg.MaskStdout.Patterns) > 0 {
			parts = append(parts, fmt.Sprintf("+%d custom pattern(s)", len(cfg.MaskStdout.Patterns)))
		}
		fmt.Fprintf(os.Stderr, "[aigate] mask_stdout: %s\n", strings.Join(parts, "; "))
	}
}
