package actions

import (
	"fmt"
	"os"
	"slices"
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

	workDir, _ := os.Getwd()
	globalCfg, profile, err := buildRunProfile(a.configSvc, workDir, c.String("identity"), c.StringSlice("allow-path"))
	if err != nil {
		return err
	}
	merged, identity := &profile.Config, profile.Identity
	judgeOff, err := judgeOffForRun(a.configSvc, c.String("judge"), &profile)
	if err != nil {
		return err
	}
	if !judgeOff {
		stopJudge, err := startJudgeBroker(a.configSvc, globalCfg, &profile)
		if err != nil {
			return err
		}
		defer stopJudge()
	}

	helpers.Log.Debug().
		Str("command", cmd).
		Strs("args", cmdArgs).
		Str("platform", a.platform.Name()).
		Int("deny_read", len(merged.DenyRead)).
		Int("deny_exec", len(merged.DenyExec)).
		Int("allow_net", len(merged.AllowNet)).
		Int("allowed_paths", len(merged.AllowedPaths)).
		Msg("Running sandboxed command")

	printIdentityBanner(globalCfg, identity)
	printSandboxBanner(merged, workDir)

	return a.runner.Run(profile, cmd, cmdArgs)
}

// buildRunProfile resolves everything `aigate run` enforces: global +
// project config, session --allow-path, identity and its narrowed scope.
// `aigate explain` uses it too, so the two can't disagree.
func buildRunProfile(configSvc *services.ConfigService, workDir, identityFlag string, allowPaths []string) (*domain.Config, domain.SandboxProfile, error) {
	globalCfg, err := configSvc.LoadGlobal()
	if err != nil {
		return nil, domain.SandboxProfile{}, fmt.Errorf("%w", helpers.ErrNotInitialized)
	}
	// A broken project config must stop the run: ignoring it would silently
	// drop its deny rules.
	projectCfg, err := configSvc.LoadProject(workDir)
	if err != nil {
		return nil, domain.SandboxProfile{}, err
	}
	merged := configSvc.Merge(globalCfg, projectCfg)
	for _, p := range allowPaths {
		if !slices.Contains(merged.AllowedPaths, p) {
			merged.AllowedPaths = append(merged.AllowedPaths, p)
		}
	}
	identity, err := resolveRunIdentity(globalCfg, merged, identityFlag, workDir)
	if err != nil {
		return nil, domain.SandboxProfile{}, err
	}
	return globalCfg, domain.SandboxProfile{
		Config:   *merged,
		WorkDir:  workDir,
		Identity: identity,
		// Judge provider credentials stay outside, judge on or off.
		UnsetEnv: services.JudgeCredentialEnv(globalCfg.Judge),
	}, nil
}

// resolveRunIdentity picks the identity for this run and narrows merged's
// allowed_paths to it. Fatal problems with the chosen identity (or ones that
// concern several identities) stop the run; others are printed as warnings.
func resolveRunIdentity(global, merged *domain.Config, flag, workDir string) (*domain.ResolvedIdentity, error) {
	svc := services.NewIdentityService()
	id, err := svc.Resolve(global, flag, workDir)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, nil
	}

	var fatal []string
	for _, p := range svc.Validate(global) {
		relevant := p.Identity == "" || p.Identity == id.Name
		line := p.Message
		if p.Fix != "" {
			line += ". Fix: " + p.Fix
		}
		if p.Fatal && relevant {
			fatal = append(fatal, line)
		} else if relevant {
			fmt.Fprintln(os.Stderr, "[aigate] warning: "+line)
		}
	}
	if len(fatal) > 0 {
		return nil, fmt.Errorf("can't run as identity %q:\n  %s", id.Name, strings.Join(fatal, "\n  "))
	}

	allowed, err := svc.EffectiveAllowedPaths(merged, id, workDir)
	if err != nil {
		return nil, err
	}
	merged.AllowedPaths = allowed
	return id, nil
}

// printIdentityBanner says which identity is active and why, so users never
// have to guess whose logins a session can see.
func printIdentityBanner(global *domain.Config, id *domain.ResolvedIdentity) {
	switch {
	case id != nil:
		fmt.Fprintf(os.Stderr, "[aigate] identity: %s (%s)\n", id.Name, id.Reason)
	case len(global.Identities) > 0:
		fmt.Fprintln(os.Stderr, "[aigate] identity: none (pick one with --identity NAME, or bind this folder: aigate identity use NAME)")
	}
}

// printSandboxBanner prints active restrictions to stderr so AI agents
// (and users) can see exactly what is enforced inside the sandbox.
func printSandboxBanner(cfg *domain.Config, workDir string) {
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
	if len(cfg.AllowedPaths) > 0 {
		fmt.Fprintf(os.Stderr, "[aigate] allowed_paths: %s (plus the working directory; the rest of $HOME is hidden)\n", strings.Join(cfg.AllowedPaths, ", "))
		if home, err := os.UserHomeDir(); err == nil && workDir == home {
			fmt.Fprintln(os.Stderr, "[aigate] WARNING: running from your home directory — allowed_paths scoping cannot be enforced (the working directory is always accessible). cd into a project directory to enable it.")
		}
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
