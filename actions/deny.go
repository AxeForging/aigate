package actions

import (
	"fmt"
	"os"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/helpers"
	"github.com/AxeForging/aigate/services"
	"github.com/urfave/cli"
)

type DenyAction struct {
	ruleSvc   *services.RuleService
	configSvc *services.ConfigService
	platform  services.Platform
}

func NewDenyAction(r *services.RuleService, c *services.ConfigService, p services.Platform) *DenyAction {
	return &DenyAction{ruleSvc: r, configSvc: c, platform: p}
}

func (a *DenyAction) ExecuteRead(c *cli.Context) error {
	if c.Bool("verbose") {
		helpers.SetupLogger("debug")
	}
	patterns := c.Args()
	if len(patterns) == 0 {
		return fmt.Errorf("usage: aigate deny read <pattern> [pattern...]")
	}
	return a.addDeny(domain.RuleTypeRead, patterns, c.Bool("dry-run"))
}

func (a *DenyAction) ExecuteExec(c *cli.Context) error {
	if c.Bool("verbose") {
		helpers.SetupLogger("debug")
	}
	commands := c.Args()
	if len(commands) == 0 {
		return fmt.Errorf("usage: aigate deny exec <command> [command...]")
	}
	return a.addDeny(domain.RuleTypeExec, commands, c.Bool("dry-run"))
}

func (a *DenyAction) ExecuteNet(c *cli.Context) error {
	if c.Bool("verbose") {
		helpers.SetupLogger("debug")
	}
	domains := c.StringSlice("except")
	if len(domains) == 0 {
		return fmt.Errorf("usage: aigate deny net --except <domain> [--except <domain>...]")
	}
	return a.addDeny(domain.RuleTypeNet, domains, c.Bool("dry-run"))
}

func (a *DenyAction) addDeny(ruleType domain.RuleType, patterns []string, dryRun bool) error {
	cfg, err := a.configSvc.LoadGlobal()
	if err != nil {
		return fmt.Errorf("%w", helpers.ErrNotInitialized)
	}

	if err := a.ruleSvc.AddDenyRule(cfg, ruleType, patterns); err != nil {
		return err
	}

	if dryRun {
		fmt.Printf("[dry-run] Would add %s deny rules:\n", ruleType)
		for _, p := range patterns {
			fmt.Printf("  - %s\n", p)
		}
		return nil
	}

	// Apply ACLs for file rules
	if ruleType == domain.RuleTypeRead {
		workDir, _ := os.Getwd()
		if err := a.platform.SetFileACLDeny(cfg.Group, patterns, workDir); err != nil {
			helpers.Log.Warn().Err(err).Msg("Failed to apply ACLs (may need sudo)")
		}
	}

	if err := a.configSvc.SaveGlobal(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Added %s deny rules:\n", ruleType)
	for _, p := range patterns {
		fmt.Printf("  - %s\n", p)
	}
	return nil
}
