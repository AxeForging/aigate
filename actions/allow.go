package actions

import (
	"fmt"
	"os"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/helpers"
	"github.com/AxeForging/aigate/services"
	"github.com/urfave/cli"
)

type AllowAction struct {
	ruleSvc   *services.RuleService
	configSvc *services.ConfigService
	platform  services.Platform
}

func NewAllowAction(r *services.RuleService, c *services.ConfigService, p services.Platform) *AllowAction {
	return &AllowAction{ruleSvc: r, configSvc: c, platform: p}
}

func (a *AllowAction) ExecuteRead(c *cli.Context) error {
	if c.Bool("verbose") {
		helpers.SetupLogger("debug")
	}
	patterns := c.Args()
	if len(patterns) == 0 {
		return fmt.Errorf("usage: aigate allow read <pattern> [pattern...]")
	}
	return a.removeRule(domain.RuleTypeRead, patterns)
}

func (a *AllowAction) ExecuteExec(c *cli.Context) error {
	if c.Bool("verbose") {
		helpers.SetupLogger("debug")
	}
	commands := c.Args()
	if len(commands) == 0 {
		return fmt.Errorf("usage: aigate allow exec <command> [command...]")
	}
	return a.removeRule(domain.RuleTypeExec, commands)
}

func (a *AllowAction) ExecuteNet(c *cli.Context) error {
	if c.Bool("verbose") {
		helpers.SetupLogger("debug")
	}
	domains := c.Args()
	if len(domains) == 0 {
		return fmt.Errorf("usage: aigate allow net <domain> [domain...]")
	}
	return a.removeRule(domain.RuleTypeNet, domains)
}

func (a *AllowAction) removeRule(ruleType domain.RuleType, patterns []string) error {
	cfg, err := a.configSvc.LoadGlobal()
	if err != nil {
		return fmt.Errorf("%w", helpers.ErrNotInitialized)
	}

	if err := a.ruleSvc.RemoveRule(cfg, ruleType, patterns); err != nil {
		return err
	}

	// Remove ACLs for file rules
	if ruleType == domain.RuleTypeRead {
		workDir, _ := os.Getwd()
		if err := a.platform.RemoveFileACL(cfg.Group, patterns, workDir); err != nil {
			helpers.Log.Warn().Err(err).Msg("Failed to remove ACLs (may need sudo)")
		}
	}

	if err := a.configSvc.SaveGlobal(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Removed %s rules:\n", ruleType)
	for _, p := range patterns {
		fmt.Printf("  - %s\n", p)
	}
	return nil
}
