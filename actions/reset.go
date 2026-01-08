package actions

import (
	"fmt"

	"github.com/AxeForging/aigate/helpers"
	"github.com/AxeForging/aigate/services"
	"github.com/urfave/cli"
)

type ResetAction struct {
	platform  services.Platform
	configSvc *services.ConfigService
}

func NewResetAction(p services.Platform, c *services.ConfigService) *ResetAction {
	return &ResetAction{platform: p, configSvc: c}
}

func (a *ResetAction) Execute(c *cli.Context) error {
	if c.Bool("verbose") {
		helpers.SetupLogger("debug")
	}

	if !c.Bool("force") {
		return fmt.Errorf("reset will remove the sandbox group, user, and all configuration. Use --force to confirm")
	}

	cfg, err := a.configSvc.LoadGlobal()
	if err != nil {
		helpers.Log.Warn().Msg("No config found, cleaning up anyway")
		cfg = a.configSvc.InitDefaultConfig()
	}

	// Delete user first (must be removed before group)
	helpers.Log.Info().Str("user", cfg.User).Msg("Removing sandbox user")
	if err := a.platform.DeleteUser(cfg.User); err != nil {
		helpers.Log.Warn().Err(err).Msg("Failed to delete user")
	}

	// Delete group
	helpers.Log.Info().Str("group", cfg.Group).Msg("Removing sandbox group")
	if err := a.platform.DeleteGroup(cfg.Group); err != nil {
		helpers.Log.Warn().Err(err).Msg("Failed to delete group")
	}

	// Remove config
	if err := a.configSvc.RemoveConfig(); err != nil {
		helpers.Log.Warn().Err(err).Msg("Failed to remove config directory")
	}

	fmt.Println("aigate sandbox removed successfully")
	return nil
}
