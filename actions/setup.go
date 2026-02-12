package actions

import (
	"errors"
	"fmt"

	"github.com/AxeForging/aigate/helpers"
	"github.com/AxeForging/aigate/services"
	"github.com/urfave/cli"
)

type SetupAction struct {
	platform  services.Platform
	configSvc *services.ConfigService
}

func NewSetupAction(p services.Platform, c *services.ConfigService) *SetupAction {
	return &SetupAction{platform: p, configSvc: c}
}

func (a *SetupAction) Execute(c *cli.Context) error {
	if c.Bool("verbose") {
		helpers.SetupLogger("debug")
	}

	group := c.String("group")
	user := c.String("user")

	helpers.Log.Info().Str("platform", a.platform.Name()).Msg("Setting up aigate system resources")

	// Create group — skip if already exists
	helpers.Log.Info().Str("group", group).Msg("Creating sandbox group")
	if err := a.platform.CreateGroup(group); err != nil {
		if errors.Is(err, helpers.ErrAlreadyInit) {
			helpers.Log.Info().Str("group", group).Msg("group already exists, skipping")
		} else {
			return fmt.Errorf("failed to create group: %w", err)
		}
	}

	// Create user — skip if already exists
	helpers.Log.Info().Str("user", user).Str("group", group).Msg("Creating sandbox user")
	if err := a.platform.CreateUser(user, group); err != nil {
		if errors.Is(err, helpers.ErrAlreadyInit) {
			helpers.Log.Info().Str("user", user).Msg("user already exists, skipping")
		} else {
			return fmt.Errorf("failed to create user: %w", err)
		}
	}

	fmt.Printf("System setup complete\n")
	fmt.Printf("  Group: %s\n", group)
	fmt.Printf("  User:  %s\n", user)
	return nil
}
