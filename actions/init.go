package actions

import (
	"fmt"

	"github.com/AxeForging/aigate/helpers"
	"github.com/AxeForging/aigate/services"
	"github.com/urfave/cli"
)

type InitAction struct {
	platform  services.Platform
	configSvc *services.ConfigService
}

func NewInitAction(p services.Platform, c *services.ConfigService) *InitAction {
	return &InitAction{platform: p, configSvc: c}
}

func (a *InitAction) Execute(c *cli.Context) error {
	if c.Bool("verbose") {
		helpers.SetupLogger("debug")
	}

	group := c.String("group")
	user := c.String("user")

	if !c.Bool("force") && a.configSvc.ConfigExists() {
		return fmt.Errorf("%w: use --force to reinitialize", helpers.ErrAlreadyInit)
	}

	helpers.Log.Info().Str("platform", a.platform.Name()).Msg("Initializing aigate sandbox")

	// Create group
	helpers.Log.Info().Str("group", group).Msg("Creating sandbox group")
	if err := a.platform.CreateGroup(group); err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}

	// Create user
	helpers.Log.Info().Str("user", user).Str("group", group).Msg("Creating sandbox user")
	if err := a.platform.CreateUser(user, group); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Write default config
	cfg := a.configSvc.InitDefaultConfig()
	cfg.Group = group
	cfg.User = user
	if err := a.configSvc.SaveGlobal(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	configPath, _ := a.configSvc.GlobalConfigPath()
	helpers.Log.Info().Str("config", configPath).Msg("Default config created")
	fmt.Printf("aigate initialized successfully\n")
	fmt.Printf("  Group: %s\n", group)
	fmt.Printf("  User:  %s\n", user)
	fmt.Printf("  Config: %s\n", configPath)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  aigate deny read .env secrets/    # Add file restrictions\n")
	fmt.Printf("  aigate deny exec curl wget        # Block commands\n")
	fmt.Printf("  aigate run -- claude               # Run AI tool in sandbox\n")
	return nil
}
