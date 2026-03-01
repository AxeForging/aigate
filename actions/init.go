package actions

import (
	"fmt"

	"github.com/AxeForging/aigate/helpers"
	"github.com/AxeForging/aigate/services"
	"github.com/urfave/cli"
)

type InitAction struct {
	configSvc *services.ConfigService
}

func NewInitAction(c *services.ConfigService) *InitAction {
	return &InitAction{configSvc: c}
}

func (a *InitAction) Execute(c *cli.Context) error {
	if c.Bool("verbose") {
		helpers.SetupLogger("debug")
	}

	if !c.Bool("force") && a.configSvc.ConfigExists() {
		return fmt.Errorf("%w: use --force to reinitialize", helpers.ErrAlreadyInit)
	}

	cfg := a.configSvc.InitDefaultConfig()
	if err := a.configSvc.SaveGlobal(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	configPath, _ := a.configSvc.GlobalConfigPath()
	fmt.Printf("aigate initialized\n")
	fmt.Printf("  Config: %s\n", configPath)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  sudo aigate setup              # Create OS group/user (one-time)\n")
	fmt.Printf("  aigate deny read .env secrets/  # Add file restrictions\n")
	fmt.Printf("  aigate run -- claude            # Run AI tool in sandbox\n")
	return nil
}
