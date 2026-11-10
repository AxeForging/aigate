package actions

import (
	"fmt"
	"strings"

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

	if c.Bool("upgrade") {
		return a.upgrade()
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

// upgrade adds what newer aigate versions protect by default (today: mask
// presets) without touching the user's own rules. A no-op leaves the file
// untouched.
func (a *InitAction) upgrade() error {
	cfg, err := a.configSvc.LoadGlobal()
	if err != nil {
		return fmt.Errorf("no config to upgrade yet; create one with: aigate init")
	}
	missing := a.configSvc.MissingDefaultPresets(cfg)
	if len(missing) == 0 {
		fmt.Println("Config already up to date: every built-in secret format is masked.")
		return nil
	}
	cfg.MaskStdout.Presets = append(cfg.MaskStdout.Presets, missing...)
	if err := a.configSvc.SaveGlobal(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	path, _ := a.configSvc.GlobalConfigPath()
	fmt.Printf("Added %d secret formats to output masking: %s\n", len(missing), strings.Join(missing, ", "))
	fmt.Printf("  Config: %s (your other rules are unchanged)\n", services.TildePath(path))
	return nil
}
