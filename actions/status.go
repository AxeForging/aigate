package actions

import (
	"fmt"
	"runtime"

	"github.com/AxeForging/aigate/helpers"
	"github.com/AxeForging/aigate/services"
	"github.com/urfave/cli"
)

type StatusAction struct {
	configSvc *services.ConfigService
	platform  services.Platform
}

func NewStatusAction(c *services.ConfigService, p services.Platform) *StatusAction {
	return &StatusAction{configSvc: c, platform: p}
}

func (a *StatusAction) Execute(c *cli.Context) error {
	if c.Bool("verbose") {
		helpers.SetupLogger("debug")
	}

	fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Sandbox engine: %s\n\n", a.platform.Name())

	// Check config
	if !a.configSvc.ConfigExists() {
		fmt.Println("Status: NOT INITIALIZED")
		fmt.Println("  Run 'aigate init' to set up the sandbox")
		return nil
	}

	cfg, err := a.configSvc.LoadGlobal()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	fmt.Println("Status: INITIALIZED")
	fmt.Printf("  Group: %s\n", cfg.Group)
	fmt.Printf("  User:  %s\n\n", cfg.User)

	// Check group/user existence
	groupExists, _ := a.platform.GroupExists(cfg.Group)
	userExists, _ := a.platform.UserExists(cfg.User)
	fmt.Printf("OS State:\n")
	fmt.Printf("  Group exists: %v\n", groupExists)
	fmt.Printf("  User exists:  %v\n\n", userExists)

	// Show rules
	fmt.Println("Deny Read Rules:")
	if len(cfg.DenyRead) == 0 {
		fmt.Println("  (none)")
	}
	for _, r := range cfg.DenyRead {
		fmt.Printf("  - %s\n", r)
	}

	fmt.Println("\nDeny Exec Rules:")
	if len(cfg.DenyExec) == 0 {
		fmt.Println("  (none)")
	}
	for _, r := range cfg.DenyExec {
		fmt.Printf("  - %s\n", r)
	}

	fmt.Println("\nAllowed Network Domains:")
	if len(cfg.AllowNet) == 0 {
		fmt.Println("  (none - all network allowed)")
	}
	for _, r := range cfg.AllowNet {
		fmt.Printf("  - %s\n", r)
	}

	fmt.Printf("\nResource Limits:\n")
	fmt.Printf("  Max Memory:  %s\n", cfg.ResourceLimits.MaxMemory)
	fmt.Printf("  Max CPU:     %d%%\n", cfg.ResourceLimits.MaxCPUPercent)
	fmt.Printf("  Max PIDs:    %d\n", cfg.ResourceLimits.MaxPIDs)

	return nil
}
