package main

import (
	"fmt"
	"os"

	"github.com/AxeForging/aigate/actions"
	"github.com/AxeForging/aigate/helpers"
	"github.com/AxeForging/aigate/services"

	"github.com/urfave/cli"
)

// Version information - set during build
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	helpers.SetupLogger("info")

	platform := services.DetectPlatform()
	configSvc := services.NewConfigService()
	ruleSvc := services.NewRuleService()
	runnerSvc := services.NewRunnerService(platform)

	initAction := actions.NewInitAction(configSvc)
	setupAction := actions.NewSetupAction(platform, configSvc)
	helpAIAction := actions.NewHelpAIAction()
	denyAction := actions.NewDenyAction(ruleSvc, configSvc, platform)
	allowAction := actions.NewAllowAction(ruleSvc, configSvc, platform)
	runAction := actions.NewRunAction(runnerSvc, configSvc, platform)
	statusAction := actions.NewStatusAction(configSvc, platform)
	resetAction := actions.NewResetAction(platform, configSvc)

	app := cli.NewApp()
	app.Name = "aigate"
	app.Usage = "OS-level sandbox for AI coding agents"
	app.Version = Version

	app.Commands = []cli.Command{
		{
			Name:    "init",
			Aliases: []string{"i"},
			Usage:   "Create default config (~/.aigate/config.yaml)",
			Flags:   []cli.Flag{verboseFlag, forceFlag},
			Action:  initAction.Execute,
		},
		{
			Name:   "setup",
			Usage:  "Create OS group and user for sandbox (requires sudo)",
			Flags:  []cli.Flag{groupFlag, userFlag, verboseFlag},
			Action: setupAction.Execute,
		},
		{
			Name:  "deny",
			Usage: "Add deny rules for AI agent isolation",
			Subcommands: []cli.Command{
				{
					Name:   "read",
					Usage:  "Deny AI agent read access to files/directories",
					Flags:  []cli.Flag{verboseFlag, dryRunFlag},
					Action: denyAction.ExecuteRead,
				},
				{
					Name:   "exec",
					Usage:  "Deny AI agent from executing specific commands",
					Flags:  []cli.Flag{verboseFlag, dryRunFlag},
					Action: denyAction.ExecuteExec,
				},
				{
					Name:   "net",
					Usage:  "Restrict AI agent network access (allow only --except domains)",
					Flags:  []cli.Flag{exceptFlag, verboseFlag, dryRunFlag},
					Action: denyAction.ExecuteNet,
				},
			},
		},
		{
			Name:  "allow",
			Usage: "Remove deny rules",
			Subcommands: []cli.Command{
				{
					Name:   "read",
					Usage:  "Remove file read deny rules",
					Flags:  []cli.Flag{verboseFlag},
					Action: allowAction.ExecuteRead,
				},
				{
					Name:   "exec",
					Usage:  "Remove command execution deny rules",
					Flags:  []cli.Flag{verboseFlag},
					Action: allowAction.ExecuteExec,
				},
				{
					Name:   "net",
					Usage:  "Remove network deny rules (add allowed domains)",
					Flags:  []cli.Flag{verboseFlag},
					Action: allowAction.ExecuteNet,
				},
			},
		},
		{
			Name:    "run",
			Aliases: []string{"r"},
			Usage:   "Run a command inside the AI sandbox (use -- before command)",
			Flags:   []cli.Flag{verboseFlag, configFlag},
			Action:  runAction.Execute,
		},
		{
			Name:    "status",
			Aliases: []string{"s"},
			Usage:   "Show current sandbox configuration and state",
			Flags:   []cli.Flag{verboseFlag},
			Action:  statusAction.Execute,
		},
		{
			Name:   "reset",
			Usage:  "Remove sandbox group, user, and all rules",
			Flags:  []cli.Flag{forceFlag, verboseFlag},
			Action: resetAction.Execute,
		},
		{
			Name:  "help-ai",
			Usage: "Show AI-friendly usage examples",
			Action: helpAIAction.Execute,
		},
		{
			Name:  "version",
			Usage: "Show version information",
			Action: func(c *cli.Context) error {
				fmt.Printf("aigate version %s\n", Version)
				fmt.Printf("Build time: %s\n", BuildTime)
				fmt.Printf("Git commit: %s\n", GitCommit)
				return nil
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
