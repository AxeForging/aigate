package main

import "github.com/urfave/cli"

var verboseFlag = cli.BoolFlag{
	Name:  "verbose, v",
	Usage: "Enable verbose logging",
}

var forceFlag = cli.BoolFlag{
	Name:  "force, f",
	Usage: "Force operation without confirmation",
}

var groupFlag = cli.StringFlag{
	Name:  "group, g",
	Value: "ai-agents",
	Usage: "OS group name for AI agent isolation",
}

var userFlag = cli.StringFlag{
	Name:  "user, u",
	Value: "ai-runner",
	Usage: "OS user name for AI agent isolation",
}

var exceptFlag = cli.StringSliceFlag{
	Name:  "except, e",
	Usage: "Exceptions (e.g. --except api.anthropic.com)",
}

var configFlag = cli.StringFlag{
	Name:  "config, c",
	Value: "",
	Usage: "Path to config file (default: ~/.aigate/config.yaml)",
}

var dryRunFlag = cli.BoolFlag{
	Name:  "dry-run",
	Usage: "Preview changes without applying them",
}
