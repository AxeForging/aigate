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

var allowPathFlag = cli.StringSliceFlag{
	Name:  "allow-path, p",
	Usage: "Session-only scope path (repeatable); with scope active, only the workdir and allowed paths are accessible",
}

var portFlag = cli.StringSliceFlag{
	Name:  "port",
	Usage: "Make a server started inside reachable at localhost:PORT on your machine (repeatable), e.g. --port 3000",
}

var identityFlag = cli.StringFlag{
	Name:  "identity, i",
	Usage: "Run as this identity (see: aigate identity list). Default: the identity bound to this folder, then default_identity",
}

var judgeModeFlag = cli.StringFlag{
	Name:  "judge",
	Usage: "off: run this session without the judge (audited; the sandbox still applies)",
}
