package main

import (
	"context"
	"fmt"
	"os"

	"github.com/AxeForging/aigate/actions"
	"github.com/AxeForging/aigate/helpers"
	"github.com/AxeForging/aigate/internal/web"
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
	// Last step inside a Linux sandbox: drop capabilities, exec the command.
	if len(os.Args) > 1 && os.Args[1] == services.SandboxExecArg {
		os.Exit(services.SandboxExec(os.Args[2:]))
	}
	helpers.SetupLogger("info")

	platform := services.DetectPlatform()
	configSvc := services.NewConfigService()
	auditSvc := services.NewAuditService(configSvc)
	ruleSvc := services.NewRuleService()
	runnerSvc := services.NewRunnerServiceWithAudit(platform, auditSvc)

	initAction := actions.NewInitAction(configSvc)
	setupAction := actions.NewSetupAction(platform, configSvc)
	helpAIAction := actions.NewHelpAIAction()
	doctorAction := actions.NewDoctorAction(configSvc, platform)
	explainAction := actions.NewExplainAction(configSvc)
	denyAction := actions.NewDenyAction(ruleSvc, configSvc, platform)
	allowAction := actions.NewAllowAction(ruleSvc, configSvc, platform)
	runAction := actions.NewRunAction(runnerSvc, configSvc, platform)
	statusAction := actions.NewStatusAction(configSvc, platform)
	resetAction := actions.NewResetAction(platform, configSvc)
	identityAction := actions.NewIdentityAction(configSvc, runnerSvc)
	whoamiAction := actions.NewWhoamiAction(configSvc)
	judgeAction := actions.NewJudgeAction(configSvc)

	app := cli.NewApp()
	app.Name = "aigate"
	app.Usage = "OS-level sandbox for AI coding agents"
	app.Version = Version

	app.Commands = []cli.Command{
		{
			Name:    "init",
			Aliases: []string{"i"},
			Usage:   "Create default config (~/.aigate/config.yaml)",
			Flags:   []cli.Flag{verboseFlag, forceFlag, upgradeFlag},
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
					Name:        "read",
					Usage:       "Deny AI agent read access to files/directories",
					Description: "Examples:\n   aigate deny read .env secrets/ '*.pem'\n   aigate deny read ~/.aws/ terraform.tfstate",
					Flags:       []cli.Flag{verboseFlag, dryRunFlag},
					Action:      denyAction.ExecuteRead,
				},
				{
					Name:        "exec",
					Usage:       "Deny AI agent from executing specific commands",
					Description: "Examples:\n   aigate deny exec curl wget ssh\n   aigate deny exec 'kubectl delete'   # block a single subcommand",
					Flags:       []cli.Flag{verboseFlag, dryRunFlag},
					Action:      denyAction.ExecuteExec,
				},
				{
					Name:        "net",
					Usage:       "Restrict AI agent network access (allow only --except domains)",
					Description: "Examples:\n   aigate deny net --except api.anthropic.com --except api.github.com",
					Flags:       []cli.Flag{exceptFlag, verboseFlag, dryRunFlag},
					Action:      denyAction.ExecuteNet,
				},
				{
					Name:        "path",
					Usage:       "Remove a path from the allowed_paths scope (narrows sandbox access)",
					Description: "Examples:\n   aigate deny path ~/.npm\n\nRemoving the last entry turns scope mode off ($HOME fully accessible again).",
					Flags:       []cli.Flag{verboseFlag},
					Action:      denyAction.ExecutePath,
				},
			},
		},
		{
			Name:  "allow",
			Usage: "Remove deny rules / widen the sandbox scope",
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
				{
					Name:        "path",
					Usage:       "Add a path to the allowed_paths scope (activates scope mode)",
					Description: "With scope mode active, only the working directory and allowed paths are\naccessible inside the sandbox — the rest of $HOME is hidden (reads AND writes).\n\nExamples:\n   aigate allow path ~/.cache ~/.config\n   aigate allow path ../shared-lib",
					Flags:       []cli.Flag{verboseFlag},
					Action:      allowAction.ExecutePath,
				},
			},
		},
		{
			Name:        "identity",
			Usage:       "Manage identities (separate Claude/gh/git/ssh logins per account)",
			Description: "Each identity only sees its own logins inside the sandbox.\n\nExamples:\n   aigate identity list\n   aigate identity use work        # this folder (and inside it) runs as work\n   aigate identity use none        # unbind this folder\n   aigate identity show work",
			Subcommands: []cli.Command{
				{
					Name:        "add",
					Usage:       "Create an identity (asks a few questions, then logs in to Claude and gh)",
					ArgsUsage:   "NAME",
					Description: "Examples:\n   aigate identity add work\n   aigate identity add work --use            # also bind the current folder\n   aigate identity add ci --yes --git-email ci@example.com   # no questions",
					Flags: []cli.Flag{
						cli.StringFlag{Name: "claude-dir", Usage: "Claude folder (default ~/.claude-NAME)"},
						cli.StringFlag{Name: "gh-dir", Usage: "GitHub CLI folder (default ~/.config/gh-NAME)"},
						cli.StringFlag{Name: "git-name", Usage: "Git author name (default: your global git config)"},
						cli.StringFlag{Name: "git-email", Usage: "Git author email (default: your global git config)"},
						cli.StringFlag{Name: "ssh-key", Usage: "Private key used for git over ssh (mounted read-only)"},
						cli.BoolFlag{Name: "default", Usage: "Make it the default identity (automatic for the first one)"},
						cli.BoolFlag{Name: "use", Usage: "Bind the current folder to it"},
						cli.BoolFlag{Name: "login", Usage: "Run the Claude and gh logins even without a terminal"},
						cli.BoolFlag{Name: "yes, y", Usage: "No questions: take defaults and skip logins (unless --login)"},
					},
					Action: identityAction.Add,
				},
				{
					Name:    "list",
					Aliases: []string{"ls"},
					Usage:   "List identities (* = active in this folder)",
					Action:  identityAction.List,
				},
				{
					Name:      "show",
					Usage:     "Show one identity, its folders and any problems",
					ArgsUsage: "NAME",
					Action:    identityAction.Show,
				},
				{
					Name:      "use",
					Usage:     "Bind a folder (default: current) to an identity; NAME \"none\" unbinds",
					ArgsUsage: "NAME [FOLDER]",
					Action:    identityAction.Use,
				},
				{
					Name:      "remove",
					Aliases:   []string{"rm"},
					Usage:     "Remove an identity from config (its login folders are kept)",
					ArgsUsage: "NAME",
					Action:    identityAction.Remove,
				},
			},
		},
		{
			Name:        "judge",
			Usage:       "Claude Code hook: judge a tool call (reads the hook payload on stdin)",
			Description: "Extra layer on top of the sandbox: it can deny or ask, never allow.\nConfigure under judge: in ~/.aigate/config.yaml (off by default).\n\nExamples:\n   aigate judge install                    # one-time: add the hooks to Claude Code, turn the judge on\n   aigate judge < payload.json             # as a PreToolUse/PostToolUse hook\n   aigate judge --dry-run < payload.json   # show what a model would receive; sends nothing",
			Flags: []cli.Flag{
				cli.BoolFlag{Name: "dry-run", Usage: "Print the exact payload a model judge would receive and the local verdict; send nothing"},
			},
			Action: judgeAction.Hook,
			Subcommands: []cli.Command{
				{
					Name:   "install",
					Usage:  "Add the judge hooks to Claude Code (identity active here, or ~/.claude) and turn the judge on",
					Flags:  []cli.Flag{identityFlag},
					Action: judgeAction.Install,
				},
				{
					Name:  "eval",
					Usage: "Score the rules, each available model and the chain on a labeled corpus",
					Flags: []cli.Flag{
						cli.StringFlag{Name: "corpus", Usage: "JSON array of cases (default: the built-in synthetic corpus)"},
						cli.BoolFlag{Name: "json", Usage: "Machine-readable output"},
					},
					Action: judgeAction.Eval,
				},
				{
					Name:      "allow-once",
					Usage:     "Let one blocked call through (type it yourself, in your terminal)",
					ArgsUsage: "ID",
					Flags:     []cli.Flag{cli.StringFlag{Name: "reason", Usage: "Why (recorded in the audit log)"}},
					Action:    judgeAction.AllowOnce,
				},
				{
					Name:   "uninstall",
					Usage:  "Remove exactly what install added (restores the file if unchanged since)",
					Flags:  []cli.Flag{identityFlag},
					Action: judgeAction.Uninstall,
				},
			},
		},
		{
			Name:   "whoami",
			Usage:  "Show which identity aigate run uses in this folder, and why",
			Flags:  []cli.Flag{identityFlag},
			Action: whoamiAction.Execute,
		},
		{
			Name:        "run",
			Aliases:     []string{"r"},
			Usage:       "Run a command inside the AI sandbox (use -- before command)",
			Description: "Examples:\n   aigate run -- claude\n   aigate run -- bash -c \"npm test\"\n   aigate run --allow-path ~/notes -- claude   # extra scope path, this session only\n   aigate run --identity work -- claude        # only work's logins are visible\n   aigate run --port 3000 -- claude            # open the agent's dev server at localhost:3000",
			Flags:       []cli.Flag{verboseFlag, configFlag, allowPathFlag, identityFlag, judgeModeFlag, portFlag},
			Action:      runAction.Execute,
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
			Name:        "explain",
			Usage:       "Say whether a path or command would be allowed here, which layer decides, and how to change it",
			ArgsUsage:   "PATH | -- COMMAND [ARGS…]",
			Description: "Runs nothing. Uses exactly what `aigate run` would enforce in this folder\n(config, project .aigate.yaml, identity, judge rules). Exits 1 when blocked.\n\nExamples:\n   aigate explain ~/.ssh/id_ed25519\n   aigate explain .env\n   aigate explain -- curl https://example.com\n   aigate explain --identity personal ~/.config/gh-work/hosts.yml\n   aigate explain --judge -- rm -rf ~/      # also ask the judge models",
			Flags: []cli.Flag{
				identityFlag, allowPathFlag,
				cli.BoolFlag{Name: "judge", Usage: "Also ask the judge's models (contacts the provider)"},
				cli.BoolFlag{Name: "path", Usage: "Treat the argument as a path"},
				cli.BoolFlag{Name: "command", Usage: "Treat the arguments as a command"},
				cli.BoolFlag{Name: "json", Usage: "Machine-readable output"},
			},
			Action: explainAction.Execute,
		},
		{
			Name:        "doctor",
			Usage:       "Check sandbox prerequisites and show active isolation mode",
			Description: "Checks config, sandbox tooling, agent-socket hiding, identities and the judge,\nthen prints a verdict (READY / DEGRADED / BLOCKED) with copy-pasteable fixes.\nExits non-zero when blocked, so scripts can gate on it.\n\nExamples:\n   aigate doctor\n   aigate doctor --json      # for scripts\n   aigate doctor --report    # safe to paste in a public issue",
			Flags: []cli.Flag{
				cli.BoolFlag{Name: "json", Usage: "Machine-readable output (versioned schema)"},
				cli.BoolFlag{Name: "report", Usage: "Plain text with home paths, user names and secrets removed, for bug reports"},
				cli.BoolFlag{Name: "offline", Usage: "Don't contact judge model providers"},
			},
			Action: doctorAction.Execute,
		},
		{
			Name:  "serve",
			Usage: "Run the local web dashboard",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "addr",
					Value:  "127.0.0.1:8080",
					Usage:  "Address to listen on (host:port)",
					EnvVar: "AIGATE_ADDR",
				},
			},
			Action: func(c *cli.Context) error {
				srv, err := web.New(web.Options{
					Addr:      c.String("addr"),
					ConfigSvc: configSvc,
					AuditSvc:  auditSvc,
				})
				if err != nil {
					return fmt.Errorf("init web server: %w", err)
				}
				fmt.Printf("\n  Open http://%s in your browser.\n\n", srv.Addr())
				return srv.ListenAndServe(context.Background())
			},
		},
		{
			Name:   "help-ai",
			Usage:  "Show AI-friendly usage examples",
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
