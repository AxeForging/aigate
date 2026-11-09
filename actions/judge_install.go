package actions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/services"
	"github.com/urfave/cli"
)

// Install adds aigate's judge hooks to the Claude settings of the identity
// active here (or ~/.claude) and turns the judge on.
func (a *JudgeAction) Install(c *cli.Context) error {
	cfg, settings, who, err := a.installTarget(c)
	if err != nil {
		return err
	}
	res, err := a.installer().Install(settings)
	if err != nil {
		return err
	}
	if res.Note == "already installed" {
		fmt.Printf("The aigate judge hook is already installed in %s (%s).\n", tildePath(settings), who)
	} else {
		fmt.Printf("Installed the aigate judge hook in %s (%s).\n", tildePath(settings), who)
	}
	if !cfg.Judge.Enabled {
		cfg.Judge.Enabled = true
		if err := a.configSvc.SaveGlobal(cfg); err != nil {
			return err
		}
		fmt.Println("Turned the judge on in ~/.aigate/config.yaml.")
	}
	s, err := services.ResolveJudgeSettings(cfg.Judge)
	if err != nil {
		return err
	}
	fmt.Printf("Chain: %s. ", strings.Join(s.Chain, " → "))
	if os.Getenv(s.CFTokenEnv) == "" || os.Getenv(s.CFAccountEnv) == "" {
		fmt.Printf("Model judges need %s and %s in your shell; without them only the local rules run.\n", s.CFAccountEnv, s.CFTokenEnv)
	} else {
		fmt.Println("Model credentials found.")
	}
	fmt.Println("It can only deny or ask, never allow; the sandbox still applies. Remove it with: aigate judge uninstall")
	return nil
}

// Uninstall removes exactly what Install added.
func (a *JudgeAction) Uninstall(c *cli.Context) error {
	_, settings, who, err := a.installTarget(c)
	if err != nil {
		return err
	}
	res, err := a.installer().Uninstall(settings)
	if err != nil {
		return err
	}
	if !res.Changed {
		fmt.Printf("No aigate judge hook in %s (%s); nothing to remove.\n", tildePath(settings), who)
		return nil
	}
	fmt.Printf("Removed the aigate judge hook from %s (%s): %s.\n", tildePath(settings), who, res.Note)
	fmt.Println("judge.enabled stays as it is in ~/.aigate/config.yaml (other identities may use it).")
	return nil
}

func (a *JudgeAction) installer() services.JudgeHookInstaller {
	exe, err := os.Executable()
	if err == nil {
		if r, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			exe = r
		}
	} else {
		exe = "aigate"
	}
	if strings.ContainsAny(exe, " '\"\\$") {
		exe = "'" + strings.ReplaceAll(exe, "'", `'\''`) + "'"
	}
	dir, _ := a.configSvc.GlobalConfigDir()
	return services.JudgeHookInstaller{Command: exe + " judge", BackupDir: filepath.Join(dir, "judge-install")}
}

// installTarget picks the settings.json: the identity active here (flag,
// bound folder, default), else $CLAUDE_CONFIG_DIR, else ~/.claude.
func (a *JudgeAction) installTarget(c *cli.Context) (*domain.Config, string, string, error) {
	cfg, err := a.configSvc.LoadGlobal()
	if err != nil {
		return nil, "", "", fmt.Errorf("aigate isn't set up yet. Run: aigate init")
	}
	wd, _ := os.Getwd()
	path, who, err := services.ClaudeSettingsFor(cfg, c.String("identity"), wd)
	return cfg, path, who, err
}
