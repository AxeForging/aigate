package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/AxeForging/aigate/services"
	"github.com/urfave/cli"
)

// judgeHowToAllow is shown with every judge block.
const judgeHowToAllow = "set judge.enabled: false in ~/.aigate/config.yaml (the sandbox still applies)"

type JudgeAction struct {
	configSvc *services.ConfigService
	stdin     io.Reader
	stdout    io.Writer
	stderr    io.Writer
}

func NewJudgeAction(c *services.ConfigService) *JudgeAction {
	return &JudgeAction{configSvc: c, stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr}
}

// Hook runs as a Claude Code PreToolUse/PostToolUse hook: payload on stdin,
// decision JSON (or nothing) on stdout. It always exits 0: a broken judge
// must never block work, the sandbox stays the boundary.
func (a *JudgeAction) Hook(c *cli.Context) error {
	raw, err := io.ReadAll(io.LimitReader(a.stdin, 8<<20))
	if err != nil {
		return a.warn("could not read hook input: %v", err)
	}
	var in services.HookInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return a.warn("hook input is not JSON (%v); expected a Claude Code PreToolUse/PostToolUse payload", err)
	}
	call, ok := services.CallFromHook(in)
	if !ok {
		return nil
	}
	cfg, err := a.configSvc.LoadGlobal()
	if err != nil {
		return a.warn("aigate isn't set up (run: aigate init); judge skipped")
	}
	settings, err := services.ResolveJudgeSettings(cfg.Judge)
	if err != nil {
		return a.warn("%v", err)
	}

	if c.Bool("dry-run") {
		return a.dryRun(call, settings)
	}
	if !settings.Enabled {
		return nil
	}
	chain := services.BuildJudgeChain(settings)
	v := chain.Decide(context.Background(), call)
	if v.Fallback != "" {
		_, _ = fmt.Fprintf(a.stderr, "[aigate] judge: %s\n", v.Fallback)
	}
	if out := services.HookOutput(call, v, judgeHowToAllow); out != nil {
		_, _ = a.stdout.Write(append(out, '\n'))
	}
	return nil
}

// dryRun prints exactly what a model judge would receive, plus the local
// verdict, without contacting anyone.
func (a *JudgeAction) dryRun(call services.Call, s services.JudgeSettings) error {
	payload := services.BuildJudgePayload(call, s.ExcerptBytes)
	rules, _ := services.RulesJudge{}.Judge(context.Background(), call)
	out, _ := json.MarshalIndent(map[string]any{
		"enabled":         s.Enabled,
		"chain":           s.Chain,
		"would_send":      payload,
		"local_rules":     map[string]string{"outcome": rules.Outcome.String(), "reason": rules.Reason},
		"note":            "dry run: nothing was sent; would_send is exactly what a model judge receives",
		"credentials_env": []string{s.CFAccountEnv, s.CFTokenEnv, s.JevTokenEnv},
	}, "", "  ")
	_, _ = fmt.Fprintln(a.stdout, string(out))
	return nil
}

func (a *JudgeAction) warn(format string, args ...any) error {
	_, _ = fmt.Fprintf(a.stderr, "[aigate] judge: "+format+"\n", args...)
	return nil
}
