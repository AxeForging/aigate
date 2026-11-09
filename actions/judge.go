package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/AxeForging/aigate/domain"
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
	if sock := os.Getenv("AIGATE_JUDGE_SOCK"); sock != "" && !c.Bool("dry-run") {
		return a.viaBroker(sock, raw)
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
	broker := &services.JudgeBroker{Chain: services.BuildJudgeChain(settings),
		Audit: services.NewAuditService(a.configSvc), HowToAllow: judgeHowToAllow, Warn: a.stderr}
	a.emit(broker.Handle(raw))
	return nil
}

// viaBroker forwards the payload to the host-side broker of `aigate run`.
// If it can't be reached, local rules still decide (they need no
// credentials), so a sandboxed session is never left unjudged.
func (a *JudgeAction) viaBroker(sock string, raw []byte) error {
	out, err := services.AskJudgeBroker(sock, raw)
	if err == nil {
		a.emit(out)
		return nil
	}
	_, _ = fmt.Fprintf(a.stderr, "[aigate] judge: broker unreachable (%v); used local rules\n", err)
	var in services.HookInput
	if json.Unmarshal(raw, &in) != nil {
		return nil
	}
	call, ok := services.CallFromHook(in)
	if !ok {
		return nil
	}
	v, _ := services.RulesJudge{}.Judge(context.Background(), call)
	a.emit(services.HookOutput(call, v, judgeHowToAllow))
	return nil
}

func (a *JudgeAction) emit(out []byte) {
	if len(out) > 0 {
		_, _ = a.stdout.Write(append(out, '\n'))
	}
}

// startJudgeBroker serves the judge for a sandboxed session when it is
// enabled. It never fails the run over judge problems: those are warnings.
func startJudgeBroker(configSvc *services.ConfigService, global *domain.Config, profile *domain.SandboxProfile) (stop func(), err error) {
	noop := func() {}
	settings, err := services.ResolveJudgeSettings(global.Judge)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[aigate] judge: off — %v\n", err)
		return noop, nil
	}
	if !settings.Enabled || slices.Equal(settings.Chain, []string{services.JudgeOff}) {
		return noop, nil
	}
	dir, err := os.MkdirTemp("", "aigate-judge-")
	if err != nil {
		return noop, fmt.Errorf("judge: %w", err)
	}
	sock := filepath.Join(dir, "judge.sock")
	broker := &services.JudgeBroker{Chain: services.BuildJudgeChain(settings),
		Audit: services.NewAuditService(configSvc), Profile: *profile, HowToAllow: judgeHowToAllow,
		Warn: os.Stderr, WarnOnce: true}
	stopServe, err := services.ServeJudgeBroker(sock, broker)
	if err != nil {
		_ = os.RemoveAll(dir)
		return noop, err
	}
	profile.JudgeSocket = sock
	fmt.Fprintf(os.Stderr, "[aigate] judge: on (%s)\n", strings.Join(settings.Chain, " → "))
	return func() {
		stopServe()
		_ = os.RemoveAll(dir)
	}, nil
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
