package actions

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/AxeForging/aigate/services"
	"github.com/urfave/cli"
)

// Eval scores the local rules, each available model and the configured
// chain on a labeled corpus (the built-in one by default).
func (a *JudgeAction) Eval(c *cli.Context) error {
	cases, err := services.LoadJudgeCorpus(c.String("corpus"))
	if err != nil {
		return err
	}
	settings := services.DefaultJudgeSettings()
	if cfg, err := a.configSvc.LoadGlobal(); err == nil {
		if settings, err = services.ResolveJudgeSettings(cfg.Judge); err != nil {
			return err
		}
	}
	chain := services.BuildJudgeChain(settings)
	results := []services.EvalResult{services.EvaluateJudge("rules", &services.Chain{Rules: services.RulesJudge{}}, cases)}
	for _, m := range chain.Models {
		alone := &services.Chain{Models: []services.Judge{m}, EscalateBelow: settings.EscalateBelow, Timeout: settings.Timeout}
		results = append(results, services.EvaluateJudge(m.Name(), alone, cases))
	}
	if len(chain.Models) > 0 {
		results = append(results, services.EvaluateJudge("chain ("+strings.Join(settings.Chain, " → ")+")", chain, cases))
	}

	if c.Bool("json") {
		out, _ := json.MarshalIndent(map[string]any{"cases": len(cases), "results": results, "skipped": chain.Skipped}, "", "  ")
		fmt.Println(string(out))
		return nil
	}
	fmt.Printf("Judge eval on %d cases (positives = unsafe + injection; flagged = ask or deny)\n\n", len(cases))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "JUDGE\tPRECISION\tRECALL\tMEAN\tP95\tFALLBACKS")
	for _, r := range results {
		_, _ = fmt.Fprintf(w, "%s\t%.2f\t%.2f\t%s\t%s\t%d\n", r.Judge, r.Precision, r.Recall,
			r.MeanLatency.Round(time.Microsecond), r.P95Latency.Round(time.Microsecond), r.Errors)
	}
	_ = w.Flush()
	for _, r := range results {
		if len(r.Missed)+len(r.FalseAlarms) > 0 {
			fmt.Printf("\n%s missed: %s", r.Judge, orDash(strings.Join(r.Missed, ", ")))
			fmt.Printf("\n%s false alarms: %s", r.Judge, orDash(strings.Join(r.FalseAlarms, ", ")))
		}
	}
	fmt.Println()
	if len(chain.Skipped) > 0 {
		fmt.Println()
	}
	for _, s := range chain.Skipped {
		fmt.Printf("skipped %s\n", s)
	}
	return nil
}
