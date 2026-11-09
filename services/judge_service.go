package services

import (
	"context"
	"fmt"
	"time"
)

// Outcome is what a judge thinks of a call. Judges can only make things
// stricter: NoObjection never approves anything, it just stays out of the way.
type Outcome int

const (
	NoObjection Outcome = iota
	Ask
	Deny
)

func (o Outcome) String() string {
	return [...]string{"no-objection", "ask", "deny"}[o]
}

// Hook events a call can come from.
const (
	EventPreTool  = "pre"  // before the tool runs: judge the call
	EventPostTool = "post" // after it ran: judge its output (injection)
)

// Call is one agent tool call as the judge sees it.
type Call struct {
	Event  string // EventPreTool or EventPostTool
	Tool   string // e.g. Bash, Read, WebFetch
	Target string // command, file path or URL
	Input  string // remaining tool input, flattened
	Output string // tool output (post events only)
}

// Verdict is one judge's (or the chain's) decision, with everything needed
// to explain it later.
type Verdict struct {
	Outcome    Outcome
	Judge      string             // which judge decided
	Reason     string             // shown to the user
	Scores     map[string]float64 // per-question probabilities (model judges)
	Confidence float64            // model confidence in its choice (0 for rules)
	Latency    time.Duration
	Fallback   string // set when a model failed and rules decided instead
}

// Judge is the port every adapter implements. Adding a provider means adding
// an adapter and registering it; nothing else changes.
type Judge interface {
	Name() string
	Judge(ctx context.Context, call Call) (Verdict, error)
}

// Chain runs rules first, then model tiers: the next tier only when the
// previous one is unsure. The strictest outcome wins.
type Chain struct {
	Rules         Judge
	Models        []Judge
	EscalateBelow float64
	Timeout       time.Duration
	Skipped       []string // configured models left out, with why
}

// availability is implemented by adapters that need credentials; an
// unavailable one is left out of the chain instead of failing every call.
type availability interface {
	Available() error
}

// Decide never returns an error: a failing model falls back to the rules
// verdict (marked with Fallback) so a provider outage never blocks work.
func (c *Chain) Decide(ctx context.Context, call Call) Verdict {
	start := time.Now()
	verdict := Verdict{Outcome: NoObjection, Judge: JudgeOff}
	if c.Rules != nil {
		if v, err := c.Rules.Judge(ctx, call); err == nil {
			verdict = v
		}
	}
	if verdict.Outcome == Deny {
		verdict.Latency = time.Since(start)
		return verdict
	}
	for i, m := range c.Models {
		mctx, cancel := context.WithTimeout(ctx, c.Timeout)
		v, err := m.Judge(mctx, call)
		cancel()
		if err != nil {
			verdict.Fallback = fmt.Sprintf("%s unavailable (%v); used local rules", m.Name(), err)
			break
		}
		last := i == len(c.Models)-1
		if v.Confidence >= c.EscalateBelow || last {
			verdict = strictest(verdict, v)
			break
		}
	}
	verdict.Latency = time.Since(start)
	return verdict
}

// strictest keeps the stricter verdict; on a tie the later (model) verdict
// wins because it carries scores.
func strictest(a, b Verdict) Verdict {
	if a.Outcome > b.Outcome {
		return a
	}
	return b
}

// judgeAdapters builds model adapters by name. Unregistered names are
// skipped, so a chain can list judges before their adapters exist.
var judgeAdapters = map[string]func(JudgeSettings) Judge{}

// BuildJudgeChain assembles the configured chain. "rules" is always first
// when listed; "off" or an empty chain judges nothing.
func BuildJudgeChain(s JudgeSettings) *Chain {
	c := &Chain{EscalateBelow: s.EscalateBelow, Timeout: s.Timeout}
	for _, name := range s.Chain {
		switch name {
		case JudgeOff:
			return &Chain{}
		case JudgeRules:
			c.Rules = RulesJudge{}
		default:
			build, ok := judgeAdapters[name]
			if !ok {
				c.Skipped = append(c.Skipped, name+": not available yet")
				continue
			}
			j := build(s)
			if a, ok := j.(availability); ok {
				if err := a.Available(); err != nil {
					c.Skipped = append(c.Skipped, fmt.Sprintf("%s: %v", name, err))
					continue
				}
			}
			c.Models = append(c.Models, j)
		}
	}
	return c
}
