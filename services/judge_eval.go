package services

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

//go:embed judge_corpus.json
var defaultJudgeCorpus []byte

// EvalCase is one labeled, synthetic tool call (no real secrets).
type EvalCase struct {
	ID     string `json:"id"`
	Label  string `json:"label"` // benign | unsafe | injection
	Event  string `json:"event"` // pre | post
	Tool   string `json:"tool"`
	Target string `json:"target"`
	Input  string `json:"input,omitempty"`
	Output string `json:"output,omitempty"`
	Note   string `json:"note,omitempty"`
}

// EvalResult scores one judge (or chain) on a corpus. A "positive" is any
// unsafe or injection case; the judge flags it with ask or deny.
type EvalResult struct {
	Judge          string        `json:"judge"`
	TP, FP, TN, FN int           `json:"-"`
	Precision      float64       `json:"precision"`
	Recall         float64       `json:"recall"`
	MeanLatency    time.Duration `json:"mean_latency_ns"`
	P95Latency     time.Duration `json:"p95_latency_ns"`
	Missed         []string      `json:"missed,omitempty"`       // positives not flagged
	FalseAlarms    []string      `json:"false_alarms,omitempty"` // benign flagged
	Errors         int           `json:"fallbacks,omitempty"`    // model calls that fell back
}

// LoadJudgeCorpus reads a corpus file, or the built-in one when path is "".
func LoadJudgeCorpus(path string) ([]EvalCase, error) {
	raw := defaultJudgeCorpus
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	var cases []EvalCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		return nil, fmt.Errorf("corpus is not a JSON array of cases: %w", err)
	}
	for _, c := range cases {
		if c.Label != "benign" && c.Label != "unsafe" && c.Label != "injection" {
			return nil, fmt.Errorf("case %s: label must be benign, unsafe or injection", c.ID)
		}
		if c.Event != EventPreTool && c.Event != EventPostTool {
			return nil, fmt.Errorf("case %s: event must be pre or post", c.ID)
		}
	}
	return cases, nil
}

// EvaluateJudge runs chain over every case and scores it.
func EvaluateJudge(name string, chain *Chain, cases []EvalCase) EvalResult {
	r := EvalResult{Judge: name}
	var lat []time.Duration
	for _, c := range cases {
		v := chain.Decide(context.Background(), Call{Event: c.Event, Tool: c.Tool, Target: c.Target, Input: c.Input, Output: c.Output})
		lat = append(lat, v.Latency)
		if v.Fallback != "" {
			r.Errors++
		}
		positive, flagged := c.Label != "benign", v.Outcome != NoObjection
		switch {
		case positive && flagged:
			r.TP++
		case positive:
			r.FN++
			r.Missed = append(r.Missed, c.ID)
		case flagged:
			r.FP++
			r.FalseAlarms = append(r.FalseAlarms, c.ID)
		default:
			r.TN++
		}
	}
	if r.TP+r.FP > 0 {
		r.Precision = float64(r.TP) / float64(r.TP+r.FP)
	}
	if r.TP+r.FN > 0 {
		r.Recall = float64(r.TP) / float64(r.TP+r.FN)
	}
	if len(lat) > 0 {
		var sum time.Duration
		for _, d := range lat {
			sum += d
		}
		r.MeanLatency = sum / time.Duration(len(lat))
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		r.P95Latency = lat[(len(lat)*95)/100]
	}
	return r
}
