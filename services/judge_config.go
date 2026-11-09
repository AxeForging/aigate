package services

import (
	"fmt"
	"strings"
	"time"

	"github.com/AxeForging/aigate/domain"
)

// Judge adapter names usable in judge.chain.
const (
	JudgeRules      = "rules"
	JudgeClefFlash  = "clef-flash"
	JudgeClef       = "clef"
	JudgeJev        = "jev"
	JudgeOff        = "off"
	maxJudgeTimeout = 30 * time.Second
)

var knownJudges = []string{JudgeRules, JudgeClefFlash, JudgeClef, JudgeJev, JudgeOff}

// JudgeSettings is a JudgeConfig with defaults applied and values parsed.
type JudgeSettings struct {
	Enabled       bool
	Chain         []string
	EscalateBelow float64
	DenyAbove     float64
	AskAbove      float64
	Timeout       time.Duration
	ExcerptBytes  int
	CFAccountEnv  string
	CFTokenEnv    string
	JevTokenEnv   string
}

// DefaultJudgeSettings mirrors the spec: rules first, then the fast model,
// the precise one only when the fast one is unsure.
func DefaultJudgeSettings() JudgeSettings {
	return JudgeSettings{
		Chain:         []string{JudgeRules, JudgeClefFlash, JudgeClef},
		EscalateBelow: 0.6,
		DenyAbove:     0.8,
		AskAbove:      0.5,
		Timeout:       1500 * time.Millisecond,
		ExcerptBytes:  4096,
		CFAccountEnv:  "AIGATE_CF_ACCOUNT",
		CFTokenEnv:    "AIGATE_CF_TOKEN",
		JevTokenEnv:   "AIGATE_JEV_TOKEN",
	}
}

// ResolveJudgeSettings applies defaults to cfg and validates it. Any problem
// is returned with the setting to change; the result is unusable then.
func ResolveJudgeSettings(cfg domain.JudgeConfig) (JudgeSettings, error) {
	s := DefaultJudgeSettings()
	s.Enabled = cfg.Enabled
	var errs []string
	bad := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }

	if len(cfg.Chain) > 0 {
		s.Chain = cfg.Chain
	}
	for _, name := range s.Chain {
		if !containsPath(knownJudges, name) {
			bad("judge.chain: unknown judge %q (use: %s)", name, strings.Join(knownJudges, ", "))
		}
	}
	for _, f := range []struct {
		key string
		in  float64
		out *float64
	}{{"escalate_below", cfg.EscalateBelow, &s.EscalateBelow}, {"deny_above", cfg.DenyAbove, &s.DenyAbove}, {"ask_above", cfg.AskAbove, &s.AskAbove}} {
		if f.in == 0 {
			continue
		}
		if f.in < 0 || f.in > 1 {
			bad("judge.%s must be between 0 and 1, got %v", f.key, f.in)
			continue
		}
		*f.out = f.in
	}
	if s.AskAbove > s.DenyAbove {
		bad("judge.ask_above (%v) must not be higher than judge.deny_above (%v)", s.AskAbove, s.DenyAbove)
	}
	if cfg.Timeout != "" {
		d, err := time.ParseDuration(cfg.Timeout)
		switch {
		case err != nil:
			bad("judge.timeout %q is not a duration (e.g. 1.5s)", cfg.Timeout)
		case d <= 0 || d > maxJudgeTimeout:
			bad("judge.timeout must be between 0 and %s, got %s", maxJudgeTimeout, d)
		default:
			s.Timeout = d
		}
	}
	if cfg.ExcerptBytes != 0 {
		if cfg.ExcerptBytes < 256 || cfg.ExcerptBytes > 65536 {
			bad("judge.excerpt_bytes must be between 256 and 65536, got %d", cfg.ExcerptBytes)
		} else {
			s.ExcerptBytes = cfg.ExcerptBytes
		}
	}
	for _, e := range []struct {
		key, val string
		out      *string
	}{
		{"providers.cloudflare.account_env", cfg.Providers.Cloudflare.AccountEnv, &s.CFAccountEnv},
		{"providers.cloudflare.token_env", cfg.Providers.Cloudflare.TokenEnv, &s.CFTokenEnv},
		{"providers.jev.token_env", cfg.Providers.Jev.TokenEnv, &s.JevTokenEnv},
	} {
		if e.val == "" {
			continue
		}
		if !envNameRe.MatchString(e.val) {
			bad("judge.%s must name an environment variable (not hold the secret itself), got %q", e.key, maskedHint(e.val))
			continue
		}
		*e.out = e.val
	}
	if len(errs) > 0 {
		return JudgeSettings{}, fmt.Errorf("invalid judge config in ~/.aigate/config.yaml:\n  %s", strings.Join(errs, "\n  "))
	}
	return s, nil
}

// maskedHint shows only the shape of a value that may be a pasted secret.
func maskedHint(v string) string {
	if len(v) <= 4 {
		return "***"
	}
	return v[:2] + "***"
}
