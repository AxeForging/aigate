package services

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// judgeRule is one local check. It only sees the parts of the call its event
// cares about: calls before they run, or output after.
type judgeRule struct {
	name    string
	event   string
	outcome Outcome
	reason  string
	hints   []string // lowercase keywords; without any of them the rule is skipped (speed)
	match   func(text string) bool
}

func reRule(expr string) func(string) bool {
	re := regexp.MustCompile(expr)
	return re.MatchString
}

var (
	reNetFetch  = regexp.MustCompile(`(?i)\b(curl|wget|fetch|iwr|invoke-webrequest)\b`)
	reNetSend   = regexp.MustCompile(`(?i)\b(curl|wget|nc|ncat|netcat|scp|rsync|sftp|ftp)\b`)
	reArchive   = regexp.MustCompile(`(?i)\b(tar|zip|7z|gzip)\b`)
	reHomeDirs  = regexp.MustCompile(`(~/|\$HOME|/home/[^/\s]+|/Users/[^/\s]+)(\s|/|$)`)
	reEnvDump   = regexp.MustCompile(`(?i)\b(env|printenv|set)\b\s*(\||>)`)
	reCredFiles = regexp.MustCompile(`(?i)(\.ssh/(id_[a-z0-9_]+|[^\s/]+\.pem)($|[\s'"();|&>])|\.config/gh[^/\s]*/hosts\.ya?ml|\.claude[^/\s]*/\.credentials\.json|\.aws/credentials|\.netrc\b|\.docker/config\.json|\.kube/config)`)
	reDotEnv    = regexp.MustCompile(`(^|[\s/'"=])\.env(\.[a-z0-9]+)?($|[\s'"])`)
)

// localRules catch the obvious cases fast, before (or instead of) a model.
var localRules = []judgeRule{
	{
		name: "pipe-to-shell", event: EventPreTool, outcome: Deny, hints: []string{"curl", "wget", "fetch"},
		reason: "downloads code from the network and runs it directly",
		match: reRule(`(?i)\b(curl|wget|fetch)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k|fi)?sh\b` +
			`|(ba|z)?sh\s+(-c\s+["']?\$\(|<\()\s*(curl|wget)\b` +
			`|\b(python3?|perl|ruby|node)\b\s+-\s*<\s*<\(\s*(curl|wget)`),
	},
	{
		name: "credential-read", event: EventPreTool, outcome: Deny,
		hints:  []string{".ssh/", "hosts.y", ".credentials.json", ".aws/", ".netrc", ".docker/", ".kube/"},
		reason: "reads a login or key file (ssh, gh, Claude, cloud)",
		match:  reCredFiles.MatchString,
	},
	{
		name: "env-read", event: EventPreTool, outcome: Ask, hints: []string{".env"},
		reason: "reads a .env file, which usually holds secrets",
		match:  reDotEnv.MatchString,
	},
	{
		name: "home-upload", event: EventPreTool, outcome: Deny, hints: []string{"tar", "zip", "7z", "gzip"},
		reason: "archives home folders and sends them over the network",
		match: func(t string) bool {
			return reArchive.MatchString(t) && reHomeDirs.MatchString(t) && reNetSend.MatchString(t)
		},
	},
	{
		name: "env-exfil", event: EventPreTool, outcome: Deny, hints: []string{"env", "set"},
		reason: "sends environment variables over the network",
		match: func(t string) bool {
			return reEnvDump.MatchString(t) && (reNetFetch.MatchString(t) || reNetSend.MatchString(t))
		},
	},
	{
		name: "instructions-to-ai", event: EventPostTool, outcome: Ask,
		hints:  []string{"ignore", "note", "message", "instruction", "assistant", "agent", "llm", "system", "mode"},
		reason: "the output contains instructions aimed at the AI assistant (possible prompt injection)",
		match: reRule(`(?i)(ignore (all |any )?(the )?(previous|prior|above) (instructions|prompts?)` +
			`|(note|message|instructions?) (to|for) (the )?(ai|llm|assistant|claude|agent|copilot)s?\b` +
			`|\b(ai|llm|coding) (assistants?|agents?)\s*[:,-]\s*(please |you must )?(run|execute|send|commit|upload|cat|curl|delete)` +
			`|</?\s*(system|instructions?|assistant)\s*>` +
			`|you are now (in )?(developer|admin|jailbreak|dan) mode)`),
	},
}

// RulesJudge is the local, always-available judge.
type RulesJudge struct{}

func (RulesJudge) Name() string { return JudgeRules }

// Judge returns the strictest matching rule, or NoObjection.
func (RulesJudge) Judge(_ context.Context, call Call) (Verdict, error) {
	start := time.Now()
	text := call.Target + "\n" + call.Input
	if call.Event == EventPostTool {
		text = call.Output
	}
	v := Verdict{Outcome: NoObjection, Judge: JudgeRules}
	lower := strings.ToLower(text)
	var reasons []string
	for _, r := range localRules {
		if r.event != call.Event || !hasAnyHint(lower, r.hints) || !r.match(text) {
			continue
		}
		if r.outcome > v.Outcome {
			v.Outcome = r.outcome
			reasons = append([]string{r.reason}, reasons...)
		} else {
			reasons = append(reasons, r.reason)
		}
	}
	if len(reasons) > 0 {
		v.Reason = strings.Join(reasons, "; ")
	}
	v.Latency = time.Since(start)
	return v, nil
}

func hasAnyHint(lower string, hints []string) bool {
	if len(hints) == 0 {
		return true
	}
	for _, h := range hints {
		if strings.Contains(lower, h) {
			return true
		}
	}
	return false
}
