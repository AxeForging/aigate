package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AxeForging/aigate/domain"
)

const maxHookPayload = 8 << 20

// JudgeBroker answers hook payloads. `aigate run` serves it on a socket bound
// into the sandbox, so hooks running inside never see the config, provider
// credentials or audit log; outside a sandbox the hook uses it in-process.
type JudgeBroker struct {
	Chain      *Chain
	Audit      *AuditService // nil: no audit
	Profile    domain.SandboxProfile
	HowToAllow string
	Warn       io.Writer // fallback warnings; nil: none
	WarnOnce   bool      // only the first fallback (long sessions)

	warnMu sync.Mutex
	warned bool
}

// Handle turns one raw hook payload into hook output (nil: no decision).
func (b *JudgeBroker) Handle(raw []byte) []byte {
	var in HookInput
	if json.Unmarshal(raw, &in) != nil {
		return nil
	}
	call, ok := CallFromHook(in)
	if !ok {
		return nil
	}
	v := b.Chain.Decide(context.Background(), call)
	b.record(call, v, in.Cwd)
	b.warn(v)
	return HookOutput(call, v, b.HowToAllow)
}

func (b *JudgeBroker) warn(v Verdict) {
	if b.Warn == nil || v.Fallback == "" {
		return
	}
	b.warnMu.Lock()
	defer b.warnMu.Unlock()
	if b.WarnOnce && b.warned {
		return
	}
	b.warned = true
	suffix := ""
	if b.WarnOnce {
		suffix = " (shown once; all fallbacks are in the audit log)"
	}
	_, _ = fmt.Fprintf(b.Warn, "[aigate] judge: %s%s\n", v.Fallback, suffix)
}

// record audits every block, every fallback and every model decision; plain
// local "no objection" calls are not logged (one per tool call is too noisy).
func (b *JudgeBroker) record(call Call, v Verdict, cwd string) {
	if b.Audit == nil {
		return
	}
	workDir := b.Profile.WorkDir
	if workDir == "" {
		workDir = cwd
	}
	profile := b.Profile
	profile.WorkDir = workDir
	command := oneLine(maskSecrets(strings.TrimSpace(call.Tool+" "+call.Target)), 200)
	if v.Fallback != "" {
		_ = b.Audit.Log(AuditEvent{Kind: "judge_fallback", Identity: identityName(profile), WorkDir: workDir,
			Rule: v.Judge, Command: command, Detail: v.Fallback})
	}
	if v.Outcome == NoObjection && (v.Judge == JudgeRules || v.Judge == JudgeOff) {
		return
	}
	meta := map[string]string{
		"outcome":    v.Outcome.String(),
		"event":      call.Event,
		"latency_ms": strconv.FormatInt(v.Latency.Milliseconds(), 10),
	}
	if v.Confidence > 0 {
		meta["confidence"] = strconv.FormatFloat(v.Confidence, 'f', 3, 64)
	}
	for k, p := range v.Scores {
		meta["score_"+k] = strconv.FormatFloat(p, 'f', 3, 64)
	}
	_ = b.Audit.Log(AuditEvent{Kind: "judge_decision", Identity: identityName(profile), WorkDir: workDir,
		Rule: v.Judge, Command: command, Detail: v.Reason, Meta: meta})
}

// ServeJudgeBroker listens on a unix socket at path (owner-only) and answers
// one payload per connection. stop closes the listener and removes the file.
func ServeJudgeBroker(path string, b *JudgeBroker) (stop func(), err error) {
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("start judge broker: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(maxJudgeTimeout + 5*time.Second))
				raw, err := io.ReadAll(io.LimitReader(c, maxHookPayload))
				if err != nil {
					return
				}
				_, _ = c.Write(b.Handle(raw))
			}(conn)
		}
	}()
	return func() {
		_ = ln.Close()
		<-done
		_ = os.Remove(path)
	}, nil
}

// AskJudgeBroker sends one payload and returns the broker's hook output.
func AskJudgeBroker(path string, raw []byte) ([]byte, error) {
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(maxJudgeTimeout + 5*time.Second))
	if _, err := conn.Write(raw); err != nil {
		return nil, err
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.New("judge broker: not a unix socket")
	}
	if err := uc.CloseWrite(); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(conn, 1<<20))
}

// JudgeCredentialEnv lists the provider credential variables a config names;
// they are removed from every sandbox so the agent can't read them.
func JudgeCredentialEnv(cfg domain.JudgeConfig) []string {
	s, err := ResolveJudgeSettings(cfg)
	if err != nil {
		s = DefaultJudgeSettings()
	}
	return []string{s.CFAccountEnv, s.CFTokenEnv, s.JevTokenEnv}
}
