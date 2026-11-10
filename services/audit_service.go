package services

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/AxeForging/aigate/domain"
)

const auditLogFile = "audit.jsonl"

// AuditEvent is a compact event record used by the local dashboard.
type AuditEvent struct {
	Time     time.Time         `json:"time"`
	Kind     string            `json:"kind"`
	Identity string            `json:"identity,omitempty"`
	Rule     string            `json:"rule,omitempty"`
	Command  string            `json:"command,omitempty"`
	WorkDir  string            `json:"work_dir,omitempty"`
	Source   string            `json:"source,omitempty"`
	Detail   string            `json:"detail,omitempty"`
	Counts   map[string]int    `json:"counts,omitempty"`
	Meta     map[string]string `json:"meta,omitempty"`
}

type AuditService struct {
	configSvc *ConfigService
	mu        sync.Mutex
}

func NewAuditService(configSvc *ConfigService) *AuditService {
	if configSvc == nil {
		configSvc = NewConfigService()
	}
	return &AuditService{configSvc: configSvc}
}

func (s *AuditService) Log(event AuditEvent) error {
	if event.Time.IsZero() {
		event.Time = time.Now()
	}
	path, err := s.Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create audit dir: %w", err)
	}
	b, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return nil
}

func (s *AuditService) LogRunStarted(profile domain.SandboxProfile, cmd string, args []string) {
	_ = s.Log(AuditEvent{
		Kind:     "run_started",
		Identity: identityName(profile),
		Command:  formatCommand(cmd, args),
		WorkDir:  profile.WorkDir,
		Counts: map[string]int{
			"deny_read": len(profile.Config.DenyRead),
			"deny_exec": len(profile.Config.DenyExec),
			"allow_net": len(profile.Config.AllowNet),
			"masking":   len(profile.Config.MaskStdout.Presets) + len(profile.Config.MaskStdout.Patterns),
		},
	})
}

func (s *AuditService) LogBlocked(profile domain.SandboxProfile, cmd string, args []string, rule, source, detail string) {
	_ = s.Log(AuditEvent{
		Kind:     "blocked",
		Identity: identityName(profile),
		Rule:     rule,
		Command:  formatCommand(cmd, args),
		WorkDir:  profile.WorkDir,
		Source:   source,
		Detail:   detail,
	})
}

func (s *AuditService) Path() (string, error) {
	dir, err := s.configSvc.GlobalConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, auditLogFile), nil
}

func (s *AuditService) Recent(limit int) ([]AuditEvent, error) {
	path, err := s.Path()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var events []AuditEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var event AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err == nil && !isJudgeEcho(event) {
			events = append(events, event)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

// isJudgeEcho: older versions also recorded the judge's message, as shown in
// the session's output, as a sandbox block. The judge logs that decision
// itself, so the echo is a duplicate.
func isJudgeEcho(e AuditEvent) bool {
	return e.Kind == "blocked" && (e.Source == "stdout" || e.Source == "stderr") && strings.Contains(e.Detail, "— judge:")
}

func formatCommand(cmd string, args []string) string {
	if len(args) == 0 {
		return cmd
	}
	return strings.Join(append([]string{cmd}, args...), " ")
}

type auditWriter struct {
	dst     io.Writer
	audit   *AuditService
	profile domain.SandboxProfile
	cmd     string
	args    []string
	source  string
	buf     string
	seen    map[string]bool
}

const (
	// auditChunk: output without newlines (TUIs) is inspected in chunks of
	// this size, keeping auditOverlap bytes so a message cut at the end of
	// one chunk is seen whole in the next.
	auditChunk   = 4096
	auditOverlap = 1024
	// auditKeyLen: messages agreeing on this many leading characters are the
	// same block redrawn, recorded once per session.
	auditKeyLen = 80
)

func NewAuditWriter(dst io.Writer, audit *AuditService, profile domain.SandboxProfile, cmd string, args []string, source string) io.Writer {
	if dst == nil || audit == nil {
		return dst
	}
	return &auditWriter{dst: dst, audit: audit, profile: profile, cmd: cmd, args: args, source: source, seen: map[string]bool{}}
}

func (w *auditWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	w.observe(string(p))
	return n, err
}

// Flush inspects output left without a final newline. Call it when the
// session ends.
func (w *auditWriter) Flush() {
	w.inspect(w.buf, true)
	w.buf = ""
}

func (w *auditWriter) observe(chunk string) {
	w.buf += chunk
	for {
		idx := strings.IndexByte(w.buf, '\n')
		if idx < 0 {
			if len(w.buf) > auditChunk {
				w.inspect(w.buf, false)
				w.buf = w.buf[len(w.buf)-auditOverlap:]
			}
			return
		}
		line := w.buf[:idx]
		w.buf = w.buf[idx+1:]
		w.inspect(line, true)
	}
}

// inspect records each aigate block message in text. complete is false when
// text was cut mid-output; a message reaching its end is then left for the
// next chunk.
func (w *auditWriter) inspect(text string, complete bool) {
	if !strings.Contains(text, "[aigate]") {
		return
	}
	// A cursor jump to another screen position ends what was drawn before it.
	parts := cursorJumpRe.Split(text, -1)
	for i, p := range parts {
		w.inspectLine(p, complete || i < len(parts)-1)
	}
}

func (w *auditWriter) inspectLine(text string, complete bool) {
	if !strings.Contains(text, "[aigate]") {
		return
	}
	msgs := strings.Split(plainText(text), "[aigate]")[1:]
	for i, m := range msgs {
		if !complete && i == len(msgs)-1 && len([]rune(m)) < maxAuditText {
			continue
		}
		msg := clipText("[aigate]"+strings.TrimRight(m, " "), maxAuditText)
		rule := blockRule(msg)
		if rule == "" {
			continue
		}
		key := clipText(msg, auditKeyLen)
		if w.seen[key] {
			continue
		}
		w.seen[key] = true
		w.audit.LogBlocked(w.profile, w.cmd, w.args, rule, w.source, msg)
	}
}

// cursorJumpRe matches absolute cursor moves (CSI row;col H or f).
var cursorJumpRe = regexp.MustCompile(`\x1b\[[0-9;]*[Hf]`)

// blockRule names the rule behind a sandbox block message, or "" for other
// aigate output. Judge messages are skipped: the judge logs its own decisions.
func blockRule(msg string) string {
	switch {
	case strings.Contains(msg, "— judge:"):
		return ""
	case strings.HasPrefix(msg, "[aigate] blocked read") || strings.Contains(msg, "access denied"):
		return "deny_read"
	case strings.Contains(msg, "blocked") || strings.Contains(msg, "denied by sandbox policy"):
		return "deny_exec"
	case strings.Contains(msg, "network"):
		return "allow_net"
	}
	return ""
}

func identityName(profile domain.SandboxProfile) string {
	if profile.Identity == nil {
		return ""
	}
	return profile.Identity.Name
}
