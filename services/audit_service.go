package services

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AxeForging/aigate/domain"
)

const auditLogFile = "audit.jsonl"

// AuditEvent is a compact event record used by the local dashboard.
type AuditEvent struct {
	Time    time.Time         `json:"time"`
	Kind    string            `json:"kind"`
	Rule    string            `json:"rule,omitempty"`
	Command string            `json:"command,omitempty"`
	WorkDir string            `json:"work_dir,omitempty"`
	Source  string            `json:"source,omitempty"`
	Detail  string            `json:"detail,omitempty"`
	Counts  map[string]int    `json:"counts,omitempty"`
	Meta    map[string]string `json:"meta,omitempty"`
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
		Kind:    "run_started",
		Command: formatCommand(cmd, args),
		WorkDir: profile.WorkDir,
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
		Kind:    "blocked",
		Rule:    rule,
		Command: formatCommand(cmd, args),
		WorkDir: profile.WorkDir,
		Source:  source,
		Detail:  detail,
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
		if err := json.Unmarshal(scanner.Bytes(), &event); err == nil {
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
}

func NewAuditWriter(dst io.Writer, audit *AuditService, profile domain.SandboxProfile, cmd string, args []string, source string) io.Writer {
	if dst == nil || audit == nil {
		return dst
	}
	return &auditWriter{dst: dst, audit: audit, profile: profile, cmd: cmd, args: args, source: source}
}

func (w *auditWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	w.observe(string(p))
	return n, err
}

func (w *auditWriter) observe(chunk string) {
	w.buf += chunk
	for {
		idx := strings.IndexByte(w.buf, '\n')
		if idx < 0 {
			if len(w.buf) > 4096 {
				w.inspect(w.buf)
				w.buf = ""
			}
			return
		}
		line := w.buf[:idx]
		w.buf = w.buf[idx+1:]
		w.inspect(line)
	}
}

func (w *auditWriter) inspect(line string) {
	line = strings.TrimSpace(line)
	if line == "" || !strings.Contains(line, "[aigate]") {
		return
	}
	rule := ""
	switch {
	case strings.Contains(line, "access denied"):
		rule = "deny_read"
	case strings.Contains(line, "blocked") || strings.Contains(line, "denied by sandbox policy"):
		rule = "deny_exec"
	case strings.Contains(line, "network"):
		rule = "allow_net"
	}
	if rule == "" {
		return
	}
	w.audit.LogBlocked(w.profile, w.cmd, w.args, rule, w.source, line)
}
