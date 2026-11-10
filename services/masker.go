package services

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/AxeForging/aigate/domain"
)

// builtinPresets maps preset names to their regex pattern and how many leading
// bytes to preserve before the *** replacement (0 = fully masked).
var builtinPresets = map[string]struct {
	pattern    string
	showPrefix int
	hints      []string // literals one of which every match contains; lines without them skip the regex
}{
	// OpenAI: sk-... or sk-proj-...
	"openai": {`sk-[a-zA-Z0-9\-_]{20,}`, 3, []string{"sk-"}},
	// Anthropic: sk-ant-api03-...
	"anthropic": {`sk-ant-[a-zA-Z0-9\-_]{20,}`, 7, []string{"sk-ant-"}},
	// AWS access key ID
	"aws_key": {`AKIA[0-9A-Z]{16}`, 4, []string{"AKIA"}},
	// AWS secret access key (matched by env var name since the value has no fixed prefix)
	"aws_secret": {`AWS_SECRET_ACCESS_KEY\s*[=:]\s*\S+`, 22, []string{"AWS_SECRET_ACCESS_KEY"}},
	// GitHub tokens: ghp_, gho_, ghu_, ghs_, ghr_ and fine-grained github_pat_
	"github": {`gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,}`, 4, []string{"gh", "github_pat_"}},
	// Generic Bearer token in headers/logs
	"bearer": {`(?i)Bearer [A-Za-z0-9._\-]{20,}`, 7, nil}, // any capitalization: no literal prefilter
	// Cloudflare scannable credentials: cfut_ (user token), cfat_ (account
	// token), cfk_ (global key) + 40 chars + 8 hex checksum
	"cloudflare": {`cf(?:ut|at|k)_[A-Za-z0-9]{40}[0-9a-f]{8}`, 4, []string{"cf"}},
	// GitLab personal/project access tokens
	"gitlab": {`glpat-[A-Za-z0-9\-_]{20,}`, 6, []string{"glpat-"}},
	// Slack bot/user/app tokens
	"slack": {`xox[baprs]-[A-Za-z0-9\-]{10,}`, 5, []string{"xox"}},
	// Stripe live secret and restricted keys
	"stripe": {`(?:sk|rk)_live_[A-Za-z0-9]{20,}`, 8, []string{"_live_"}},
	// Google API keys
	"google": {`AIza[0-9A-Za-z\-_]{35}`, 4, []string{"AIza"}},
	// npm access tokens
	"npm": {`npm_[A-Za-z0-9]{36}`, 4, []string{"npm_"}},
	// Hugging Face access tokens
	"huggingface": {`hf_[A-Za-z0-9]{34,}`, 3, []string{"hf_"}},
}

// BuiltinPresetNames returns the sorted list of available preset names.
// Used for validation and documentation.
func BuiltinPresetNames() []string {
	names := make([]string, 0, len(builtinPresets))
	for k := range builtinPresets {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

type maskRule struct {
	re         *regexp.Regexp
	showPrefix int
	hints      [][]byte // empty: always run the regex
}

// MaskingWriter wraps an io.Writer and redacts secrets before forwarding to
// the underlying writer. Output is passed on as it arrives, so prompts and
// TUI redraws that never end a line still show. Only the last few words of an
// unfinished line are held back, so a secret split across two writes is still
// caught; they are released, masked, once output pauses for maskIdle.
type MaskingWriter struct {
	out   io.Writer
	rules []maskRule
	idle  time.Duration

	mu    sync.Mutex
	buf   []byte
	timer *time.Timer
}

const (
	// maskIdle: how long a held tail waits for more output before it is shown.
	maskIdle = 25 * time.Millisecond
	// maskHoldWords: words held back at the end of an unfinished line. The
	// longest preset ("AWS_SECRET_ACCESS_KEY = value") spans three.
	maskHoldWords = 3
	// maskMaxHold: a tail longer than this is shown anyway.
	maskMaxHold = 4096
)

// NewMaskingWriter builds a MaskingWriter from the given MaskStdout config.
// Returns (nil, nil) when no presets or patterns are configured — callers
// should fall back to the raw writer in that case.
func NewMaskingWriter(out io.Writer, cfg domain.MaskStdout) (*MaskingWriter, error) {
	var rules []maskRule

	for _, name := range cfg.Presets {
		p, ok := builtinPresets[name]
		if !ok {
			return nil, fmt.Errorf("unknown mask_stdout preset %q (available: %s)", name, strings.Join(BuiltinPresetNames(), ", "))
		}
		re, err := regexp.Compile(p.pattern)
		if err != nil {
			return nil, fmt.Errorf("internal error compiling preset %q: %w", name, err)
		}
		rule := maskRule{re: re, showPrefix: p.showPrefix}
		for _, h := range p.hints {
			rule.hints = append(rule.hints, []byte(h))
		}
		rules = append(rules, rule)
	}

	for _, mp := range cfg.Patterns {
		pattern := mp.Regex
		if mp.CaseInsensitive {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid mask_stdout pattern %q: %w", mp.Regex, err)
		}
		rules = append(rules, maskRule{re: re, showPrefix: mp.ShowPrefix})
	}

	if len(rules) == 0 {
		return nil, nil
	}
	return &MaskingWriter{out: out, rules: rules, idle: maskIdle}, nil
}

// Write redacts and forwards complete lines and everything of an unfinished
// line except its last few words, and returns len(p).
func (m *MaskingWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.buf = append(m.buf, p...)
	for {
		idx := bytes.IndexByte(m.buf, '\n')
		if idx < 0 {
			break
		}
		if err := m.emit(idx + 1); err != nil {
			return 0, err
		}
	}
	if err := m.emit(m.safeSplit()); err != nil {
		return 0, err
	}
	if len(m.buf) > 0 {
		m.armIdle()
	}
	return len(p), nil
}

// Flush writes any remaining buffered bytes (last line without a trailing newline).
// Call this after the child process exits.
func (m *MaskingWriter) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.timer != nil {
		m.timer.Stop()
	}
	return m.emit(len(m.buf))
}

// emit redacts and writes buf[:n], keeping the rest.
func (m *MaskingWriter) emit(n int) error {
	if n <= 0 {
		return nil
	}
	_, err := m.out.Write(m.redact(m.buf[:n]))
	m.buf = append(m.buf[:0], m.buf[n:]...)
	return err
}

// safeSplit is how much of an unfinished line can be shown now: up to its
// last few words, and never cutting through text a rule already matches
// (e.g. "AWS_SECRET_ACCESS_KEY = value" where the value has just arrived).
func (m *MaskingWriter) safeSplit() int {
	split := holdFrom(m.buf)
	for moved := true; moved && split > 0; {
		moved = false
		for _, rule := range m.rules {
			if !rule.mayMatch(m.buf) {
				continue
			}
			for _, loc := range rule.re.FindAllIndex(m.buf, -1) {
				if loc[0] < split && loc[1] > split {
					split, moved = loc[0], true
				}
			}
		}
	}
	return split
}

func (m *MaskingWriter) armIdle() {
	if m.timer == nil {
		m.timer = time.AfterFunc(m.idle, func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			_ = m.emit(len(m.buf))
		})
		return
	}
	m.timer.Reset(m.idle)
}

// holdFrom returns where the held-back tail of an unfinished line starts: the
// beginning of its last maskHoldWords words. Whitespace and control bytes
// (including the escape sequences TUIs draw with) separate words.
func holdFrom(line []byte) int {
	if len(line) > maskMaxHold {
		return len(line)
	}
	words, i := 0, len(line)
	for i > 0 {
		for i > 0 && isMaskSeparator(line[i-1]) {
			i--
		}
		if i == 0 {
			break
		}
		for i > 0 && !isMaskSeparator(line[i-1]) {
			i--
		}
		if i > 0 && line[i-1] == 0x1b { // keep an escape sequence whole
			i--
		}
		if words++; words == maskHoldWords {
			break
		}
	}
	return i
}

func isMaskSeparator(b byte) bool { return b <= ' ' || b == 0x7f }

// redact applies all masking rules to a single line.
func (m *MaskingWriter) redact(line []byte) []byte {
	result := line
	for _, rule := range m.rules {
		if !rule.mayMatch(result) {
			continue
		}
		result = rule.re.ReplaceAllFunc(result, func(match []byte) []byte {
			if rule.showPrefix > 0 && len(match) > rule.showPrefix {
				out := make([]byte, rule.showPrefix+3)
				copy(out, match[:rule.showPrefix])
				copy(out[rule.showPrefix:], "***")
				return out
			}
			return []byte("***")
		})
	}
	return result
}

// mayMatch is a cheap prefilter: without any hint literal in the line the
// preset's regex can't match, so it is skipped.
func (r maskRule) mayMatch(line []byte) bool {
	if len(r.hints) == 0 {
		return true
	}
	for _, h := range r.hints {
		if bytes.Contains(line, h) {
			return true
		}
	}
	return false
}
