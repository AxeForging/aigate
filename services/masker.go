package services

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

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

// MaskingWriter wraps an io.Writer and redacts secrets from each line before
// forwarding to the underlying writer. It buffers across Write calls so that
// secrets spanning chunk boundaries on the same line are still caught.
type MaskingWriter struct {
	out   io.Writer
	rules []maskRule
	buf   []byte
}

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
	return &MaskingWriter{out: out, rules: rules}, nil
}

// Write buffers p, flushes complete lines through the redactor, and returns
// len(p) so callers treat the write as fully consumed.
func (m *MaskingWriter) Write(p []byte) (int, error) {
	m.buf = append(m.buf, p...)
	for {
		idx := bytes.IndexByte(m.buf, '\n')
		if idx < 0 {
			break
		}
		line := m.buf[:idx+1]
		if _, err := m.out.Write(m.redact(line)); err != nil {
			return 0, err
		}
		m.buf = m.buf[idx+1:]
	}
	return len(p), nil
}

// Flush writes any remaining buffered bytes (last line without a trailing newline).
// Call this after the child process exits.
func (m *MaskingWriter) Flush() error {
	if len(m.buf) == 0 {
		return nil
	}
	_, err := m.out.Write(m.redact(m.buf))
	m.buf = m.buf[:0]
	return err
}

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
