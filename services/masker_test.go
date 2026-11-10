package services

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/AxeForging/aigate/domain"
)

func TestNewMaskingWriter_NilWhenEmpty(t *testing.T) {
	mw, err := NewMaskingWriter(&bytes.Buffer{}, domain.MaskStdout{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mw != nil {
		t.Fatal("expected nil MaskingWriter when no rules configured")
	}
}

func TestNewMaskingWriter_UnknownPreset(t *testing.T) {
	_, err := NewMaskingWriter(&bytes.Buffer{}, domain.MaskStdout{Presets: []string{"not-a-preset"}})
	if err == nil {
		t.Fatal("expected error for unknown preset")
	}
	if !strings.Contains(err.Error(), "not-a-preset") {
		t.Errorf("error should name the bad preset, got: %v", err)
	}
}

func TestNewMaskingWriter_InvalidCustomPattern(t *testing.T) {
	cfg := domain.MaskStdout{
		Patterns: []domain.MaskPattern{{Regex: "[invalid"}},
	}
	_, err := NewMaskingWriter(&bytes.Buffer{}, cfg)
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

// newMasker returns a masking writer over a buffer it also returns.
func newMasker(t *testing.T, cfg domain.MaskStdout) (*MaskingWriter, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	mw, err := NewMaskingWriter(&buf, cfg)
	if err != nil {
		t.Fatalf("NewMaskingWriter: %v", err)
	}
	return mw, &buf
}

// maskOnce writes input through a fresh masker and returns what came out.
func maskOnce(t *testing.T, cfg domain.MaskStdout, input string) string {
	t.Helper()
	mw, buf := newMasker(t, cfg)
	if _, err := mw.Write([]byte(input)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return buf.String()
}

func presets(names ...string) domain.MaskStdout { return domain.MaskStdout{Presets: names} }

func pattern(p domain.MaskPattern) domain.MaskStdout {
	return domain.MaskStdout{Patterns: []domain.MaskPattern{p}}
}

// TestMaskingWriter_Masks: each secret format is hidden (gone) and leaves the
// documented prefix (want); lines without a secret pass through unchanged.
func TestMaskingWriter_Masks(t *testing.T) {
	cases := []struct {
		name  string
		cfg   domain.MaskStdout
		input string
		gone  []string // must not appear in the output
		want  string   // must appear; "" = output equals input
	}{
		{"openai", presets("openai"), "Using key sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKL\n", []string{"sk-abcdefghijklmnopqrstuvwxyz"}, "sk-***"},
		{"anthropic", presets("anthropic"), "key=sk-ant-api03-" + strings.Repeat("A", 72) + "\n", []string{"api03"}, "sk-ant-***"},
		{"aws_key", presets("aws_key"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", []string{"AKIAIOSFODNN7EXAMPLE"}, "AKIA***"},
		{"github", presets("github"), "token: ghp_" + strings.Repeat("A", 36) + "\n", []string{"ghp_AAAA"}, "ghp_***"},
		{"bearer", presets("bearer"), "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload\n", []string{"eyJhbGci"}, "Bearer ***"},
		{"aws_secret, = form", presets("aws_secret"), "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", []string{"wJalrXUtnFEMI"}, "AWS_SECRET_ACCESS_KEY=***"},
		{"aws_secret, YAML form", presets("aws_secret"), "AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", []string{"wJalrXUtnFEMI"}, "***"},
		{"aws_secret leaves the key ID to aws_key", presets("aws_secret"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", nil, ""},
		{"two secrets on one line", presets("openai", "github"), "openai=sk-abcdefghijklmnopqrstuvwxyz123456789012 github=ghp_" + strings.Repeat("A", 36) + "\n", []string{"abcdefghijk", "ghp_AAAA"}, "***"},
		{"clean line untouched", presets("openai", "github", "aws_key"), "hello world, no secrets here\n", nil, ""},
		{"custom pattern, fully masked", pattern(domain.MaskPattern{Regex: `mysecret-[a-z0-9]+`}), "value=mysecret-abc123xyz\n", []string{"mysecret-abc123xyz"}, "***"},
		{"custom pattern, prefix kept", pattern(domain.MaskPattern{Regex: `token-[a-zA-Z0-9]{16}`, ShowPrefix: 6}), "token-ABCDEFGHIJKLMNOP logged\n", []string{"ABCDEF"}, "token-***"},
		{"case-sensitive by default", pattern(domain.MaskPattern{Regex: `mysecret-[a-z0-9]+`}), "value=MYSECRET-abc123\n", nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := maskOnce(t, c.cfg, c.input)
			for _, g := range c.gone {
				if strings.Contains(out, g) {
					t.Errorf("output still contains %q: %q", g, out)
				}
			}
			if c.want == "" && out != c.input {
				t.Errorf("want the line unchanged, got %q", out)
			}
			if c.want != "" && !strings.Contains(out, c.want) {
				t.Errorf("want %q in %q", c.want, out)
			}
		})
	}
}

func TestMaskingWriter_CaseInsensitive(t *testing.T) {
	cfg := pattern(domain.MaskPattern{Regex: `mysecret-[a-z0-9]+`, CaseInsensitive: true})
	for _, input := range []string{"value=MYSECRET-abc123\n", "value=mysecret-abc123\n", "value=MySecret-ABC123\n"} {
		if out := maskOnce(t, cfg, input); !strings.Contains(out, "***") {
			t.Errorf("case-insensitive match failed for %q, got %q", input, out)
		}
	}
}

func TestMaskingWriter_MultipleWritesAcrossChunks(t *testing.T) {
	mw, buf := newMasker(t, presets("openai"))
	// Split mid-key across two writes.
	for _, chunk := range []string{"key=sk-abcdefghijklmnopqrst", "uvwxyz1234567890ABCDEFGHIJKL\n"} {
		if _, err := mw.Write([]byte(chunk)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if out := buf.String(); strings.Contains(out, "sk-abcdefghijklmnopqrstuv") {
		t.Errorf("key split across chunks should still be masked: %q", out)
	}
}

func TestMaskingWriter_FlushIncompleteLastLine(t *testing.T) {
	mw, buf := newMasker(t, pattern(domain.MaskPattern{Regex: `secret`}))
	if _, err := mw.Write([]byte("contains secret")); err != nil { // no trailing newline
		t.Fatalf("Write: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("incomplete line should be buffered, got: %q", buf.String())
	}
	if err := mw.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if out := buf.String(); strings.Contains(out, "secret") || !strings.Contains(out, "***") {
		t.Errorf("flushed content should be masked, got: %q", out)
	}
}

func TestMaskingWriter_AWSBothPresets(t *testing.T) {
	var buf bytes.Buffer
	mw, err := NewMaskingWriter(&buf, domain.MaskStdout{Presets: []string{"aws_key", "aws_secret"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cases := []struct {
		input       string
		shouldMask  string
		description string
	}{
		{
			"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
			"AKIAIOSFODNN7EXAMPLE",
			"aws_key should mask access key ID",
		},
		{
			"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
			"wJalrXUtnFEMI",
			"aws_secret should mask secret access key",
		},
	}

	for _, tc := range cases {
		buf.Reset()
		if _, err := mw.Write([]byte(tc.input)); err != nil {
			t.Fatalf("Write error: %v", err)
		}
		if strings.Contains(buf.String(), tc.shouldMask) {
			t.Errorf("%s: got %q", tc.description, buf.String())
		}
	}
}

func TestBuiltinPresetNames(t *testing.T) {
	names := BuiltinPresetNames()
	expected := []string{"openai", "anthropic", "aws_key", "aws_secret", "github", "bearer"}
	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}
	for _, want := range expected {
		if !nameSet[want] {
			t.Errorf("expected preset %q in BuiltinPresetNames()", want)
		}
	}
}

// Token-shaped values are assembled at runtime so no literal that looks like a
// real credential sits in the (public) source. They are obviously fake.
func TestMaskingWriter_ExtraPresets(t *testing.T) {
	r := strings.Repeat
	tests := []struct {
		preset, secret, masked, nearMiss string
	}{
		{"cloudflare", "cf" + "ut_" + r("a", 40) + "deadbeef", "cfut***", "cf" + "ut_" + r("a", 20)},
		{"cloudflare", "cf" + "at_" + r("B", 40) + "0123abcd", "cfat***", "cf" + "xx_" + r("a", 48)},
		{"cloudflare", "cf" + "k_" + r("c", 40) + "00000000", "cfk_***", "cf" + "k_" + r("c", 40) + "ZZZZZZZZ"},
		{"github", "github" + "_pat_" + r("A", 30), "gith***", "github" + "_pat_" + r("A", 5)},
		{"gitlab", "gl" + "pat-" + r("x", 20), "glpat-***", "gl" + "pat-" + r("x", 5)},
		{"slack", "xo" + "xb-" + r("1", 12), "xoxb-***", "xo" + "xz-" + r("1", 12)},
		{"stripe", "sk" + "_live_" + r("z", 24), "sk_live_***", "sk" + "_test_" + r("z", 24)},
		{"google", "AI" + "za" + r("Q", 35), "AIza***", "AI" + "za" + r("Q", 10)},
		{"npm", "np" + "m_" + r("n", 36), "npm_***", "np" + "m_" + r("n", 10)},
		{"huggingface", "h" + "f_" + r("h", 34), "hf_***", "h" + "f_" + r("h", 10)},
	}
	for _, tt := range tests {
		t.Run(tt.preset+"/"+tt.masked, func(t *testing.T) {
			var buf bytes.Buffer
			mw, err := NewMaskingWriter(&buf, domain.MaskStdout{Presets: []string{tt.preset}})
			if err != nil {
				t.Fatalf("preset %q: %v", tt.preset, err)
			}
			if _, err := mw.Write([]byte("key=" + tt.secret + " near=" + tt.nearMiss + "\n")); err != nil {
				t.Fatal(err)
			}
			_ = mw.Flush()
			out := buf.String()
			if strings.Contains(out, tt.secret) {
				t.Errorf("secret not masked: %q", out)
			}
			if !strings.Contains(out, "key="+tt.masked) {
				t.Errorf("want %q in %q", "key="+tt.masked, out)
			}
			if !strings.Contains(out, "near="+tt.nearMiss) {
				t.Errorf("near-miss must stay untouched: %q", out)
			}
		})
	}
}

func TestInitDefaultConfig_EnablesNewPresets(t *testing.T) {
	presets := NewConfigService().InitDefaultConfig().MaskStdout.Presets
	for _, want := range []string{"anthropic", "cloudflare", "github", "gitlab", "slack", "stripe", "google", "npm", "huggingface"} {
		found := false
		for _, p := range presets {
			found = found || p == want
		}
		if !found {
			t.Errorf("default config should enable %q", want)
		}
		if _, ok := builtinPresets[want]; !ok {
			t.Errorf("default preset %q is not a builtin", want)
		}
	}
}

// TestMaskingWriter_PrefilterKeepsMatches: the literal prefilter must never
// skip a line the regex would have masked (mixed-case Bearer, prefixes mid-line).
func TestMaskingWriter_PrefilterKeepsMatches(t *testing.T) {
	cases := map[string]string{
		"bearer":    "Authorization: BeArEr " + strings.Repeat("t", 24),
		"anthropic": "x=" + "sk-" + "ant-" + strings.Repeat("k", 24),
		"github":    "(" + "gh" + "p_" + strings.Repeat("G", 36) + ")",
	}
	for preset, line := range cases {
		var buf bytes.Buffer
		mw, err := NewMaskingWriter(&buf, domain.MaskStdout{Presets: []string{preset}})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = mw.Write([]byte(line + "\n"))
		if !strings.Contains(buf.String(), "***") {
			t.Errorf("%s: prefilter skipped a real match: %q", preset, buf.String())
		}
	}
}

func TestNewMaskingWriter_UnknownPresetListsAll(t *testing.T) {
	_, err := NewMaskingWriter(io.Discard, domain.MaskStdout{Presets: []string{"nope"}})
	if err == nil || !strings.Contains(err.Error(), "cloudflare") || !strings.Contains(err.Error(), "huggingface") {
		t.Errorf("error should list every preset, got %v", err)
	}
}
