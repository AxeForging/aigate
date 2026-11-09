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

func TestMaskingWriter_OpenAIPreset(t *testing.T) {
	var buf bytes.Buffer
	mw, err := NewMaskingWriter(&buf, domain.MaskStdout{Presets: []string{"openai"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	input := "Using key sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKL\n"
	if _, err := mw.Write([]byte(input)); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "sk-abcdefghijklmnopqrstuvwxyz") {
		t.Errorf("output should not contain the raw key: %q", out)
	}
	if !strings.Contains(out, "sk-***") {
		t.Errorf("output should contain masked key prefix, got: %q", out)
	}
}

func TestMaskingWriter_AnthropicPreset(t *testing.T) {
	var buf bytes.Buffer
	mw, err := NewMaskingWriter(&buf, domain.MaskStdout{Presets: []string{"anthropic"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	input := "key=sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
	if _, err := mw.Write([]byte(input)); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "api03") {
		t.Errorf("output should not contain raw anthropic key: %q", out)
	}
	if !strings.Contains(out, "sk-ant-***") {
		t.Errorf("output should contain 'sk-ant-***', got: %q", out)
	}
}

func TestMaskingWriter_AWSKeyPreset(t *testing.T) {
	var buf bytes.Buffer
	mw, err := NewMaskingWriter(&buf, domain.MaskStdout{Presets: []string{"aws_key"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	input := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
	if _, err := mw.Write([]byte(input)); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("output should not contain raw AWS key: %q", out)
	}
	if !strings.Contains(out, "AKIA***") {
		t.Errorf("output should contain masked AWS key prefix, got: %q", out)
	}
}

func TestMaskingWriter_GitHubPreset(t *testing.T) {
	var buf bytes.Buffer
	mw, err := NewMaskingWriter(&buf, domain.MaskStdout{Presets: []string{"github"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	input := "token: ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
	if _, err := mw.Write([]byte(input)); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "ghp_AAAA") {
		t.Errorf("output should not contain raw GitHub token: %q", out)
	}
	if !strings.Contains(out, "ghp_***") {
		t.Errorf("output should contain masked GitHub prefix, got: %q", out)
	}
}

func TestMaskingWriter_BearerPreset(t *testing.T) {
	var buf bytes.Buffer
	mw, err := NewMaskingWriter(&buf, domain.MaskStdout{Presets: []string{"bearer"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	input := "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload\n"
	if _, err := mw.Write([]byte(input)); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "eyJhbGci") {
		t.Errorf("output should not contain raw bearer token: %q", out)
	}
	if !strings.Contains(out, "Bearer ***") {
		t.Errorf("output should contain 'Bearer ***', got: %q", out)
	}
}

func TestMaskingWriter_CustomPattern_FullMask(t *testing.T) {
	var buf bytes.Buffer
	cfg := domain.MaskStdout{
		Patterns: []domain.MaskPattern{
			{Regex: `mysecret-[a-z0-9]+`, ShowPrefix: 0},
		},
	}
	mw, err := NewMaskingWriter(&buf, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	input := "value=mysecret-abc123xyz\n"
	if _, err := mw.Write([]byte(input)); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "mysecret-abc123xyz") {
		t.Errorf("output should not contain raw secret: %q", out)
	}
	if !strings.Contains(out, "***") {
		t.Errorf("output should contain ***, got: %q", out)
	}
}

func TestMaskingWriter_CustomPattern_ShowPrefix(t *testing.T) {
	var buf bytes.Buffer
	cfg := domain.MaskStdout{
		Patterns: []domain.MaskPattern{
			{Regex: `token-[a-zA-Z0-9]{16}`, ShowPrefix: 6},
		},
	}
	mw, err := NewMaskingWriter(&buf, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	input := "token-ABCDEFGHIJKLMNOP logged\n"
	if _, err := mw.Write([]byte(input)); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "token-***") {
		t.Errorf("expected 'token-***', got: %q", out)
	}
	if strings.Contains(out, "ABCDEF") {
		t.Errorf("should not contain characters after prefix, got: %q", out)
	}
}

func TestMaskingWriter_NoFalsePositives(t *testing.T) {
	var buf bytes.Buffer
	mw, err := NewMaskingWriter(&buf, domain.MaskStdout{Presets: []string{"openai", "github", "aws_key"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	input := "hello world, no secrets here\n"
	if _, err := mw.Write([]byte(input)); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	out := buf.String()
	if out != input {
		t.Errorf("clean line should pass through unchanged, got: %q", out)
	}
}

func TestMaskingWriter_MultipleWritesAcrossChunks(t *testing.T) {
	var buf bytes.Buffer
	mw, err := NewMaskingWriter(&buf, domain.MaskStdout{Presets: []string{"openai"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Write in two chunks, split mid-key
	chunk1 := "key=sk-abcdefghijklmnopqrst"
	chunk2 := "uvwxyz1234567890ABCDEFGHIJKL\n"
	if _, err := mw.Write([]byte(chunk1)); err != nil {
		t.Fatalf("Write chunk1 error: %v", err)
	}
	if _, err := mw.Write([]byte(chunk2)); err != nil {
		t.Fatalf("Write chunk2 error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "sk-abcdefghijklmnopqrstuv") {
		t.Errorf("key split across chunks should still be masked: %q", out)
	}
}

func TestMaskingWriter_FlushIncompleteLastLine(t *testing.T) {
	var buf bytes.Buffer
	cfg := domain.MaskStdout{
		Patterns: []domain.MaskPattern{{Regex: `secret`, ShowPrefix: 0}},
	}
	mw, err := NewMaskingWriter(&buf, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No trailing newline
	if _, err := mw.Write([]byte("contains secret")); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	// Nothing flushed yet
	if buf.Len() != 0 {
		t.Errorf("incomplete line should be buffered, got: %q", buf.String())
	}

	if err := mw.Flush(); err != nil {
		t.Fatalf("Flush error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "secret") {
		t.Errorf("flushed content should be masked: %q", out)
	}
	if !strings.Contains(out, "***") {
		t.Errorf("flushed content should contain ***, got: %q", out)
	}
}

func TestMaskingWriter_MultipleSecretsOnOneLine(t *testing.T) {
	var buf bytes.Buffer
	mw, err := NewMaskingWriter(&buf, domain.MaskStdout{Presets: []string{"openai", "github"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	input := "openai=sk-abcdefghijklmnopqrstuvwxyz123456789012 github=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
	if _, err := mw.Write([]byte(input)); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "abcdefghijk") {
		t.Errorf("openai key should be masked: %q", out)
	}
	if strings.Contains(out, "ghp_AAAA") {
		t.Errorf("github token should be masked: %q", out)
	}
}

func TestMaskingWriter_CaseInsensitive(t *testing.T) {
	var buf bytes.Buffer
	cfg := domain.MaskStdout{
		Patterns: []domain.MaskPattern{
			{Regex: `mysecret-[a-z0-9]+`, ShowPrefix: 0, CaseInsensitive: true},
		},
	}
	mw, err := NewMaskingWriter(&buf, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, input := range []string{
		"value=MYSECRET-abc123\n",
		"value=mysecret-abc123\n",
		"value=MySecret-ABC123\n",
	} {
		buf.Reset()
		if _, err := mw.Write([]byte(input)); err != nil {
			t.Fatalf("Write error: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "***") {
			t.Errorf("case-insensitive match failed for input %q, got: %q", input, out)
		}
	}
}

func TestMaskingWriter_CaseSensitiveByDefault(t *testing.T) {
	var buf bytes.Buffer
	cfg := domain.MaskStdout{
		Patterns: []domain.MaskPattern{
			{Regex: `mysecret-[a-z0-9]+`, ShowPrefix: 0},
		},
	}
	mw, err := NewMaskingWriter(&buf, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// uppercase should NOT match when case_insensitive is false
	input := "value=MYSECRET-abc123\n"
	if _, err := mw.Write([]byte(input)); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	out := buf.String()
	if out != input {
		t.Errorf("case-sensitive pattern should not match uppercase, got: %q", out)
	}
}

func TestMaskingWriter_AWSSecretPreset(t *testing.T) {
	var buf bytes.Buffer
	mw, err := NewMaskingWriter(&buf, domain.MaskStdout{Presets: []string{"aws_secret"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Standard .env assignment format
	input := "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	if _, err := mw.Write([]byte(input)); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "wJalrXUtnFEMI") {
		t.Errorf("output should not contain raw AWS secret value: %q", out)
	}
	if !strings.Contains(out, "AWS_SECRET_ACCESS_KEY=***") {
		t.Errorf("output should show key name and mask value, got: %q", out)
	}
}

func TestMaskingWriter_AWSSecretPreset_ColonFormat(t *testing.T) {
	var buf bytes.Buffer
	mw, err := NewMaskingWriter(&buf, domain.MaskStdout{Presets: []string{"aws_secret"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// YAML/config colon format
	input := "AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	if _, err := mw.Write([]byte(input)); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "wJalrXUtnFEMI") {
		t.Errorf("output should not contain raw AWS secret value: %q", out)
	}
	if !strings.Contains(out, "***") {
		t.Errorf("output should mask the value, got: %q", out)
	}
}

func TestMaskingWriter_AWSSecretPreset_NoFalsePositiveOnKeyID(t *testing.T) {
	var buf bytes.Buffer
	// aws_secret preset should NOT mask AWS_ACCESS_KEY_ID (that's aws_key's job)
	mw, err := NewMaskingWriter(&buf, domain.MaskStdout{Presets: []string{"aws_secret"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	input := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
	if _, err := mw.Write([]byte(input)); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	out := buf.String()
	if out != input {
		t.Errorf("aws_secret preset should not mask AWS_ACCESS_KEY_ID line, got: %q", out)
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
