package services

import (
	"bytes"
	"unicode/utf8"
)

// JudgePayload is exactly what a model judge may send off the machine: the
// tool, its target, and capped excerpts, all secret-masked first.
type JudgePayload struct {
	Event         string `json:"event"`
	Tool          string `json:"tool"`
	Target        string `json:"target,omitempty"`
	Input         string `json:"input,omitempty"`
	OutputExcerpt string `json:"output_excerpt,omitempty"`
}

// BuildJudgePayload masks every field with all builtin secret presets (and
// the generic key=value pattern), then caps the free-text fields.
func BuildJudgePayload(call Call, excerptBytes int) JudgePayload {
	return JudgePayload{
		Event:         call.Event,
		Tool:          call.Tool,
		Target:        capBytes(maskSecrets(call.Target), excerptBytes),
		Input:         capBytes(maskSecrets(call.Input), excerptBytes),
		OutputExcerpt: capBytes(maskSecrets(call.Output), excerptBytes),
	}
}

// maskSecrets runs text through a masking writer with every builtin preset,
// independent of the user's mask_stdout choices: nothing unmasked may leave.
func maskSecrets(text string) string {
	if text == "" {
		return ""
	}
	cfg := NewConfigService().InitDefaultConfig().MaskStdout
	cfg.Presets = BuiltinPresetNames()
	var buf bytes.Buffer
	mw, err := NewMaskingWriter(&buf, cfg)
	if err != nil || mw == nil {
		return "[redacted: masking unavailable]"
	}
	_, _ = mw.Write([]byte(text))
	_ = mw.Flush()
	return buf.String()
}

const truncatedMark = "…[truncated]"

// capBytes keeps at most n bytes without splitting a UTF-8 character.
func capBytes(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	cut := n - len(truncatedMark)
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + truncatedMark
}
