package services

import (
	"io"
	"strings"
	"testing"
)

// BenchmarkMaskingWriter_DefaultPresets: typical agent output (code + logs)
// through every default preset.
func BenchmarkMaskingWriter_DefaultPresets(b *testing.B) {
	cfg := NewConfigService().InitDefaultConfig().MaskStdout
	line := "2026-11-09T10:00:00Z INFO building package github.com/x/y: ok (1.2s) func main() { fmt.Println(\"hi\") }\n"
	chunk := []byte(strings.Repeat(line, 400)) // ~44 KB
	mw, err := NewMaskingWriter(io.Discard, cfg)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mw.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
}
