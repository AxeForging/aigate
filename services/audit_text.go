package services

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	// maxAuditText caps a captured message; block messages are well under it.
	maxAuditText = 300
	// maxDisplayText caps text shown in the dashboard, which folds it to a
	// few lines with "Show more".
	maxDisplayText = 1000
)

// ansiRe matches terminal escape sequences: CSI (colors, cursor moves),
// OSC (titles, links) and two-byte escapes.
var ansiRe = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-Z\\-_]`)

// plainText removes escape codes and control characters and collapses
// whitespace, so text captured from a TUI reads as one plain line.
func plainText(s string) string {
	s = ansiRe.ReplaceAllString(s, " ")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

func clipText(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// CleanAuditText makes a stored command or detail displayable: plain text,
// starting at the aigate message it contains (older versions stored raw TUI
// screen output around it), capped at maxDisplayText.
func CleanAuditText(s string) string {
	s = plainText(s)
	if i := strings.Index(s, "[aigate]"); i > 0 {
		s = s[i:]
	}
	return clipText(s, maxDisplayText)
}
