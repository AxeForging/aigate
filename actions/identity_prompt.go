package actions

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// prompter asks questions on a terminal. Without one (or with --yes) every
// question silently takes its default, so scripts never hang.
type prompter struct {
	interactive bool
	in          *bufio.Reader
}

func newPrompter(yes bool) *prompter {
	fi, err := os.Stdin.Stat()
	tty := err == nil && fi.Mode()&os.ModeCharDevice != 0
	return &prompter{interactive: tty && !yes, in: bufio.NewReader(os.Stdin)}
}

func (p *prompter) line() string {
	s, _ := p.in.ReadString('\n')
	return strings.TrimSpace(s)
}

// ask returns the answer, or def on Enter / non-interactive.
func (p *prompter) ask(question, def string) string {
	if !p.interactive {
		return def
	}
	if def != "" {
		fmt.Printf("%s [%s]: ", question, def)
	} else {
		fmt.Printf("%s: ", question)
	}
	if v := p.line(); v != "" {
		return v
	}
	return def
}

func (p *prompter) confirm(question string, def bool) bool {
	if !p.interactive {
		return def
	}
	hint := "[Y/n]"
	if !def {
		hint = "[y/N]"
	}
	fmt.Printf("%s %s ", question, hint)
	switch strings.ToLower(p.line()) {
	case "":
		return def
	case "y", "yes":
		return true
	default:
		return false
	}
}

// choose lists options by number; Enter (or no options) means none.
func (p *prompter) choose(question string, options []string) string {
	if !p.interactive || len(options) == 0 {
		return ""
	}
	fmt.Println(question + ":")
	for i, o := range options {
		fmt.Printf("  %d) %s\n", i+1, o)
	}
	for {
		fmt.Print("Choice: ")
		v := p.line()
		if v == "" {
			return ""
		}
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= len(options) {
			return options[n-1]
		}
		fmt.Printf("Enter a number from 1 to %d, or press Enter for none.\n", len(options))
	}
}
