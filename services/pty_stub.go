//go:build !linux && !darwin

package services

import (
	"io"
	"os"
	"os/exec"
)

// runWithPTY is a stub for unsupported platforms. It runs the command with
// the masked writer as stdout/stderr so masking still applies, even though
// interactive TTY detection is not preserved.
func runWithPTY(out io.Writer, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd.Run()
}
