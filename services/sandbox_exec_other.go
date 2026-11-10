//go:build !linux

package services

import (
	"fmt"
	"os"
)

// SandboxExecArg is the hidden first argument for the sandbox's last step.
// Only Linux sandboxes use it (macOS Seatbelt never grants capabilities).
const SandboxExecArg = "__sandbox-exec"

// SandboxExec is Linux-only.
func SandboxExec([]string) int {
	fmt.Fprintln(os.Stderr, "[aigate] "+SandboxExecArg+" is only used inside Linux sandboxes")
	return 126
}
