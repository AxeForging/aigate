package services

import (
	"os"
	"testing"
)

// TestMain lets this test binary stand in for aigate inside sandboxes that
// tests start: the sandbox's last step re-runs the binary as
// `<binary> __sandbox-exec -- CMD`, which must exec CMD, not the tests.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == SandboxExecArg {
		os.Exit(SandboxExec(os.Args[2:]))
	}
	os.Exit(m.Run())
}
