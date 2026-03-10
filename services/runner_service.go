package services

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/helpers"
)

type RunnerService struct {
	platform Platform
}

func NewRunnerService(platform Platform) *RunnerService {
	return &RunnerService{platform: platform}
}

func (s *RunnerService) Run(profile domain.SandboxProfile, cmd string, args []string) error {
	// Extract the base command name for deny_exec checking
	baseName := filepath.Base(cmd)
	for _, denied := range profile.Config.DenyExec {
		parts := strings.SplitN(denied, " ", 2)
		if len(parts) == 2 {
			// Subcommand rule: "command subcommand" — block only when subcommand is in args
			if parts[0] == baseName || parts[0] == cmd {
				for _, arg := range args {
					if arg == parts[1] {
						return fmt.Errorf("%w: %q with subcommand %q is in the deny_exec list", helpers.ErrCommandBlocked, cmd, parts[1])
					}
				}
			}
		} else {
			// Full command rule: block all usage
			if denied == baseName || denied == cmd {
				return fmt.Errorf("%w: %q is in the deny_exec list", helpers.ErrCommandBlocked, cmd)
			}
		}
	}

	stdout, stderr := buildOutputWriters(profile.Config.MaskStdout)
	if mw, ok := stdout.(*MaskingWriter); ok {
		defer mw.Flush() //nolint:errcheck
	}
	if mw, ok := stderr.(*MaskingWriter); ok {
		defer mw.Flush() //nolint:errcheck
	}
	return s.platform.RunSandboxed(profile, cmd, args, stdout, stderr)
}

// buildOutputWriters returns (stdout, stderr) writers with masking applied when
// mask_stdout is configured. Falls back to os.Stdout/os.Stderr on error or when
// no masking rules are defined.
func buildOutputWriters(cfg domain.MaskStdout) (io.Writer, io.Writer) {
	outMasker, err := NewMaskingWriter(os.Stdout, cfg)
	if err != nil {
		helpers.Log.Warn().Err(err).Msg("mask_stdout configuration error; output masking disabled")
		return os.Stdout, os.Stderr
	}
	if outMasker == nil {
		return os.Stdout, os.Stderr
	}
	errMasker, _ := NewMaskingWriter(os.Stderr, cfg)
	return outMasker, errMasker
}
