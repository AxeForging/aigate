package services

import (
	"fmt"
	"path/filepath"

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
		if denied == baseName || denied == cmd {
			return fmt.Errorf("%w: %q is in the deny_exec list", helpers.ErrCommandBlocked, cmd)
		}
	}

	return s.platform.RunSandboxed(profile, cmd, args)
}
