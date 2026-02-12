package services

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/AxeForging/aigate/domain"
)

// Platform abstracts OS-level sandbox operations.
type Platform interface {
	Name() string
	CreateGroup(name string) error
	CreateUser(name, group string) error
	DeleteGroup(name string) error
	DeleteUser(name string) error
	GroupExists(name string) (bool, error)
	UserExists(name string) (bool, error)
	SetFileACLDeny(group string, patterns []string, workDir string) error
	RemoveFileACL(group string, patterns []string, workDir string) error
	ListACLs(workDir string) ([]string, error)
	RunSandboxed(profile domain.SandboxProfile, cmd string, args []string) error
}

// Executor abstracts command execution for testability.
type Executor interface {
	Run(name string, args ...string) ([]byte, error)
	RunPassthrough(name string, args ...string) error
}

// RealExecutor executes real OS commands.
type RealExecutor struct{}

func (e *RealExecutor) Run(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func (e *RealExecutor) RunPassthrough(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// DetectPlatform returns the appropriate Platform for the current OS.
func DetectPlatform() Platform {
	return DetectPlatformWithExecutor(&RealExecutor{})
}

// DetectPlatformWithExecutor returns the appropriate Platform using the given executor.
// Implementation is in platform_linux.go and platform_darwin.go via build tags.
func DetectPlatformWithExecutor(exec Executor) Platform {
	return newPlatform(exec)
}

// resolvePatterns expands glob patterns relative to workDir into absolute paths.
func resolvePatterns(patterns []string, workDir string) ([]string, error) {
	var resolved []string
	for _, pattern := range patterns {
		var absPattern string
		if filepath.IsAbs(pattern) {
			absPattern = pattern
		} else {
			absPattern = filepath.Join(workDir, pattern)
		}
		matches, err := filepath.Glob(absPattern)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", pattern, err)
		}
		if len(matches) > 0 {
			resolved = append(resolved, matches...)
		} else {
			resolved = append(resolved, absPattern)
		}
	}
	return resolved, nil
}
