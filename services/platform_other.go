//go:build !linux && !darwin

package services

import (
	"io"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/helpers"
)

func newPlatform(exec Executor) Platform {
	// Fallback: WSL reports as linux, so this covers only native Windows
	// which uses Linux-like commands via WSL under the hood.
	return &unsupportedPlatform{}
}

type unsupportedPlatform struct{}

func (p *unsupportedPlatform) Name() string                         { return "unsupported" }
func (p *unsupportedPlatform) CreateGroup(string) error             { return errUnsupported }
func (p *unsupportedPlatform) CreateUser(string, string) error      { return errUnsupported }
func (p *unsupportedPlatform) DeleteGroup(string) error             { return errUnsupported }
func (p *unsupportedPlatform) DeleteUser(string) error              { return errUnsupported }
func (p *unsupportedPlatform) GroupExists(string) (bool, error)     { return false, errUnsupported }
func (p *unsupportedPlatform) UserExists(string) (bool, error)      { return false, errUnsupported }

func (p *unsupportedPlatform) SetFileACLDeny(string, []string, string) error { return errUnsupported }
func (p *unsupportedPlatform) RemoveFileACL(string, []string, string) error  { return errUnsupported }
func (p *unsupportedPlatform) ListACLs(string) ([]string, error)             { return nil, errUnsupported }

func (p *unsupportedPlatform) RunSandboxed(_ domain.SandboxProfile, _ string, _ []string, _, _ io.Writer) error {
	return errUnsupported
}

var errUnsupported = helpers.ErrUnsupportedOS
