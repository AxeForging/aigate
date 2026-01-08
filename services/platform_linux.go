//go:build linux

package services

import (
	"fmt"
	"os"
	"strings"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/helpers"
)

func newPlatform(exec Executor) Platform {
	return &LinuxPlatform{exec: exec}
}

// LinuxPlatform implements sandbox operations using Linux ACLs, namespaces, and cgroups.
type LinuxPlatform struct {
	exec Executor
}

func (p *LinuxPlatform) Name() string {
	return "linux"
}

func (p *LinuxPlatform) CreateGroup(name string) error {
	exists, err := p.GroupExists(name)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: group %q", helpers.ErrAlreadyInit, name)
	}
	out, err := p.exec.Run("groupadd", "--system", name)
	if err != nil {
		return fmt.Errorf("failed to create group %q: %s (%w)", name, string(out), err)
	}
	return nil
}

func (p *LinuxPlatform) CreateUser(name, group string) error {
	exists, err := p.UserExists(name)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: user %q", helpers.ErrAlreadyInit, name)
	}
	out, err := p.exec.Run("useradd", "--system", "--gid", group, "--shell", "/usr/sbin/nologin", "--no-create-home", name)
	if err != nil {
		return fmt.Errorf("failed to create user %q: %s (%w)", name, string(out), err)
	}
	return nil
}

func (p *LinuxPlatform) DeleteGroup(name string) error {
	exists, err := p.GroupExists(name)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	out, err := p.exec.Run("groupdel", name)
	if err != nil {
		return fmt.Errorf("failed to delete group %q: %s (%w)", name, string(out), err)
	}
	return nil
}

func (p *LinuxPlatform) DeleteUser(name string) error {
	exists, err := p.UserExists(name)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	out, err := p.exec.Run("userdel", name)
	if err != nil {
		return fmt.Errorf("failed to delete user %q: %s (%w)", name, string(out), err)
	}
	return nil
}

func (p *LinuxPlatform) GroupExists(name string) (bool, error) {
	_, err := p.exec.Run("getent", "group", name)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (p *LinuxPlatform) UserExists(name string) (bool, error) {
	_, err := p.exec.Run("getent", "passwd", name)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (p *LinuxPlatform) SetFileACLDeny(group string, patterns []string, workDir string) error {
	paths, err := resolvePatterns(patterns, workDir)
	if err != nil {
		return err
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			helpers.Log.Warn().Str("path", path).Msg("skipping (not found)")
			continue
		}
		aclEntry := fmt.Sprintf("g:%s:---", group)
		if info.IsDir() {
			// Set access ACL recursively + default ACL for inheritance
			out, err := p.exec.Run("setfacl", "-R", "-m", aclEntry, path)
			if err != nil {
				return fmt.Errorf("setfacl failed for %s: %s (%w)", path, string(out), err)
			}
			defaultEntry := fmt.Sprintf("d:g:%s:---", group)
			out, err = p.exec.Run("setfacl", "-R", "-m", defaultEntry, path)
			if err != nil {
				return fmt.Errorf("setfacl default failed for %s: %s (%w)", path, string(out), err)
			}
		} else {
			out, err := p.exec.Run("setfacl", "-m", aclEntry, path)
			if err != nil {
				return fmt.Errorf("setfacl failed for %s: %s (%w)", path, string(out), err)
			}
		}
		helpers.Log.Info().Str("path", path).Msg("ACL deny set")
	}
	return nil
}

func (p *LinuxPlatform) RemoveFileACL(group string, patterns []string, workDir string) error {
	paths, err := resolvePatterns(patterns, workDir)
	if err != nil {
		return err
	}
	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		aclEntry := fmt.Sprintf("g:%s", group)
		out, err := p.exec.Run("setfacl", "-R", "-x", aclEntry, path)
		if err != nil {
			helpers.Log.Warn().Str("path", path).Str("output", string(out)).Msg("failed to remove ACL")
		}
		defaultEntry := fmt.Sprintf("d:g:%s", group)
		p.exec.Run("setfacl", "-R", "-x", defaultEntry, path)
	}
	return nil
}

func (p *LinuxPlatform) ListACLs(workDir string) ([]string, error) {
	out, err := p.exec.Run("getfacl", "-R", "--absolute-names", workDir)
	if err != nil {
		return nil, fmt.Errorf("getfacl failed: %w", err)
	}
	var results []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "group:ai-agents") || strings.HasPrefix(line, "# file:") {
			results = append(results, line)
		}
	}
	return results, nil
}

func (p *LinuxPlatform) RunSandboxed(profile domain.SandboxProfile, cmd string, args []string) error {
	// Build unshare command for namespace isolation
	unshareArgs := []string{
		"--mount",         // Mount namespace
		"--pid",           // PID namespace
		"--fork",          // Required for PID namespace
		"--map-root-user", // User namespace mapping
	}

	// Add network isolation if allow_net is configured
	if len(profile.Config.AllowNet) > 0 {
		unshareArgs = append(unshareArgs, "--net")
	}

	unshareArgs = append(unshareArgs, "--")

	// Build the inner command that runs inside the namespace
	// First overmount denied directories with empty tmpfs
	var mountCmds []string
	for _, pattern := range profile.Config.DenyRead {
		paths, _ := resolvePatterns([]string{pattern}, profile.WorkDir)
		for _, path := range paths {
			if info, err := os.Stat(path); err == nil {
				if info.IsDir() {
					mountCmds = append(mountCmds, fmt.Sprintf("mount -t tmpfs -o ro,size=0 tmpfs %s", path))
				} else {
					mountCmds = append(mountCmds, fmt.Sprintf("mount --bind /dev/null %s", path))
				}
			}
		}
	}

	// Build shell command: mount overrides then exec the target command
	var shellCmd string
	if len(mountCmds) > 0 {
		shellCmd = strings.Join(mountCmds, " && ") + " && "
	}
	shellCmd += cmd
	for _, a := range args {
		shellCmd += " " + a
	}

	fullArgs := append(unshareArgs, "sh", "-c", shellCmd)
	return p.exec.RunPassthrough("unshare", fullArgs...)
}
