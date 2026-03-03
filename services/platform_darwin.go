//go:build darwin

package services

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/helpers"
)

func newPlatform(exec Executor) Platform {
	return &DarwinPlatform{exec: exec}
}

// DarwinPlatform implements sandbox operations using macOS ACLs and sandbox-exec.
type DarwinPlatform struct {
	exec Executor
}

func (p *DarwinPlatform) Name() string {
	return "darwin"
}

func (p *DarwinPlatform) CreateGroup(name string) error {
	exists, err := p.GroupExists(name)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: group %q", helpers.ErrAlreadyInit, name)
	}
	// Find next available GID above 500
	gid := "600"
	out, err := p.exec.Run("dscl", ".", "-create", fmt.Sprintf("/Groups/%s", name))
	if err != nil {
		return fmt.Errorf("failed to create group %q: %s (%w)", name, string(out), err)
	}
	out, err = p.exec.Run("dscl", ".", "-create", fmt.Sprintf("/Groups/%s", name), "PrimaryGroupID", gid)
	if err != nil {
		return fmt.Errorf("failed to set GID for group %q: %s (%w)", name, string(out), err)
	}
	return nil
}

func (p *DarwinPlatform) CreateUser(name, group string) error {
	exists, err := p.UserExists(name)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: user %q", helpers.ErrAlreadyInit, name)
	}
	uid := "600"
	cmds := [][]string{
		{"dscl", ".", "-create", fmt.Sprintf("/Users/%s", name)},
		{"dscl", ".", "-create", fmt.Sprintf("/Users/%s", name), "UniqueID", uid},
		{"dscl", ".", "-create", fmt.Sprintf("/Users/%s", name), "PrimaryGroupID", "600"},
		{"dscl", ".", "-create", fmt.Sprintf("/Users/%s", name), "UserShell", "/usr/bin/false"},
		{"dscl", ".", "-create", fmt.Sprintf("/Users/%s", name), "NFSHomeDirectory", "/var/empty"},
	}
	for _, c := range cmds {
		out, err := p.exec.Run(c[0], c[1:]...)
		if err != nil {
			return fmt.Errorf("failed to create user %q: %s (%w)", name, string(out), err)
		}
	}
	return nil
}

func (p *DarwinPlatform) DeleteGroup(name string) error {
	exists, err := p.GroupExists(name)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	out, err := p.exec.Run("dscl", ".", "-delete", fmt.Sprintf("/Groups/%s", name))
	if err != nil {
		return fmt.Errorf("failed to delete group %q: %s (%w)", name, string(out), err)
	}
	return nil
}

func (p *DarwinPlatform) DeleteUser(name string) error {
	exists, err := p.UserExists(name)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	out, err := p.exec.Run("dscl", ".", "-delete", fmt.Sprintf("/Users/%s", name))
	if err != nil {
		return fmt.Errorf("failed to delete user %q: %s (%w)", name, string(out), err)
	}
	return nil
}

func (p *DarwinPlatform) GroupExists(name string) (bool, error) {
	_, err := p.exec.Run("dscl", ".", "-read", fmt.Sprintf("/Groups/%s", name))
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (p *DarwinPlatform) UserExists(name string) (bool, error) {
	_, err := p.exec.Run("dscl", ".", "-read", fmt.Sprintf("/Users/%s", name))
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (p *DarwinPlatform) SetFileACLDeny(group string, patterns []string, workDir string) error {
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
		aclPerms := "deny read,readattr,readextattr,readsecurity"
		if info.IsDir() {
			aclPerms += ",list,search,file_inherit,directory_inherit"
			out, err := p.exec.Run("chmod", "+a", fmt.Sprintf("group:%s %s", group, aclPerms), path)
			if err != nil {
				return fmt.Errorf("chmod +a failed for %s: %s (%w)", path, string(out), err)
			}
		} else {
			out, err := p.exec.Run("chmod", "+a", fmt.Sprintf("group:%s %s", group, aclPerms), path)
			if err != nil {
				return fmt.Errorf("chmod +a failed for %s: %s (%w)", path, string(out), err)
			}
		}
		helpers.Log.Info().Str("path", path).Msg("ACL deny set")
	}
	return nil
}

func (p *DarwinPlatform) RemoveFileACL(group string, patterns []string, workDir string) error {
	paths, err := resolvePatterns(patterns, workDir)
	if err != nil {
		return err
	}
	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		// Remove all ACL entries for the group
		out, err := p.exec.Run("chmod", "-a", fmt.Sprintf("group:%s deny read,readattr,readextattr,readsecurity", group), path)
		if err != nil {
			helpers.Log.Warn().Str("path", path).Str("output", string(out)).Msg("failed to remove ACL")
		}
	}
	return nil
}

func (p *DarwinPlatform) ListACLs(workDir string) ([]string, error) {
	out, err := p.exec.Run("ls", "-leR", workDir)
	if err != nil {
		return nil, fmt.Errorf("ls -leR failed: %w", err)
	}
	var results []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "ai-agents") || strings.Contains(line, "ai-runner") {
			results = append(results, strings.TrimSpace(line))
		}
	}
	return results, nil
}

func (p *DarwinPlatform) RunSandboxed(profile domain.SandboxProfile, cmd string, args []string) error {
	// Generate sandbox-exec profile
	sbProfile := generateSeatbeltProfile(profile)

	// Write profile to temp file
	tmpFile, err := os.CreateTemp("", "aigate-sandbox-*.sb")
	if err != nil {
		return fmt.Errorf("failed to create sandbox profile: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(sbProfile); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write sandbox profile: %w", err)
	}
	tmpFile.Close()

	// Run command under sandbox-exec
	sandboxArgs := []string{"-f", tmpFile.Name(), cmd}
	sandboxArgs = append(sandboxArgs, args...)
	return p.exec.RunPassthrough("sandbox-exec", sandboxArgs...)
}

func generateSeatbeltProfile(profile domain.SandboxProfile) string {
	var sb strings.Builder
	sb.WriteString("(version 1)\n")
	sb.WriteString("(allow default)\n")

	// Deny read access to protected paths
	for _, pattern := range profile.Config.DenyRead {
		paths, _ := resolvePatterns([]string{pattern}, profile.WorkDir)
		for _, path := range paths {
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			if info.IsDir() {
				sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %q))\n", path))
			} else {
				sb.WriteString(fmt.Sprintf("(deny file-read* (literal %q))\n", path))
			}
		}
	}

	// Deny read access to aigate config directory
	if home, err := os.UserHomeDir(); err == nil {
		configDir := filepath.Join(home, ".aigate")
		sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %q))\n", configDir))
	}

	// Deny execution of blocked commands
	for _, entry := range profile.Config.DenyExec {
		parts := strings.SplitN(entry, " ", 2)
		if len(parts) == 2 {
			// Subcommand blocks can't be enforced via Seatbelt; pre-sandbox check handles these
			continue
		}
		// Full command block: find all instances via PATH
		if path, err := exec.LookPath(entry); err == nil {
			sb.WriteString(fmt.Sprintf("(deny process-exec (literal %q))\n", path))
		}
	}

	// Network restrictions
	if len(profile.Config.AllowNet) > 0 {
		sb.WriteString("(deny network-outbound)\n")
		sb.WriteString("(allow network-outbound (local ip))\n")
		for _, host := range profile.Config.AllowNet {
			sb.WriteString(fmt.Sprintf("(allow network-outbound (remote ip %q))\n", host))
		}
	}

	return sb.String()
}
