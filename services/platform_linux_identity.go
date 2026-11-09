//go:build linux

package services

import (
	"fmt"
	"strings"

	"github.com/AxeForging/aigate/domain"
)

// bwrapIdentityArgs mounts the identity's ssh key read-only and sets/unsets
// its env vars. Its dirs reach the sandbox through allowed_paths (scope
// mode). Append after deny_read mounts: the default deny on ~/.ssh/ would
// otherwise hide the key again.
func bwrapIdentityArgs(id *domain.ResolvedIdentity) []string {
	if id == nil {
		return nil
	}
	var args []string
	if id.SSHKey != "" {
		args = append(args, "--ro-bind", id.SSHKey, id.SSHKey)
	}
	set, unset := identityEnv(id)
	for _, v := range unset {
		args = append(args, "--unsetenv", v)
	}
	for _, v := range set {
		args = append(args, "--setenv", v.Name, v.Value)
	}
	return args
}

// checkFallbackIdentity refuses identity features the unshare fallback can't
// enforce, instead of silently running with less isolation.
func checkFallbackIdentity(profile domain.SandboxProfile) error {
	if profile.Identity != nil && profile.Identity.SSHKey != "" {
		return fmt.Errorf("identity %q uses ssh_key, which needs bubblewrap. Install it (e.g. sudo dnf install bubblewrap / sudo apt install bubblewrap) or remove ssh_key",
			profile.Identity.Name)
	}
	return nil
}

// buildIdentityOverrides is the unshare-fallback equivalent of the env part
// of bwrapIdentityArgs.
func buildIdentityOverrides(profile domain.SandboxProfile) string {
	set, unset := identityEnv(profile.Identity)
	if len(set) == 0 && len(unset) == 0 {
		return ""
	}
	var sb strings.Builder
	if len(unset) > 0 {
		fmt.Fprintf(&sb, "unset %s\n", strings.Join(unset, " "))
	}
	for _, v := range set {
		fmt.Fprintf(&sb, "export %s=%s\n", v.Name, shellQuote(v.Value))
	}
	return sb.String()
}
