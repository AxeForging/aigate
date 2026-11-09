package services

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/AxeForging/aigate/domain"
)

// credentialEnvVars carry logins that would bypass identity isolation if
// inherited from the host shell. They are unset inside an identity's sandbox
// unless the identity lists them in pass_env.
var credentialEnvVars = []string{
	"ANTHROPIC_API_KEY",
	"ANTHROPIC_AUTH_TOKEN",
	"CLAUDE_CODE_OAUTH_TOKEN",
	"GH_TOKEN",
	"GITHUB_TOKEN",
	"GH_ENTERPRISE_TOKEN",
	"GITHUB_ENTERPRISE_TOKEN",
	"GIT_ASKPASS",
	"SSH_ASKPASS",
}

// EnvVar is one variable set inside the sandbox.
type EnvVar struct{ Name, Value string }

// identityEnv returns the variables to set and to unset for an identity.
// Set values point tools at the identity's own dirs and git author.
func identityEnv(id *domain.ResolvedIdentity) (set []EnvVar, unset []string) {
	if id == nil {
		return nil, nil
	}
	set = []EnvVar{
		{"GH_CONFIG_DIR", id.GhDir},
		{"AIGATE_IDENTITY", id.Name},
	}
	// Claude Code treats an explicit CLAUDE_CONFIG_DIR=~/.claude differently
	// from leaving it unset (other .claude.json location, other macOS
	// Keychain item), so the identity using the default dir leaves it unset.
	if !usesDefaultClaudeDir(id) {
		set = append([]EnvVar{{"CLAUDE_CONFIG_DIR", id.ClaudeDir}}, set...)
	} else {
		unset = append(unset, "CLAUDE_CONFIG_DIR")
	}
	if id.Git.Name != "" {
		set = append(set, EnvVar{"GIT_AUTHOR_NAME", id.Git.Name}, EnvVar{"GIT_COMMITTER_NAME", id.Git.Name})
	}
	if id.Git.Email != "" {
		set = append(set, EnvVar{"GIT_AUTHOR_EMAIL", id.Git.Email}, EnvVar{"GIT_COMMITTER_EMAIL", id.Git.Email})
	}
	if id.SSHKey != "" {
		// Only this key, never an agent: other identities' keys may be loaded there.
		set = append(set, EnvVar{"GIT_SSH_COMMAND",
			"ssh -i " + singleQuote(id.SSHKey) + " -o IdentitiesOnly=yes -o IdentityAgent=none"})
	}

	pass := map[string]bool{}
	for _, v := range id.PassEnv {
		pass[v] = true
	}
	for _, v := range credentialEnvVars {
		if !pass[v] {
			unset = append(unset, v)
		}
	}
	sort.Strings(unset)
	return set, unset
}

// singleQuote quotes s for sh, which is how git runs GIT_SSH_COMMAND.
func singleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// defaultClaudePaths are where Claude Code keeps its login and settings when
// CLAUDE_CONFIG_DIR is unset.
func defaultClaudePaths() (dir, settings string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", ""
	}
	return filepath.Join(home, ".claude"), filepath.Join(home, ".claude.json")
}

func usesDefaultClaudeDir(id *domain.ResolvedIdentity) bool {
	dir, _ := defaultClaudePaths()
	return dir != "" && filepath.Clean(id.ClaudeDir) == dir
}

// JudgeSocketInSandbox is where bwrap binds the judge broker socket.
const JudgeSocketInSandbox = "/tmp/.aigate-judge.sock"

// sessionEnv adds what every sandboxed session needs beyond its identity:
// the judge broker address (as seen inside) and extra variables to remove.
func sessionEnv(profile domain.SandboxProfile, sockInside string) (set []EnvVar, unset []string) {
	set, unset = identityEnv(profile.Identity)
	if profile.JudgeSocket != "" {
		set = append(set, EnvVar{"AIGATE_JUDGE_SOCK", sockInside})
	}
	unset = append(unset, profile.UnsetEnv...)
	return set, unset
}
