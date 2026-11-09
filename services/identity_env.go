package services

import (
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
		{"CLAUDE_CONFIG_DIR", id.ClaudeDir},
		{"GH_CONFIG_DIR", id.GhDir},
		{"AIGATE_IDENTITY", id.Name},
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
