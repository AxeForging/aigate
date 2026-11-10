package services

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/AxeForging/aigate/domain"
)

// scopeHidesCommand reports when filesystem scope hides the program being
// run, e.g. ~/.local/bin/claude linking into ~/.local/share/claude. Without
// this the sandbox fails with bwrap's "execvp: No such file or directory".
func scopeHidesCommand(profile domain.SandboxProfile, cmd string) (Block, bool) {
	if len(profile.Config.AllowedPaths) == 0 {
		return Block{}, false
	}
	path, err := exec.LookPath(cmd)
	if err != nil {
		return Block{}, false
	}
	paths := []string{path}
	if real, err := filepath.EvalSymlinks(path); err == nil && real != path {
		paths = append(paths, real)
	}
	var dirs []string
	for _, p := range paths {
		if abs, err := filepath.Abs(p); err == nil && ExplainPath(profile, nil, abs).Access == AccessHidden {
			dirs = appendUnique(dirs, []string{TildePath(filepath.Dir(abs))})
		}
	}
	if len(dirs) == 0 {
		return Block{}, false
	}
	name := filepath.Base(cmd)
	fix := dirs
	if name == "claude" { // its logins live here; without them it asks to log in again
		home, _ := os.UserHomeDir()
		listed, _ := resolvePatterns(profile.Config.AllowedPaths, profile.WorkDir)
		for _, p := range []string{".claude", ".claude.json"} {
			if !underAny(filepath.Join(home, p), listed) { // listed but not created yet counts as allowed
				fix = appendUnique(fix, []string{"~/" + p})
			}
		}
	}
	args := make([]string, len(fix))
	for i, d := range fix {
		args[i] = shellArg(d)
	}
	return Block{
		What:   "run " + name,
		Layer:  LayerSandbox,
		Reason: fmt.Sprintf("%s is installed in %s, which the filesystem scope hides", name, strings.Join(dirs, " and ")),
		Fix:    "aigate allow path " + strings.Join(args, " "),
	}, true
}

// DefaultScopeFix turns filesystem scope on with the default folders agent
// tools need (their logins, caches and installs), not just one of them.
func DefaultScopeFix() string {
	return "aigate allow path " + strings.Join((&ConfigService{}).InitDefaultConfig().AllowedPaths, " ") + "   # turns on filesystem scope"
}
