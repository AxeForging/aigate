package services

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Ubuntu 23.10+ lets unprivileged processes create user namespaces only
// without capabilities unless an AppArmor profile allows it. `unshare --user
// true` still succeeds there, but bwrap can't set up its mounts.
const apparmorUsernsSysctl = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"

// UsernsProblem explains why bwrap can't create its namespaces, and how to fix it.
type UsernsProblem struct {
	Reason string
	Fix    string // copy-pasteable commands
	Alt    string // simpler but weaker alternative
}

func (p *UsernsProblem) Error() string {
	return fmt.Sprintf("%s\n\nFix (allows only bwrap):\n%s\n\nOr (turns the protection off for every program):\n  %s", p.Reason, p.Fix, p.Alt)
}

// DetectUsernsProblem returns nil when bwrap can create its namespaces, or
// when the AppArmor restriction isn't active (nothing is probed then).
func DetectUsernsProblem() *UsernsProblem {
	return detectUsernsProblem(apparmorUsernsSysctl, probeBwrap)
}

func detectUsernsProblem(sysctlPath string, probe func() (string, error)) *UsernsProblem {
	data, err := os.ReadFile(sysctlPath)
	if err != nil || strings.TrimSpace(string(data)) != "1" {
		return nil
	}
	bwrapPath, err := probe()
	if err == nil {
		return nil
	}
	if bwrapPath == "" {
		bwrapPath = "/usr/bin/bwrap"
	}
	return &UsernsProblem{
		Reason: "AppArmor is blocking the user namespaces bubblewrap needs (kernel.apparmor_restrict_unprivileged_userns=1, the Ubuntu 23.10+ default).",
		Fix: fmt.Sprintf(`  sudo tee /etc/apparmor.d/bwrap >/dev/null <<'EOF'
abi <abi/4.0>,
include <tunables/global>
profile bwrap %s flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
EOF
  sudo systemctl reload apparmor`, bwrapPath),
		Alt: "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0",
	}
}

// probeBwrap runs the smallest bwrap call that needs the same namespaces as
// the sandbox. It returns bwrap's path.
func probeBwrap() (string, error) {
	path, err := exec.LookPath("bwrap")
	if err != nil {
		return "", err
	}
	return path, exec.Command(path, "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
		"--unshare-pid", "--unshare-user", "--", "true").Run()
}
