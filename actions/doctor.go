package actions

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/urfave/cli"
)

type DoctorAction struct{}

func NewDoctorAction() *DoctorAction {
	return &DoctorAction{}
}

func (a *DoctorAction) Execute(c *cli.Context) error {
	fmt.Printf("aigate doctor — runtime checks (%s/%s)\n\n", runtime.GOOS, runtime.GOARCH)

	switch runtime.GOOS {
	case "linux":
		runLinuxChecks()
	case "darwin":
		runDarwinChecks()
	default:
		fmt.Println("  No platform-specific checks for this OS.")
	}

	return nil
}

// ── Linux ────────────────────────────────────────────────────────────────────

func runLinuxChecks() {
	bwrapOK := printCheck("bwrap",
		"sandbox isolation (mount / pid / user namespaces)",
		"sudo dnf install bubblewrap   OR   sudo apt install bubblewrap")

	slirpOK := printCheck("slirp4netns",
		"network filtering — required for allow_net rules",
		"sudo dnf install slirp4netns   OR   sudo apt install slirp4netns")

	printCheck("setfacl",
		"persistent ACLs — deny_read enforced on disk between sessions",
		"sudo dnf install acl   OR   sudo apt install acl")

	unshareOK := checkUserNamespaces()

	fmt.Println()
	printLinuxIsolationMode(bwrapOK, slirpOK, unshareOK)
}

// printCheck looks up tool by name, prints a status line, and returns true if found.
// installHint is printed on a second line when the tool is missing.
func printCheck(name, desc, installHint string) bool {
	path, err := exec.LookPath(name)
	if err != nil {
		fmt.Printf("  WARN  %-16s not found\n", name)
		fmt.Printf("          %s\n", desc)
		if installHint != "" {
			fmt.Printf("          Install: %s\n", installHint)
		}
		return false
	}

	ver := toolVersion(name)
	if ver != "" {
		fmt.Printf("  ok    %-16s %s (%s)\n", name, ver, path)
	} else {
		fmt.Printf("  ok    %-16s %s\n", name, path)
	}
	fmt.Printf("          %s\n", desc)
	return true
}

// toolVersion runs `name --version` and returns the first meaningful token.
func toolVersion(name string) string {
	out, err := exec.Command(name, "--version").CombinedOutput() //nolint:gosec
	if err != nil {
		return ""
	}
	line := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	// Keep only the version token (e.g. "bubblewrap 0.10.0" → "v0.10.0")
	parts := strings.Fields(line)
	for _, p := range parts {
		if len(p) > 0 && (p[0] >= '0' && p[0] <= '9') {
			return "v" + p
		}
	}
	return ""
}

// checkUserNamespaces verifies that unprivileged user namespaces are enabled.
func checkUserNamespaces() bool {
	// Attempt a trivial unshare; if it fails the kernel has them disabled.
	err := exec.Command("unshare", "--user", "--", "true").Run()
	if err != nil {
		fmt.Printf("  WARN  %-16s disabled\n", "user namespaces")
		fmt.Printf("          Required for all sandbox modes.\n")
		fmt.Printf("          Enable: echo 1 | sudo tee /proc/sys/kernel/unprivileged_userns_clone\n")
		return false
	}
	fmt.Printf("  ok    %-16s enabled\n", "user namespaces")
	fmt.Printf("          Required for all sandbox modes.\n")
	return true
}

// printLinuxIsolationMode describes which sandbox path will be taken based on
// available tools, mirroring the dispatch logic in RunSandboxed.
func printLinuxIsolationMode(bwrap, slirp, unshare bool) {
	fmt.Println("Isolation mode:")

	switch {
	case bwrap && slirp:
		fmt.Println("  bwrap + slirp4netns  (full isolation)")
		fmt.Println()
		fmt.Println("  deny_read   bwrap bind mounts           kernel-enforced, per-run")
		fmt.Println("  deny_exec   bwrap bind mounts           kernel-enforced, per-run")
		fmt.Println("  allow_net   bwrap --unshare-net         network namespace via bwrap")
		fmt.Println("              slirp4netns + iptables      egress filtered to allowed hosts")
		fmt.Println("  config dir  bwrap tmpfs overlay         ~/.aigate hidden from agent")
	case bwrap && !slirp:
		fmt.Println("  bwrap  (no network filtering — slirp4netns missing)")
		fmt.Println()
		fmt.Println("  deny_read   bwrap bind mounts           kernel-enforced, per-run")
		fmt.Println("  deny_exec   bwrap bind mounts           kernel-enforced, per-run")
		fmt.Println("  allow_net   INACTIVE                    install slirp4netns to enable")
		fmt.Println("  config dir  bwrap tmpfs overlay         ~/.aigate hidden from agent")
	case !bwrap && slirp && unshare:
		fmt.Println("  unshare + slirp4netns  (fallback — install bwrap for stronger isolation)")
		fmt.Println()
		fmt.Println("  deny_read   mount namespace overrides   shell-script-based")
		fmt.Println("  deny_exec   mount namespace overrides   shell-script-based")
		fmt.Println("  allow_net   unshare --net + slirp4netns egress filtered to allowed hosts")
		fmt.Println("  config dir  tmpfs mount                 ~/.aigate hidden from agent")
	case !bwrap && !slirp && unshare:
		fmt.Println("  unshare  (fallback — install bwrap for stronger isolation)")
		fmt.Println()
		fmt.Println("  deny_read   mount namespace overrides   shell-script-based")
		fmt.Println("  deny_exec   mount namespace overrides   shell-script-based")
		fmt.Println("  allow_net   INACTIVE                    install slirp4netns to enable")
		fmt.Println("  config dir  tmpfs mount                 ~/.aigate hidden from agent")
	default:
		fmt.Println("  NONE — user namespaces are disabled; sandbox cannot run")
	}
}

// ── macOS ────────────────────────────────────────────────────────────────────

func runDarwinChecks() {
	printCheck("sandbox-exec",
		"macOS Seatbelt sandbox (deny_read, deny_exec, allow_net)",
		"Built into macOS — should always be present")

	fmt.Println()
	fmt.Println("Isolation mode: sandbox-exec (Seatbelt)")
	fmt.Println()
	fmt.Println("  deny_read   Seatbelt file-read* deny rules  kernel-enforced")
	fmt.Println("  deny_exec   Seatbelt process-exec deny       kernel-enforced")
	fmt.Println("  allow_net   Seatbelt network-outbound rules  kernel-enforced")
}
