package actions

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/AxeForging/aigate/services"
	"github.com/urfave/cli"
	"golang.org/x/term"
)

type DoctorAction struct {
	configSvc *services.ConfigService
	platform  services.Platform
}

func NewDoctorAction(c *services.ConfigService, p services.Platform) *DoctorAction {
	return &DoctorAction{configSvc: c, platform: p}
}

// doctorReport accumulates check outcomes so the run can end with a single
// verdict and a copy-pasteable list of next steps.
type doctorReport struct {
	nextSteps []string
	blocked   bool // sandbox cannot run at all
	degraded  bool // sandbox runs with reduced isolation
}

func (r *doctorReport) step(s string) {
	if s == "" {
		return
	}
	for _, existing := range r.nextSteps {
		if existing == s {
			return
		}
	}
	r.nextSteps = append(r.nextSteps, s)
}

// useColor is true when stdout is a terminal and NO_COLOR is unset.
var useColor = term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == ""

func colorize(code, s string) string {
	if !useColor {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func okTag() string   { return colorize("32", "  ok  ") }
func warnTag() string { return colorize("33", " WARN ") }
func failTag() string { return colorize("31", " FAIL ") }

func (a *DoctorAction) Execute(c *cli.Context) error {
	fmt.Printf("aigate doctor — environment checks (%s/%s)\n\n", runtime.GOOS, runtime.GOARCH)

	report := &doctorReport{}

	fmt.Println("Setup")
	a.runSetupChecks(report)
	fmt.Println()

	fmt.Println("Tools")
	switch runtime.GOOS {
	case "linux":
		runLinuxChecks(report)
	case "darwin":
		runDarwinChecks(report)
	default:
		fmt.Println("  No platform-specific checks for this OS.")
		report.blocked = true
		report.step("aigate sandboxing supports Linux and macOS only")
	}

	printVerdict(report)

	if report.blocked {
		return cli.NewExitError("", 1)
	}
	return nil
}

// runSetupChecks verifies the one-time setup state: config file and the
// sandbox OS group/user.
func (a *DoctorAction) runSetupChecks(report *doctorReport) {
	cfgPath, _ := a.configSvc.GlobalConfigPath()
	cfg, err := a.configSvc.LoadGlobal()
	if err != nil || cfg == nil {
		fmt.Printf("%s %-16s not found\n", warnTag(), "config")
		fmt.Printf("          Expected at %s\n", cfgPath)
		report.degraded = true
		report.step("aigate init                      # create the default config")
		return
	}

	scope := "scope OFF ($HOME fully accessible)"
	if len(cfg.AllowedPaths) > 0 {
		scope = fmt.Sprintf("%d allowed_paths (scope ON)", len(cfg.AllowedPaths))
	}
	fmt.Printf("%s %-16s %s\n", okTag(), "config", cfgPath)
	fmt.Printf("          %d deny_read, %d deny_exec, %d allow_net, %s\n",
		len(cfg.DenyRead), len(cfg.DenyExec), len(cfg.AllowNet), scope)
	if len(cfg.AllowedPaths) == 0 {
		report.step("aigate allow path ~/.cache       # optional: turn on filesystem scope mode")
	}

	groupExists, _ := a.platform.GroupExists(cfg.Group)
	userExists, _ := a.platform.UserExists(cfg.User)
	if groupExists && userExists {
		fmt.Printf("%s %-16s group %q and user %q exist\n", okTag(), "os accounts", cfg.Group, cfg.User)
	} else {
		fmt.Printf("%s %-16s group %q or user %q missing\n", warnTag(), "os accounts", cfg.Group, cfg.User)
		fmt.Printf("          Only needed for persistent ACL rules; namespace sandboxing works without them.\n")
		report.step("sudo aigate setup                # optional: create sandbox group/user for ACLs")
	}
}

// printVerdict prints the final one-line verdict plus collected next steps.
func printVerdict(report *doctorReport) {
	fmt.Println()
	switch {
	case report.blocked:
		fmt.Printf("Verdict: %s — the sandbox cannot run on this host.\n", colorize("31;1", "BLOCKED"))
	case report.degraded:
		fmt.Printf("Verdict: %s — the sandbox runs, but with reduced isolation or setup pending.\n", colorize("33;1", "DEGRADED"))
	default:
		fmt.Printf("Verdict: %s — full isolation available. Try: aigate run -- claude\n", colorize("32;1", "READY"))
	}
	if len(report.nextSteps) > 0 {
		fmt.Println("\nNext steps:")
		for _, s := range report.nextSteps {
			fmt.Printf("  %s\n", s)
		}
	}
}

// ── Linux ────────────────────────────────────────────────────────────────────

func runLinuxChecks(report *doctorReport) {
	bwrapOK := printCheck(report,
		"bwrap",
		"sandbox isolation (mount / pid / user namespaces)",
		"sudo dnf install bubblewrap   OR   sudo apt install bubblewrap")

	slirpOK := printCheck(report,
		"slirp4netns",
		"network filtering — required for allow_net rules",
		"sudo dnf install slirp4netns   OR   sudo apt install slirp4netns")

	printCheck(report,
		"ip6tables",
		"IPv6 egress filtering — optional; when missing, sandbox runs IPv4-only",
		"sudo dnf install iptables   OR   sudo apt install iptables")

	printCheck(report,
		"setfacl",
		"persistent ACLs — deny_read enforced on disk between sessions",
		"sudo dnf install acl   OR   sudo apt install acl")

	unshareOK := checkUserNamespaces(report)
	if unshareOK && bwrapOK {
		unshareOK = checkAppArmorUserns(report)
	}

	fmt.Println()
	printLinuxIsolationMode(bwrapOK, slirpOK, unshareOK)

	switch {
	case !unshareOK:
		report.blocked = true
	case !bwrapOK || !slirpOK:
		report.degraded = true
	}
}

// printCheck looks up tool by name, prints a status line, and returns true if
// found. installHint is printed (and queued as a next step) when missing.
func printCheck(report *doctorReport, name, desc, installHint string) bool {
	path, err := exec.LookPath(name)
	if err != nil {
		fmt.Printf("%s %-16s not found\n", warnTag(), name)
		fmt.Printf("          %s\n", desc)
		if installHint != "" {
			fmt.Printf("          Install: %s\n", installHint)
			report.step(installHint)
		}
		return false
	}

	ver := toolVersion(name)
	if ver != "" {
		fmt.Printf("%s %-16s %s (%s)\n", okTag(), name, ver, path)
	} else {
		fmt.Printf("%s %-16s %s\n", okTag(), name, path)
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

// ip6tablesAvailable mirrors the runtime check used by the sandbox: kernel v6
// must be enabled AND ip6tables must be on PATH. Either missing → v4-only.
func ip6tablesAvailable() bool {
	if _, err := exec.LookPath("ip6tables"); err != nil {
		return false
	}
	// Match the services-layer check; if v6 is disabled at the kernel, ip6tables
	// in the namespace will fail and we'd be running unfiltered v6 — refuse it.
	data, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "0"
}

// checkUserNamespaces verifies that unprivileged user namespaces are enabled.
func checkUserNamespaces(report *doctorReport) bool {
	// Attempt a trivial unshare; if it fails the kernel has them disabled.
	err := exec.Command("unshare", "--user", "--", "true").Run()
	if err != nil {
		fmt.Printf("%s %-16s disabled\n", failTag(), "user namespaces")
		fmt.Printf("          Required for all sandbox modes.\n")
		fmt.Printf("          Enable: echo 1 | sudo tee /proc/sys/kernel/unprivileged_userns_clone\n")
		report.step("echo 1 | sudo tee /proc/sys/kernel/unprivileged_userns_clone")
		return false
	}
	fmt.Printf("%s %-16s enabled\n", okTag(), "user namespaces")
	fmt.Printf("          Required for all sandbox modes.\n")
	return true
}

// checkAppArmorUserns catches Ubuntu's AppArmor restriction, which lets
// `unshare --user` pass while blocking bwrap.
func checkAppArmorUserns(report *doctorReport) bool {
	problem := services.DetectUsernsProblem()
	if problem == nil {
		fmt.Printf("%s %-16s bwrap can create its namespaces\n", okTag(), "apparmor userns")
		return true
	}
	fmt.Printf("%s %-16s blocking bwrap\n", failTag(), "apparmor userns")
	for _, line := range strings.Split(problem.Error(), "\n") {
		fmt.Printf("          %s\n", line)
	}
	report.step("allow bwrap in AppArmor (see the apparmor userns check above)")
	return false
}

// printLinuxIsolationMode describes which sandbox path will be taken based on
// available tools, mirroring the dispatch logic in RunSandboxed.
func printLinuxIsolationMode(bwrap, slirp, unshare bool) {
	fmt.Println("Isolation mode:")

	switch {
	case bwrap && slirp:
		fmt.Println("  bwrap + slirp4netns  (full isolation)")
		fmt.Println()
		fmt.Println("  deny_read      bwrap bind mounts           kernel-enforced, per-run")
		fmt.Println("  deny_exec      bwrap bind mounts           kernel-enforced, per-run")
		fmt.Println("  allowed_paths  bwrap tmpfs over $HOME      non-scoped files hidden, kernel-enforced")
		fmt.Println("  allow_net      bwrap --unshare-net         network namespace via bwrap")
		fmt.Println("                 slirp4netns + iptables      egress filtered to allowed hosts")
		if ip6tablesAvailable() {
			fmt.Println("                 + ip6tables                 IPv6 egress filtered in parallel")
		} else {
			fmt.Println("                 IPv4-only                   install ip6tables to enable v6 filtering")
		}
		fmt.Println("  config dir     bwrap tmpfs overlay         ~/.aigate hidden from agent")
	case bwrap && !slirp:
		fmt.Println("  bwrap  (no network filtering — slirp4netns missing)")
		fmt.Println()
		fmt.Println("  deny_read      bwrap bind mounts           kernel-enforced, per-run")
		fmt.Println("  deny_exec      bwrap bind mounts           kernel-enforced, per-run")
		fmt.Println("  allowed_paths  bwrap tmpfs over $HOME      non-scoped files hidden, kernel-enforced")
		fmt.Println("  allow_net      INACTIVE                    install slirp4netns to enable")
		fmt.Println("  config dir     bwrap tmpfs overlay         ~/.aigate hidden from agent")
	case !bwrap && slirp && unshare:
		fmt.Println("  unshare + slirp4netns  (fallback — install bwrap for stronger isolation)")
		fmt.Println()
		fmt.Println("  deny_read      mount namespace overrides   shell-script-based")
		fmt.Println("  deny_exec      mount namespace overrides   shell-script-based")
		fmt.Println("  allowed_paths  tmpfs over $HOME            non-scoped files hidden")
		fmt.Println("  allow_net      unshare --net + slirp4netns egress filtered to allowed hosts")
		fmt.Println("  config dir     tmpfs mount                 ~/.aigate hidden from agent")
	case !bwrap && !slirp && unshare:
		fmt.Println("  unshare  (fallback — install bwrap for stronger isolation)")
		fmt.Println()
		fmt.Println("  deny_read      mount namespace overrides   shell-script-based")
		fmt.Println("  deny_exec      mount namespace overrides   shell-script-based")
		fmt.Println("  allowed_paths  tmpfs over $HOME            non-scoped files hidden")
		fmt.Println("  allow_net      INACTIVE                    install slirp4netns to enable")
		fmt.Println("  config dir     tmpfs mount                 ~/.aigate hidden from agent")
	default:
		fmt.Println("  NONE — user namespaces are disabled; sandbox cannot run")
	}
}

// ── macOS ────────────────────────────────────────────────────────────────────

func runDarwinChecks(report *doctorReport) {
	sbOK := printCheck(report,
		"sandbox-exec",
		"macOS Seatbelt sandbox (deny_read, deny_exec, allow_net, allowed_paths)",
		"Built into macOS — should always be present")
	if !sbOK {
		report.blocked = true
	}

	fmt.Println()
	fmt.Println("Isolation mode: sandbox-exec (Seatbelt)")
	fmt.Println()
	fmt.Println("  deny_read      Seatbelt file-read* deny rules   kernel-enforced")
	fmt.Println("  deny_exec      Seatbelt process-exec deny       kernel-enforced")
	fmt.Println("  allowed_paths  Seatbelt read+write deny on $HOME with scope allows")
	fmt.Println("  allow_net      Seatbelt network-outbound rules  kernel-enforced")
	fmt.Println()
	fmt.Println("Identities on macOS:")
	fmt.Println("  isolated       files, gh login, git author, ssh key (Seatbelt hides other identities)")
	fmt.Println("  NOT isolated   Claude logins: Claude Code keeps one Keychain item per identity, but")
	fmt.Println("                 the Keychain doesn't stop a sandboxed process from asking for another")
	fmt.Println("                 identity's item. Use separate macOS users if that matters to you.")
}
