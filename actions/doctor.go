package actions

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/AxeForging/aigate/domain"
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

// useColor is true when stdout is a terminal and NO_COLOR is unset.
var useColor = term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == ""

var statusColor = map[string]string{
	services.StatusOK: "32", services.StatusNote: "36", services.StatusWarn: "33", services.StatusFail: "31",
}

// Execute runs every check, prints them (text, --json or --report) and exits
// non-zero when the verdict is blocked.
func (a *DoctorAction) Execute(c *cli.Context) error {
	checks := a.collect(!c.Bool("offline"))
	verdict := services.DoctorVerdict(checks)
	switch {
	case c.Bool("json"):
		out, _ := json.MarshalIndent(map[string]any{
			"version": services.DoctorSchemaVersion, "verdict": verdict,
			"platform": runtime.GOOS + "/" + runtime.GOARCH, "checks": checks,
		}, "", "  ")
		fmt.Println(string(out))
	case c.Bool("report"):
		fmt.Print(services.RedactForReport(renderDoctor(checks, verdict, false)))
	default:
		fmt.Print(renderDoctor(checks, verdict, useColor))
	}
	if verdict == services.VerdictBlocked {
		return cli.NewExitError("", 1)
	}
	return nil
}

func (a *DoctorAction) collect(online bool) []services.Check {
	cfg, cfgErr := a.configSvc.LoadGlobal()
	checks := a.setupChecks(cfg, cfgErr)
	switch runtime.GOOS {
	case "linux":
		checks = append(checks, linuxChecks()...)
	case "darwin":
		checks = append(checks, darwinChecks()...)
	default:
		checks = append(checks, services.Check{ID: "os", Group: "Sandbox", Name: "operating system", Status: services.StatusFail,
			Detail: runtime.GOOS + " is not supported; aigate sandboxes on Linux and macOS"})
	}
	if services.DoctorVerdict(checks) != services.VerdictBlocked {
		checks = append(checks, a.socketCheck())
	}
	if cfgErr == nil {
		checks = append(checks, services.IdentityChecks(cfg)...)
		wd, _ := os.Getwd()
		if settings, _, err := services.ClaudeSettingsFor(cfg, "", wd); err == nil {
			checks = append(checks, services.JudgeChecks(cfg, settings, services.HasJudgeHook, online)...)
		}
	}
	return checks
}

func (a *DoctorAction) setupChecks(cfg *domain.Config, err error) []services.Check {
	path, _ := a.configSvc.GlobalConfigPath()
	if err != nil || cfg == nil {
		return []services.Check{{ID: "config", Group: "Setup", Name: "config", Status: services.StatusWarn,
			Detail: "not found at " + services.TildePath(path), Fix: "aigate init"}}
	}
	scope := "scope OFF ($HOME fully accessible)"
	if len(cfg.AllowedPaths) > 0 {
		scope = fmt.Sprintf("%d allowed_paths (scope ON)", len(cfg.AllowedPaths))
	}
	conf := services.Check{ID: "config", Group: "Setup", Name: "config", Status: services.StatusOK,
		Detail: fmt.Sprintf("%s — %d deny_read, %d deny_exec, %d allow_net, %s", services.TildePath(path),
			len(cfg.DenyRead), len(cfg.DenyExec), len(cfg.AllowNet), scope)}
	if len(cfg.AllowedPaths) == 0 {
		conf.Status, conf.Fix = services.StatusWarn, "aigate allow path ~/.cache   # turns on filesystem scope"
	}
	masks := services.Check{ID: "mask-presets", Group: "Setup", Name: "secret masking", Status: services.StatusOK,
		Detail: fmt.Sprintf("%d built-in secret formats masked in output", len(cfg.MaskStdout.Presets))}
	if missing := a.configSvc.MissingDefaultPresets(cfg); len(missing) > 0 {
		masks.Status, masks.Fix = services.StatusWarn, "aigate init --upgrade"
		masks.Detail = "newer secret formats not masked yet: " + strings.Join(missing, ", ")
	}
	groupOK, _ := a.platform.GroupExists(cfg.Group)
	userOK, _ := a.platform.UserExists(cfg.User)
	acct := services.Check{ID: "os-accounts", Group: "Setup", Name: "os accounts", Status: services.StatusOK,
		Detail: fmt.Sprintf("group %q and user %q exist", cfg.Group, cfg.User)}
	if !groupOK || !userOK {
		acct.Status, acct.Fix = services.StatusNote, "sudo aigate setup   # optional"
		acct.Detail = "missing; only needed for on-disk ACL rules, sandboxing works without them"
	}
	return []services.Check{conf, masks, acct}
}

// tool reports a binary on PATH; missing is the status when it isn't there.
func tool(name, desc, missing, install string) services.Check {
	c := services.Check{ID: name, Group: "Sandbox", Name: name, Status: services.StatusOK, Detail: desc}
	if _, err := exec.LookPath(name); err != nil {
		c.Status, c.Detail, c.Fix = missing, "not found — "+desc, install
	}
	return c
}

func linuxChecks() []services.Check {
	checks := []services.Check{
		tool("bwrap", "sandbox isolation (mount, pid, user namespaces)", services.StatusWarn,
			"sudo dnf install bubblewrap   # or: sudo apt install bubblewrap"),
		tool("slirp4netns", "network filtering for allow_net", services.StatusWarn,
			"sudo dnf install slirp4netns   # or: sudo apt install slirp4netns"),
		tool("ip6tables", "IPv6 egress filtering (optional; IPv4-only without it)", services.StatusNote,
			"sudo dnf install iptables   # or: sudo apt install iptables"),
		tool("setfacl", "on-disk ACLs between sessions (optional)", services.StatusNote,
			"sudo dnf install acl   # or: sudo apt install acl"),
	}
	userns := services.Check{ID: "userns", Group: "Sandbox", Name: "user namespaces", Status: services.StatusOK, Detail: "enabled"}
	if exec.Command("unshare", "--user", "--", "true").Run() != nil {
		userns.Status, userns.Detail = services.StatusFail, "disabled; every sandbox mode needs them"
		userns.Fix = "echo 1 | sudo tee /proc/sys/kernel/unprivileged_userns_clone"
	}
	checks = append(checks, userns)
	if userns.Status == services.StatusOK && checks[0].Status == services.StatusOK {
		aa := services.Check{ID: "apparmor-userns", Group: "Sandbox", Name: "apparmor userns", Status: services.StatusOK,
			Detail: "bwrap can create its namespaces"}
		if p := services.DetectUsernsProblem(); p != nil {
			aa.Status, aa.Detail, aa.Fix = services.StatusFail, p.Reason, strings.TrimSpace(p.Fix)
		}
		checks = append(checks, aa)
	}
	return checks
}

func darwinChecks() []services.Check {
	return []services.Check{
		tool("sandbox-exec", "macOS Seatbelt sandbox", services.StatusFail, "built into macOS; reinstall the command line tools"),
		{ID: "macos-keychain", Group: "Identities", Name: "claude logins (macOS)", Status: services.StatusNote,
			Detail: "files, gh login, git author and ssh key are isolated per identity; Claude logins live in the Keychain, which a sandboxed process can still ask for. Use separate macOS users if that matters."},
	}
}

// socketCheck runs a real sandbox and checks that agent sockets and their env
// vars are gone inside (ssh-agent, session bus, keyrings).
func (a *DoctorAction) socketCheck() services.Check {
	c := services.Check{ID: "agent-sockets", Group: "Sandbox", Name: "agent sockets", Status: services.StatusOK,
		Detail: "ssh-agent, session bus and keyring sockets hidden inside the sandbox (tested)"}
	script := `ls -A "/run/user/$(id -u)" 2>/dev/null; printf '%s%s' "${SSH_AUTH_SOCK:-}" "${DBUS_SESSION_BUS_ADDRESS:-}"`
	if runtime.GOOS == "darwin" {
		script = `printf '%s' "${SSH_AUTH_SOCK:-}"`
	}
	wd, err := os.MkdirTemp("", "aigate-doctor-")
	if err != nil {
		c.Status, c.Detail = services.StatusWarn, "could not create a test folder: "+err.Error()
		return c
	}
	defer func() { _ = os.RemoveAll(wd) }()
	var out bytes.Buffer
	err = a.platform.RunSandboxed(domain.SandboxProfile{WorkDir: wd}, "sh", []string{"-c", script}, &out, &out)
	switch {
	case err != nil:
		c.Status, c.Detail = services.StatusWarn, "could not start a test sandbox: "+err.Error()
		c.Fix = "aigate run -- true   # shows the full error"
	case strings.TrimSpace(out.String()) != "":
		c.Status, c.Detail = services.StatusFail, "visible inside the sandbox: "+strings.TrimSpace(out.String())
		c.Fix = "update aigate; report it with the output of: aigate doctor --report"
	}
	return c
}

// renderDoctor prints checks by group, one verdict line, then the fixes.
func renderDoctor(checks []services.Check, verdict string, color bool) string {
	paint := func(code, s string) string {
		if !color {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "aigate doctor — %s/%s\n", runtime.GOOS, runtime.GOARCH)
	group := ""
	var fixes []string
	for _, c := range checks {
		if c.Group != group {
			group = c.Group
			fmt.Fprintf(&b, "\n%s\n", group)
		}
		fmt.Fprintf(&b, "%s %-22s %s\n", paint(statusColor[c.Status], fmt.Sprintf(" %-4s ", strings.ToUpper(c.Status))), c.Name, c.Detail)
		if c.Fix == "" || c.Status == services.StatusOK {
			continue
		}
		for i, line := range strings.Split(c.Fix, "\n") {
			label := "fix:"
			if i > 0 {
				label = "    "
			}
			fmt.Fprintf(&b, "%29s %s %s\n", "", label, line)
		}
		if c.Status != services.StatusNote && !strings.Contains(c.Fix, "\n") {
			fixes = append(fixes, c.Fix)
		}
	}
	b.WriteString("\n")
	switch verdict {
	case services.VerdictBlocked:
		fmt.Fprintf(&b, "Verdict: %s — aigate can't run safely here; fix the FAIL lines above.\n", paint("31;1", "BLOCKED"))
	case services.VerdictDegraded:
		fmt.Fprintf(&b, "Verdict: %s — aigate runs, with less protection until the WARN lines are fixed.\n", paint("33;1", "DEGRADED"))
	default:
		fmt.Fprintf(&b, "Verdict: %s — full isolation available. Try: aigate run -- claude\n", paint("32;1", "READY"))
	}
	if len(fixes) > 0 {
		b.WriteString("\nNext steps:\n")
		for _, f := range fixes {
			fmt.Fprintf(&b, "  %s\n", f)
		}
	}
	return b.String()
}
