package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A config written before the newer mask presets existed (#33), with the
// user's own rules that an upgrade must keep.
const preUpgradeConfig = `group: ai-agents
user: ai-runner
deny_read: [".env", "my-secrets/"]
deny_exec: [curl]
allow_net: [api.anthropic.com]
mask_stdout:
  presets: [openai, anthropic, github]
  patterns:
    - regex: 'MY_TOKEN=\S+'
`

func initUpgrade(t *testing.T, bin, home string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, "init", "--upgrade")
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func presetCheck(t *testing.T, bin, home string) (status, detail, fix string) {
	t.Helper()
	out, _ := doctor(t, bin, home, nil, "--json")
	var d doctorJSON
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	for _, c := range d.Checks {
		if c.ID == "mask-presets" {
			return c.Status, c.Detail, c.Fix
		}
	}
	t.Fatalf("no mask-presets check in:\n%s", out)
	return "", "", ""
}

// TestInitUpgrade_AddsNewPresetsKeepsUserRules: doctor points at the missing
// presets, `init --upgrade` adds exactly those, keeps every user rule, and is
// a no-op the second time.
func TestInitUpgrade_AddsNewPresetsKeepsUserRules(t *testing.T) {
	bin := buildBinary(t)
	home := cliHome(t, preUpgradeConfig)

	status, detail, fix := presetCheck(t, bin, home)
	if status != "warn" || !strings.Contains(detail, "cloudflare") || fix != "aigate init --upgrade" {
		t.Fatalf("doctor before upgrade: %s / %s / %s", status, detail, fix)
	}

	out, err := initUpgrade(t, bin, home)
	if err != nil || !strings.Contains(out, "cloudflare") || !strings.Contains(out, "Added") {
		t.Fatalf("init --upgrade: %v\n%s", err, out)
	}
	cfg := readFile(t, filepath.Join(home, ".aigate/config.yaml"))
	for _, keep := range []string{"my-secrets/", "curl", "api.anthropic.com", `MY_TOKEN=\S+`, "openai", "cloudflare", "huggingface"} {
		if !strings.Contains(cfg, keep) {
			t.Errorf("config after upgrade lost or lacks %q:\n%s", keep, cfg)
		}
	}
	if strings.Count(cfg, "- openai") > 1 {
		t.Errorf("presets duplicated:\n%s", cfg)
	}

	if status, _, _ := presetCheck(t, bin, home); status != "ok" {
		t.Errorf("doctor after upgrade: %s", status)
	}
	before := readFile(t, filepath.Join(home, ".aigate/config.yaml"))
	out, err = initUpgrade(t, bin, home)
	if err != nil || !strings.Contains(out, "already up to date") {
		t.Errorf("second upgrade should be a no-op: %v\n%s", err, out)
	}
	if after := readFile(t, filepath.Join(home, ".aigate/config.yaml")); after != before {
		t.Error("a no-op upgrade must not rewrite the config")
	}
}

func TestInitUpgrade_WithoutConfigPointsToInit(t *testing.T) {
	bin := buildBinary(t)
	out, err := initUpgrade(t, bin, t.TempDir())
	if err == nil || !strings.Contains(out, "aigate init") {
		t.Errorf("want an error pointing to aigate init, got %v\n%s", err, out)
	}
}
