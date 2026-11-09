package integration

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func doctor(t *testing.T, bin, home string, env []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"doctor", "--offline"}, args...)...)
	cmd.Env = append(append(os.Environ(), "HOME="+home, "NO_COLOR=1"), env...)
	cmd.Dir = home
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	}
	return string(out), code
}

type doctorJSON struct {
	Version int    `json:"version"`
	Verdict string `json:"verdict"`
	Checks  []struct {
		ID, Status, Detail, Fix string
	} `json:"checks"`
}

func TestDoctor_JSONSchema(t *testing.T) {
	bin := buildBinary(t)
	home := cliHome(t, identityCLIConfig+"allowed_paths: [\"~/.cache\"]\n")
	out, _ := doctor(t, bin, home, nil, "--json")
	var d doctorJSON
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if d.Version != 1 || d.Verdict == "" || len(d.Checks) < 5 {
		t.Fatalf("schema wrong: %+v", d)
	}
	ids := map[string]string{}
	for _, c := range d.Checks {
		ids[c.ID] = c.Status
		if c.Status != "ok" && c.Status != "note" && c.Status != "warn" && c.Status != "fail" {
			t.Errorf("unknown status %q on %s", c.Status, c.ID)
		}
	}
	for _, want := range []string{"config", "identity.work", "identity.personal", "judge"} {
		if _, ok := ids[want]; !ok {
			t.Errorf("missing check %s in %v", want, ids)
		}
	}
}

func TestDoctor_BlockedExitsNonZeroAndShowsFix(t *testing.T) {
	bin := buildBinary(t)
	home := cliHome(t, identityCLIConfig)
	if err := os.RemoveAll(home + "/.config/gh-work"); err != nil {
		t.Fatal(err)
	}
	out, code := doctor(t, bin, home, nil)
	if code == 0 {
		t.Fatalf("a broken identity must make doctor exit non-zero:\n%s", out)
	}
	mustContain(t, out, "FAIL", "identity work", "fix: mkdir -p "+home+"/.config/gh-work", "Verdict: BLOCKED")
}

func TestDoctor_NotInitializedPointsToInit(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()
	out, _ := doctor(t, bin, home, nil)
	mustContain(t, out, "config", "fix: aigate init")
}

func TestDoctor_ReportIsSafeToPaste(t *testing.T) {
	bin := buildBinary(t)
	home := cliHome(t, identityCLIConfig+"judge:\n  enabled: true\n")
	canary := "canary-doctor-report-token"
	out, _ := doctor(t, bin, home, []string{"AIGATE_CF_ACCOUNT=acct", "AIGATE_CF_TOKEN=" + canary}, "--report")
	for _, leak := range []string{home, canary, os.Getenv("USER") + "/"} {
		if leak != "/" && strings.Contains(out, leak) {
			t.Errorf("report leaks %q:\n%s", leak, out)
		}
	}
	mustContain(t, out, "Verdict:", "~/.aigate/config.yaml")
}
