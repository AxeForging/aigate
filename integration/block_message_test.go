package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// uniformBlock is the one format every layer uses (R5).
var uniformBlock = regexp.MustCompile(`\[aigate\] blocked (.+?) — (sandbox|rule|identity|judge|identity "[^"]+"): (.+?)\. To allow: (.+)`)

// TestBlockMessages_Uniform: a denied file, a denied command, a denied
// subcommand and the pre-run refusal all speak the same format, inside a
// real sandbox.
func TestBlockMessages_Uniform(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	skipWithoutSandbox(t)
	bin := buildBinary(t)
	home, work := t.TempDir(), t.TempDir()
	tool := filepath.Join(work, "fake-tool")
	writeTree(t, work, 0o755, map[string]string{"fake-tool": "#!/bin/sh\necho RAN $*\n", "secret.env": "canary-secret-value"})
	writeTree(t, home, 0o644, map[string]string{".aigate/config.yaml": "group: ai-agents\nuser: ai-runner\n" +
		"deny_read: [secret.env]\ndeny_exec: [\"" + tool + " rm\", blocked-tool]\nallow_net: []\n"})
	writeTree(t, work, 0o755, map[string]string{"blocked-tool": "#!/bin/sh\necho SHOULD_NOT_RUN\n"})
	env := append(os.Environ(), "HOME="+home, "PATH="+work+":"+os.Getenv("PATH"))

	run := func(args ...string) string {
		cmd := exec.Command(bin, append([]string{"run", "--"}, args...)...)
		cmd.Env, cmd.Dir = env, work
		out, _ := cmd.CombinedOutput()
		return string(out)
	}
	tests := []struct {
		name, out, what, fix string
	}{
		{"denied file", run("sh", "-c", "cat secret.env"), "read of this file", "aigate allow read"},
		{"denied command inside", run("sh", "-c", "blocked-tool; true"), "exec blocked-tool", "aigate allow exec blocked-tool"},
		{"denied subcommand inside", run("sh", "-c", tool+" rm x; true"), "fake-tool rm", "aigate allow exec '" + tool + " rm'"},
		{"pre-run refusal", run("blocked-tool"), "exec blocked-tool", "aigate allow exec blocked-tool"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := uniformBlock.FindStringSubmatch(tt.out)
			if m == nil {
				t.Fatalf("no uniform block message in:\n%s", tt.out)
			}
			if !strings.Contains(m[1], tt.what) || !strings.Contains(m[4], tt.fix) {
				t.Errorf("what=%q fix=%q, want %q / %q", m[1], m[4], tt.what, tt.fix)
			}
			if strings.Contains(tt.out, "canary-secret-value") || strings.Contains(tt.out, "SHOULD_NOT_RUN") {
				t.Errorf("block didn't hold:\n%s", tt.out)
			}
		})
	}
	if out := run("sh", "-c", tool+" ls"); !strings.Contains(out, "RAN ls") {
		t.Errorf("other subcommands must still run:\n%s", out)
	}
}
