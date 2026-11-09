package services

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectUsernsProblem(t *testing.T) {
	dir := t.TempDir()
	write := func(name, v string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	failing := func() (string, error) { return "/opt/bin/bwrap", errors.New("setting up uid map: Permission denied") }
	working := func() (string, error) { return "/usr/bin/bwrap", nil }
	probed := false
	spy := func() (string, error) { probed = true; return "", nil }

	tests := []struct {
		name    string
		sysctl  string
		probe   func() (string, error)
		problem bool
	}{
		{"no sysctl (not Ubuntu / old kernel)", filepath.Join(dir, "missing"), failing, false},
		{"restriction off", write("off", "0\n"), failing, false},
		{"restricted but bwrap allowed", write("on-ok", "1\n"), working, false},
		{"restricted and bwrap blocked", write("on-bad", "1\n"), failing, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := detectUsernsProblem(tt.sysctl, tt.probe)
			if (p != nil) != tt.problem {
				t.Fatalf("problem = %v, want %v", p, tt.problem)
			}
			if p == nil {
				return
			}
			msg := p.Error()
			for _, want := range []string{"AppArmor", "sudo tee /etc/apparmor.d/bwrap", "profile bwrap /opt/bin/bwrap flags=(unconfined)", "userns,", "sudo systemctl reload apparmor", "apparmor_restrict_unprivileged_userns=0"} {
				if !strings.Contains(msg, want) {
					t.Errorf("message missing %q:\n%s", want, msg)
				}
			}
		})
	}

	_ = detectUsernsProblem(write("off2", "0"), spy)
	if probed {
		t.Error("bwrap must not be probed when the restriction is off (keeps normal runs fast)")
	}
}
