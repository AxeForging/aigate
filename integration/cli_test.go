package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "aigate-test")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}
	return bin
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	return filepath.Dir(wd) // integration/ is one level deep
}

func TestCLI_Help(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "--help")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--help failed: %v\n%s", err, string(out))
	}
	output := string(out)
	if !strings.Contains(output, "aigate") {
		t.Error("--help should contain 'aigate'")
	}
	if !strings.Contains(output, "init") {
		t.Error("--help should list 'init' command")
	}
	if !strings.Contains(output, "deny") {
		t.Error("--help should list 'deny' command")
	}
	if !strings.Contains(output, "run") {
		t.Error("--help should list 'run' command")
	}
	if !strings.Contains(output, "status") {
		t.Error("--help should list 'status' command")
	}
}

func TestCLI_Version(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version failed: %v\n%s", err, string(out))
	}
	output := string(out)
	if !strings.Contains(output, "aigate version") {
		t.Error("version should show 'aigate version'")
	}
	if !strings.Contains(output, "Build time:") {
		t.Error("version should show Build time")
	}
	if !strings.Contains(output, "Git commit:") {
		t.Error("version should show Git commit")
	}
}

func TestCLI_StatusNotInitialized(t *testing.T) {
	bin := buildBinary(t)
	tmpHome := t.TempDir()

	cmd := exec.Command(bin, "status")
	cmd.Env = append(os.Environ(), "HOME="+tmpHome)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("status failed: %v\n%s", err, string(out))
	}
	output := string(out)
	if !strings.Contains(output, "NOT INITIALIZED") {
		t.Error("status should show NOT INITIALIZED when no config exists")
	}
}

func TestCLI_DenyReadAndAllow(t *testing.T) {
	bin := buildBinary(t)
	tmpHome := t.TempDir()
	tmpWork := t.TempDir()
	env := append(os.Environ(), "HOME="+tmpHome)

	// Create a minimal config manually (skip init which needs root)
	configDir := filepath.Join(tmpHome, ".aigate")
	_ = os.MkdirAll(configDir, 0o755)
	configContent := "group: ai-agents\nuser: ai-runner\ndeny_read: []\ndeny_exec: []\nallow_net: []\n"
	_ = os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configContent), 0o644)

	// Add deny rules
	cmd := exec.Command(bin, "deny", "read", ".env", "secrets/")
	cmd.Env = env
	cmd.Dir = tmpWork
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("deny read failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), ".env") {
		t.Error("deny read output should mention .env")
	}

	// Verify status shows rules
	cmd = exec.Command(bin, "status")
	cmd.Env = env
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("status failed: %v\n%s", err, string(out))
	}
	output := string(out)
	if !strings.Contains(output, ".env") {
		t.Error("status should show .env in deny rules")
	}
	if !strings.Contains(output, "secrets/") {
		t.Error("status should show secrets/ in deny rules")
	}

	// Remove a deny rule
	cmd = exec.Command(bin, "allow", "read", ".env")
	cmd.Env = env
	cmd.Dir = tmpWork
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("allow read failed: %v\n%s", err, string(out))
	}

	// Verify it's removed
	cmd = exec.Command(bin, "status")
	cmd.Env = env
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("status failed: %v\n%s", err, string(out))
	}
	output = string(out)
	if strings.Contains(output, "  - .env\n") {
		t.Error("status should not show .env after allow")
	}
	if !strings.Contains(output, "secrets/") {
		t.Error("status should still show secrets/")
	}
}

func TestCLI_DenyExec(t *testing.T) {
	bin := buildBinary(t)
	tmpHome := t.TempDir()
	env := append(os.Environ(), "HOME="+tmpHome)

	// Create minimal config
	configDir := filepath.Join(tmpHome, ".aigate")
	_ = os.MkdirAll(configDir, 0o755)
	configContent := "group: ai-agents\nuser: ai-runner\ndeny_read: []\ndeny_exec: []\nallow_net: []\n"
	_ = os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configContent), 0o644)

	cmd := exec.Command(bin, "deny", "exec", "curl", "wget")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("deny exec failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "curl") {
		t.Error("deny exec output should mention curl")
	}
}

func TestCLI_DenyExecSubcommand(t *testing.T) {
	bin := buildBinary(t)
	tmpHome := t.TempDir()
	env := append(os.Environ(), "HOME="+tmpHome)

	// Create minimal config
	configDir := filepath.Join(tmpHome, ".aigate")
	_ = os.MkdirAll(configDir, 0o755)
	configContent := "group: ai-agents\nuser: ai-runner\ndeny_read: []\ndeny_exec: []\nallow_net: []\n"
	_ = os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configContent), 0o644)

	// Add subcommand deny rule
	cmd := exec.Command(bin, "deny", "exec", "kubectl delete", "kubectl create")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("deny exec subcommand failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "kubectl delete") {
		t.Error("deny exec output should mention 'kubectl delete'")
	}

	// Verify status shows the subcommand rules
	cmd = exec.Command(bin, "status")
	cmd.Env = env
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("status failed: %v\n%s", err, string(out))
	}
	output := string(out)
	if !strings.Contains(output, "kubectl delete") {
		t.Error("status should show 'kubectl delete' in deny rules")
	}
	if !strings.Contains(output, "kubectl create") {
		t.Error("status should show 'kubectl create' in deny rules")
	}

	// Remove one subcommand rule
	cmd = exec.Command(bin, "allow", "exec", "kubectl delete")
	cmd.Env = env
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("allow exec subcommand failed: %v\n%s", err, string(out))
	}

	// Verify it's removed but the other remains
	cmd = exec.Command(bin, "status")
	cmd.Env = env
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("status failed: %v\n%s", err, string(out))
	}
	output = string(out)
	if strings.Contains(output, "kubectl delete") {
		t.Error("status should not show 'kubectl delete' after allow")
	}
	if !strings.Contains(output, "kubectl create") {
		t.Error("status should still show 'kubectl create'")
	}
}

func TestCLI_DenyReadNoArgs(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "deny", "read")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("deny read with no args should fail")
	}
	if !strings.Contains(string(out), "usage") {
		t.Errorf("deny read error should show usage, got: %s", string(out))
	}
}

func TestCLI_RunNoArgs(t *testing.T) {
	bin := buildBinary(t)
	tmpHome := t.TempDir()
	env := append(os.Environ(), "HOME="+tmpHome)

	// Create minimal config
	configDir := filepath.Join(tmpHome, ".aigate")
	_ = os.MkdirAll(configDir, 0o755)
	configContent := "group: ai-agents\nuser: ai-runner\ndeny_read: []\ndeny_exec: []\nallow_net: []\n"
	_ = os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configContent), 0o644)

	cmd := exec.Command(bin, "run")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("run with no args should fail")
	}
	if !strings.Contains(string(out), "usage") {
		t.Errorf("run error should show usage, got: %s", string(out))
	}
}

func TestCLI_ResetNoForce(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "reset")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("reset without --force should fail")
	}
	if !strings.Contains(string(out), "--force") {
		t.Errorf("reset error should mention --force, got: %s", string(out))
	}
}
