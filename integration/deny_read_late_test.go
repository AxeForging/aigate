package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDenyRead_LateFiles: files matching deny_read that appear while a
// session runs (a `vercel env pull` in another terminal, an editor saving
// .env by renaming a temp file over it) are hidden like those present at
// start. Unrelated new files stay readable. Regression test for #51.
func TestDenyRead_LateFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox integration test in short mode")
	}
	skipWithoutBwrap(t)
	if _, err := exec.LookPath("slirp4netns"); err != nil {
		t.Skip("slirp4netns not found: late deny_read needs the host-side setup path")
	}
	bin := buildBinary(t)
	tmpHome, env := sandboxEnv(t)
	cfg := "group: ai-agents\nuser: ai-runner\ndeny_read: [\".env\", \"secrets/\", \"*.pem\"]\ndeny_exec: []\nallow_net: []\n"
	if err := os.WriteFile(filepath.Join(tmpHome, ".aigate", "config.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(work, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("existing.pem", "OLD_PEM\n")

	script := `touch started
while [ ! -e go ]; do sleep 0.05; done
echo "ENV=[$(cat .env 2>&1)]"
echo "SECRET=[$(cat secrets/k 2>&1)]"
echo "PEM=[$(cat existing.pem 2>&1)]"
echo "NOTES=[$(cat notes.txt 2>&1)]"
echo DONE`
	cmd := exec.Command(bin, "run", "--", "/bin/sh", "-c", script)
	cmd.Env, cmd.Dir = env, work
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(work, "started")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("sandbox never started:\n%s", out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Appear after start: a new .env, a new secrets/ dir, an editor-style
	// replace of an existing hidden file, and an unrelated file.
	write(".env", "LATE_ENV=fake\n")
	write("secrets/k", "LATE_SECRET=fake\n")
	write("existing.pem.tmp", "NEW_PEM\n")
	if err := os.Rename(filepath.Join(work, "existing.pem.tmp"), filepath.Join(work, "existing.pem")); err != nil {
		t.Fatal(err)
	}
	write("notes.txt", "NOTES_OK\n")
	time.Sleep(time.Second) // the host-side watcher hides new files within milliseconds
	write("go", "")

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("sandbox failed: %v\n%s", err, out.String())
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("sandbox timed out:\n%s", out.String())
	}
	got := out.String()
	for _, leak := range []string{"LATE_ENV", "LATE_SECRET", "NEW_PEM"} {
		if strings.Contains(got, leak) {
			t.Errorf("late file content %s readable inside the sandbox:\n%s", leak, got)
		}
	}
	for _, want := range []string{"ENV=[[aigate] blocked read", "PEM=[[aigate] blocked read", "NOTES=[NOTES_OK]", "DONE"} {
		if !strings.Contains(got, want) {
			t.Errorf("want %q in:\n%s", want, got)
		}
	}
}
