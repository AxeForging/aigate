package integration_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInstallScript_InstallsVerifiedRelease(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unsupported")
	}
	tmp := t.TempDir()
	base := "aigate-" + runtime.GOOS + "-" + runtime.GOARCH
	payload := filepath.Join(tmp, "payload")
	mustWrite(t, filepath.Join(payload, base), "#!/bin/sh\nexit 0\n", 0o755)
	asset := base + ".tar.gz"
	archive := filepath.Join(tmp, asset)
	if out, err := exec.Command("tar", "-czf", archive, "-C", payload, base).CombinedOutput(); err != nil {
		t.Fatalf("archive: %v %s", err, out)
	}
	b, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	sums := filepath.Join(tmp, "checksums.txt")
	mustWrite(t, sums, fmt.Sprintf("%x  %s\n", sha256.Sum256(b), asset), 0o644)
	bin := filepath.Join(tmp, "bin")
	mustWrite(t, filepath.Join(bin, "curl"), `#!/bin/sh
while [ "$#" -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; -*) shift;; *) url="$1"; shift;; esac; done
case "$url" in */checksums.txt) cp "$SUMS" "$out";; *) cp "$ARCHIVE" "$out";; esac
`, 0o755)
	dest := filepath.Join(tmp, "install")
	cmd := exec.Command("sh", filepath.Join("..", "install.sh"))
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "AIGATE_VERSION=v0.7.0", "AIGATE_INSTALL_DIR="+dest, "ARCHIVE="+archive, "SUMS="+sums)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install: %v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dest, "aigate")); err != nil {
		t.Fatal(err)
	}
}
func mustWrite(t *testing.T, p, s string, m os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), m); err != nil {
		t.Fatal(err)
	}
}
