package services

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// sbinDirs hold admin tools that some distros (Debian) keep off a normal
// user's PATH.
var sbinDirs = []string{"/usr/sbin", "/sbin", "/usr/local/sbin"}

// FindTool looks for the first of names on PATH, then in sbinDirs.
func FindTool(names ...string) (string, error) {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p, nil
		}
		for _, d := range sbinDirs {
			if p := filepath.Join(d, n); isExecutable(p) {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("%s not found", strings.Join(names, " or "))
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
}
