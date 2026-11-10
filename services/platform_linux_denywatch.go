//go:build linux

package services

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/helpers"
	"golang.org/x/sys/unix"
)

// deny_read is applied by bind mounts when the sandbox starts, so a matching
// file that appears later (env pulled in another terminal, an editor saving
// .env by renaming a temp file over it) would be readable. The guard watches
// the folders deny_read points at from the host and covers new matches inside
// the running sandbox, the same way the network is set up: nsenter into the
// mount namespace's owner user namespace (#51). Hiding happens within
// milliseconds of the file appearing.

// sandboxDenyMarker is where the deny marker is bound inside the sandbox.
const sandboxDenyMarker = "/tmp/.aigate-denied"

// coverScript hides each argument path inside the sandbox: folders get an
// empty tmpfs, files the deny marker. Paths not visible there are skipped.
const coverScript = `for p; do
  [ -e "$p" ] || [ -L "$p" ] || continue
  if [ -d "$p" ]; then mount -t tmpfs tmpfs "$p"; else mount --bind ` + sandboxDenyMarker + ` "$p"; fi || echo "$p" >&2
done`

// lateDenyWatch lists the absolute deny_read patterns and the folders to
// watch for them. Patterns whose folder part has glob characters are not
// watched.
func lateDenyWatch(patterns []string, workDir string) (abs []string, dirs []string) {
	seen := map[string]bool{}
	for _, p := range patterns {
		a, err := absPatternOf(p, workDir)
		if err != nil {
			continue
		}
		abs = append(abs, a)
		d := filepath.Dir(a)
		if strings.ContainsAny(d, "*?[") || seen[d] {
			continue
		}
		seen[d] = true
		dirs = append(dirs, d)
	}
	return abs, dirs
}

func matchesAnyPattern(path string, abs []string) bool {
	for _, p := range abs {
		if ok, _ := filepath.Match(p, path); ok {
			return true
		}
	}
	return false
}

// denyMatchesNow lists the deny_read matches that exist now. Taken before the
// sandbox's mounts are planned: those are handled by the startup mounts (and
// their exceptions, like an identity's ssh key inside ~/.ssh).
func denyMatchesNow(profile domain.SandboxProfile) map[string]bool {
	now := map[string]bool{}
	paths, _ := resolvePatterns(profile.Config.DenyRead, profile.WorkDir)
	for _, p := range paths {
		if _, err := os.Lstat(p); err == nil {
			now[p] = true
		}
	}
	return now
}

// startLateDenyGuard covers deny_read matches that appeared since known was
// taken, and any that appear until stop is called. Problems are reported,
// never fatal: the startup mounts still apply.
func startLateDenyGuard(pid int, profile domain.SandboxProfile, known map[string]bool) (stop func()) {
	noop := func() {}
	if len(profile.Config.DenyRead) == 0 {
		return noop
	}
	warn := func(err error) {
		fmt.Fprintf(os.Stderr, "[aigate] warning: files matching deny_read that appear during this session won't be hidden: %v\n", err)
	}
	mnt, err := os.Open(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	if err != nil {
		warn(err)
		return noop
	}
	ownerFD, err := unix.IoctlRetInt(int(mnt.Fd()), unix.NS_GET_USERNS)
	_ = mnt.Close()
	if err != nil {
		warn(fmt.Errorf("find the sandbox's owner namespace: %w", err))
		return noop
	}
	owner := os.NewFile(uintptr(ownerFD), "userns")
	cover := func(paths []string) {
		if len(paths) == 0 {
			return
		}
		args := append([]string{"--user=/proc/self/fd/3", fmt.Sprintf("--mount=/proc/%d/ns/mnt", pid),
			fmt.Sprintf("--root=/proc/%d/root", pid), "--wd=/", "--preserve-credentials",
			"--", "/bin/sh", "-c", coverScript, "sh"}, paths...)
		cmd := exec.Command("nsenter", args...)
		cmd.ExtraFiles = []*os.File{owner}
		out, err := cmd.CombinedOutput()
		if err != nil || len(bytes.TrimSpace(out)) > 0 {
			fmt.Fprintf(os.Stderr, "[aigate] warning: couldn't hide a new file matching deny_read: %v %s\n", err, strings.TrimSpace(string(out)))
			return
		}
		helpers.Log.Debug().Strs("paths", paths).Msg("deny_read: hid files that appeared during the session")
	}

	abs, dirs := lateDenyWatch(profile.Config.DenyRead, profile.WorkDir)
	ifd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		_ = owner.Close()
		warn(err)
		return noop
	}
	watched := map[int]string{}
	for _, d := range dirs {
		if wd, err := unix.InotifyAddWatch(ifd, d, unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_ONLYDIR); err == nil {
			watched[wd] = d
		}
	}
	rescan := func() {
		var late []string
		for p := range denyMatchesNow(profile) {
			if !known[p] {
				late = append(late, p)
			}
		}
		cover(late)
	}
	rescan()

	f := os.NewFile(uintptr(ifd), "inotify") // pollable: Close unblocks Read
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64*1024)
		for {
			n, err := f.Read(buf)
			if err != nil {
				return
			}
			var hits []string
			overflow := false
			for off := 0; off+unix.SizeofInotifyEvent <= n; {
				ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
				name := strings.TrimRight(string(buf[off+unix.SizeofInotifyEvent:off+unix.SizeofInotifyEvent+int(ev.Len)]), "\x00")
				off += unix.SizeofInotifyEvent + int(ev.Len)
				if ev.Mask&unix.IN_Q_OVERFLOW != 0 {
					overflow = true
					continue
				}
				if dir, ok := watched[int(ev.Wd)]; ok && name != "" {
					if p := filepath.Join(dir, name); matchesAnyPattern(p, abs) {
						hits = append(hits, p)
					}
				}
			}
			if overflow {
				rescan()
			}
			cover(hits)
		}
	}()
	return func() {
		_ = f.Close()
		<-done
		_ = owner.Close()
	}
}
