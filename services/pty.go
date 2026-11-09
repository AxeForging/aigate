//go:build linux || darwin

package services

import (
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
)

// runWithPTY starts name with args under a pseudo-terminal so that child
// processes see a TTY on their stdout/stderr. Output from the PTY master is
// written through out, enabling masking while preserving interactive behavior.
//
// Falls back to a plain pipe if PTY creation fails or if stdin is not a
// terminal (e.g. CI pipelines), so masking still works in non-interactive mode.
func runWithPTY(out io.Writer, name string, args ...string) error {
	// If stdin is not a terminal there is no interactive session to preserve;
	// skip the PTY and use a regular pipe (masks secrets in piped output too).
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		cmd := exec.Command(name, args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = out
		cmd.Stderr = out
		return cmd.Run()
	}

	cmd := exec.Command(name, args...)
	// pty.Start forks the child and returns the PTY master fd (ptm) to the
	// parent. The master fd is opened via os.OpenFile("/dev/ptmx", ...) which
	// Go's stdlib always opens with O_CLOEXEC (see os/file_unix.go). This
	// guarantees the master fd is closed in the child across every exec()
	// boundary, so sandboxed processes can never access or impersonate the
	// parent's terminal.
	ptm, err := pty.Start(cmd)
	if err != nil {
		// PTY unavailable — fall back so masking still applies.
		cmd = exec.Command(name, args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = out
		cmd.Stderr = out
		return cmd.Run()
	}
	defer func() { _ = ptm.Close() }()

	// Inherit terminal size from the parent terminal.
	if ws, err := pty.GetsizeFull(os.Stdin); err == nil {
		_ = pty.Setsize(ptm, ws)
	}

	// Propagate terminal resize events to the PTY.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	go func() {
		for range sigCh {
			if ws, err := pty.GetsizeFull(os.Stdin); err == nil {
				_ = pty.Setsize(ptm, ws)
			}
		}
	}()
	defer func() {
		signal.Stop(sigCh)
		close(sigCh)
	}()

	// Raw mode: disable local echo and line buffering so every keystroke goes
	// directly to the PTY master without being processed by the terminal driver.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err == nil {
		defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()
	}

	// Forward parent stdin → PTY master → child stdin, stopped once the child
	// is done.
	stopStdin := copyStdin(ptm)
	defer stopStdin()

	// Copy PTY master output (child stdout+stderr) through the masker.
	_, _ = io.Copy(out, ptm)

	return cmd.Wait()
}

// copyStdin copies the terminal into dst until stop is called. It reads from
// a non-blocking duplicate of stdin so stop can interrupt a pending read; a
// read left running after the child exits would swallow the user's next input
// (e.g. the next question in `aigate identity add`).
func copyStdin(dst io.Writer) (stop func()) {
	fd := int(os.Stdin.Fd())
	unstoppable := func() func() {
		go func() { _, _ = io.Copy(dst, os.Stdin) }()
		return func() {}
	}
	dupFd, err := syscall.Dup(fd)
	if err != nil {
		return unstoppable()
	}
	if err := syscall.SetNonblock(dupFd, true); err != nil {
		_ = syscall.Close(dupFd)
		return unstoppable()
	}
	f := os.NewFile(uintptr(dupFd), "stdin")
	restore := func() {
		_ = f.Close()
		_ = syscall.SetNonblock(fd, false) // the flag is shared with stdin
	}
	if err := f.SetReadDeadline(time.Time{}); err != nil {
		// Not pollable: can't interrupt it, so don't leave stdin non-blocking.
		restore()
		return unstoppable()
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(dst, f)
		close(done)
	}()
	return func() {
		_ = f.SetReadDeadline(time.Now())
		<-done
		restore()
	}
}
