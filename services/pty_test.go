//go:build linux || darwin

package services

import (
	"bufio"
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/creack/pty"
)

// TestRunWithPTY_DoesNotStealStdinAfterExit: once the child exits, input
// typed afterwards must reach the caller (e.g. the next wizard question), not
// a leftover copy goroutine.
func TestRunWithPTY_DoesNotStealStdinAfterExit(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("no pty available: %v", err)
	}
	defer master.Close() //nolint:errcheck
	defer slave.Close()  //nolint:errcheck

	orig := os.Stdin
	os.Stdin = slave
	defer func() { os.Stdin = orig }()

	var out bytes.Buffer
	if err := runWithPTY(&out, "true"); err != nil {
		t.Fatalf("runWithPTY: %v", err)
	}

	if _, err := master.Write([]byte("next-answer\n")); err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		got <- line
	}()
	select {
	case line := <-got:
		if line != "next-answer\n" {
			t.Errorf("caller read %q, want %q", line, "next-answer\n")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("input typed after the child exited never reached the caller (stolen by the stdin copy)")
	}
}
