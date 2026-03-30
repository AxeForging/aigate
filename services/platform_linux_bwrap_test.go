//go:build linux

package services

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/AxeForging/aigate/domain"
)

// ── arg-list helpers ────────────────────────────────────────────────────────

func containsFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func containsPair(args []string, a, b string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == a && args[i+1] == b {
			return true
		}
	}
	return false
}

func containsTriple(args []string, a, b, c string) bool {
	for i := 0; i+2 < len(args); i++ {
		if args[i] == a && args[i+1] == b && args[i+2] == c {
			return true
		}
	}
	return false
}

// dest is the third element of --bind src dest or --ro-bind src dest.
func hasBwrapBindDest(args []string, dest string) bool {
	for i := 0; i+2 < len(args); i++ {
		if (args[i] == "--bind" || args[i] == "--ro-bind") && args[i+2] == dest {
			return true
		}
	}
	return false
}

// ── policyFileContent ────────────────────────────────────────────────────────

func TestPolicyFileContent_Header(t *testing.T) {
	profile := domain.SandboxProfile{}
	content := policyFileContent(profile)
	if !strings.Contains(content, "[aigate] sandbox policy") {
		t.Error("policy content should contain header")
	}
}

func TestPolicyFileContent_DenyRead(t *testing.T) {
	profile := domain.SandboxProfile{
		Config: domain.Config{DenyRead: []string{".env", "secrets/"}},
	}
	content := policyFileContent(profile)
	if !strings.Contains(content, "deny_read: .env, secrets/") {
		t.Errorf("policy content should list deny_read, got:\n%s", content)
	}
}

func TestPolicyFileContent_DenyExec(t *testing.T) {
	profile := domain.SandboxProfile{
		Config: domain.Config{DenyExec: []string{"curl", "wget"}},
	}
	content := policyFileContent(profile)
	if !strings.Contains(content, "deny_exec: curl, wget") {
		t.Errorf("policy content should list deny_exec, got:\n%s", content)
	}
}

func TestPolicyFileContent_AllowNet(t *testing.T) {
	profile := domain.SandboxProfile{
		Config: domain.Config{AllowNet: []string{"api.example.com"}},
	}
	content := policyFileContent(profile)
	if !strings.Contains(content, "allow_net: api.example.com") {
		t.Errorf("policy content should list allow_net, got:\n%s", content)
	}
}

func TestPolicyFileContent_EmptyProfile(t *testing.T) {
	profile := domain.SandboxProfile{}
	content := policyFileContent(profile)
	// Should not mention any sections when all lists are empty
	if strings.Contains(content, "deny_read:") {
		t.Error("empty profile should not mention deny_read")
	}
	if strings.Contains(content, "deny_exec:") {
		t.Error("empty profile should not mention deny_exec")
	}
	if strings.Contains(content, "allow_net:") {
		t.Error("empty profile should not mention allow_net")
	}
}

// ── writeTmpFile ─────────────────────────────────────────────────────────────

func TestWriteTmpFile_CreatesFileWithContent(t *testing.T) {
	path, err := writeTmpFile("aigate-test-*", "hello world\n")
	if err != nil {
		t.Fatalf("writeTmpFile() error = %v", err)
	}
	defer os.Remove(path) //nolint:errcheck

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != "hello world\n" {
		t.Errorf("content = %q, want %q", string(data), "hello world\n")
	}
}

func TestWriteTmpFile_ReturnsUniqueFiles(t *testing.T) {
	p1, err := writeTmpFile("aigate-test-*", "a")
	if err != nil {
		t.Fatalf("first writeTmpFile() error = %v", err)
	}
	defer os.Remove(p1) //nolint:errcheck

	p2, err := writeTmpFile("aigate-test-*", "b")
	if err != nil {
		t.Fatalf("second writeTmpFile() error = %v", err)
	}
	defer os.Remove(p2) //nolint:errcheck

	if p1 == p2 {
		t.Error("writeTmpFile() should return unique paths")
	}
}

// ── buildBwrapArgs ───────────────────────────────────────────────────────────

func setupBwrapArgsTest(t *testing.T, profile domain.SandboxProfile) ([]string, []string) {
	t.Helper()
	p := &LinuxPlatform{exec: newMockExecutor()}
	var tmp []string
	args, err := p.buildBwrapArgs(profile, &tmp)
	if err != nil {
		t.Fatalf("buildBwrapArgs() error = %v", err)
	}
	return args, tmp
}

func cleanupTmp(tmp []string) {
	for _, f := range tmp {
		os.Remove(f) //nolint:errcheck
	}
}

func TestBuildBwrapArgs_ReadOnlyRoot(t *testing.T) {
	profile := domain.SandboxProfile{Config: domain.Config{}, WorkDir: "/tmp"}
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	if !containsTriple(args, "--ro-bind", "/", "/") {
		t.Errorf("args should contain --ro-bind / /, got: %v", args)
	}
	// Must NOT have --bind / / (read-write root)
	if containsTriple(args, "--bind", "/", "/") {
		t.Errorf("args should NOT contain --bind / / (must be --ro-bind), got: %v", args)
	}
}

func TestBuildBwrapArgs_HomeWritable(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	profile := domain.SandboxProfile{Config: domain.Config{}, WorkDir: tmpHome + "/project"}
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	if !containsTriple(args, "--bind", tmpHome, tmpHome) {
		t.Errorf("args should contain --bind %q %q for writable home, got: %v", tmpHome, tmpHome, args)
	}
}

func TestBuildBwrapArgs_SensitiveDotfilesReadOnly(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Create sensitive dotfiles
	for _, name := range []string{".ssh", ".gnupg"} {
		if err := os.MkdirAll(tmpHome+"/"+name, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{".bashrc", ".gitconfig"} {
		writeTestFile(t, tmpHome+"/"+name, "content")
	}

	profile := domain.SandboxProfile{Config: domain.Config{}, WorkDir: tmpHome + "/project"}
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	for _, name := range []string{".ssh", ".gnupg", ".bashrc", ".gitconfig"} {
		path := tmpHome + "/" + name
		if !containsTriple(args, "--ro-bind", path, path) {
			t.Errorf("args should contain --ro-bind %q %q for sensitive dotfile", path, path)
		}
	}
}

func TestBuildBwrapArgs_WorkdirOutsideHome(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	workDir := t.TempDir() // separate from home
	profile := domain.SandboxProfile{Config: domain.Config{}, WorkDir: workDir}
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	if !containsTriple(args, "--bind", workDir, workDir) {
		t.Errorf("args should contain --bind %q %q for workdir outside home, got: %v", workDir, workDir, args)
	}
}

func TestBuildBwrapArgs_TmpfsIsolated(t *testing.T) {
	profile := domain.SandboxProfile{Config: domain.Config{}, WorkDir: "/tmp"}
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	if !containsPair(args, "--tmpfs", "/tmp") {
		t.Errorf("args should contain --tmpfs /tmp, got: %v", args)
	}
}

func TestBuildBwrapArgs_DevAndProc(t *testing.T) {
	profile := domain.SandboxProfile{Config: domain.Config{}, WorkDir: "/tmp"}
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	if !containsPair(args, "--dev", "/dev") {
		t.Errorf("args should contain --dev /dev, got: %v", args)
	}
	if !containsPair(args, "--proc", "/proc") {
		t.Errorf("args should contain --proc /proc, got: %v", args)
	}
}

func TestBuildBwrapArgs_NamespaceFlags(t *testing.T) {
	profile := domain.SandboxProfile{Config: domain.Config{}, WorkDir: "/tmp"}
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	for _, flag := range []string{"--unshare-pid", "--unshare-user", "--die-with-parent"} {
		if !containsFlag(args, flag) {
			t.Errorf("args should contain %q, got: %v", flag, args)
		}
	}
}

func TestBuildBwrapArgs_ConfigDirHidden(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	profile := domain.SandboxProfile{Config: domain.Config{}, WorkDir: "/tmp"}
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	expectedConfigDir := tmpHome + "/.aigate"
	if !containsPair(args, "--tmpfs", expectedConfigDir) {
		t.Errorf("args should have --tmpfs %q, got: %v", expectedConfigDir, args)
	}
}

func TestBuildBwrapArgs_PolicyFileBound(t *testing.T) {
	profile := domain.SandboxProfile{Config: domain.Config{}, WorkDir: "/tmp"}
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	if !hasBwrapBindDest(args, "/tmp/.aigate-policy") {
		t.Errorf("args should bind a file to /tmp/.aigate-policy, got: %v", args)
	}

	// The policy temp file should actually exist and contain the header
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--bind" && args[i+2] == "/tmp/.aigate-policy" {
			data, err := os.ReadFile(args[i+1])
			if err != nil {
				t.Fatalf("policy file %q should be readable: %v", args[i+1], err)
			}
			if !strings.Contains(string(data), "[aigate] sandbox policy") {
				t.Errorf("policy file content = %q, missing header", string(data))
			}
			return
		}
	}
}

func TestBuildBwrapArgs_DenyReadFile(t *testing.T) {
	tmpDir := t.TempDir()
	writeTestFile(t, tmpDir+"/secret.txt", "secret")

	profile := domain.SandboxProfile{
		Config:  domain.Config{DenyRead: []string{"secret.txt"}},
		WorkDir: tmpDir,
	}
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	secretPath := tmpDir + "/secret.txt"
	if !hasBwrapBindDest(args, secretPath) {
		t.Errorf("args should bind deny marker over %q, got: %v", secretPath, args)
	}

	// The bound source should be a file with the deny message
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--bind" && args[i+2] == secretPath {
			data, err := os.ReadFile(args[i+1])
			if err != nil {
				t.Fatalf("deny marker %q should be readable: %v", args[i+1], err)
			}
			if !strings.Contains(string(data), "[aigate] access denied") {
				t.Errorf("deny marker content = %q, missing deny message", string(data))
			}
			return
		}
	}
}

func TestBuildBwrapArgs_DenyReadDir(t *testing.T) {
	tmpDir := t.TempDir()
	_ = os.MkdirAll(tmpDir+"/secrets", 0o755)

	profile := domain.SandboxProfile{
		Config:  domain.Config{DenyRead: []string{"secrets/"}},
		WorkDir: tmpDir,
	}
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	secretsPath := tmpDir + "/secrets"
	if !containsPair(args, "--tmpfs", secretsPath) {
		t.Errorf("args should have --tmpfs %q for denied dir, got: %v", secretsPath, args)
	}
}

func TestBuildBwrapArgs_DenyReadNonExistent(t *testing.T) {
	tmpDir := t.TempDir()

	profile := domain.SandboxProfile{
		Config:  domain.Config{DenyRead: []string{"nonexistent.txt"}},
		WorkDir: tmpDir,
	}
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	nonexPath := tmpDir + "/nonexistent.txt"
	// Non-existent path should not produce a bind or tmpfs entry
	if hasBwrapBindDest(args, nonexPath) {
		t.Errorf("should not bind non-existent path %q", nonexPath)
	}
	if containsPair(args, "--tmpfs", nonexPath) {
		t.Errorf("should not tmpfs non-existent path %q", nonexPath)
	}
}

func TestBuildBwrapArgs_SharedDenyMarkerForMultipleFiles(t *testing.T) {
	tmpDir := t.TempDir()
	writeTestFile(t, tmpDir+"/a.txt", "a")
	writeTestFile(t, tmpDir+"/b.txt", "b")

	profile := domain.SandboxProfile{
		Config:  domain.Config{DenyRead: []string{"a.txt", "b.txt"}},
		WorkDir: tmpDir,
	}
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	// Find source paths for both binds
	var sources []string
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--bind" && (args[i+2] == tmpDir+"/a.txt" || args[i+2] == tmpDir+"/b.txt") {
			sources = append(sources, args[i+1])
		}
	}
	if len(sources) != 2 {
		t.Fatalf("expected 2 bind args for 2 files, got %d", len(sources))
	}
	// Both files should share the same deny marker (single temp file)
	if sources[0] != sources[1] {
		t.Errorf("two denied files should share the same deny marker: got %q and %q", sources[0], sources[1])
	}
}

func TestBuildBwrapArgs_DenyReadHardlink(t *testing.T) {
	tmpDir := t.TempDir()
	writeTestFile(t, tmpDir+"/secret.txt", "secret-data")

	// Create a hardlink to the secret file
	if err := os.Link(tmpDir+"/secret.txt", tmpDir+"/hardlink.txt"); err != nil {
		t.Skip("hardlinks not supported on this filesystem")
	}

	profile := domain.SandboxProfile{
		Config:  domain.Config{DenyRead: []string{"secret.txt"}},
		WorkDir: tmpDir,
	}
	args, tmp := setupBwrapArgsTest(t, profile)
	defer cleanupTmp(tmp)

	// Both the original AND the hardlink should have deny bind mounts
	secretPath := tmpDir + "/secret.txt"
	hardlinkPath := tmpDir + "/hardlink.txt"
	if !hasBwrapBindDest(args, secretPath) {
		t.Errorf("args should bind deny marker over %q", secretPath)
	}
	if !hasBwrapBindDest(args, hardlinkPath) {
		t.Errorf("args should bind deny marker over hardlink %q (same inode)", hardlinkPath)
	}
}

func TestBuildBwrapExecDenyArgs_WorkdirBinary(t *testing.T) {
	tmpDir := t.TempDir()
	blockedBin := tmpDir + "/blocked-tool"
	writeTestFile(t, blockedBin, "#!/bin/sh\necho BLOCKED\n")
	if err := os.Chmod(blockedBin, 0o755); err != nil {
		t.Fatal(err)
	}

	profile := domain.SandboxProfile{
		Config:  domain.Config{DenyExec: []string{"blocked-tool"}},
		WorkDir: tmpDir,
	}
	args, tmp, err := buildBwrapExecDenyArgs(profile)
	defer cleanupTmp(tmp)
	if err != nil {
		t.Fatalf("buildBwrapExecDenyArgs() error = %v", err)
	}

	// The workdir binary should be covered by a deny bind mount
	if !hasBwrapBindDest(args, blockedBin) {
		t.Errorf("args should bind deny stub over workdir binary %q, got: %v", blockedBin, args)
	}
}

// ── buildBwrapExecDenyArgs ───────────────────────────────────────────────────

func TestBuildBwrapExecDenyArgs_Empty(t *testing.T) {
	profile := domain.SandboxProfile{Config: domain.Config{DenyExec: nil}}
	args, tmp, err := buildBwrapExecDenyArgs(profile)
	if err != nil {
		t.Fatalf("buildBwrapExecDenyArgs() error = %v", err)
	}
	if len(args) != 0 {
		t.Errorf("expected empty args, got: %v", args)
	}
	if len(tmp) != 0 {
		t.Errorf("expected no tmp files, got: %v", tmp)
	}
}

func TestBuildBwrapExecDenyArgs_FullBlock(t *testing.T) {
	// sh is on every Linux system; use it as a reliable test target.
	profile := domain.SandboxProfile{
		Config: domain.Config{DenyExec: []string{"sh"}},
	}
	args, tmp, err := buildBwrapExecDenyArgs(profile)
	defer cleanupTmp(tmp)
	if err != nil {
		t.Fatalf("buildBwrapExecDenyArgs() error = %v", err)
	}

	if len(args) == 0 {
		t.Fatal("expected bind args for 'sh'")
	}
	if args[0] != "--bind" {
		t.Errorf("first arg should be --bind, got %q", args[0])
	}

	// The stub file should exist and be executable
	if len(args) >= 2 {
		info, err := os.Stat(args[1])
		if err != nil {
			t.Errorf("stub file should exist: %v", err)
		} else if info.Mode()&0o111 == 0 {
			t.Error("stub file should be executable")
		}
	}

	// Stub should exit 126 and print the deny message
	data, err := os.ReadFile(args[1])
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(data), "exit 126") {
		t.Errorf("stub should exit 126, content: %s", data)
	}
	if !strings.Contains(string(data), "[aigate] blocked") {
		t.Errorf("stub should mention [aigate] blocked, content: %s", data)
	}

	if len(tmp) == 0 {
		t.Error("should have at least one tmp file")
	}
}

func TestBuildBwrapExecDenyArgs_FullBlock_UnknownCommand(t *testing.T) {
	// An unknown command should not produce any bind arg (binary not found).
	profile := domain.SandboxProfile{
		Config: domain.Config{DenyExec: []string{"this-binary-does-not-exist-ever"}},
	}
	args, tmp, err := buildBwrapExecDenyArgs(profile)
	defer cleanupTmp(tmp)
	if err != nil {
		t.Fatalf("buildBwrapExecDenyArgs() error = %v", err)
	}
	// The stub is created (len(fullBlocks) > 0), but no --bind because LookPath fails.
	// So args should be empty.
	if len(args) != 0 {
		t.Errorf("unknown command should produce no bind args, got: %v", args)
	}
}

func TestBuildBwrapExecDenyArgs_SubBlock(t *testing.T) {
	// "sh -c" is a stable test case: sh is always available.
	profile := domain.SandboxProfile{
		Config: domain.Config{DenyExec: []string{"sh -c"}},
	}
	args, tmp, err := buildBwrapExecDenyArgs(profile)
	defer cleanupTmp(tmp)
	if err != nil {
		t.Fatalf("buildBwrapExecDenyArgs() error = %v", err)
	}

	// Expect at least two bind pairs: origPath→origInSandbox and wrapPath→origPath
	if len(args) < 6 {
		t.Fatalf("expected at least 6 args (two --bind pairs), got %d: %v", len(args), args)
	}

	// origInSandbox should be referenced
	if !containsFlag(args, "/tmp/.aigate-orig-sh") {
		t.Errorf("args should reference /tmp/.aigate-orig-sh, got: %v", args)
	}

	// Find the wrapper file (source of --bind wrapPath resolvedPath).
	// Symlinks are resolved for the destination, so use resolveForBwrap.
	origPath, _ := exec.LookPath("sh")
	resolvedSh := resolveForBwrap(origPath)
	var wrapperPath string
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--bind" && args[i+1] != origPath && args[i+2] == resolvedSh {
			wrapperPath = args[i+1]
		}
	}
	if wrapperPath == "" {
		t.Fatalf("could not find wrapper bind (--bind <wrap> %s), args: %v", resolvedSh, args)
	}

	data, err := os.ReadFile(wrapperPath)
	if err != nil {
		t.Fatalf("wrapper file should be readable: %v", err)
	}
	wrapContent := string(data)

	if !strings.Contains(wrapContent, "/tmp/.aigate-orig-sh") {
		t.Errorf("wrapper should exec /tmp/.aigate-orig-sh, content:\n%s", wrapContent)
	}
	if !strings.Contains(wrapContent, "-c)") {
		t.Errorf("wrapper should contain case arm for '-c', content:\n%s", wrapContent)
	}
	if !strings.Contains(wrapContent, "exit 126") {
		t.Errorf("wrapper should exit 126 for denied subcommand, content:\n%s", wrapContent)
	}

	// Wrapper must be executable
	info, err := os.Stat(wrapperPath)
	if err != nil {
		t.Fatalf("os.Stat(wrapper) error = %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Error("wrapper file should be executable")
	}
}

func TestBuildBwrapExecDenyArgs_Mixed(t *testing.T) {
	// One full block (sh) + one subcommand block (sh -c).
	// We use "sh" for both because it's always present.
	profile := domain.SandboxProfile{
		Config: domain.Config{DenyExec: []string{"sh", "sh -c"}},
	}
	args, tmp, err := buildBwrapExecDenyArgs(profile)
	defer cleanupTmp(tmp)
	if err != nil {
		t.Fatalf("buildBwrapExecDenyArgs() error = %v", err)
	}
	if len(args) == 0 {
		t.Error("expected args for mixed deny_exec config")
	}
}

// ── runWithBwrap ─────────────────────────────────────────────────────────────

func TestRunWithBwrap_CallsBwrapExecutor(t *testing.T) {
	mock := newMockExecutor()
	p := &LinuxPlatform{exec: mock}
	profile := domain.SandboxProfile{Config: domain.Config{}, WorkDir: "/tmp"}

	_ = p.runWithBwrap(profile, "echo", []string{"hello"}, os.Stdout, os.Stderr)

	if mock.callCount() == 0 {
		t.Fatal("expected executor to be called")
	}
	last := mock.lastCall()
	if last.Name != "bwrap" {
		t.Errorf("expected bwrap call, got %q", last.Name)
	}
}

func TestRunWithBwrap_CmdArgsAfterSeparator(t *testing.T) {
	mock := newMockExecutor()
	p := &LinuxPlatform{exec: mock}
	profile := domain.SandboxProfile{Config: domain.Config{}, WorkDir: "/tmp"}

	_ = p.runWithBwrap(profile, "mycommand", []string{"--flag", "value with spaces"}, os.Stdout, os.Stderr)

	last := mock.lastCall()
	args := last.Args

	separatorIdx := -1
	for i, a := range args {
		if a == "--" {
			separatorIdx = i
			break
		}
	}
	if separatorIdx == -1 {
		t.Fatal("bwrap args should contain -- separator")
	}

	afterSep := args[separatorIdx+1:]
	if len(afterSep) < 3 {
		t.Fatalf("expected cmd + 2 args after --, got: %v", afterSep)
	}
	if afterSep[0] != "mycommand" {
		t.Errorf("first arg after -- should be cmd, got %q", afterSep[0])
	}
	if afterSep[1] != "--flag" {
		t.Errorf("second arg after -- should be --flag, got %q", afterSep[1])
	}
	// Arg with spaces must be passed verbatim (no shell splitting).
	if afterSep[2] != "value with spaces" {
		t.Errorf("third arg after -- should be %q, got %q", "value with spaces", afterSep[2])
	}
}

func TestRunWithBwrap_CleansTmpFilesAfterRun(t *testing.T) {
	mock := newMockExecutor()
	p := &LinuxPlatform{exec: mock}
	profile := domain.SandboxProfile{
		Config: domain.Config{
			DenyRead: []string{"nonexistent-for-test.txt"},
		},
		WorkDir: t.TempDir(),
	}

	_ = p.runWithBwrap(profile, "echo", nil, os.Stdout, os.Stderr)

	// After runWithBwrap returns, extract the policy file path from the recorded
	// bwrap call and verify it has been deleted.
	last := mock.lastCall()
	for i := 0; i+2 < len(last.Args); i++ {
		if last.Args[i] == "--bind" && last.Args[i+2] == "/tmp/.aigate-policy" {
			policyPath := last.Args[i+1]
			if _, err := os.Stat(policyPath); !os.IsNotExist(err) {
				t.Errorf("policy temp file %q should be cleaned up after run", policyPath)
			}
			return
		}
	}
	t.Error("could not find policy file path in bwrap args")
}

// ── RunSandboxed dispatch (bwrap-aware) ──────────────────────────────────────

func TestRunSandboxedDispatch_BwrapPreferredOverUnshare(t *testing.T) {
	if !hasBwrap() {
		t.Skip("bwrap not installed; test covers bwrap dispatch path only")
	}
	mock := newMockExecutor()
	p := &LinuxPlatform{exec: mock}
	profile := domain.SandboxProfile{Config: domain.Config{}, WorkDir: "/tmp"}

	_ = p.RunSandboxed(profile, "echo", []string{"hello"}, os.Stdout, os.Stderr)

	if mock.callCount() == 0 {
		t.Fatal("expected executor to be called")
	}
	last := mock.lastCall()
	if last.Name != "bwrap" {
		t.Errorf("RunSandboxed should prefer bwrap when available, got %q", last.Name)
	}
}

func TestRunSandboxedDispatch_FallsBackToUnshareWhenNoBwrap(t *testing.T) {
	if hasBwrap() {
		t.Skip("bwrap is installed; test covers unshare fallback path only")
	}
	mock := newMockExecutor()
	p := &LinuxPlatform{exec: mock}
	profile := domain.SandboxProfile{Config: domain.Config{}, WorkDir: "/tmp"}

	_ = p.RunSandboxed(profile, "echo", []string{"hello"}, os.Stdout, os.Stderr)

	if mock.callCount() == 0 {
		t.Fatal("expected executor to be called")
	}
	last := mock.lastCall()
	if last.Name != "unshare" {
		t.Errorf("RunSandboxed should fall back to unshare when bwrap absent, got %q", last.Name)
	}
}

// ── buildNetOnlyScript ───────────────────────────────────────────────────────

func TestBuildNetOnlyScript_HasNetworkSetup(t *testing.T) {
	script := buildNetOnlyScript(nil, nil, "echo", []string{"hello"})

	for _, want := range []string{
		"mount --make-rprivate /",
		"ip addr show tap0",
		"nameserver 10.0.2.3",
		"iptables -A OUTPUT -o lo -j ACCEPT",
		"iptables -A OUTPUT -j REJECT",
		"exec echo hello",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("buildNetOnlyScript should contain %q, got:\n%s", want, script)
		}
	}
}

func TestBuildNetOnlyScript_HasNoAigateMarkers(t *testing.T) {
	// bwrap handles policy/mount/exec isolation — the net-only script should not.
	script := buildNetOnlyScript(nil, nil, "echo", nil)

	for _, forbidden := range []string{
		"aigate-policy",
		"aigate-denied",
		"aigate-deny-exec",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("buildNetOnlyScript should NOT contain %q (bwrap handles this), got:\n%s", forbidden, script)
		}
	}
}

func TestBuildNetOnlyScript_AllowNetRules(t *testing.T) {
	script := buildNetOnlyScript(
		[]string{"api.anthropic.com", "1.2.3.4"},
		[]string{"8.8.8.8"},
		"echo", nil,
	)

	if !strings.Contains(script, `getent ahostsv4 "api.anthropic.com"`) {
		t.Error("should resolve api.anthropic.com via getent inside namespace")
	}
	if !strings.Contains(script, `getent ahostsv4 "1.2.3.4"`) {
		t.Error("should include raw IP via getent")
	}
	if !strings.Contains(script, "iptables -A OUTPUT -d 8.8.8.8 -j ACCEPT") {
		t.Error("should allow upstream DNS server 8.8.8.8")
	}
	if !strings.Contains(script, "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT") {
		t.Error("should allow UDP DNS")
	}
}

func TestBuildNetOnlyScript_ArgWithSpaces(t *testing.T) {
	// Verify that shellEscape fix propagates: args with spaces are quoted.
	script := buildNetOnlyScript(nil, nil, "python3", []string{"my script.py"})
	if !strings.Contains(script, "'my script.py'") {
		t.Errorf("arg with spaces should be single-quoted in net-only script, got:\n%s", script)
	}
}

// ── appendBwrapNetArgs / runWithBwrapNetFilter ───────────────────────────────
//
// runWithBwrapNetFilter uses exec.Command directly (not the mock Executor)
// because it needs Start/Wait + ExtraFiles for the info-fd pipe. Tests verify
// the arg construction helpers rather than the executor call.

func TestAppendBwrapNetArgs_HasUnshareNetAndInfoFd(t *testing.T) {
	args := appendBwrapNetArgs(nil, []string{"example.com"}, []string{"8.8.8.8"}, "echo", []string{"hi"})

	if !containsFlag(args, "--unshare-net") {
		t.Errorf("args should contain --unshare-net, got: %v", args)
	}
	if !containsPair(args, "--info-fd", "3") {
		t.Errorf("args should contain --info-fd 3, got: %v", args)
	}
}

func TestAppendBwrapNetArgs_InnerScriptPassedToSh(t *testing.T) {
	args := appendBwrapNetArgs(nil, []string{"example.com"}, nil, "echo", []string{"hello"})

	sepIdx := -1
	for i, a := range args {
		if a == "--" {
			sepIdx = i
		}
	}
	if sepIdx == -1 {
		t.Fatal("args should contain -- separator")
	}
	afterSep := args[sepIdx+1:]
	if len(afterSep) < 3 || afterSep[0] != "sh" || afterSep[1] != "-c" {
		t.Errorf("expected 'sh -c <script>' after --, got: %v", afterSep)
	}
	script := afterSep[2]
	// Inner script: net-only setup (no slirp4netns — launched from host side).
	if strings.Contains(script, "slirp4netns") {
		t.Errorf("inner script should NOT contain slirp4netns (launched from Go), got:\n%s", script)
	}
	if !strings.Contains(script, "tap0") {
		t.Errorf("inner script should wait for tap0, got:\n%s", script)
	}
	if !strings.Contains(script, "iptables") {
		t.Errorf("inner script should contain iptables rules, got:\n%s", script)
	}
}

func TestAppendBwrapNetArgs_IsolationFlagsFromBuildBwrapArgs(t *testing.T) {
	p := &LinuxPlatform{exec: newMockExecutor()}
	profile := domain.SandboxProfile{
		Config:  domain.Config{AllowNet: []string{"example.com"}},
		WorkDir: "/tmp",
	}
	var tmp []string
	base, err := p.buildBwrapArgs(profile, &tmp)
	if err != nil {
		t.Fatalf("buildBwrapArgs error: %v", err)
	}
	args := appendBwrapNetArgs(base, profile.Config.AllowNet, nil, "echo", nil)

	for _, flag := range []string{"--unshare-user", "--unshare-pid", "--die-with-parent", "--unshare-net"} {
		if !containsFlag(args, flag) {
			t.Errorf("args should contain %q, got: %v", flag, args)
		}
	}
	if !containsTriple(args, "--ro-bind", "/", "/") {
		t.Errorf("args should contain --ro-bind / /, got: %v", args)
	}
}

func TestAppendBwrapNetArgs_NoAigateMarkersInInnerScript(t *testing.T) {
	args := appendBwrapNetArgs(nil, nil, nil, "echo", nil)
	script := ""
	for i, a := range args {
		if a == "-c" && i+1 < len(args) {
			script = args[i+1]
		}
	}
	for _, forbidden := range []string{"aigate-denied", "aigate-deny-exec", "setfacl"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("inner script should not contain %q (bwrap handles this)", forbidden)
		}
	}
}

// TestRunSandboxedDispatch_BwrapNetFilter is a smoke test that actually executes
// bwrap + slirp4netns. It lives here (not integration/) because it specifically
// tests the dispatch logic inside RunSandboxed. Skipped with -short.
func TestRunSandboxedDispatch_BwrapNetFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-exec test in short mode")
	}
	if !hasBwrap() {
		t.Skip("bwrap not installed")
	}
	if !hasSlirp4netns() {
		t.Skip("slirp4netns not installed")
	}
	p := &LinuxPlatform{exec: &RealExecutor{}}
	profile := domain.SandboxProfile{
		Config:  domain.Config{AllowNet: []string{"127.0.0.1"}},
		WorkDir: "/tmp",
	}
	if err := p.RunSandboxed(profile, "true", nil, os.Stdout, os.Stderr); err != nil {
		t.Errorf("RunSandboxed with bwrap+slirp returned error: %v", err)
	}
}
