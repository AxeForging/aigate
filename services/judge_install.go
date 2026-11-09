package services

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// judgeHookEvents are the Claude Code events aigate judge handles.
var judgeHookEvents = []string{"PreToolUse", "PostToolUse"}

// InstallResult says what Install/Uninstall did, for the user.
type InstallResult struct {
	Settings string
	Changed  bool
	Note     string
}

// JudgeHookInstaller edits a Claude Code settings.json. The original bytes
// are kept under ~/.aigate so uninstall can restore them exactly.
type JudgeHookInstaller struct {
	Command   string // hook command, e.g. "/usr/local/bin/aigate judge"
	BackupDir string // e.g. ~/.aigate/judge-install
}

func (i JudgeHookInstaller) backupPath(settings string) string {
	sum := sha256.Sum256([]byte(settings))
	return filepath.Join(i.BackupDir, hex.EncodeToString(sum[:8])+".json")
}

// Install adds aigate's hooks; running it twice changes nothing.
func (i JudgeHookInstaller) Install(settings string) (InstallResult, error) {
	res := InstallResult{Settings: settings}
	orig, err := os.ReadFile(settings)
	existed := err == nil
	if err != nil && !os.IsNotExist(err) {
		return res, err
	}
	doc := map[string]any{}
	if existed && len(bytes.TrimSpace(orig)) > 0 {
		if err := json.Unmarshal(orig, &doc); err != nil {
			return res, fmt.Errorf("%s is not valid JSON (%v); fix it first, nothing was changed", settings, err)
		}
	}
	if i.installed(doc) {
		res.Note = "already installed"
		return res, nil
	}
	hooks, _ := doc["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	for _, ev := range judgeHookEvents {
		groups, _ := hooks[ev].([]any)
		if i.hasOurs(groups) {
			continue // only add what is missing
		}
		hooks[ev] = append(groups, map[string]any{
			"matcher": "*",
			"hooks":   []any{map[string]any{"type": "command", "command": i.Command, "timeout": 30}},
		})
	}
	doc["hooks"] = hooks
	out, _ := json.MarshalIndent(doc, "", "  ")
	out = append(out, '\n')

	backup := map[string]any{"existed": existed, "original": string(orig), "installed": string(out)}
	b, _ := json.Marshal(backup)
	if err := os.MkdirAll(i.BackupDir, 0o700); err != nil {
		return res, err
	}
	if err := os.WriteFile(i.backupPath(settings), b, 0o600); err != nil {
		return res, err
	}
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		return res, err
	}
	if err := os.WriteFile(settings, out, 0o600); err != nil {
		return res, err
	}
	res.Changed = true
	return res, nil
}

// Uninstall restores the original file exactly when it is unchanged since
// install; otherwise it removes only aigate's entries.
func (i JudgeHookInstaller) Uninstall(settings string) (InstallResult, error) {
	res := InstallResult{Settings: settings}
	cur, err := os.ReadFile(settings)
	if os.IsNotExist(err) {
		res.Note = "nothing to remove"
		return res, nil
	}
	if err != nil {
		return res, err
	}
	var backup struct {
		Existed   bool   `json:"existed"`
		Original  string `json:"original"`
		Installed string `json:"installed"`
	}
	bpath := i.backupPath(settings)
	if b, err := os.ReadFile(bpath); err == nil && json.Unmarshal(b, &backup) == nil && backup.Installed == string(cur) {
		if backup.Existed {
			err = os.WriteFile(settings, []byte(backup.Original), 0o600)
		} else {
			err = os.Remove(settings)
		}
		if err != nil {
			return res, err
		}
		_ = os.Remove(bpath)
		res.Changed, res.Note = true, "restored exactly as before install"
		return res, nil
	}
	doc := map[string]any{}
	if err := json.Unmarshal(cur, &doc); err != nil {
		return res, fmt.Errorf("%s is not valid JSON (%v); nothing was changed", settings, err)
	}
	if !i.installed(doc) {
		res.Note = "nothing to remove"
		return res, nil
	}
	hooks, _ := doc["hooks"].(map[string]any)
	for _, ev := range judgeHookEvents {
		groups, _ := hooks[ev].([]any)
		var kept []any
		for _, g := range groups {
			if !i.isOurs(g) {
				kept = append(kept, g)
			}
		}
		if len(kept) == 0 {
			delete(hooks, ev)
		} else {
			hooks[ev] = kept
		}
	}
	if len(hooks) == 0 {
		delete(doc, "hooks")
	}
	out, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(settings, append(out, '\n'), 0o600); err != nil {
		return res, err
	}
	_ = os.Remove(bpath)
	res.Changed, res.Note = true, "removed aigate's hooks; the file was edited since install, so its formatting may differ"
	return res, nil
}

func (i JudgeHookInstaller) installed(doc map[string]any) bool {
	hooks, _ := doc["hooks"].(map[string]any)
	for _, ev := range judgeHookEvents {
		groups, _ := hooks[ev].([]any)
		if !i.hasOurs(groups) {
			return false
		}
	}
	return true
}

func (i JudgeHookInstaller) hasOurs(groups []any) bool {
	for _, g := range groups {
		if i.isOurs(g) {
			return true
		}
	}
	return false
}

// isOurs reports whether a matcher group holds exactly aigate's hook.
func (i JudgeHookInstaller) isOurs(group any) bool {
	g, _ := group.(map[string]any)
	hs, _ := g["hooks"].([]any)
	if len(hs) != 1 {
		return false
	}
	h, _ := hs[0].(map[string]any)
	return h["command"] == i.Command
}
