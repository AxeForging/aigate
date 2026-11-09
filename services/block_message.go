package services

import (
	"fmt"
	"strings"
)

// Layers that can block something. Every block message names one, so users
// know which part of aigate to look at.
const (
	LayerSandbox  = "sandbox"
	LayerRule     = "rule"
	LayerIdentity = "identity"
	LayerJudge    = "judge"
)

// Block describes something aigate refused, in the one format every layer
// uses: what, which layer and why, and the command that allows it.
type Block struct {
	What     string // e.g. "read ~/.config/gh"
	Layer    string // one of the Layer* constants
	Reason   string
	Fix      string // command that allows it; empty when nothing should
	Identity string // active identity, if any
}

// String renders: [aigate] blocked <what> — <layer>: <reason>. To allow: <fix>
// With an identity: [aigate] blocked <what> — identity "work": <reason>. …
// or, for other layers, the identity is appended: … (identity "work")
func (b Block) String() string {
	layer := b.Layer
	if b.Layer == LayerIdentity && b.Identity != "" {
		layer = fmt.Sprintf("identity %q", b.Identity)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "[aigate] blocked %s — %s: %s", b.What, layer, strings.TrimSuffix(b.Reason, "."))
	if b.Identity != "" && b.Layer != LayerIdentity {
		fmt.Fprintf(&sb, " (identity %q)", b.Identity)
	}
	sb.WriteString(".")
	if b.Fix != "" {
		fmt.Fprintf(&sb, " To allow: %s", b.Fix)
	}
	return sb.String()
}

// Error lets a Block be returned where an error is expected.
func (b Block) Error() string { return b.String() }

// Fixed texts for blocks that happen inside the sandbox, where only a person
// outside can change the rules.
const outsideHint = "a person runs, outside the sandbox: "

// DenyReadMarker is what a denied file reads as inside the sandbox.
func DenyReadMarker() string {
	return Block{What: "read of this file", Layer: LayerRule, Reason: "it matches a deny_read rule",
		Fix: outsideHint + "aigate allow read PATTERN (rules: cat /tmp/.aigate-policy)"}.String() + "\n"
}

// DenyReadDirMarker is the note left in a denied directory.
func DenyReadDirMarker() string {
	return Block{What: "read of this folder", Layer: LayerRule, Reason: "it matches a deny_read rule",
		Fix: outsideHint + "aigate allow read PATTERN (rules: cat /tmp/.aigate-policy)"}.String() + "\n"
}

// DenyExecShellMessage is text for a double-quoted sh echo: what names the
// command (may be shell, e.g. $(basename "$0")), allowArg is the argument
// for `aigate allow exec`.
func DenyExecShellMessage(what, allowArg string) string {
	return Block{What: "exec " + what, Layer: LayerRule, Reason: "it is in deny_exec",
		Fix: outsideHint + "aigate allow exec " + allowArg}.String()
}

// DenyExecBlock is the pre-run refusal for a denied command or subcommand.
func DenyExecBlock(entry string) Block {
	return Block{What: "exec " + entry, Layer: LayerRule, Reason: fmt.Sprintf("%q is in deny_exec", entry),
		Fix: "aigate allow exec " + shellArg(entry)}
}

// NoSlirpBlock: allow_net is set but can't be enforced, so the run stops
// instead of silently going out unfiltered.
func NoSlirpBlock() Block {
	return Block{What: "this run", Layer: LayerSandbox,
		Reason: "allow_net is set but slirp4netns is missing, so the network can't be filtered",
		Fix:    "install slirp4netns (sudo apt install slirp4netns, or sudo dnf install slirp4netns), or remove the hosts with: aigate deny net HOST"}
}
