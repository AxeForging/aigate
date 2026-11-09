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
