package services

import (
	"errors"
	"testing"
)

func TestBlock_String(t *testing.T) {
	tests := []struct {
		name string
		b    Block
		want string
	}{
		{
			"identity layer names the identity",
			Block{What: "read ~/.config/gh", Layer: LayerIdentity, Identity: "work",
				Reason: "it belongs to identity \"personal\"", Fix: "aigate run --identity personal"},
			`[aigate] blocked read ~/.config/gh — identity "work": it belongs to identity "personal". To allow: aigate run --identity personal`,
		},
		{
			"other layer appends identity",
			Block{What: "exec curl", Layer: LayerRule, Identity: "work", Reason: "deny_exec rule curl.", Fix: "aigate deny exec --remove curl"},
			`[aigate] blocked exec curl — rule: deny_exec rule curl (identity "work"). To allow: aigate deny exec --remove curl`,
		},
		{
			"no identity, no fix",
			Block{What: "write /etc/hosts", Layer: LayerSandbox, Reason: "system paths are read-only"},
			`[aigate] blocked write /etc/hosts — sandbox: system paths are read-only.`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.b.String(); got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

func TestBlock_IsError(t *testing.T) {
	var err error = Block{What: "x", Layer: LayerJudge, Reason: "unsafe"}
	var b Block
	if !errors.As(err, &b) || b.Layer != LayerJudge {
		t.Errorf("Block should work with errors.As, got %v", err)
	}
}
