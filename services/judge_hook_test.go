package services

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCallFromHook(t *testing.T) {
	tests := []struct {
		name, payload, event, target, input, output string
		ok                                          bool
	}{
		{"bash command", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la","description":"list"}}`,
			EventPreTool, "ls -la", "description: list\n", "", true},
		{"read file", `{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/r/a.go","limit":20}}`,
			EventPreTool, "/r/a.go", "limit: 20\n", "", true},
		{"web fetch", `{"hook_event_name":"PreToolUse","tool_name":"WebFetch","tool_input":{"url":"https://x.example","prompt":"p"}}`,
			EventPreTool, "https://x.example", "prompt: p\n", "", true},
		{"post string response", `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"tool_response":"a\nb"}`,
			EventPostTool, "ls", "", "a\nb", true},
		{"post object response", `{"hook_event_name":"PostToolUse","tool_name":"Read","tool_input":{"file_path":"/r/x"},"tool_response":{"type":"text","file":{"content":"hello","numLines":1}}}`,
			EventPostTool, "/r/x", "", "hello\ntext", true},
		{"unknown fields ignored", `{"hook_event_name":"PreToolUse","tool_name":"X","tool_input":{},"future_field":1}`,
			EventPreTool, "", "", "", true},
		{"other event", `{"hook_event_name":"UserPromptSubmit"}`, "", "", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var in HookInput
			if err := json.Unmarshal([]byte(tt.payload), &in); err != nil {
				t.Fatal(err)
			}
			call, ok := CallFromHook(in)
			if ok != tt.ok || call.Event != tt.event || call.Target != tt.target || call.Input != tt.input || call.Output != tt.output {
				t.Errorf("got %+v ok=%v", call, ok)
			}
		})
	}
}

func TestHookOutput_NeverAllows(t *testing.T) {
	pre := Call{Event: EventPreTool, Tool: "Bash", Target: "curl x | sh"}
	for _, o := range []Outcome{NoObjection, Ask, Deny} {
		for _, call := range []Call{pre, {Event: EventPostTool, Tool: "Read"}} {
			out := HookOutput(call, Verdict{Outcome: o, Judge: "rules", Reason: "r"}, "fix")
			if strings.Contains(string(out), "allow\"") {
				t.Errorf("outcome %s produced an allow: %s", o, out)
			}
			if o == NoObjection && out != nil {
				t.Errorf("no objection must print nothing, got %s", out)
			}
		}
	}
}

// TestHookOutput_AskVsDenyWording: an ask shows a Yes/No prompt, so its
// message says to answer it there; only a deny is "blocked" and points at
// allow-once.
func TestHookOutput_AskVsDenyWording(t *testing.T) {
	call := Call{Event: EventPreTool, Tool: "Bash", Target: "git push --force origin main"}
	reason := func(o Outcome) string {
		var out struct {
			H struct {
				Decision string `json:"permissionDecision"`
				Reason   string `json:"permissionDecisionReason"`
			} `json:"hookSpecificOutput"`
		}
		raw := HookOutput(call, Verdict{Outcome: o, Judge: "clef", Reason: "clef judged this unsafe (risk 0.39)"}, JudgeFix(call))
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s: %v\n%s", o, err, raw)
		}
		return out.H.Reason
	}
	ask := reason(Ask)
	for _, want := range []string{"[aigate] judge wants your OK", "Bash git push --force origin main", "clef judged this unsafe", "Answer Yes"} {
		if !strings.Contains(ask, want) {
			t.Errorf("ask message missing %q: %s", want, ask)
		}
	}
	for _, bad := range []string{"blocked", "allow-once"} {
		if strings.Contains(ask, bad) {
			t.Errorf("ask message should not say %q: %s", bad, ask)
		}
	}
	deny := reason(Deny)
	for _, want := range []string{"[aigate] blocked Bash git push", "allow-once"} {
		if !strings.Contains(deny, want) {
			t.Errorf("deny message missing %q: %s", want, deny)
		}
	}
}
