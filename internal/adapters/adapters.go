// Package adapters maps each harness's hook protocol onto the guard and the redactor.
package adapters

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/koalabs-ai/ai-hooks/internal/guard"
	"github.com/koalabs-ai/ai-hooks/internal/redact"
)

// Harness describes one supported integration.
type Harness struct {
	Name   string
	Pre    bool   // can block a command before it runs
	Post   bool   // can rewrite output after it ran
	Status string // "verified" (run for real here) or "docs" (implemented from the vendor's docs, not run)
}

// Harnesses lists the names accepted by `ai-hooks hook <harness>` and `ai-hooks install <harness>`.
var Harnesses = []Harness{
	{"claude", true, true, "verified"},
	{"kimi", true, false, "verified"},
	{"opencode", true, true, "verified"},
	{"codex", true, true, "docs"},
	{"cursor", true, false, "docs"},
	{"gemini", true, false, "docs"},
	{"copilot", true, true, "docs"},
	{"windsurf", true, false, "docs"},
	{"devin", true, false, "docs"},
}

func known(name string) (Harness, bool) {
	for _, h := range Harnesses {
		if h.Name == name {
			return h, true
		}
	}
	return Harness{}, false
}

// event is the harness-neutral view of one hook payload.
type event struct {
	post     bool
	cmd      string
	response json.RawMessage // PostToolUse: the tool's output, in the harness's own shape
}

func strField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func parse(raw []byte) (event, bool) {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return event{}, false
	}
	var ev event
	name := strings.ToLower(strField(m, "hook_event_name", "event", "agent_action_name", "hookEventName"))
	ev.post = strings.Contains(name, "post") || strings.Contains(name, "after")
	// the command, wherever this harness keeps it
	if ti, ok := m["tool_input"].(map[string]any); ok {
		ev.cmd = strField(ti, "command", "cmd")
	}
	if ev.cmd == "" {
		ev.cmd = strField(m, "command")
	}
	if ev.cmd == "" {
		if ti, ok := m["tool_info"].(map[string]any); ok {
			ev.cmd = strField(ti, "command_line", "command")
		}
	}
	if ev.cmd == "" {
		switch ta := m["toolArgs"].(type) {
		case string:
			var a map[string]any
			if json.Unmarshal([]byte(ta), &a) == nil {
				ev.cmd = strField(a, "command")
			}
		case map[string]any:
			ev.cmd = strField(ta, "command")
		}
	}
	for _, k := range []string{"tool_response", "tool_result", "toolResult", "output"} {
		if v, ok := m[k]; ok && v != nil {
			b, _ := json.Marshal(v)
			ev.response = b
			break
		}
	}
	return ev, true
}

// Run handles one hook invocation: payload on in, decision on out/errw.
// Returns the process exit code. It never fails closed: a payload it cannot
// read is allowed.
func Run(harness string, in io.Reader, out, errw io.Writer) int {
	h, ok := known(harness)
	if !ok {
		fmt.Fprintf(errw, "ai-hooks: unknown harness %q\n", harness)
		return 1
	}
	raw, _ := io.ReadAll(io.LimitReader(in, 64<<20))
	ev, ok := parse(raw)
	if !ok {
		return 0
	}
	if ev.post {
		return post(h, ev, out)
	}
	return pre(h, ev, out, errw)
}

func pre(h Harness, ev event, out, errw io.Writer) int {
	if ev.cmd == "" {
		return 0
	}
	r := guard.Check(ev.cmd)
	if r.Overridden != "" {
		LogOverride(ev.cmd, r)
	}
	if !r.Blocked {
		return 0
	}
	reason := "ai-hooks [" + r.Rule + "]: " + r.Message()
	switch h.Name {
	case "claude", "kimi", "codex":
		return emit(out, map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}})
	case "cursor":
		return emit(out, map[string]any{"permission": "deny", "user_message": reason, "agent_message": reason})
	case "gemini":
		return emit(out, map[string]any{"decision": "deny", "reason": reason})
	case "copilot":
		return emit(out, map[string]any{"permissionDecision": "deny", "permissionDecisionReason": reason})
	default: // windsurf, devin: exit 2 with the reason on stderr
		fmt.Fprintln(errw, reason)
		return 2
	}
}

func emit(out io.Writer, v any) int {
	b, _ := json.Marshal(v)
	fmt.Fprintln(out, string(b))
	return 0
}

// post replaces the tool output the model will see with a redacted copy.
func post(h Harness, ev event, out io.Writer) int {
	if !h.Post || len(ev.response) == 0 {
		return 0
	}
	var v any
	if json.Unmarshal(ev.response, &v) != nil {
		return 0
	}
	known := redact.LoadKnown()
	total := 0
	v = walk(v, known, &total)
	if total == 0 {
		return 0
	}
	switch h.Name {
	case "claude":
		return emit(out, map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName": "PostToolUse", "updatedToolOutput": v}})
	case "copilot":
		text := flatten(v)
		return emit(out, map[string]any{"modifiedResult": map[string]any{"resultType": "success", "textResultForLlm": text}})
	case "codex":
		// Codex has no output-rewrite field; a "block" decision replaces the result with the reason text.
		return emit(out, map[string]any{"decision": "block", "reason": flatten(v)})
	}
	return 0
}

func flatten(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		var parts []string
		for _, k := range []string{"stdout", "stderr", "textResultForLlm", "output", "text"} {
			if s, ok := t[k].(string); ok && s != "" {
				parts = append(parts, s)
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "\n")
		}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func walk(v any, known map[string]string, total *int) any {
	switch t := v.(type) {
	case string:
		s, c := redact.RedactReport(t, known)
		for _, n := range c {
			*total += n
		}
		return s
	case []any:
		for i := range t {
			t[i] = walk(t[i], known, total)
		}
	case map[string]any:
		for k := range t {
			t[k] = walk(t[k], known, total)
		}
	}
	return v
}

// LogPath is where overrides are recorded.
func LogPath() string {
	if p := os.Getenv("AI_HOOKS_LOG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "ai-hooks", "overrides.log")
}

// LogOverride records that an override comment let a blocked command run.
// The command is stored redacted and truncated.
func LogOverride(cmd string, r guard.Result) {
	p := LogPath()
	if p == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	c := redact.Redact(cmd, nil)
	if len(c) > 300 {
		c = c[:300] + "..."
	}
	b, _ := json.Marshal(map[string]string{
		"ts": time.Now().UTC().Format(time.RFC3339), "rule": r.Rule, "override": r.Overridden,
		"command": strings.ReplaceAll(c, "\n", "\\n")})
	f.Write(append(b, '\n'))
}
