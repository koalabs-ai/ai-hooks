package adapters

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, harness, payload string) string {
	t.Helper()
	t.Setenv("AI_HOOKS_LOG", filepath.Join(t.TempDir(), "log"))
	t.Setenv("AI_HOOKS_RULES", filepath.Join(t.TempDir(), "none.json"))
	var out bytes.Buffer
	if code := Run(harness, strings.NewReader(payload), &out, &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	return out.String()
}

func TestPreToolUseDeniesWithReason(t *testing.T) {
	out := run(t, "claude", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"journalctl -u app"}}`)
	var v struct {
		H struct{ D, R string } `json:"hookSpecificOutput"`
	}
	var raw map[string]map[string]string
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("not json: %q", out)
	}
	_ = v
	h := raw["hookSpecificOutput"]
	if h["permissionDecision"] != "deny" || !strings.Contains(h["permissionDecisionReason"], "ai-hooks redact") {
		t.Errorf("got %v", h)
	}
}

func TestPreToolUseAllowsQuietly(t *testing.T) {
	if out := run(t, "claude", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}`); out != "" {
		t.Errorf("expected no output, got %q", out)
	}
}

func TestOverrideIsLogged(t *testing.T) {
	log := filepath.Join(t.TempDir(), "log")
	t.Setenv("AI_HOOKS_LOG", log)
	t.Setenv("AI_HOOKS_RULES", filepath.Join(t.TempDir(), "none.json"))
	var out bytes.Buffer
	Run("claude", strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"docker inspect web # noredact"}}`), &out, &out)
	b, _ := os.ReadFile(log)
	if !strings.Contains(string(b), `"rule":"docker-inspect"`) || !strings.Contains(string(b), `"override":"noredact"`) {
		t.Errorf("log: %q", b)
	}
}

func TestPostToolUseRedactsOutputShape(t *testing.T) {
	out := run(t, "claude", `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"x"},"tool_response":{"stdout":"key AKIAIOSFODNN7EXAMPLE ok","stderr":"","interrupted":false,"isImage":false}}`)
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") || !strings.Contains(out, "updatedToolOutput") ||
		!strings.Contains(out, `"interrupted":false`) {
		t.Errorf("got %q", out)
	}
}

func TestPostToolUseSilentWhenNothingToRedact(t *testing.T) {
	if out := run(t, "claude", `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"hello","stderr":""}}`); out != "" {
		t.Errorf("got %q", out)
	}
}

func TestKimiPostIsIgnoredAndGarbageAllowed(t *testing.T) {
	if out := run(t, "kimi", `{"hook_event_name":"PostToolUse","tool_response":{"stdout":"AKIAIOSFODNN7EXAMPLE"}}`); out != "" {
		t.Errorf("kimi post should be a no-op, got %q", out)
	}
	if out := run(t, "claude", `not json`); out != "" {
		t.Errorf("garbage must be allowed, got %q", out)
	}
}
