package mcp

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

func run(t *testing.T, o Options, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := Serve(strings.NewReader(strings.Join(lines, "\n")+"\n"), &out, o); err != nil {
		t.Fatal(err)
	}
	var rs []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not json: %q", l)
		}
		rs = append(rs, m)
	}
	return rs
}

func textOf(r map[string]any) string {
	c := r["result"].(map[string]any)["content"].([]any)
	return c[0].(map[string]any)["text"].(string)
}

func TestInitializeNegotiatesVersion(t *testing.T) {
	for want, req := range map[string]string{"2025-06-18": "2025-06-18", "2025-11-25": "1999-01-01", "2024-11-05": "2024-11-05"} {
		rs := run(t, Options{}, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+req+`"}}`)
		if got := rs[0]["result"].(map[string]any)["protocolVersion"]; got != want {
			t.Errorf("asked %s: got %v want %s", req, got, want)
		}
	}
}

func TestNotificationsGetNoReply(t *testing.T) {
	rs := run(t, Options{}, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, `{"jsonrpc":"2.0","id":7,"method":"ping"}`)
	if len(rs) != 1 || rs[0]["id"].(float64) != 7 {
		t.Errorf("got %v", rs)
	}
}

func TestToolsAndAnnotations(t *testing.T) {
	rs := run(t, Options{}, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	tools := rs[0]["result"].(map[string]any)["tools"].([]any)
	names := map[string]bool{}
	for _, x := range tools {
		m := x.(map[string]any)
		names[m["name"].(string)] = true
		if m["inputSchema"].(map[string]any)["type"] != "object" {
			t.Errorf("%v: inputSchema must be an object", m["name"])
		}
	}
	for _, n := range []string{"guard", "redact", "scan", "safe_run"} {
		if !names[n] {
			t.Errorf("missing tool %s", n)
		}
	}
	rs = run(t, Options{NoRun: true}, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if len(rs[0]["result"].(map[string]any)["tools"].([]any)) != 3 {
		t.Error("--no-run must hide safe_run")
	}
}

func TestRedactAndGuardAndScan(t *testing.T) {
	rs := run(t, Options{},
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"redact","arguments":{"text":"k AKIAIOSFODNN7EXAMPLE"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"guard","arguments":{"command":"docker inspect web"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scan","arguments":{"text":"a\nAKIAIOSFODNN7EXAMPLE\n"}}}`)
	if s := textOf(rs[0]); strings.Contains(s, "AKIA") || !strings.Contains(s, "REDACTED:aws-access-key") {
		t.Errorf("redact: %q", s)
	}
	// some clients show the model only structuredContent: the redacted text must be in it
	sc := rs[0]["result"].(map[string]any)["structuredContent"].(map[string]any)
	if v, _ := sc["text"].(string); strings.Contains(v, "AKIA") || !strings.Contains(v, "REDACTED") {
		t.Errorf("structuredContent.text: %v", sc)
	}
	if s := textOf(rs[1]); !strings.HasPrefix(s, "blocked [") {
		t.Errorf("guard: %q", s)
	}
	b, _ := json.Marshal(rs[2])
	if strings.Contains(string(b), "AKIAIOSFODNN7EXAMPLE") || !strings.Contains(string(b), `"line":2`) {
		t.Errorf("scan leaks the value or lacks the line: %s", b)
	}
}

func TestSafeRun(t *testing.T) {
	call := func(args string) map[string]any {
		return run(t, Options{}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_run","arguments":`+args+`}}`)[0]
	}
	if s := textOf(call(`{"command":"echo hi"}`)); !strings.HasPrefix(s, "hi") {
		t.Errorf("echo: %q", s)
	}
	// secrets in the output are redacted
	if s := textOf(call(`{"command":"echo AKIAIOSFODNN7EXAMPLE"}`)); strings.Contains(s, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("not redacted: %q", s)
	}
	// a command the guard blocks even through the redactor is not run (xtrace)
	r := call(`{"command":"echo $DB_PASSWORD &"}`)
	res := r["result"].(map[string]any)
	if res["isError"] != true || !strings.Contains(textOf(r), "blocked") {
		t.Errorf("background-secret should be blocked: %v", r)
	}
	// bad inputs are protocol errors, not crashes
	for _, a := range []string{`{}`, `{"command":""}`, `{"command":"x","extra":1}`, `[]`} {
		if call(a)["error"] == nil {
			t.Errorf("args %s should be rejected", a)
		}
	}
	if r := call(`{"command":"echo x","cwd":"relative/dir"}`); r["result"].(map[string]any)["isError"] != true {
		t.Error("relative cwd must be refused")
	}
	// timeout
	if r := call(`{"command":"sleep 5","timeout_seconds":1}`); !strings.Contains(textOf(r), "timed out") {
		t.Errorf("timeout: %v", r)
	}
}

func TestSafeRunAllowList(t *testing.T) {
	o := Options{Allow: []*regexp.Regexp{regexp.MustCompile(`^(ls|echo) `)}}
	rs := run(t, o,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_run","arguments":{"command":"echo ok"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"safe_run","arguments":{"command":"uname -a"}}}`)
	if rs[0]["result"].(map[string]any)["isError"] == true {
		t.Error("allowed command refused")
	}
	if rs[1]["result"].(map[string]any)["isError"] != true {
		t.Error("command outside the allow list must be refused")
	}
	rs = run(t, o, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_run","arguments":{"command":"echo ok; uname"}}}`)
	if rs[0]["result"].(map[string]any)["isError"] != true {
		t.Error("an allowed prefix must not carry a second command")
	}
}

func TestMalformedInputDoesNotCrash(t *testing.T) {
	rs := run(t, Options{}, `not json`, `{"jsonrpc":"2.0","id":1,"method":"nope"}`, `{"id":2,"method":"tools/call","params":"x"}`, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"zzz","arguments":{}}}`)
	if len(rs) != 4 {
		t.Fatalf("got %d replies", len(rs))
	}
	for _, r := range rs {
		if r["error"] == nil {
			t.Errorf("expected an error: %v", r)
		}
	}
}

func TestTimeoutKillsChildrenAndReturns(t *testing.T) {
	st := time.Now()
	rs := run(t, Options{}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_run","arguments":{"command":"sleep 30 & sleep 30","timeout_seconds":1}}}`)
	if d := time.Since(st); d > 10*time.Second {
		t.Errorf("did not return after the timeout: %v", d)
	}
	if !strings.Contains(textOf(rs[0]), "timed out") {
		t.Errorf("got %q", textOf(rs[0]))
	}
}
