// Package mcp is a minimal Model Context Protocol server over stdio (one JSON-RPC
// message per line) exposing the guard, the redactor, the scanner and a guarded
// command runner. Standard library only; no network.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/koalabs-ai/ai-hooks/internal/guard"
	"github.com/koalabs-ai/ai-hooks/internal/redact"
)

// Options configures the server.
type Options struct {
	Version string
	NoRun   bool             // do not offer safe_run
	Allow   []*regexp.Regexp // if set, safe_run only runs commands matching one of these
}

var supported = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

const (
	maxCommand   = 64 << 10
	maxText      = 16 << 20
	maxRawOutput = 16 << 20
	maxOutput    = 1 << 20
	defTimeout   = 60
	maxTimeout   = 600
)

type request struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve reads requests from in and writes responses to out until in closes.
func Serve(in io.Reader, out io.Writer, o Options) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), maxText+(1<<20))
	w := bufio.NewWriter(out)
	reply := func(id json.RawMessage, result any, e *rpcError) {
		m := map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id)}
		if e != nil {
			m["error"] = e
		} else {
			m["result"] = result
		}
		b, _ := json.Marshal(m)
		w.Write(b)
		w.WriteByte('\n')
		w.Flush()
	}
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			reply(json.RawMessage("null"), nil, &rpcError{-32700, "parse error"})
			continue
		}
		if len(req.ID) == 0 { // notification: no answer
			continue
		}
		switch req.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			json.Unmarshal(req.Params, &p)
			v := supported[0]
			for _, s := range supported {
				if s == p.ProtocolVersion {
					v = s
				}
			}
			reply(req.ID, map[string]any{
				"protocolVersion": v,
				"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
				"serverInfo":      map[string]any{"name": "ai-hooks", "version": o.Version},
				"instructions":    "Use guard before running a shell command that might print secrets, redact on any text that might contain secrets, and safe_run to run a command with the guard applied and its output redacted. No network access.",
			}, nil)
		case "ping":
			reply(req.ID, map[string]any{}, nil)
		case "tools/list":
			reply(req.ID, map[string]any{"tools": tools(o)}, nil)
		case "tools/call":
			var p struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			if err := json.Unmarshal(req.Params, &p); err != nil {
				reply(req.ID, nil, &rpcError{-32602, "invalid params"})
				continue
			}
			res, e := call(p.Name, p.Arguments, o)
			reply(req.ID, res, e)
		default:
			reply(req.ID, nil, &rpcError{-32601, "method not found: " + req.Method})
		}
	}
	return sc.Err()
}

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func tools(o Options) []any {
	ro := map[string]any{"readOnlyHint": true, "idempotentHint": true, "destructiveHint": false, "openWorldHint": false}
	t := []any{
		map[string]any{"name": "guard", "title": "Check a shell command for secret leaks",
			"description": "Decide, before a command runs, whether it is likely to print secrets. Returns blocked, the rule id and a one-line instruction. Nothing is executed.",
			"inputSchema": obj(map[string]any{"command": map[string]any{"type": "string", "description": "The shell command line to check."}}, "command"),
			"annotations": ro},
		map[string]any{"name": "redact", "title": "Redact secrets in text",
			"description": "Replace secret-shaped strings in text with <REDACTED:type:fingerprint>. Also returns how many values of each type were replaced (never the values).",
			"inputSchema": obj(map[string]any{"text": map[string]any{"type": "string"}}, "text"),
			"annotations": ro},
		map[string]any{"name": "scan", "title": "Find secrets in text",
			"description": "List secret-shaped values in text as findings (type, fingerprint, line). The values are never returned.",
			"inputSchema": obj(map[string]any{"text": map[string]any{"type": "string"}}, "text"),
			"annotations": ro},
	}
	if !o.NoRun {
		t = append(t, map[string]any{"name": "safe_run", "title": "Run a command with secret protection",
			"description": "Run a shell command (sh -c) after the guard has allowed it, with its output redacted. Blocked commands are not run. Same privileges as the user that runs this server; time-limited; output capped.",
			"inputSchema": obj(map[string]any{
				"command":         map[string]any{"type": "string"},
				"cwd":             map[string]any{"type": "string", "description": "Absolute directory to run in (optional)."},
				"timeout_seconds": map[string]any{"type": "integer", "minimum": 1, "maximum": maxTimeout},
			}, "command"),
			"annotations": map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": false}})
	}
	return t
}

func textResult(text string, structured any, isErr bool) map[string]any {
	r := map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}, "isError": isErr}
	if structured != nil {
		r["structuredContent"] = structured
	}
	return r
}

func call(name string, args json.RawMessage, o Options) (any, *rpcError) {
	switch name {
	case "guard":
		var a struct {
			Command string `json:"command"`
		}
		if err := strictDecode(args, &a); err != nil || a.Command == "" || len(a.Command) > maxCommand {
			return nil, &rpcError{-32602, "guard needs a command string of at most 64 KiB"}
		}
		r := guard.Check(a.Command)
		s := map[string]any{"blocked": r.Blocked, "rule": r.Rule, "detail": r.Detail, "overridden": r.Overridden}
		msg := "allowed"
		if r.Blocked {
			s["message"] = r.Message()
			msg = "blocked [" + r.Rule + "]: " + r.Message()
		}
		return textResult(msg, s, false), nil
	case "redact":
		var a struct {
			Text string `json:"text"`
		}
		if err := strictDecode(args, &a); err != nil || len(a.Text) > maxText {
			return nil, &rpcError{-32602, "redact needs a text string of at most 16 MiB"}
		}
		out, counts := redact.RedactReport(a.Text, redact.LoadKnown())
		n := 0
		for _, c := range counts {
			n += c
		}
		if counts == nil {
			counts = map[string]int{}
		}
		return textResult(out, map[string]any{"text": out, "redacted": n, "by_type": counts}, false), nil
	case "scan":
		var a struct {
			Text string `json:"text"`
		}
		if err := strictDecode(args, &a); err != nil || len(a.Text) > maxText {
			return nil, &rpcError{-32602, "scan needs a text string of at most 16 MiB"}
		}
		f, _ := redact.Scan(strings.NewReader(a.Text), redact.LoadKnown())
		if f == nil {
			f = []redact.Finding{}
		}
		return textResult(fmt.Sprintf("%d finding(s)", len(f)), map[string]any{"findings": f, "total": len(f)}, false), nil
	case "safe_run":
		if o.NoRun {
			return nil, &rpcError{-32602, "safe_run is disabled on this server"}
		}
		var a struct {
			Command string `json:"command"`
			Cwd     string `json:"cwd"`
			Timeout int    `json:"timeout_seconds"`
		}
		if err := strictDecode(args, &a); err != nil || a.Command == "" || len(a.Command) > maxCommand {
			return nil, &rpcError{-32602, "safe_run needs a command string of at most 64 KiB"}
		}
		return safeRun(a.Command, a.Cwd, a.Timeout, o), nil
	}
	return nil, &rpcError{-32602, "unknown tool: " + name}
}

func strictDecode(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return fmt.Errorf("no arguments")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

type capWriter struct {
	buf bytes.Buffer
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.buf.Len() < maxRawOutput {
		room := maxRawOutput - c.buf.Len()
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

func safeRun(command, cwd string, timeout int, o Options) any {
	if len(o.Allow) > 0 {
		// an allow list selects simple commands: shell metacharacters are refused so that
		// an allowed prefix cannot carry a second command ("ls; rm -rf x")
		if strings.ContainsAny(command, ";&|<>`$()\n\\") {
			return textResult("not allowed: with --allow-run, commands cannot contain shell metacharacters (; & | < > ` $ ( ) backslash or a newline)", map[string]any{"blocked": true, "rule": "allow-list"}, true)
		}
		ok := false
		for _, re := range o.Allow {
			if re.MatchString(command) {
				ok = true
			}
		}
		if !ok {
			return textResult("not allowed: this server only runs commands matching its allow list", map[string]any{"blocked": true, "rule": "allow-list"}, true)
		}
	}
	// this tool redacts everything the command prints (see guard.CheckExec)
	r := guard.CheckExec(command)
	if r.Blocked {
		return textResult("blocked ["+r.Rule+"]: "+r.Message(), map[string]any{"blocked": true, "rule": r.Rule}, true)
	}
	if cwd != "" {
		st, err := os.Stat(cwd)
		if err != nil || !st.IsDir() || !strings.HasPrefix(cwd, "/") {
			return textResult("cwd must be an existing absolute directory", nil, true)
		}
	}
	if timeout <= 0 {
		timeout = defTimeout
	}
	if timeout > maxTimeout {
		timeout = maxTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "sh", "-c", command)
	c.Dir = cwd
	c.Stdin = nil
	setupProc(c)
	cw := &capWriter{}
	c.Stdout, c.Stderr = cw, cw
	err := c.Run()
	code := 0
	timedOut := ctx.Err() == context.DeadlineExceeded
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	// redact the whole output first, then cut it to size, so a secret is never cut in half
	text, counts := redact.RedactReport(cw.buf.String(), redact.LoadKnown())
	truncated := false
	if len(text) > maxOutput {
		text, truncated = text[:maxOutput], true
	}
	n := 0
	for _, c := range counts {
		n += c
	}
	if timedOut {
		text += fmt.Sprintf("\n[timed out after %ds]", timeout)
	}
	s := map[string]any{"output": text, "exit_code": code, "redacted": n, "truncated": truncated, "timed_out": timedOut}
	return textResult(text, s, code != 0)
}
