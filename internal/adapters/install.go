package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// InstallOptions controls install and uninstall.
type InstallOptions struct {
	Harness string
	Project bool   // write into the current directory's config instead of the user's
	Path    string // explicit config file (tests, unusual layouts)
	Bin     string // command to put in the config; default: "ai-hooks" if it is on PATH, else this binary's path
	DryRun  bool
	Remove  bool
}

const (
	tomlBegin = "# >>> ai-hooks >>>"
	tomlEnd   = "# <<< ai-hooks <<<"
)

// Install adds (or with Remove, takes out) the hooks for one harness and returns
// a human-readable list of what it did. It only touches entries that run
// `ai-hooks hook <harness>`; everything else in the file is kept as is.
func Install(o InstallOptions) ([]string, error) {
	h, ok := known(o.Harness)
	if !ok {
		return nil, fmt.Errorf("unknown harness %q (known: %s)", o.Harness, harnessNames())
	}
	bin := o.Bin
	if bin == "" {
		bin = defaultBin()
	}
	path := o.Path
	if path == "" {
		var err error
		if path, err = configPath(h.Name, o.Project); err != nil {
			return nil, err
		}
	}
	var msgs []string
	var err error
	switch h.Name {
	case "kimi":
		msgs, err = editTOML(path, bin, o)
	case "opencode":
		msgs, err = editOwnFile(path, opencodePlugin(bin), o)
	case "copilot":
		msgs, err = editOwnFile(path, mustJSON(copilotDoc(bin)), o)
	default:
		msgs, err = editJSON(h, path, bin, o)
	}
	return msgs, err
}

func harnessNames() string {
	var n []string
	for _, h := range Harnesses {
		n = append(n, h.Name)
	}
	return strings.Join(n, ", ")
}

func defaultBin() string {
	self, _ := os.Executable()
	if p, err := exec.LookPath("ai-hooks"); err == nil {
		a, _ := filepath.EvalSymlinks(p)
		b, _ := filepath.EvalSymlinks(self)
		if a == b {
			return "ai-hooks"
		}
	}
	return self
}

func configPath(name string, project bool) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	pick := func(user, proj string) string {
		if project {
			return proj
		}
		return user
	}
	switch name {
	case "claude":
		return pick(filepath.Join(home, ".claude", "settings.json"), filepath.Join(".claude", "settings.json")), nil
	case "kimi":
		if project {
			return "", fmt.Errorf("kimi code reads hooks only from its user-level config.toml; use install kimi without --project")
		}
		d := os.Getenv("KIMI_CODE_HOME")
		if d == "" {
			d = filepath.Join(home, ".kimi-code")
		}
		return filepath.Join(d, "config.toml"), nil
	case "codex":
		d := os.Getenv("CODEX_HOME")
		if d == "" {
			d = filepath.Join(home, ".codex")
		}
		return pick(filepath.Join(d, "hooks.json"), filepath.Join(".codex", "hooks.json")), nil
	case "cursor":
		return pick(filepath.Join(home, ".cursor", "hooks.json"), filepath.Join(".cursor", "hooks.json")), nil
	case "gemini":
		return pick(filepath.Join(home, ".gemini", "settings.json"), filepath.Join(".gemini", "settings.json")), nil
	case "copilot":
		return pick(filepath.Join(home, ".copilot", "hooks", "ai-hooks.json"), filepath.Join(".github", "hooks", "ai-hooks.json")), nil
	case "windsurf":
		return pick(filepath.Join(home, ".codeium", "windsurf", "hooks.json"), filepath.Join(".windsurf", "hooks.json")), nil
	case "devin":
		return pick(filepath.Join(home, ".config", "devin", "hooks.v1.json"), filepath.Join(".devin", "hooks.v1.json")), nil
	case "opencode":
		return pick(filepath.Join(home, ".config", "opencode", "plugins", "ai-hooks.js"), filepath.Join(".opencode", "plugins", "ai-hooks.js")), nil
	}
	return "", fmt.Errorf("no config location for %s", name)
}

// ---------------------------------------------------------------- safe file writes

// realPath follows a symlink so we edit the file the link points at and keep the link.
func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

func writeFile(path string, data []byte, o InstallOptions) error {
	if o.DryRun {
		return nil
	}
	path = realPath(path)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
		if st.IsDir() {
			return fmt.Errorf("%s is a directory", path)
		}
		// the backup is created exclusively: if something (even a symlink) is already there, it is left alone
		if old, err := os.ReadFile(path); err == nil {
			if f, err := os.OpenFile(path+".ai-hooks-bak", os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode); err == nil {
				_, werr := f.Write(old)
				f.Close()
				if werr != nil {
					return werr
				}
			}
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ai-hooks-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func readIfExists(path string) ([]byte, bool, error) {
	b, err := os.ReadFile(realPath(path))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return b, err == nil, err
}

// ---------------------------------------------------------------- JSON settings (nested hook groups)

func hookCmd(bin, harness string) string { return shellWord(bin) + " hook " + harness }

func shellWord(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\r\n'\"\\$`&|;<>()*?[]{}#~!") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func isOurs(cmd, harness string) bool {
	suffix := " hook " + harness
	c := strings.TrimSpace(cmd)
	if !strings.HasSuffix(c, suffix) {
		return false
	}
	prog := strings.TrimSpace(strings.TrimSuffix(c, suffix))
	if len(prog) >= 2 && (prog[0] == '\'' || prog[0] == '"') && prog[len(prog)-1] == prog[0] {
		prog = prog[1 : len(prog)-1]
	}
	return strings.HasPrefix(filepath.Base(prog), "ai-hooks")
}

type spec struct {
	event   string
	matcher string
	entry   map[string]any
	nested  bool // entry lives in a {matcher, hooks:[...]} group
}

func specsFor(h Harness, bin string) (top string, wrap bool, specs []spec) {
	c := hookCmd(bin, h.Name)
	cmd := map[string]any{"type": "command", "command": c, "timeout": 10}
	switch h.Name {
	case "claude":
		specs = []spec{{"PreToolUse", "Bash", cmd, true}, {"PostToolUse", "Bash", cmd, true}}
		return "hooks", true, specs
	case "codex":
		specs = []spec{{"PreToolUse", "Bash", map[string]any{"type": "command", "command": c, "timeout": 30}, true}}
		return "hooks", true, specs
	case "gemini":
		specs = []spec{{"BeforeTool", "run_shell_command", map[string]any{"name": "ai-hooks", "type": "command", "command": c, "timeout": 5000}, true}}
		return "hooks", true, specs
	case "cursor":
		specs = []spec{{"beforeShellExecution", "", map[string]any{"command": c, "timeout": 30}, false}}
		return "hooks", true, specs
	case "windsurf":
		specs = []spec{{"pre_run_command", "", map[string]any{"command": c, "show_output": true}, false}}
		return "hooks", true, specs
	case "devin":
		specs = []spec{{"PreToolUse", "exec", map[string]any{"type": "command", "command": c}, true}}
		return "", false, specs
	}
	return "", false, nil
}

func editJSON(h Harness, path, bin string, o InstallOptions) ([]string, error) {
	data, exists, err := readIfExists(path)
	if err != nil {
		return nil, err
	}
	doc := map[string]any{}
	if exists && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("%s is not valid JSON (%v); not touching it", path, err)
		}
	}
	top, wrap, specs := specsFor(h, bin)
	container := doc
	if wrap {
		c, ok := doc[top].(map[string]any)
		if !ok {
			if doc[top] != nil {
				return nil, fmt.Errorf("%s: %q is not an object; not touching it", path, top)
			}
			c = map[string]any{}
			doc[top] = c
		}
		container = c
	}
	if h.Name == "cursor" || h.Name == "copilot" {
		if _, ok := doc["version"]; !ok {
			doc["version"] = 1
		}
	}
	var msgs []string
	for _, sp := range specs {
		list, _ := container[sp.event].([]any)
		var kept []any
		removed := 0
		for _, g := range list {
			gm, ok := g.(map[string]any)
			if !ok {
				kept = append(kept, g)
				continue
			}
			ng, hit, keep := stripOurs(gm, h.Name)
			if hit {
				removed++
			}
			if keep {
				kept = append(kept, ng)
			}
		}
		if o.Remove {
			if removed > 0 {
				msgs = append(msgs, fmt.Sprintf("removed %s hook from %s", sp.event, path))
			}
		} else {
			var g any = sp.entry
			if sp.nested {
				g = map[string]any{"matcher": sp.matcher, "hooks": []any{sp.entry}}
			}
			kept = append(kept, g)
			if removed > 0 {
				msgs = append(msgs, fmt.Sprintf("refreshed %s hook in %s", sp.event, path))
			} else {
				msgs = append(msgs, fmt.Sprintf("added %s hook (%s) to %s", sp.event, sp.matcherOr(), path))
			}
		}
		if len(kept) > 0 {
			container[sp.event] = kept
		} else {
			delete(container, sp.event)
		}
	}
	if o.Remove && len(msgs) == 0 {
		return []string{"nothing to remove in " + path}, nil
	}
	if wrap && o.Remove {
		if c, ok := doc[top].(map[string]any); ok && len(c) == 0 {
			delete(doc, top)
		}
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeFile(path, append(out, '\n'), o); err != nil {
		return nil, err
	}
	return msgs, nil
}

func (s spec) matcherOr() string {
	if s.matcher == "" {
		return "all"
	}
	return s.matcher
}

// stripOurs removes this tool's hook entries from one group. hit: something was
// removed; keep: the group still has other content and must stay.
func stripOurs(g map[string]any, harness string) (out map[string]any, hit, keep bool) {
	if c, ok := g["command"].(string); ok && isOurs(c, harness) {
		return g, true, false
	}
	if b, ok := g["bash"].(string); ok && isOurs(b, harness) {
		return g, true, false
	}
	hs, ok := g["hooks"].([]any)
	if !ok {
		return g, false, true
	}
	var rest []any
	for _, x := range hs {
		if xm, ok := x.(map[string]any); ok {
			if c, _ := xm["command"].(string); isOurs(c, harness) {
				hit = true
				continue
			}
		}
		rest = append(rest, x)
	}
	if !hit {
		return g, false, true
	}
	if len(rest) == 0 {
		return g, true, false
	}
	ng := map[string]any{}
	for k, v := range g {
		ng[k] = v
	}
	ng["hooks"] = rest
	return ng, true, true
}

// ---------------------------------------------------------------- Kimi (TOML block between markers)

func editTOML(path, bin string, o InstallOptions) ([]string, error) {
	data, _, err := readIfExists(path)
	if err != nil {
		return nil, err
	}
	s := string(data)
	var out string
	if i := strings.Index(s, tomlBegin); i >= 0 {
		j := strings.Index(s[i:], tomlEnd)
		if j < 0 {
			return nil, fmt.Errorf("%s has a start marker without an end marker; not touching it", path)
		}
		out = s[:i] + strings.TrimPrefix(s[i+j+len(tomlEnd):], "\n")
	} else {
		out = s
	}
	var msg string
	if o.Remove {
		if out == s {
			return []string{"nothing to remove in " + path}, nil
		}
		msg = "removed the ai-hooks block from " + path
	} else {
		block := fmt.Sprintf("%s\n[[hooks]]\nevent = \"PreToolUse\"\nmatcher = \"Bash\"\ncommand = %s\ntimeout = 10\n%s\n", tomlBegin, tomlString(hookCmd(bin, "kimi")), tomlEnd)
		if out != "" && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		out += block
		msg = "added a PreToolUse hook (Bash) to " + path
		if strings.Contains(s, tomlBegin) {
			msg = "refreshed the ai-hooks block in " + path
		}
	}
	if err := writeFile(path, []byte(out), o); err != nil {
		return nil, err
	}
	return []string{msg}, nil
}

// tomlString is a TOML basic string: only \\, \" and control characters need escapes.
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\\' || r == '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\u%04X", r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ---------------------------------------------------------------- files that are entirely ours

func editOwnFile(path string, content []byte, o InstallOptions) ([]string, error) {
	if o.Remove {
		p := realPath(path)
		b, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			return []string{"nothing to remove: " + path + " does not exist"}, nil
		}
		if err != nil {
			return nil, err
		}
		if !isOurFile(b) {
			return nil, fmt.Errorf("%s does not look like an ai-hooks file; not removing it", path)
		}
		if !o.DryRun {
			if err := os.Remove(path); err != nil {
				return nil, err
			}
		}
		return []string{"removed " + path}, nil
	}
	if b, ok, _ := readIfExists(path); ok && !isOurFile(b) {
		return nil, fmt.Errorf("%s exists and is not an ai-hooks file; not overwriting it", path)
	}
	if err := writeFile(path, content, o); err != nil {
		return nil, err
	}
	return []string{"wrote " + path}, nil
}

func mustJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return append(b, '\n')
}

func copilotDoc(bin string) map[string]any {
	c := hookCmd(bin, "copilot")
	return map[string]any{"version": 1, "hooks": map[string]any{
		"preToolUse":  []any{map[string]any{"type": "command", "bash": c, "matcher": "bash", "timeoutSec": 30}},
		"postToolUse": []any{map[string]any{"type": "command", "bash": c, "matcher": "bash", "timeoutSec": 30}},
	}}
}

// opencodePlugin is an opencode (v2 server plugin API) plugin: no shell is
// involved, the command is passed to the binary as one argument.
func opencodePlugin(bin string) []byte {
	b, _ := json.Marshal(bin)
	return []byte(`// ai-hooks plugin for opencode (written by ` + "`ai-hooks install opencode`" + `; remove with ` + "`ai-hooks uninstall opencode`" + `).
import { spawnSync } from "node:child_process"

const BIN = ` + string(b) + `
const SHELL_TOOLS = new Set(["bash", "shell"])

function redact(text) {
  const r = spawnSync(BIN, ["redact"], { input: text, encoding: "utf8", maxBuffer: 256 << 20 })
  return r.status === 0 && typeof r.stdout === "string" ? r.stdout : text
}

function redactDeep(v, depth = 0) {
  if (depth > 6 || v == null) return v
  if (typeof v === "string") return redact(v)
  if (Array.isArray(v)) return v.map((x) => redactDeep(x, depth + 1))
  if (typeof v === "object") {
    for (const k of Object.keys(v)) v[k] = redactDeep(v[k], depth + 1)
  }
  return v
}

export default {
  id: "ai-hooks",
  async setup(ctx) {
    await ctx.tool.hook("execute.before", (event) => {
      if (!SHELL_TOOLS.has(event.tool)) return
      const cmd = event.input && event.input.command
      if (typeof cmd !== "string" || cmd === "") return
      const r = spawnSync(BIN, ["guard", "--", cmd], { encoding: "utf8", maxBuffer: 1 << 20 })
      if (r.status === 2) throw new Error((r.stderr || "blocked by ai-hooks").trim())
    })
    await ctx.tool.hook("execute.after", (event) => {
      if (!SHELL_TOOLS.has(event.tool) || event.status !== "completed" || event.result == null) return
      event.result = redactDeep(event.result)
    })
  },
}
`)
}

// ConfigSnippet prints the settings a user adds by hand for a harness.
func ConfigSnippet(harness, bin string) (string, bool) {
	h, ok := known(harness)
	if !ok {
		return "", false
	}
	dir, _ := os.MkdirTemp("", "ai-hooks-snippet-")
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "cfg")
	if _, err := Install(InstallOptions{Harness: h.Name, Path: p, Bin: bin}); err != nil {
		return "", false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// isOurFile: files written by editOwnFile start with a known first line.
func isOurFile(b []byte) bool {
	if bytes.HasPrefix(b, []byte("// ai-hooks plugin for opencode (written by")) {
		return true
	}
	var doc struct {
		Hooks map[string][]map[string]any `json:"hooks"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return false
	}
	for _, list := range doc.Hooks {
		for _, g := range list {
			if c, _ := g["bash"].(string); isOurs(c, "copilot") {
				return true
			}
		}
	}
	return false
}
