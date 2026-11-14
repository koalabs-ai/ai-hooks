package adapters

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInstallClaudeKeepsOtherSettingsAndIsIdempotent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(p, []byte(`{"theme":"dark","hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo done"}]}],"PreToolUse":[{"matcher":"Edit","hooks":[{"type":"command","command":"my-edit-hook"}]}]}}`), 0o640)
	o := InstallOptions{Harness: "claude", Path: p, Bin: "/opt/ai-hooks"}
	for i := 0; i < 3; i++ {
		if _, err := Install(o); err != nil {
			t.Fatal(err)
		}
	}
	s := read(t, p)
	if strings.Count(s, "/opt/ai-hooks hook claude") != 2 {
		t.Errorf("expected exactly one Pre and one Post entry:\n%s", s)
	}
	for _, keep := range []string{`"theme": "dark"`, "echo done", "my-edit-hook"} {
		if !strings.Contains(s, keep) {
			t.Errorf("lost %q", keep)
		}
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o640 {
		t.Errorf("mode changed to %v", st.Mode().Perm())
	}
	if _, err := os.Stat(p + ".ai-hooks-bak"); err != nil {
		t.Error("no backup written")
	}
	o.Remove = true
	if _, err := Install(o); err != nil {
		t.Fatal(err)
	}
	s = read(t, p)
	if strings.Contains(s, "ai-hooks") || !strings.Contains(s, "my-edit-hook") || !strings.Contains(s, "echo done") {
		t.Errorf("uninstall left or removed the wrong things:\n%s", s)
	}
}

func TestInstallRefusesBrokenJSONAndDirectories(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "settings.json")
	os.WriteFile(p, []byte(`{"hooks": [1,2`), 0o600)
	if _, err := Install(InstallOptions{Harness: "claude", Path: p}); err == nil {
		t.Error("must not touch invalid JSON")
	}
	if read(t, p) != `{"hooks": [1,2` {
		t.Error("file was modified")
	}
	os.WriteFile(p, []byte(`{"hooks": 5}`), 0o600)
	if _, err := Install(InstallOptions{Harness: "claude", Path: p}); err == nil {
		t.Error("hooks that is not an object must be refused")
	}
	if _, err := Install(InstallOptions{Harness: "claude", Path: d}); err == nil {
		t.Error("a directory path must be refused")
	}
}

func TestInstallFollowsSymlinkAndKeepsIt(t *testing.T) {
	d := t.TempDir()
	real := filepath.Join(d, "dotfiles", "settings.json")
	os.MkdirAll(filepath.Dir(real), 0o700)
	os.WriteFile(real, []byte(`{}`), 0o600)
	link := filepath.Join(d, "settings.json")
	os.Symlink(real, link)
	if _, err := Install(InstallOptions{Harness: "claude", Path: link, Bin: "ai-hooks"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Lstat(link); st.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced by a regular file")
	}
	if !strings.Contains(read(t, real), "ai-hooks hook claude") {
		t.Error("the linked file was not edited")
	}
}

func TestNewFilesAreOwnerOnly(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "sub", "hooks.json")
	if _, err := Install(InstallOptions{Harness: "codex", Path: p, Bin: "ai-hooks"}); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm()&0o077 != 0 {
		t.Errorf("new config is group/world accessible: %v", st.Mode().Perm())
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x", "settings.json")
	msgs, err := Install(InstallOptions{Harness: "claude", Path: p, DryRun: true})
	if err != nil || len(msgs) == 0 {
		t.Fatal(err, msgs)
	}
	if _, err := os.Stat(p); err == nil {
		t.Error("dry run wrote a file")
	}
}

func TestInstallKimiTOMLBlock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.toml")
	orig := "default_model = \"x\"\n\n[[hooks]]\nevent = \"Stop\"\ncommand = \"echo bye\"\n"
	os.WriteFile(p, []byte(orig), 0o600)
	o := InstallOptions{Harness: "kimi", Path: p, Bin: "/opt/ai-hooks"}
	Install(o)
	Install(o)
	s := read(t, p)
	if strings.Count(s, "[[hooks]]") != 2 || strings.Count(s, tomlBegin) != 1 || !strings.Contains(s, `command = "/opt/ai-hooks hook kimi"`) {
		t.Errorf("bad toml:\n%s", s)
	}
	o.Remove = true
	Install(o)
	if read(t, p) != orig {
		t.Errorf("uninstall did not restore the file:\n%s", read(t, p))
	}
	// a start marker without an end marker: refuse
	os.WriteFile(p, []byte(tomlBegin+"\nstuff\n"), 0o600)
	if _, err := Install(InstallOptions{Harness: "kimi", Path: p}); err == nil {
		t.Error("unbalanced marker must be refused")
	}
}

func TestOwnFilesAreNotClobbered(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ai-hooks.js")
	os.WriteFile(p, []byte("// somebody else's plugin\n"), 0o600)
	if _, err := Install(InstallOptions{Harness: "opencode", Path: p}); err == nil {
		t.Error("must not overwrite a file that is not ours")
	}
	if _, err := Install(InstallOptions{Harness: "opencode", Path: p, Remove: true}); err == nil {
		t.Error("must not delete a file that is not ours")
	}
	os.Remove(p)
	if _, err := Install(InstallOptions{Harness: "opencode", Path: p, Bin: "/opt/ai hooks/ai-hooks"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, p), `"/opt/ai hooks/ai-hooks"`) {
		t.Error("binary path must be embedded as a JSON string")
	}
	if _, err := Install(InstallOptions{Harness: "opencode", Path: p, Remove: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Error("not removed")
	}
}

func TestHookCommandQuotesOddPaths(t *testing.T) {
	if got := hookCmd("/opt/my tools/ai-hooks", "claude"); got != `'/opt/my tools/ai-hooks' hook claude` {
		t.Errorf("got %q", got)
	}
	if !isOurs(`'/opt/my tools/ai-hooks' hook claude`, "claude") || isOurs("echo hook claude", "claude") {
		t.Error("isOurs is wrong")
	}
}

func hook(t *testing.T, harness, payload string) (string, string, int) {
	t.Helper()
	t.Setenv("AI_HOOKS_LOG", filepath.Join(t.TempDir(), "log"))
	t.Setenv("AI_HOOKS_RULES", filepath.Join(t.TempDir(), "none"))
	var out, errw bytes.Buffer
	code := Run(harness, strings.NewReader(payload), &out, &errw)
	return out.String(), errw.String(), code
}

func TestEveryHarnessBlocksWithItsOwnProtocol(t *testing.T) {
	cmdLine := "docker inspect web"
	cases := map[string]string{
		"claude":   `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"` + cmdLine + `"}}`,
		"kimi":     `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"` + cmdLine + `"}}`,
		"codex":    `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"` + cmdLine + `"}}`,
		"cursor":   `{"hook_event_name":"beforeShellExecution","command":"` + cmdLine + `","cwd":"/x"}`,
		"gemini":   `{"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"` + cmdLine + `"}}`,
		"copilot":  `{"toolName":"bash","toolArgs":"{\"command\":\"` + cmdLine + `\"}"}`,
		"windsurf": `{"agent_action_name":"pre_run_command","tool_info":{"command_line":"` + cmdLine + `"}}`,
		"devin":    `{"hook_event_name":"PreToolUse","tool_name":"exec","tool_input":{"command":"` + cmdLine + `"}}`,
	}
	for h, payload := range cases {
		out, errw, code := hook(t, h, payload)
		switch h {
		case "windsurf", "devin":
			if code != 2 || !strings.Contains(errw, "ai-hooks [") {
				t.Errorf("%s: code=%d stderr=%q", h, code, errw)
			}
		default:
			var m map[string]any
			if json.Unmarshal([]byte(out), &m) != nil || !strings.Contains(out, "ai-hooks [") || !strings.Contains(strings.ToLower(out), "deny") {
				t.Errorf("%s: out=%q", h, out)
			}
		}
		// and a harmless command is allowed everywhere
		ok := strings.ReplaceAll(payload, cmdLine, "ls -la")
		if o, e, c := hook(t, h, ok); o != "" || e != "" || c != 0 {
			t.Errorf("%s: harmless command got out=%q err=%q code=%d", h, o, e, c)
		}
	}
}

func TestPostRewriteForHarnessesThatCanDoIt(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	out, _, _ := hook(t, "copilot", `{"hook_event_name":"postToolUse","toolName":"bash","toolResult":{"resultType":"success","textResultForLlm":"k `+secret+`"}}`)
	if strings.Contains(out, secret) || !strings.Contains(out, "modifiedResult") {
		t.Errorf("copilot: %q", out)
	}
	out, _, _ = hook(t, "codex", `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"k `+secret+`"}}`)
	if strings.Contains(out, secret) || !strings.Contains(out, `"decision":"block"`) {
		t.Errorf("codex: %q", out)
	}
	for _, h := range []string{"kimi", "cursor", "gemini", "windsurf", "devin"} {
		if out, _, _ := hook(t, h, `{"hook_event_name":"PostToolUse","tool_response":{"stdout":"`+secret+`"}}`); out != "" {
			t.Errorf("%s cannot rewrite output but printed %q", h, out)
		}
	}
}

func TestUninstallKeepsOtherHooksInTheSameGroup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(p, []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"ai-hooks hook claude"},{"type":"command","command":"my-own-check"}]}]}}`), 0o600)
	if _, err := Install(InstallOptions{Harness: "claude", Path: p, Remove: true}); err != nil {
		t.Fatal(err)
	}
	s := read(t, p)
	if strings.Contains(s, "ai-hooks hook") || !strings.Contains(s, "my-own-check") {
		t.Errorf("uninstall removed the wrong things:\n%s", s)
	}
}

func TestBackupNeverFollowsAnExistingLink(t *testing.T) {
	d := t.TempDir()
	victim := filepath.Join(d, "victim.txt")
	os.WriteFile(victim, []byte("precious"), 0o600)
	p := filepath.Join(d, "settings.json")
	os.WriteFile(p, []byte(`{}`), 0o600)
	os.Symlink(victim, p+".ai-hooks-bak")
	if _, err := Install(InstallOptions{Harness: "claude", Path: p, Bin: "ai-hooks"}); err != nil {
		t.Fatal(err)
	}
	if read(t, victim) != "precious" {
		t.Error("the backup step overwrote the file a symlink pointed to")
	}
}

func TestOwnFileMarkerIsStrict(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ai-hooks.js")
	os.WriteFile(p, []byte("// my notes about ai-hooks, do not delete\n"), 0o600)
	if _, err := Install(InstallOptions{Harness: "opencode", Path: p, Remove: true}); err == nil {
		t.Error("a file that only mentions ai-hooks must not be removed")
	}
	if read(t, p) == "" {
		t.Error("file was damaged")
	}
}
