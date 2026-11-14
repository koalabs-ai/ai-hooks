package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ai-hooks-e2e-")
	if err != nil {
		panic(err)
	}
	binPath = filepath.Join(dir, "ai-hooks")
	b := exec.Command("go", "build", "-o", binPath, ".")
	b.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := b.CombinedOutput(); err != nil {
		panic(string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func run(t *testing.T, stdin string, env []string, args ...string) (string, string, int) {
	t.Helper()
	c := exec.Command(binPath, args...)
	c.Stdin = strings.NewReader(stdin)
	home := t.TempDir()
	c.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "AI_HOOKS_LOG=" + filepath.Join(home, "log"),
		"AI_HOOKS_RULES=" + filepath.Join(home, "none.json"), "AI_HOOKS_KNOWN_HASHES=" + filepath.Join(home, "none")}, env...)
	var o, e bytes.Buffer
	c.Stdout, c.Stderr = &o, &e
	err := c.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	return o.String(), e.String(), code
}

func TestExitCodesAndRedact(t *testing.T) {
	out, _, code := run(t, "k AKIAIOSFODNN7EXAMPLE\n", nil, "redact")
	if code != 0 || strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("redact: %q %d", out, code)
	}
	if _, _, code := run(t, "", nil, "guard", "--", "docker inspect x"); code != 2 {
		t.Errorf("guard block: code %d", code)
	}
	if _, _, code := run(t, "", nil, "guard", "--", "ls"); code != 0 {
		t.Errorf("guard allow: code %d", code)
	}
	if _, _, code := run(t, "", nil, "nope"); code != 2 {
		t.Errorf("unknown command: code %d", code)
	}
	out, _, _ = run(t, "a AKIAIOSFODNN7EXAMPLE b", nil, "redact", "--json")
	var rep struct {
		Redacted int
		ByType   map[string]int `json:"by_type"`
	}
	if json.Unmarshal([]byte(out), &rep) != nil || rep.Redacted != 1 || strings.Contains(out, "AKIA") {
		t.Errorf("report: %s", out)
	}
}

func TestExecRedactsAndKeepsExitCode(t *testing.T) {
	out, _, code := run(t, "", nil, "exec", "--", "sh", "-c", "echo AKIAIOSFODNN7EXAMPLE; exit 7")
	if code != 7 || strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") || !strings.Contains(out, "REDACTED") {
		t.Errorf("exec: %q code=%d", out, code)
	}
	// stderr is redacted too
	_, e, _ := run(t, "", nil, "exec", "--", "sh", "-c", "echo AKIAIOSFODNN7EXAMPLE >&2")
	if strings.Contains(e, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("stderr leaked: %q", e)
	}
	// arguments are passed as arguments, not through a shell
	out, _, _ = run(t, "", nil, "exec", "--", "printf", "%s", "a;echo INJECTED")
	if out != "a;echo INJECTED" {
		t.Errorf("argument handling: %q", out)
	}
}

func TestScanExitCodesAndNoValues(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "a.txt"), []byte("x\nAKIAIOSFODNN7EXAMPLE\n"), 0o600)
	os.WriteFile(filepath.Join(d, "clean.txt"), []byte("nothing here\n"), 0o600)
	os.WriteFile(filepath.Join(d, "bin.dat"), append([]byte{0, 1, 2}, []byte("AKIAIOSFODNN7EXAMPLE")...), 0o600)
	os.Symlink("/etc/hostname", filepath.Join(d, "link"))
	out, _, code := run(t, "", nil, "scan", d)
	if code != 1 || !strings.Contains(out, "a.txt:2: aws-access-key") || strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(out, "bin.dat") {
		t.Errorf("scan: %q code=%d", out, code)
	}
	if _, _, code := run(t, "", nil, "scan", filepath.Join(d, "clean.txt")); code != 0 {
		t.Errorf("clean scan code %d", code)
	}
	out, _, _ = run(t, "", nil, "scan", "--format", "sarif", d)
	var s struct {
		Version string
		Schema  string `json:"$schema"`
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			}
		}
	}
	if err := json.Unmarshal([]byte(out), &s); err != nil || s.Version != "2.1.0" || len(s.Runs) != 1 || len(s.Runs[0].Results) != 1 || strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("sarif: %v %s", err, out)
	}
}

func TestRulesListAndSchemaAreJSON(t *testing.T) {
	out, _, code := run(t, "", nil, "rules", "list", "--json")
	var m map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &m) != nil || m["guard_rules"] == nil || m["detectors"] == nil || m["aliases"] == nil {
		t.Errorf("rules list --json: code=%d %.200s", code, out)
	}
	out, _, _ = run(t, "", nil, "rules", "schema")
	if json.Unmarshal([]byte(out), &m) != nil || m["$schema"] == nil {
		t.Error("schema is not JSON")
	}
	f := filepath.Join(t.TempDir(), "r.json")
	os.WriteFile(f, []byte(`{"redact_rules":[{"id":"Bad ID","why":"","match":["("]}]}`), 0o600)
	if _, e, code := run(t, "", nil, "rules", "validate", f); code != 1 || !strings.Contains(e, "invalid") {
		t.Errorf("validate: code=%d %q", code, e)
	}
}

// The binary must work with no network at all: run the whole self-test and the
// main commands inside an empty network namespace.
func TestWorksWithoutNetwork(t *testing.T) {
	if err := exec.Command("unshare", "-rn", "true").Run(); err != nil {
		t.Skip("cannot create a network namespace here")
	}
	for _, args := range [][]string{{"test", "--short"}, {"version"}, {"guard", "--", "ls"}, {"rules", "list"}} {
		c := exec.Command("unshare", append([]string{"-rn", binPath}, args...)...)
		c.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
		if out, err := c.CombinedOutput(); err != nil {
			t.Errorf("%v without network: %v\n%s", args, err, out)
		}
	}
	c := exec.Command("unshare", "-rn", binPath, "redact")
	c.Stdin = strings.NewReader("AKIAIOSFODNN7EXAMPLE\n")
	out, err := c.Output()
	if err != nil || strings.Contains(string(out), "AKIA") {
		t.Errorf("redact without network: %v %q", err, out)
	}
}

// The binary must not even link a network client: no net/http, no crypto/tls, no DNS resolver.
func TestNoNetworkPackagesLinked(t *testing.T) {
	out, err := exec.Command("go", "version", "-m", binPath).CombinedOutput()
	if err != nil {
		t.Skip("go version -m unavailable")
	}
	_ = out
	deps, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skip("go list unavailable")
	}
	for _, bad := range []string{"net/http", "crypto/tls"} {
		for _, d := range strings.Split(string(deps), "\n") {
			if d == bad {
				t.Errorf("the binary depends on %s", bad)
			}
		}
	}
}

func TestShellInitRoutesRiskyCommandsThroughExec(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	dir := t.TempDir()
	os.Symlink(binPath, filepath.Join(dir, "ai-hooks"))
	init, _, code := run(t, "", nil, "shell-init", "bash")
	if code != 0 || !strings.Contains(init, "__aihooks") {
		t.Fatal("shell-init printed nothing useful")
	}
	rc := filepath.Join(dir, "shell.sh")
	os.WriteFile(rc, []byte(init), 0o600)
	c := exec.Command("bash", "-c", "printenv")
	c.Env = []string{"PATH=" + dir + ":" + os.Getenv("PATH"), "HOME=" + dir, "BASH_ENV=" + rc, "FAKE_API_TOKEN=abcdefghijklmnopqrstuvwxyz0123", "AI_HOOKS_RULES=" + dir + "/none"}
	out, err := c.Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "abcdefghijklmnopqrstuvwxyz0123") || !strings.Contains(string(out), "REDACTED") {
		t.Errorf("printenv through the shim leaked or was not redacted: %q", out)
	}
	// a harmless call goes straight through
	c = exec.Command("bash", "-c", "cat "+rc+" | head -1")
	c.Env = []string{"PATH=" + dir + ":" + os.Getenv("PATH"), "HOME=" + dir, "BASH_ENV=" + rc}
	if out, err := c.Output(); err != nil || !strings.HasPrefix(string(out), "# ai-hooks") {
		t.Errorf("harmless cat: %v %q", err, out)
	}
}

func TestMCPEndToEnd(t *testing.T) {
	out, _, code := run(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`+"\n"+
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"redact","arguments":{"text":"AKIAIOSFODNN7EXAMPLE"}}}`+"\n", nil, "mcp")
	if code != 0 || strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") || strings.Count(out, "\n") != 2 {
		t.Errorf("mcp: %q code=%d", out, code)
	}
}
