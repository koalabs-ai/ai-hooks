package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestEngine(t *testing.T) *engine {
	t.Helper()
	e, err := newEngine("")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestDecisions(t *testing.T) {
	block := map[string]string{
		"journalctl -u app -n 50":             "journalctl-unit",
		"journalctl --unit=app --since today": "", // --unit= is not the spaced form; falls to allow below
		"systemctl cat app.service":           "systemctl-cat-show",
		"systemctl --user show app":           "systemctl-cat-show",
		"cat .env":                            "read-env-file",
		"cat /etc/app-secrets/db":             "read-env-file",
		"printenv":                            "printenv",
		"env":                                 "env-dump",
		"env | sort":                          "env-dump",
		"docker inspect web":                  "docker-inspect",
		"docker exec web env":                 "env-dump",
		"kubectl get secret db -o yaml":       "kubectl-secret",
		"ssh host 'journalctl -u app'":        "journalctl-unit",
		"ssh host cat .env":                   "read-env-file",
		"grep DB_ .env":                       "print-secret-file",
		"echo $DB_PASSWORD":                   "echo-secret-var",
		"set -x; curl -H \"X-Key: $API_TOKEN\" https://x.test":           "xtrace",
		"curl -v -H \"Authorization: Bearer $API_TOKEN\" https://x.test": "curl-verbose",
		"curl -H \"X-Key: $API_TOKEN\" https://x.test &":                 "background-secret",
		"cat .env.production":         "read-env-file",
		"bash <<'EOF'\ncat .env\nEOF": "read-env-file",
		"echo \"$(cat .env)\"":        "read-env-file",
	}
	allow := []string{
		"journalctl -u app -n 50 2>&1 | ai-hooks redact",
		"cat .env | ai-hooks redact",
		"cat .env.example",
		"cut -d= -f1 .env",
		"grep -c TOKEN .env",
		"sha256sum .env",
		"ls -la",
		"git status",
		"go test ./...",
		"echo $PWD",
		"echo $TOKEN_FILE",
		"git commit -m 'document the .env file'",
		"journalctl --unit=app --since today",
		"printenv HOME",
		"cat README.md",
		"cat .env # noredact",
		"cat .env # ai-hooks: ok",
		"curl -v -H \"X-Key: $API_TOKEN\" https://x.test 2>/dev/null",
		"sed -i s/a/b/ .env",
		"cat <<EOF > notes.txt\nsee .env for details\nEOF",
	}
	e := newTestEngine(t)
	for cmd, want := range block {
		r := e.decide(cmd, false)
		if want == "" {
			continue
		}
		if !r.Blocked || r.Rule != want {
			t.Errorf("%q: got blocked=%v rule=%q, want %q", cmd, r.Blocked, r.Rule, want)
		}
	}
	for _, cmd := range allow {
		if r := e.decide(cmd, false); r.Blocked {
			t.Errorf("%q should be allowed, blocked by %s (%s)", cmd, r.Rule, r.Detail)
		}
	}
}

func TestOverrideIsReported(t *testing.T) {
	e := newTestEngine(t)
	r := e.decide("cat .env # noredact", false)
	if r.Blocked || r.Overridden != "noredact" || r.Rule != "read-env-file" {
		t.Errorf("got %+v", r)
	}
	r = e.decide("grep K .env # ai-hooks: ok", false)
	if r.Blocked || r.Overridden != "ok" {
		t.Errorf("got %+v", r)
	}
}

func TestMessageIsOneLineEnglish(t *testing.T) {
	r := newTestEngine(t).decide("journalctl -u app", false)
	m := r.Message()
	if strings.Contains(m, "\n") || !strings.Contains(m, "ai-hooks redact") || !strings.Contains(m, "# noredact") {
		t.Errorf("bad message: %q", m)
	}
}

func TestUserRules(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "rules.json")
	os.WriteFile(f, []byte(`{
	  "redact_rules":[{"id":"consul-read","why":"consul kv get prints values","match":["\\bconsul\\s+kv\\s+get\\b"]}],
	  "disable":["kubectl-secret"],
	  "allow":["^git "],
	  "secret_paths":["[\\w./-]*\\.pem"]
	}`), 0o600)
	e, err := newEngine(f)
	if err != nil {
		t.Fatal(err)
	}
	if r := e.decide("consul kv get app/db", false); !r.Blocked || r.Rule != "consul-read" {
		t.Errorf("user rule not applied: %+v", r)
	}
	if r := e.decide("kubectl get secret db", false); r.Blocked {
		t.Errorf("disabled rule still blocks")
	}
	if r := e.decide("git log -p .env", false); r.Blocked {
		t.Errorf("allow regex ignored")
	}
	if r := e.decide("cat server.pem", false); !r.Blocked || r.Rule != "print-secret-file" {
		t.Errorf("secret_paths not applied: %+v", r)
	}
}

func TestBadUserFileKeepsDefaults(t *testing.T) {
	f := filepath.Join(t.TempDir(), "rules.json")
	os.WriteFile(f, []byte("{not json"), 0o600)
	e, err := newEngine(f)
	if err == nil || e == nil {
		t.Fatal("expected a warning and a working engine")
	}
	if !e.decide("printenv", false).Blocked {
		t.Error("defaults lost")
	}
}

func TestFailOpenOnGarbage(t *testing.T) {
	e := newTestEngine(t)
	for _, c := range []string{"", "\x00\xff\xfe", strings.Repeat("(", 5000), strings.Repeat("echo $(", 200)} {
		_ = e.decide(c, false) // must not panic
	}
}
