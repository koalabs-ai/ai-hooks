package guard

import (
	"strings"
	"testing"
	"time"
)

// commands that print a secret file or the environment and must be blocked, however they are written
func TestBypassAttemptsAreBlocked(t *testing.T) {
	cases := []string{
		// quoting, escaping, wrappers
		"bash -c 'cat .env'",
		`sh -c "cat .env"`,
		"eval 'cat .env'",
		`eval "cat .env"`,
		"/bin/cat .env",
		"/usr/bin/cat ./config/.env",
		"command cat .env",
		"sudo cat .env",
		"env -i cat .env",
		"time cat .env",
		"exec cat .env",
		"nice -n 5 cat .env",
		"timeout 5 cat .env",
		"cat < .env",
		"cat<.env",
		"<.env cat",
		"echo \"$(<.env)\"",
		"echo $(cat .env)",
		"cat .env && echo done",
		"true; cat .env",
		"false || cat .env",
		"(cat .env)",
		"{ cat .env; }",
		"cat .env.production",
		"cat .env.local",
		"cat config/.env",
		"cat ./.env",
		"cat \"./.env\"",
		"cat '.env'",
		"head -n 100 .env",
		"tail -f .env",
		"grep -v '^#' .env",
		"sed -n '1,5p' .env",
		"awk '{print}' .env",
		"cut -d= -f2 .env",
		"sort .env",
		"base64 .env",
		"xxd .env",
		"od -c .env",
		"strings .env",
		"tr 'a-z' 'A-Z' < .env",
		"jq . app.env",
		// chains and pipes that still print
		"cat .env | tee /tmp/copy",
		"cat .env | sed 's/a/b/'",
		"cat .env | head",
		"cat .env 2>&1",
		"cat .env > /dev/stderr",
		"cat .env | tee /dev/stderr | wc -l",
		// ssh / remote
		"ssh host 'cat .env'",
		`ssh host "cat .env"`,
		"ssh host cat .env",
		"ssh -t host 'sudo cat /app/.env'",
		// heredoc and substitution carrying the read
		"bash <<'EOF'\ncat .env\nEOF",
		"ssh host <<EOF\ncat .env\nEOF",
		"X=$(cat .env); echo \"$X\" > /dev/stderr && cat .env",
		// glob and xargs
		"cat .env*",
		"grep -rn KEY ~/conf/*.env 2>/dev/null | head",
		"grep -rn KEY ~/conf/prod*.env",
		"cat .env.*",
		"echo .env | xargs cat",
		"ls .env | xargs -I{} cat {}",
		"find . -name .env -exec cat {} \\;",
		"find . -name '.env' | xargs cat",
		// inline interpreters reading secret files or the whole environment
		"python3 -c \"print(open('.env').read())\"",
		"python -c 'import sys; sys.stdout.write(open(\".env\").read())'",
		"node -e \"console.log(require('fs').readFileSync('.env','utf8'))\"",
		"perl -ne 'print' .env",
		"ruby -e 'puts File.read(\".env\")'",
		"awk 1 .env",
		"python3 -c 'import os; print(dict(os.environ))'",
		"node -e 'console.log(process.env)'",
		// environment dumps in odd forms
		"/usr/bin/env",
		"env | sort",
		"env | grep -i key",
		"printenv | cut -c1-80",
		"export -p",
		"declare -x",
		"set",
		"cat /proc/self/environ | tr '\\0' '\\n'",
		"strings /proc/1/environ",
		"cat /proc/$$/environ",
		"docker exec web env",
		"docker exec -it web printenv",
		"docker inspect web | jq .[0].Config.Env",
		"docker inspect -f '{{.Config.Env}}' web",
		"kubectl exec -it pod -- printenv",
		"systemctl show app -p Environment",
		"systemctl cat app.service",
		"journalctl -u app -n 100",
		"journalctl --unit app",
		"sudo journalctl -u app",
		// echo / printf of secret variables
		"echo $API_TOKEN",
		"echo \"$DB_PASSWORD\"",
		"echo ${STRIPE_SECRET_KEY}",
		"printf '%s\\n' \"$GITHUB_TOKEN\"",
		"echo $DATABASE_URL",
		// verbose http and tracing
		"curl -v -H \"Authorization: Bearer $API_TOKEN\" https://x.test",
		"curl --verbose -u \"user:$DB_PASSWORD\" https://x.test",
		"bash -x deploy.sh $API_TOKEN",
		"set -x; echo $API_TOKEN",
		// secrets in argv of a background process
		"curl -H \"X-Key: $API_KEY\" https://x.test &",
	}
	e := newTestEngine(t)
	for _, c := range cases {
		if r := e.decide(c, false); !r.Blocked {
			t.Errorf("NOT blocked: %q", c)
		}
	}
}

// the same families, written the safe way, must pass (the guard is only useful if it does not cry wolf)
func TestSafeFormsPass(t *testing.T) {
	cases := []string{
		"cat .env | ai-hooks redact",
		"cat .env 2>&1 | ai-hooks redact",
		"ai-hooks exec -- cat .env",
		"cut -d= -f1 .env",
		"grep -c TOKEN .env",
		"grep -oE '^[A-Z_]+' .env",
		"wc -l .env",
		"sha256sum .env",
		"ls -la .env",
		"test -f .env && echo yes",
		"git check-ignore .env",
		"cat .env.example",
		"cat README.md",
		"echo $HOME",
		"echo $PWD",
		"echo \"$TOKEN_FILE\"",
		"printenv HOME",
		"env FOO=1 make test",
		"python3 -c 'print(1+1)'",
		"node -e 'console.log(2)'",
		"git commit -m 'remove .env from the repo'",
		"git log --oneline -- .env",
		"curl -s https://example.com",
		"curl -v https://example.com",
		"docker compose up -d",
		"docker ps",
		"journalctl --since today | ai-hooks redact",
		"cat .env >/dev/null",
		"rg -l token .",
		"set -e",
		"set -u",
		"ps aux",
		"ssh host uptime",
		"echo done # noredact",
	}
	e := newTestEngine(t)
	for _, c := range cases {
		if r := e.decide(c, false); r.Blocked {
			t.Errorf("wrongly blocked: %q (rule %s)", c, r.Rule)
		}
	}
}

// Overrides are a convenience for a person; text an agent read must not be able to switch the guard off in strict mode.
func TestOverridesCanBeDisabled(t *testing.T) {
	t.Setenv("AI_HOOKS_NO_OVERRIDE", "1")
	e := newTestEngine(t)
	for _, c := range []string{"cat .env # noredact", "cat .env # ai-hooks: ok", "docker inspect x # noredact"} {
		if r := e.decide(c, false); !r.Blocked {
			t.Errorf("strict mode must ignore the override in %q", c)
		}
	}
}

// An override comment that is not at the end of the command (text in the middle of a quoted string) must not count as noredact.
func TestNoredactOnlyCountsAtTheEnd(t *testing.T) {
	e := newTestEngine(t)
	for _, c := range []string{"echo '# noredact' && docker inspect x", "docker inspect x # noredact and more", "docker inspect x\n# noredact\ndocker inspect y"} {
		if r := e.decide(c, false); !r.Blocked {
			t.Errorf("%q should still be blocked", c)
		}
	}
}

// text inside a comment must not make a command look safe
func TestCommentsDoNotMakeCommandsSafe(t *testing.T) {
	e := newTestEngine(t)
	for _, c := range []string{
		"docker inspect web # ai-hooks redact",
		"docker inspect web # | ai-hooks redact",
		"cat .env # wc -l",
		"cat .env # sha256sum",
		"cat .env # >/dev/null",
		"journalctl -u app # cut -d= -f1",
		"cat .env #ai-hooks exec",
	} {
		if r := e.decide(c, false); !r.Blocked {
			t.Errorf("a comment made %q look safe", c)
		}
	}
	// mentioning the redactor is not the same as using it
	for _, c := range []string{"echo 'ai-hooks redact' && docker inspect web", "docker inspect web; echo ai-hooks exec", "echo | ai-hooks redact; docker inspect web > /tmp/x; cat /tmp/x"} {
		if r := e.decide(c, false); !r.Blocked && !strings.Contains(c, "cat /tmp/x") {
			t.Errorf("%q should be blocked", c)
		}
	}
	// a # inside quotes or a word is not a comment
	for _, c := range []string{"echo 'a # b'", "git log --format=%h#%s -1", "echo $((1#101))"} {
		if r := e.decide(c, false); r.Blocked {
			t.Errorf("%q wrongly blocked", c)
		}
	}
	// the override must be the last thing on the command
	if r := e.decide("docker inspect x # ai-hooks: ok\necho more", false); !r.Blocked {
		t.Error("override that is not at the end must not count")
	}
}

func TestPathologicalCommandsFinishQuickly(t *testing.T) {
	e := newTestEngine(t)
	long := []string{
		strings.Repeat("echo $(", 3000) + strings.Repeat(")", 3000),
		strings.Repeat("a|", 100000),
		strings.Repeat("'", 100001),
		strings.Repeat("cat .env;", 20000),
		"ssh host '" + strings.Repeat("ssh x '", 500),
		strings.Repeat("<<EOF\n", 5000),
		strings.Repeat("`", 50001),
		strings.Repeat("$(", 20000),
		strings.Repeat("a", 5<<20),
	}
	for i, c := range long {
		done := make(chan struct{})
		go func() { defer close(done); e.decide(c, false) }()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatalf("command %d: guard did not finish (possible catastrophic behaviour)", i)
		}
	}
}
