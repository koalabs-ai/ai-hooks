package guard

import "testing"

// Under exec/safe_run every byte of output is redacted, which satisfies "pipe it through the redactor".
// Redaction goes by shape, so a weak secret printed by name is still refused.
func TestExecModeKeepsTheWeakSecretRules(t *testing.T) {
	e := newTestEngine(t)
	for _, c := range []string{"echo $DB_PASSWORD", "printf '%s' \"$API_TOKEN\"", "printenv GITHUB_TOKEN"} {
		if r := e.decide(c, true); !r.Blocked {
			t.Errorf("exec mode must still block %q", c)
		}
	}
	for _, c := range []string{"cat .env", "journalctl -u app -n 5", "docker inspect web", "printenv", "env"} {
		if r := e.decide(c, true); r.Blocked {
			t.Errorf("exec mode should allow %q (output is redacted), blocked by %s", c, r.Rule)
		}
		if r := e.decide(c, false); !r.Blocked {
			t.Errorf("without exec mode %q must be blocked", c)
		}
	}
}
