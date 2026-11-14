package guard

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

//go:embed rules.schema.json
var schemaJSON []byte

// SchemaJSON is the JSON Schema of the rules file.
func SchemaJSON() []byte { return schemaJSON }

// RuleInfo describes one rule for listings.
type RuleInfo struct {
	ID   string
	Kind string // "redact" (data) or "structural" (code)
	Why  string
}

var structuralRules = []RuleInfo{
	{"print-secret-file", "structural", "a secrets file (.env style, /proc/*/environ) read by something that prints"},
	{"echo-secret-var", "structural", "echo/printf of a secret-named variable to the terminal"},
	{"dump-env", "structural", "environment dumps: env, printenv, docker inspect, systemctl show Environment, declare -p"},
	{"xtrace", "structural", "set -x / bash -x around something that touches secrets"},
	{"curl-verbose", "structural", "curl -v with a secret variable in a header (the trace goes to stderr)"},
	{"background-secret", "structural", "a secret expanded into the argv of a background process (visible in ps)"},
}

// Rules lists every rule in effect (defaults plus the user file).
func Rules() []RuleInfo {
	var out []RuleInfo
	e, _ := getEngine()
	if e != nil {
		for _, r := range e.rules {
			out = append(out, RuleInfo{r.ID, "redact", r.Why})
		}
	}
	return append(out, structuralRules...)
}

// ValidateFile checks a rules file against the format; it returns one message per problem.
func ValidateFile(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return []string{err.Error()}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return []string{err.Error()}
	}
	var errs []string
	if c.Version != 0 && c.Version != 1 {
		errs = append(errs, fmt.Sprintf("version %d is not supported (use 1)", c.Version))
	}
	idRe := regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	seen := map[string]bool{}
	for i, r := range c.RedactRules {
		if !idRe.MatchString(r.ID) {
			errs = append(errs, fmt.Sprintf("redact_rules[%d]: id %q must be lower-case letters, digits and dashes", i, r.ID))
		}
		if seen[r.ID] {
			errs = append(errs, fmt.Sprintf("redact_rules[%d]: duplicate id %q", i, r.ID))
		}
		seen[r.ID] = true
		if r.Why == "" {
			errs = append(errs, fmt.Sprintf("redact_rules[%d]: why is required", i))
		}
		if len(r.Match) == 0 {
			errs = append(errs, fmt.Sprintf("redact_rules[%d]: match needs at least one regex", i))
		}
		for _, m := range append(append([]string{}, r.Match...), r.Unless...) {
			if _, err := regexp.Compile(m); err != nil {
				errs = append(errs, fmt.Sprintf("redact_rules[%d]: bad regex %q: %v", i, m, err))
			}
		}
	}
	for _, group := range [][]string{c.SecretPaths, c.Allow, c.Redactors} {
		for _, m := range group {
			if _, err := regexp.Compile(m); err != nil {
				errs = append(errs, fmt.Sprintf("bad regex %q: %v", m, err))
			}
		}
	}
	return errs
}
