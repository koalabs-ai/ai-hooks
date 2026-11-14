package redact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFingerprintIsStable(t *testing.T) {
	in := "a AKIAIOSFODNN7EXAMPLE b AKIAIOSFODNN7EXAMPLE c"
	out := Redact(in, nil)
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("value survived")
	}
	parts := strings.Fields(out)
	if parts[1] != parts[3] || !strings.HasPrefix(parts[1], "<REDACTED:aws-access-key:") {
		t.Errorf("fingerprints differ or wrong type: %q", out)
	}
}

func TestReportNeverHoldsValues(t *testing.T) {
	_, rep := RedactReport("DB_PASSWORD=abcdefghijklmnopqrstuvwxyz", nil)
	for k := range rep {
		if strings.Contains(k, "abcdefgh") {
			t.Error("report leaks value")
		}
	}
	if rep["env-secret"] != 1 {
		t.Errorf("report: %v", rep)
	}
}

func TestInvocationIdIsNotASecret(t *testing.T) {
	for _, s := range []string{
		"_SYSTEMD_INVOCATION_ID=0f2b6c1d8e9a4b3c9d7e5f1a2b3c4d5e _X=1",
		"     Invocation: 0f2b6c1d8e9a4b3c9d7e5f1a2b3c4d5e\n",
	} {
		if got := Redact(s, nil); got != s {
			t.Errorf("changed: %q -> %q", s, got)
		}
	}
	if got := Redact("twilio auth 0f2b6c1d8e9a4b3c9d7e5f1a2b3c4d5e ", nil); !strings.Contains(got, "<REDACTED:twilio-auth-token:") {
		t.Errorf("a bare 32-hex token must still be redacted: %q", got)
	}
}

func TestStreamMatchesWholeTextOnSingleLineSecrets(t *testing.T) {
	in := "line one\nexport API_KEY=\"abcdefghijklmnopqrstuvwxyz0123\"\n-----BEGIN PRIVATE KEY-----\nQUJDREVGR0g=\nSUpLTE1OT1A=\n-----END PRIVATE KEY-----\ndone\n"
	var b bytes.Buffer
	counts := map[string]int{}
	if err := Stream(strings.NewReader(in), &b, nil, counts); err != nil {
		t.Fatal(err)
	}
	if b.String() != Redact(in, nil) {
		t.Errorf("stream differs:\n%s\nvs\n%s", b.String(), Redact(in, nil))
	}
	if counts["private-key-pem"] != 1 {
		t.Errorf("counts %v", counts)
	}
}

func TestStreamKeepsUnterminatedFinalLine(t *testing.T) {
	var b bytes.Buffer
	Stream(strings.NewReader("no newline at end"), &b, nil, nil)
	if b.String() != "no newline at end" {
		t.Errorf("%q", b.String())
	}
}

func TestKnownHashLayer(t *testing.T) {
	val := "plain-looking-value-without-shape-0001"
	sum := sha256.Sum256([]byte(val))
	f := filepath.Join(t.TempDir(), "known.txt")
	os.WriteFile(f, []byte(hex.EncodeToString(sum[:])+" my-service\n"), 0o600)
	t.Setenv("AI_HOOKS_KNOWN_HASHES", f)
	known := LoadKnown()
	out := Redact("value is "+val+" ok", known)
	if strings.Contains(out, val) || !strings.Contains(out, "<REDACTED:known-my-service:") {
		t.Errorf("got %q", out)
	}
	t.Setenv("AI_HOOKS_KNOWN_HASHES", filepath.Join(t.TempDir(), "missing"))
	if len(LoadKnown()) != 0 {
		t.Error("missing file must mean no known values")
	}
}

func TestEveryTypeIsExplained(t *testing.T) {
	for _, ty := range Types() {
		if _, ok := Explain(ty); !ok {
			t.Errorf("no explanation for %s", ty)
		}
	}
}

func TestPlainTextPassesThroughUnchanged(t *testing.T) {
	in := "The quick brown fox.\nSee https://example.com/a/b?c=d and run `make test`.\n"
	if Redact(in, nil) != in {
		t.Error("changed")
	}
}
