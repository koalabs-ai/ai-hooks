package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
)

const aws = "AKIAIOSFODNN7EXAMPLE"

func mustHide(t *testing.T, name, in string) {
	t.Helper()
	out := Redact(in, nil)
	if strings.Contains(out, aws) || strings.Contains(out, "IOSFODNN7") {
		t.Errorf("%s: secret survived:\n in:  %q\n out: %q", name, in, out)
	}
	if !strings.Contains(out, "<REDACTED:") {
		t.Errorf("%s: nothing was redacted: %q", name, out)
	}
}

func TestBypassANSIColourCodes(t *testing.T) {
	mustHide(t, "colour around", "\x1b[31m"+aws+"\x1b[0m")
	mustHide(t, "colour inside", "AKIA\x1b[1mIOSFODNN7\x1b[0mEXAMPLE")
	mustHide(t, "grep --color style", "KEY=\x1b[01;31m\x1b[K"+aws+"\x1b[m\x1b[K")
	mustHide(t, "OSC hyperlink", "\x1b]8;;http://x\x07"+aws+"\x1b]8;;\x07")
}

func TestBypassZeroWidthAndSoftHyphen(t *testing.T) {
	mustHide(t, "zwsp", "AKIA\u200bIOSFODNN7EXAMPLE")
	mustHide(t, "zwj + bom", "AKIA\u200dIOSF\xef\xbb\xbfODNN7EXAMPLE")
	mustHide(t, "soft hyphen", "AKIAIOSF\u00adODNN7EXAMPLE")
}

func TestBypassLineEndings(t *testing.T) {
	mustHide(t, "crlf", "KEY="+aws+"\r\nnext\r\n")
	mustHide(t, "lone cr", "a\r"+aws+"\rb")
	mustHide(t, "tabs", "\t"+aws+"\t")
}

func TestBypassEscapedForms(t *testing.T) {
	mustHide(t, "json \\u escape", `{"k":"AKIAIOSFODNN7EXAMPLE"}`)
	mustHide(t, "json \\x escape", `"\x41KIAIOSFODNN7EXAMPLE"`)
	mustHide(t, "url encoded", "https://x/?k=AKIAIOSFODNN7%45XAMPLE")
	mustHide(t, "literal \\n before token", `{"out":"line1\n`+aws+`"}`)
	mustHide(t, "literal \\t before token", `a\t`+aws)
}

func TestBypassJSONValueWithEscapes(t *testing.T) {
	out := Redact(`{"password": "Tr0ub4dor&x1y2z3"}`, nil)
	if strings.Contains(out, "Tr0ub4dor") {
		t.Errorf("json password with escape survived: %q", out)
	}
}

func TestBypassUTF16Input(t *testing.T) {
	for _, bom := range []bool{true, false} {
		u := utf16.Encode([]rune("log: " + aws + "\nend\n"))
		var b bytes.Buffer
		if bom {
			b.Write([]byte{0xFF, 0xFE})
		}
		for _, x := range u {
			b.WriteByte(byte(x))
			b.WriteByte(byte(x >> 8))
		}
		data, _ := io.ReadAll(TextReader(&b))
		out := Redact(string(data), nil)
		if strings.Contains(out, aws) || !strings.Contains(out, "REDACTED:aws-access-key") {
			t.Errorf("utf-16 (bom=%v): %q", bom, out)
		}
	}
	// UTF-8 BOM is dropped
	data, _ := io.ReadAll(TextReader(strings.NewReader("\xef\xbb\xbf" + aws)))
	if string(data) != aws {
		t.Errorf("utf-8 bom: %q", data)
	}
	// UTF-16BE with BOM
	var b bytes.Buffer
	b.Write([]byte{0xFE, 0xFF})
	for _, x := range utf16.Encode([]rune(aws)) {
		b.WriteByte(byte(x >> 8))
		b.WriteByte(byte(x))
	}
	data, _ = io.ReadAll(TextReader(&b))
	if string(data) != aws {
		t.Errorf("utf-16be: %q", data)
	}
}

func TestPEMCutMidBlock(t *testing.T) {
	body := strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldY\n", 8)
	// output cut short: BEGIN line and key material, no END
	out := Redact("before\n-----BEGIN OPENSSH PRIVATE KEY-----\n"+body, nil)
	if strings.Contains(out, "QUJDREVG") {
		t.Errorf("truncated key leaked: %q", out)
	}
	// stream: unterminated block at EOF is replaced, never printed
	var b bytes.Buffer
	Stream(strings.NewReader("x\n-----BEGIN PRIVATE KEY-----\n"+body), &b, nil, nil)
	if strings.Contains(b.String(), "QUJDREVG") || !strings.Contains(b.String(), "REDACTED") {
		t.Errorf("stream leaked an unterminated block: %q", b.String())
	}
	// a huge block that never ends does not grow memory without bound and is not printed
	big := strings.NewReader("-----BEGIN PRIVATE KEY-----\n" + strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldY\n", 100000))
	b.Reset()
	Stream(big, &b, nil, nil)
	if strings.Contains(b.String(), "QUJDREVG") {
		t.Error("huge unterminated block leaked")
	}
}

type slowReader struct {
	data []byte
	step int
}

func (s *slowReader) Read(p []byte) (int, error) {
	if len(s.data) == 0 {
		return 0, io.EOF
	}
	n := s.step
	if n > len(s.data) {
		n = len(s.data)
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, s.data[:n])
	s.data = s.data[n:]
	return n, nil
}

func TestPartialWritesAndChunkBoundaries(t *testing.T) {
	in := "start\nexport API_TOKEN=\"abcdefghijklmnopqrstuvwxyz0123\"\nkey " + aws + " end\n-----BEGIN PRIVATE KEY-----\nQUJDREVG\n-----END PRIVATE KEY-----\nlast\n"
	for _, step := range []int{1, 2, 3, 7, 13, 64} {
		var b bytes.Buffer
		Stream(&slowReader{data: []byte(in), step: step}, &b, nil, nil)
		o := b.String()
		for _, leak := range []string{aws, "abcdefghijklmnopqrstuvwxyz0123", "QUJDREVG"} {
			if strings.Contains(o, leak) {
				t.Errorf("step %d leaked %q: %q", step, leak, o)
			}
		}
		if b.String() != Redact(in, nil) {
			t.Errorf("step %d: stream differs from whole-text redaction", step)
		}
	}
}

func TestVeryLongLineStaysBoundedAndRedacted(t *testing.T) {
	line := strings.Repeat("x ", 3<<20) + aws + strings.Repeat(" y", 100) + "\n" // ~6 MB, one line
	var b bytes.Buffer
	st := time.Now()
	Stream(strings.NewReader(line), &b, nil, nil)
	if strings.Contains(b.String(), aws) {
		t.Error("secret inside a very long line survived")
	}
	if time.Since(st) > 60*time.Second {
		t.Error("very long line took too long")
	}
	// no whitespace at all: still terminates, memory bounded by maxLine pieces
	b.Reset()
	Stream(strings.NewReader(strings.Repeat("a", 9<<20)), &b, nil, nil)
	if b.Len() != 9<<20 {
		t.Errorf("lost data: %d", b.Len())
	}
}

func TestBinaryAndHostileInputDoesNotPanic(t *testing.T) {
	inputs := []string{"", "\x00\x00\x00", "\xff\xfe\xfd", strings.Repeat("\x1b[", 10000), strings.Repeat("%", 100000), strings.Repeat(`\u`, 50000),
		strings.Repeat("-----BEGIN PRIVATE KEY-----", 2000), strings.Repeat("A", 1<<20), strings.Repeat("a=", 200000)}
	for i, in := range inputs {
		done := make(chan struct{})
		go func() { defer close(done); Redact(in, nil) }()
		select {
		case <-done:
		case <-time.After(60 * time.Second):
			t.Fatalf("input %d took too long (possible catastrophic behaviour)", i)
		}
	}
}

func TestNormalTextIsReturnedExactly(t *testing.T) {
	for _, in := range []string{"plain\n", "colour \x1b[31mred\x1b[0m text\n", "zero\u200bwidth ok", "100% sure \\u00e9 and %41\n", "\r\n"} {
		if got := Redact(in, nil); got != in {
			t.Errorf("changed clean text %q -> %q", in, got)
		}
	}
}

// ---------------------------------------------------------------- fingerprints

func TestFingerprintIsKeyedPerInstall(t *testing.T) {
	dir := t.TempDir()
	run := func(keyFile string) string {
		t.Setenv("AI_HOOKS_FINGERPRINT_KEY_FILE", keyFile)
		resetFP()
		return fp("hunter2hunter2")
	}
	a := run(filepath.Join(dir, "a.key"))
	a2 := run(filepath.Join(dir, "a.key"))
	b := run(filepath.Join(dir, "b.key"))
	if a != a2 {
		t.Error("the same install must give the same fingerprint")
	}
	if a == b {
		t.Error("different installs must give different fingerprints")
	}
	plain := func() string {
		t.Setenv("AI_HOOKS_FINGERPRINT", "plain")
		resetFP()
		defer t.Setenv("AI_HOOKS_FINGERPRINT", "")
		return fp("hunter2hunter2")
	}()
	if plain == a || len(plain) != 8 {
		t.Errorf("plain construction expected to differ from keyed: %q %q", plain, a)
	}
	st, err := os.Stat(filepath.Join(dir, "a.key"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v %v", st, err)
	}
	t.Setenv("AI_HOOKS_FINGERPRINT", "")
	resetFP()
}

// A fingerprint of a weak secret must not let someone confirm a guess with plain sha256.
func TestFingerprintDoesNotMatchPlainSHA(t *testing.T) {
	t.Setenv("AI_HOOKS_FINGERPRINT_KEY_FILE", filepath.Join(t.TempDir(), "k"))
	resetFP()
	for _, weak := range []string{"hunter2", "password1", "letmein123"} {
		if fp(weak) == fpPlain(weak) {
			t.Errorf("fingerprint of %q equals its plain sha256 prefix", weak)
		}
	}
	resetFP()
}

// ---------------------------------------------------------------- documented limits (these are expected NOT to be caught)

func TestKnownLimitsRemainDocumented(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(aws))
	if strings.Contains(Redact(b64, nil), "REDACTED") {
		t.Log("base64-encoded secrets are now detected: update docs/SECURITY-MODEL.md and README limits")
	}
	if strings.Contains(Redact(hex.EncodeToString([]byte(aws)), nil), "REDACTED") {
		t.Log("hex-encoded secrets are now detected: update docs/SECURITY-MODEL.md and README limits")
	}
	// a secret split across two lines is not seen by the line-based filter (and not by the whole-text one)
	if strings.Contains(Redact("AKIAIOSFODNN7\nEXAMPLE", nil), "REDACTED") {
		t.Log("line-split secrets are now detected: update the docs")
	}
}

func resetFP() {
	fpKey = nil
	fpOnce = sync.Once{}
}
