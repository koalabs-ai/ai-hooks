package redact

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf16"
	"unicode/utf8"
)

// ---------------------------------------------------------------- fingerprints

// A fingerprint is the first 8 hex digits of HMAC-SHA256(key, value). The key is
// random and local to the install (stored with owner-only permissions), so a
// fingerprint seen in a transcript cannot be used to confirm a guess at a
// low-entropy secret. The same value has the same fingerprint on every line and
// in every run on the same machine; it differs between machines.
//
// AI_HOOKS_PARITY=1 or AI_HOOKS_FINGERPRINT=plain use the plain first 8 hex
// digits of sha256(value) instead (the original construction): stable
// everywhere, but guessable offline for weak secrets.

var (
	fpOnce sync.Once
	fpKey  []byte
)

func fpKeyPath() string {
	if p := os.Getenv("AI_HOOKS_FINGERPRINT_KEY_FILE"); p != "" {
		return p
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "ai-hooks", "fingerprint.key")
}

func loadFPKey() {
	if Parity || os.Getenv("AI_HOOKS_FINGERPRINT") == "plain" {
		return
	}
	if h := os.Getenv("AI_HOOKS_FINGERPRINT_KEY"); len(h) >= 32 {
		if k, err := hex.DecodeString(h); err == nil {
			fpKey = k
			return
		}
	}
	p := fpKeyPath()
	if p == "" {
		return
	}
	if st, err := os.Stat(p); err == nil && st.Mode().Perm()&0o077 != 0 {
		_ = os.Chmod(p, 0o600) // a key other users can read defeats its purpose: tighten it
	}
	if b, err := os.ReadFile(p); err == nil && len(b) >= 32 {
		if k, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && len(k) >= 16 {
			fpKey = k
			return
		}
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err == nil {
		// O_EXCL: two processes racing to create it end up with the same key
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			f.WriteString(hex.EncodeToString(k) + "\n")
			f.Close()
			fpKey = k
			return
		}
		if b, err := os.ReadFile(p); err == nil {
			if kk, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && len(kk) >= 16 {
				fpKey = kk
			}
		}
	}
	// could not persist a key: stay with the plain construction rather than use a key that changes every run
}

// fpPlain is the original construction: first 8 hex digits of sha256(value).
func fpPlain(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])[:8]
}

func fp(v string) string {
	fpOnce.Do(loadFPKey)
	if fpKey == nil {
		h := sha256.Sum256([]byte(v))
		return hex.EncodeToString(h[:])[:8]
	}
	m := hmac.New(sha256.New, fpKey)
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))[:8]
}

// ---------------------------------------------------------------- normalisation

var ansiRe = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]`)

// zeroWidth: characters that are invisible and can be used to break a token apart.
const zeroWidth = "\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e"

// normalize removes what hides a secret from a pattern without changing what a
// reader sees: ANSI escape sequences (colour codes) and zero-width characters.
func normalize(s string) string {
	if strings.IndexByte(s, 0x1b) >= 0 {
		s = ansiRe.ReplaceAllString(s, "")
	}
	// lead bytes of the zero-width characters: skip the rune scan when none is present
	if (strings.IndexByte(s, 0xE2) >= 0 || strings.IndexByte(s, 0xEF) >= 0 || strings.IndexByte(s, 0xC2) >= 0 || strings.IndexByte(s, 0xE1) >= 0) && strings.ContainsAny(s, zeroWidth) {
		s = strings.Map(func(r rune) rune {
			if strings.ContainsRune(zeroWidth, r) {
				return -1
			}
			return r
		}, s)
	}
	return s
}

var (
	reUEsc = regexp.MustCompile(`\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|%([0-9a-fA-F]{2})`)
)

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(a, b byte) int {
	v := func(c byte) int {
		switch {
		case c >= '0' && c <= '9':
			return int(c - '0')
		case c >= 'a' && c <= 'f':
			return int(c-'a') + 10
		}
		return int(c-'A') + 10
	}
	return v(a)<<4 | v(b)
}

func isTokenByte(v int) bool {
	return v >= '0' && v <= '9' || v >= 'A' && v <= 'Z' || v >= 'a' && v <= 'z' || v == '-' || v == '_' || v == '.' || v == '+' || v == '/' || v == '='
}

// hasLetterEscape: a cheap single pass that says whether the text has an escape
// (%XX, \xNN, \u00XX) that stands for a character a token could contain. A %20
// or a \n does not qualify, so ordinary URLs and logs skip the decoding pass.
func hasLetterEscape(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		switch s[i] {
		case '%':
			if isHexDigit(s[i+1]) && isHexDigit(s[i+2]) && isTokenByte(hexVal(s[i+1], s[i+2])) {
				return true
			}
		case '\\':
			if s[i+1] == 'x' && i+3 < len(s) && isHexDigit(s[i+2]) && isHexDigit(s[i+3]) && isTokenByte(hexVal(s[i+2], s[i+3])) {
				return true
			}
			if s[i+1] == 'u' && i+5 < len(s) && s[i+2] == '0' && s[i+3] == '0' && isHexDigit(s[i+4]) && isHexDigit(s[i+5]) && isTokenByte(hexVal(s[i+4], s[i+5])) {
				return true
			}
		}
	}
	return false
}

// decodeEscapes turns \uXXXX, \xNN and %XX into the characters they stand for,
// so a secret that was JSON- or URL-escaped can be seen. Invalid UTF-8 results
// are left as the original text.
func decodeEscapes(s string) string {
	if !hasLetterEscape(s) {
		return s
	}
	var pend []uint16
	out := reUEsc.ReplaceAllStringFunc(s, func(m string) string {
		g := reUEsc.FindStringSubmatch(m)
		switch {
		case g[1] != "":
			n, _ := strconv.ParseUint(g[1], 16, 16)
			if n >= 0xD800 && n < 0xE000 { // surrogate halves: keep as is
				return m
			}
			return string(rune(n))
		case g[2] != "":
			n, _ := strconv.ParseUint(g[2], 16, 8)
			if n < 0x80 {
				return string(rune(n))
			}
			return m
		default:
			n, _ := strconv.ParseUint(g[3], 16, 8)
			if n >= 0x20 && n < 0x7f {
				return string(rune(n))
			}
			return m
		}
	})
	_ = pend
	return out
}

// ---------------------------------------------------------------- input encodings

// TextReader turns UTF-16 (with a BOM, or NUL-interleaved ASCII) and UTF-8 with
// a BOM into plain UTF-8, so a secret in a UTF-16 log is not hidden by the
// encoding. Anything else is passed through unchanged.
func TextReader(r io.Reader) io.Reader {
	br := bufio.NewReaderSize(r, 1<<16)
	head, _ := br.Peek(64)
	switch {
	case len(head) >= 3 && head[0] == 0xEF && head[1] == 0xBB && head[2] == 0xBF:
		br.Discard(3)
		return br
	case len(head) >= 2 && head[0] == 0xFF && head[1] == 0xFE:
		br.Discard(2)
		return &utf16Reader{r: br, le: true}
	case len(head) >= 2 && head[0] == 0xFE && head[1] == 0xFF:
		br.Discard(2)
		return &utf16Reader{r: br, le: false}
	}
	if le, ok := nulInterleaved(head); ok {
		return &utf16Reader{r: br, le: le}
	}
	return br
}

func nulInterleaved(b []byte) (le bool, ok bool) {
	if len(b) < 8 {
		return false, false
	}
	even, odd := 0, 0
	for i, c := range b {
		if c == 0 {
			if i%2 == 0 {
				even++
			} else {
				odd++
			}
		}
	}
	half := len(b) / 2
	if odd >= half*3/4 && even == 0 {
		return true, true
	}
	if even >= half*3/4 && odd == 0 {
		return false, true
	}
	return false, false
}

type utf16Reader struct {
	r   io.Reader
	le  bool
	buf []byte // decoded UTF-8 not yet returned
	odd []byte // a dangling byte from the last read
	hi  uint16 // pending high surrogate
}

func (u *utf16Reader) Read(p []byte) (int, error) {
	for len(u.buf) == 0 {
		raw := make([]byte, 8192)
		n, err := u.r.Read(raw)
		raw = append(u.odd, raw[:n]...)
		u.odd = nil
		if len(raw)%2 == 1 {
			u.odd = []byte{raw[len(raw)-1]}
			raw = raw[:len(raw)-1]
		}
		var units []uint16
		for i := 0; i+1 < len(raw); i += 2 {
			if u.le {
				units = append(units, uint16(raw[i])|uint16(raw[i+1])<<8)
			} else {
				units = append(units, uint16(raw[i+1])|uint16(raw[i])<<8)
			}
		}
		if u.hi != 0 {
			units = append([]uint16{u.hi}, units...)
			u.hi = 0
		}
		if len(units) > 0 && utf16.IsSurrogate(rune(units[len(units)-1])) && units[len(units)-1] < 0xDC00 {
			u.hi = units[len(units)-1]
			units = units[:len(units)-1]
		}
		var tmp [4]byte
		for _, r := range utf16.Decode(units) {
			k := utf8.EncodeRune(tmp[:], r)
			u.buf = append(u.buf, tmp[:k]...)
		}
		if err != nil && len(u.buf) == 0 {
			return 0, err
		}
		if err != nil {
			break
		}
	}
	n := copy(p, u.buf)
	u.buf = u.buf[n:]
	return n, nil
}
