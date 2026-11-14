// Package redact replaces secret-shaped values with <REDACTED:type:fingerprint>.
//
// Two layers, applied in this order: (1) values whose sha256 appears in a
// user-supplied hash list, (2) a fixed list of shapes (provider prefixes,
// labelled values, JWTs, PEM blocks, URL credentials ...).
//
// The shape layer descends from a Python implementation built on `re`; Go's
// RE2 has no lookaround, so each Python construct is rebuilt to match the same
// text. The output was verified byte-identical to that implementation (see
// docs/PARITY.md).
//
// Go's RE2 has no lookaround, and its \s \d \b are ASCII while Python's are
// Unicode. Each Python construct is rebuilt so the match is the same:
//
//   - a lookbehind at the start of a pattern becomes a check on the text just
//     before the candidate match (pre). Lookbehinds only look at text before
//     the start, so they never change which match RE2 picks at that start;
//     when the check fails, the search moves on one character, as Python does.
//   - a trailing lookahead or \b becomes a final capture group that does
//     consume text; the match then ends where that group starts. RE2 picks
//     matches in the same priority order as Python's backtracking
//     (leftmost-first), so it chooses the same match. The search resumes at
//     the trimmed end, as Python's re.sub would.
//   - `sk-(?!ant-)` is a check right after "sk-" (mid).
//   - \s is the exact set Python's str.isspace() accepts; \d is \p{Nd};
//     a Python word character (for \b) is [\p{L}\p{N}_].
//
//   - under (?i), Python's ASCII class [A-Za-z0-9_] also takes İ ı ſ K
//     (U+0130 U+0131 U+017F U+212A), so the lookbehinds of the (?i) patterns
//     treat those as word characters too.
//
// Known differences, both outside anything a real secret looks like:
//   - Python dies on stdin that isn't valid UTF-8 (UnicodeDecodeError, no
//     output); this keeps the bytes and redacts anyway.
//   - inside a (?i) pattern, Python also lets İ/ı match i/I in keywords and
//     token classes; RE2's case folding doesn't. ſ and K do fold in both.

package redact

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
	"unsafe"
)

// pyWS is Python's \s for str patterns (== str.isspace), as a class body.
const pyWS = `\t\n\x{0b}\x{0c}\r\x{1c}-\x{1f} \x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}`

// tailB is a Python \b right after an ASCII word character: the next character
// is not a Python word character, or the text ends. Consumed and trimmed.
const tailB = `([^\p{L}\p{N}_]|$)`

// ws expands the placeholder WS inside a pattern into Python's whitespace set.
func ws(p string) string { return strings.ReplaceAll(p, `WS`, pyWS) }

const skWords = `(?:SECRET|TOKEN|PASSWORD|PASSWD|PASS|PWD|JWT|WEBHOOK|AUTH|APIKEY|API_KEY|` +
	`ACCESS_KEY|ADMIN_KEY|RELAY_KEY|SERVICE_ROLE|ANON_KEY|PRIVATE_KEY|SIGNING_KEY|` +
	`ENCRYPTION_KEY|CLIENT_SECRET|SESSION_KEY|HMAC|SALT|CIPHER|ROTATION_KEY|` +
	`BOT_KEY|HOOK_KEY|MASTER_KEY|ENC_KEY|DEK|KEK)`

type preCheck func(s string, i int) bool

type secretPat struct {
	kind   string
	src    string // the pattern, compiled on first use (most runs never need most patterns)
	re     *regexp.Regexp
	once   sync.Once
	aonce  sync.Once
	group  int      // 0 = redact the whole match, N = only group N
	pre    preCheck // lookbehind at the start; nil = none
	mid    func(s string, start int) bool
	tailed bool // last capture group is a consumed lookahead/\b: match ends at its start
	// Optional speed-up, same result: cands lists every position where a match
	// can start (ok=false = can't tell, scan everything); anch is re anchored.
	cands func(s string) (pos []int, ok bool)
	anch  *regexp.Regexp
	// needs: the pattern is skipped unless the text holds one of these literals (fold: compared lower-case).
	needs []string
	fold  bool
	// multiline: the pattern can span lines, so it runs on the whole text.
	multiline bool
	// reject: a captured value this says yes to is left alone.
	reject func(val string) bool
}

func asciiWord(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

// notAfterWord: (?<![A-Za-z0-9_]). A non-ASCII rune ends in a byte >= 0x80,
// which is never in the ASCII class, so checking one byte is exact.
func notAfterWord(s string, i int) bool { return i == 0 || !asciiWord(s[i-1]) }

// notAfterWordCI is (?<![A-Za-z0-9_]) inside a (?i) pattern.
func notAfterWordCI(s string, i int) bool {
	if i == 0 {
		return true
	}
	if asciiWord(s[i-1]) {
		return false
	}
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	return r != 0x130 && r != 0x131 && r != 0x17f && r != 0x212a
}

// wordStart is _WORD_START: (?:(?<![A-Za-z0-9_])|(?<=\\[nrt])). ci = the
// pattern has (?i), which makes [nrt] match N R T too.
func wordStart(ci bool) preCheck {
	return func(s string, i int) bool {
		if ci && notAfterWordCI(s, i) || !ci && notAfterWord(s, i) {
			return true
		}
		if i >= 2 && s[i-2] == '\\' {
			c := s[i-1]
			if ci && c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			return c == 'n' || c == 'r' || c == 't'
		}
		return false
	}
}

// Parity switches off the context exclusions below, so output is byte-identical
// to the Python original this was ported from (used by the parity checker).
var Parity = os.Getenv("AI_HOOKS_PARITY") == "1"

// hexIdentifierWords: a bare 32-hex value is a Twilio auth token, but it is also
// a systemd invocation id, an md5, an etag, a trace id ... When the same line,
// just before the value, names one of those, it is not a secret.
var hexIdentifierWords = []string{"invocation", "machine_id", "machine-id", "machine id", "boot_id", "boot-id",
	"boot id", "md5", "checksum", "etag", "digest", "hash", "sha", "integrity", "trace", "span",
	"request_id", "request-id", "request id", "container_id", "container id", "commit", "uuid", "build_id", "build-id"}

func hexNotIdentifier(s string, i int) bool {
	if !wordStart(false)(s, i) {
		return false
	}
	if Parity {
		return true
	}
	from := i - 64
	if from < 0 {
		from = 0
	}
	ctx := strings.ToLower(s[from:i])
	if nl := strings.LastIndexByte(ctx, '\n'); nl >= 0 {
		ctx = ctx[nl+1:]
	}
	for _, w := range hexIdentifierWords {
		if strings.Contains(ctx, w) {
			return false
		}
	}
	return true
}

func notAfterDigit(s string, i int) bool { return i == 0 || s[i-1] < '0' || s[i-1] > '9' }

// pyBoundaryBefore: a leading \b before a word character — the previous
// character is not a Python word character.
func pyBoundaryBefore(s string, i int) bool {
	if i == 0 {
		return true
	}
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	return !(r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r))
}

var secretPatterns []*secretPat

func sp(kind string, pre preCheck, group int, tailed bool, pattern string) *secretPat {
	return &secretPat{kind: kind, src: ws(pattern), group: group, pre: pre, tailed: tailed}
}

func (p *secretPat) rx() *regexp.Regexp {
	p.once.Do(func() {
		if p.re == nil {
			p.re = regexp.MustCompile(p.src)
		}
	})
	return p.re
}

func (p *secretPat) anchRx() *regexp.Regexp {
	p.aonce.Do(func() {
		if p.anch == nil {
			p.anch = regexp.MustCompile(`^(?:` + p.rx().String() + `)`)
		}
	})
	return p.anch
}

// Patterns compile on first use: the guard also runs on every tool call, and
// those calls must not pay for ~45 regexes they never use.
var secretOnce sync.Once

func buildSecretPatterns() {
	W, WI := wordStart(false), wordStart(true)
	secretPatterns = []*secretPat{
		sp("stripe-live", W, 0, false, `sk_live_[A-Za-z0-9_]{20,}`),
		sp("stripe-test", W, 0, false, `sk_test_[A-Za-z0-9_]{20,}`),
		sp("stripe-restricted", W, 0, false, `rk_(?:live|test)_[A-Za-z0-9_]{20,}`),
		sp("stripe-publishable", W, 0, false, `pk_(?:live|test)_[A-Za-z0-9_]{20,}`),
		sp("github-pat", W, 0, false, `gh[oprsu]_[A-Za-z0-9]{20,}`),
		sp("github-fine-pat", W, 0, false, `github_pat_[A-Za-z0-9_]{20,}`),
		sp("gitlab-pat", W, 0, false, `glpat-[A-Za-z0-9_-]{20,}`),
		sp("supabase-secret", W, 0, false, `sb_secret_[A-Za-z0-9_-]{16,}`),
		sp("supabase-publishable", W, 0, false, `sb_publishable_[A-Za-z0-9_-]{16,}`),
		sp("resend", W, 0, true, `re_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}`+tailB),
		sp("forgejo-pat", WI, 0, false, `(?i)(?:forgejo|gitea)_[a-f0-9]{40}`),
		sp("forgejo-token", WI, 1, true, `(?i)token["'WS:=]+([A-Fa-f0-9]{40})`+tailB),
		sp("aws-key-id", W, 0, true, `AKIA[0-9A-Z]{16}`+tailB),
		sp("aws-secret", nil, 1, false, `(?i)aws_secret_access_key["'WS=:]+([A-Za-z0-9/+]{40})`),
		sp("google-api", W, 0, false, `AIza[0-9A-Za-z_-]{35,}`),
		// [A-Za-z0-9_-]{16,}\b: the last character may be '-' (not a word char),
		// so the \b is "word then non-word/end" or "'-' then word".
		sp("zai-api", W, 0, true, `[a-f0-9]{32}\.[A-Za-z0-9_-]{15,}(?:[A-Za-z0-9_]([^\p{L}\p{N}_]|$)|-([\p{L}\p{N}_]))`),
		sp("anthropic", W, 0, false, `sk-ant-[A-Za-z0-9_-]{20,}`),
		{kind: "openai", src: `sk-(?:proj-)?[A-Za-z0-9_-]{20,}`, pre: W,
			mid: func(s string, start int) bool { return !strings.HasPrefix(s[start+3:], "ant-") }},
		sp("slack-bot", W, 0, false, `xox[abprs]-[A-Za-z0-9-]{10,}`),
		sp("chatwoot-bot-token", notAfterWordCI, 1, true, `(?i)(?:`+
			`CHATWOOT[A-Z0-9_]*BOT[A-Z0-9_]*TOKEN`+
			`|CHATWOOT[A-Z0-9_]*AGENT[A-Z0-9_]*BOT[A-Z0-9_]*TOKEN`+
			`|CHATWOOT[A-Z0-9_]*TOKEN`+
			`|chatwoot["'WS_-]+(?:bot["'WS_-]+)?(?:access["'WS_-]+)?token`+
			`|api["'WS_-]*access["'WS_-]+token`+
			`)["'WS:=]+([A-Za-z0-9]{24})`+tailB),
		sp("twilio-sid-secret", W, 0, true, `SK[a-f0-9]{32}`+tailB),
		sp("twilio-auth-hex", hexNotIdentifier, 0, true, `[a-f0-9]{32}(["'WS,;])`),
		sp("telegram-bot", notAfterDigit, 0, false, `\p{Nd}{8,12}:[A-Za-z0-9_-]{30,}`),
		sp("mp-token", W, 0, false, `APP_USR-[A-Za-z0-9-]{20,}`),
		sp("mp-access-test", W, 0, false, `TEST-\p{Nd}{8,15}-\p{Nd}{6}-[a-f0-9]{32}-\p{Nd}{6,12}`),
		sp("jwt", W, 0, false, `eyJ[A-Za-z0-9_=-]{8,}\.eyJ[A-Za-z0-9_=-]{8,}\.[A-Za-z0-9_=-]{8,}`),
		sp("bearer", WI, 1, false, `(?i)bearer[WS]+([A-Za-z0-9._~+/=-]{20,})`),
		sp("basic-auth", WI, 1, false, `(?i)basic[WS]+([A-Za-z0-9+/=]{20,})`),
		sp("http-secret-header", pyBoundaryBefore, 1, true,
			`(?im)(?:x-api-key|x-auth-token|authorization)["']?[WS]*:[WS]*["']?`+
				`([A-Za-z0-9._~+/=-]{8,})["']?([WS]|[,;}\]]|$)`),
		sp("uri-credentials", nil, 2, false, `([a-zA-Z][a-zA-Z0-9+.-]*://[^WS:/@]*):([^WS/@]{3,})@`),
		sp("libpq-password", notAfterWordCI, 1, false, `(?i)(?:pg)?password[WS]*=[WS]*["']?([^WS"';<]{6,})`),
		sp("env-secret-hex", notAfterWord, 2, false,
			`([A-Z][A-Z0-9_]*?`+skWords+`[A-Z0-9_]*)[WS]*[=:][WS]*["']?([A-Fa-f0-9]{24,})["']?`),
		sp("env-secret-token", notAfterWord, 2, true,
			`([A-Z][A-Z0-9_]*?`+skWords+`[A-Z0-9_]*)[WS]*[=:][WS]*["']?([A-Za-z0-9._+/=-]{20,})["']?([WS";,#]|$)`),
		sp("label-secret-hex", nil, 2, false,
			`(?i)((?:secret|access|private|admin|api|signing|encryption|master|clave|contrase[nñ]a)`+
				`[ _-]?(?:key|token)?)[WS]*[=:][WS]*[`+"`"+`"']?([A-Fa-f0-9]{20,})[`+"`"+`"']?`),
		sp("label-secret-token", nil, 2, false,
			`(?i)((?:secret|token|password|passwd|api[ _-]?key|access[ _-]?key|private[ _-]?key|`+
				`clave|contrase[nñ]a))[WS]*[=:][WS]*[`+"`"+`"']([A-Za-z0-9._+/=-]{20,})[`+"`"+`"']`),
		sp("pem", nil, 0, false,
			`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`+
				`[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`),
	}
}

// withCands attaches a candidate generator to the pattern of that kind.
func withCands(kind string, c func(string) ([]int, bool)) {
	for i := range secretPatterns {
		if secretPatterns[i].kind == kind {
			secretPatterns[i].cands = c
			return
		}
	}
	panic("no pattern " + kind)
}

func attachCands() {
	pc := prefixCands
	withCands("forgejo-pat", pc("forgejo_", "gitea_"))
	withCands("forgejo-token", pc("token"))
	withCands("aws-secret", pc("aws_secret_access_key"))
	withCands("zai-api", zaiCands)
	withCands("chatwoot-bot-token", pc("chatwoot", "api"))
	withCands("twilio-auth-hex", hexRunCands)
	withCands("telegram-bot", telegramCands)
	withCands("bearer", pc("bearer"))
	withCands("basic-auth", pc("basic"))
	withCands("http-secret-header", pc("x-api-key", "x-auth-token", "authorization"))
	withCands("uri-credentials", uriCands)
	withCands("libpq-password", pc("pgpassword", "password"))
	withCands("env-secret-hex", envCands)
	withCands("env-secret-token", envCands)
	withCands("label-secret-hex", pc("secret", "access", "private", "admin", "api", "signing", "encryption",
		"master", "clave", "contrase"))
	withCands("label-secret-token", pc("secret", "token", "password", "passwd", "api", "access", "private",
		"clave", "contrase"))
}

func sortedUnique(xs []int) []int {
	sort.Ints(xs)
	out := xs[:0]
	for i, x := range xs {
		if i == 0 || x != xs[i-1] {
			out = append(out, x)
		}
	}
	return out
}

// prefixCands: every match of a (?i) pattern starts with one of these ASCII
// words. Case folding can also turn ſ K İ ı into ASCII letters, so text that
// holds any of them is scanned in full instead.
func prefixCands(words ...string) func(string) ([]int, bool) {
	return func(s string) ([]int, bool) {
		if strings.ContainsAny(s, "\u017f\u212a\u0130\u0131") {
			return nil, false
		}
		fs := lowerOf(s)
		var xs []int
		for _, w := range words {
			for off := 0; ; {
				i := strings.Index(fs[off:], w)
				if i < 0 {
					break
				}
				xs = append(xs, off+i)
				off += i + 1
			}
		}
		return sortedUnique(xs), true
	}
}

func isLowerHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' }

// zaiCands: [a-f0-9]{32}\. — a match starts 32 bytes before a '.'.
func zaiCands(s string) ([]int, bool) {
	var xs []int
	for off := 0; ; {
		i := strings.IndexByte(s[off:], '.')
		if i < 0 {
			break
		}
		if d := off + i; d >= 32 {
			xs = append(xs, d-32)
		}
		off += i + 1
	}
	return xs, true
}

// hexRunCands: [a-f0-9]{32} followed by a non-hex delimiter — the last 32
// bytes of a lowercase-hex run.
func hexRunCands(s string) ([]int, bool) {
	var xs []int
	for i := 0; i < len(s); {
		if !isLowerHex(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isLowerHex(s[j]) {
			j++
		}
		if j-i >= 32 {
			xs = append(xs, j-32)
		}
		i = j
	}
	return xs, true
}

// telegramCands: \p{Nd}{8,12}: — 8 to 12 runes before a ':'.
func telegramCands(s string) ([]int, bool) {
	var xs []int
	for off := 0; ; {
		i := strings.IndexByte(s[off:], ':')
		if i < 0 {
			break
		}
		c := off + i
		p := c
		for k := 1; k <= 12 && p > 0; k++ {
			_, w := utf8.DecodeLastRuneInString(s[:p])
			p -= w
			if k >= 8 {
				xs = append(xs, p)
			}
		}
		off = c + 1
	}
	return sortedUnique(xs), true
}

// uriCands: [a-zA-Z][a-zA-Z0-9+.-]*:// — any letter of the scheme run before "://".
func uriCands(s string) ([]int, bool) {
	var xs []int
	scheme := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '.' || c == '-'
	}
	for off := 0; ; {
		i := strings.Index(s[off:], "://")
		if i < 0 {
			break
		}
		idx := off + i
		r := idx
		for r > 0 && scheme(s[r-1]) {
			r--
		}
		for k := r; k < idx; k++ {
			if c := s[k]; c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
				xs = append(xs, k)
			}
		}
		off = idx + 1
	}
	return sortedUnique(xs), true
}

var envKeywords = []string{"SECRET", "TOKEN", "PASS", "PWD", "JWT", "WEBHOOK", "AUTH", "APIKEY", "API_KEY",
	"ACCESS_KEY", "ADMIN_KEY", "RELAY_KEY", "SERVICE_ROLE", "ANON_KEY", "PRIVATE_KEY", "SIGNING_KEY",
	"ENCRYPTION_KEY", "SESSION_KEY", "HMAC", "SALT", "CIPHER", "ROTATION_KEY", "BOT_KEY", "HOOK_KEY",
	"MASTER_KEY", "ENC_KEY", "DEK", "KEK"}

// envCands: an upper-case identifier that starts after a non-word byte, and
// only when one of the secret keywords appears somewhere at all.
func envCands(s string) ([]int, bool) {
	any := false
	for _, k := range envKeywords {
		if strings.Contains(s, k) {
			any = true
			break
		}
	}
	if !any {
		return nil, true
	}
	var xs []int
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' && notAfterWord(s, i) {
			xs = append(xs, i)
		}
	}
	return xs, true
}

// apply is re.sub(pattern, _sub, s) with the Python semantics described at the top.
func (p *secretPat) apply(s string, counts map[string]int) string {
	if len(p.needs) == 0 {
		return p.applyPlain(s, counts)
	}
	hay := s
	if p.fold {
		hay = lowerOf(s)
	}
	if !hasAny(hay, p.needs) {
		return s
	}
	if p.multiline {
		return p.applyPlain(s, counts)
	}
	// Run the pattern only on the lines that hold one of the literals: on a
	// large log almost no line does, so the regex almost never runs.
	next := make([]int, len(p.needs))
	for i := range next {
		next[i] = -2 // not computed
	}
	var b strings.Builder
	last, pos := 0, 0
	changed := false
	for pos < len(s) {
		idx := -1
		for i, n := range p.needs {
			if next[i] != -1 && next[i] < pos {
				j := strings.Index(hay[pos:], n)
				if j < 0 {
					next[i] = -1
				} else {
					next[i] = pos + j
				}
			}
			if next[i] >= 0 && (idx < 0 || next[i] < idx) {
				idx = next[i]
			}
		}
		if idx < 0 {
			break
		}
		ls := strings.LastIndexByte(s[:idx], '\n') + 1
		le := len(s)
		if j := strings.IndexByte(s[idx:], '\n'); j >= 0 {
			le = idx + j
		}
		line := s[ls:le]
		if out := p.applyPlain(line, counts); out != line {
			b.WriteString(s[last:ls])
			b.WriteString(out)
			last = le
			changed = true
		}
		pos = le + 1
	}
	if !changed {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

var (
	lowMu  sync.Mutex
	lowSrc *byte
	lowLen int
	lowVal string
	lowStr string // keeps the source string alive so its address cannot be reused while it is cached
)

// lowerOf is asciiLower with a one-entry cache keyed by the identity of the
// string, so the many case-insensitive detectors share one lower-cased copy
// of a large text instead of making one each.
func lowerOf(s string) string {
	if len(s) < 4096 {
		return asciiLower(s)
	}
	k := unsafe.StringData(s)
	lowMu.Lock()
	defer lowMu.Unlock()
	if lowSrc == k && lowLen == len(s) && len(lowStr) == len(s) {
		return lowVal
	}
	v := asciiLower(s)
	lowSrc, lowLen, lowVal, lowStr = k, len(s), v, s
	return v
}

func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

func (p *secretPat) applyPlain(s string, counts map[string]int) string {
	name := Display(p.kind)
	var b strings.Builder
	last, pos := 0, 0
	// take handles one candidate match found at offset base; returns where the
	// search goes next and whether the match was used.
	take := func(base int, loc []int) (next int, used bool) {
		start, end := base+loc[0], base+loc[1]
		if p.tailed {
			// the consumed lookahead is the last group that took part
			for g := len(loc)/2 - 1; g >= 1; g-- {
				if loc[2*g] >= 0 {
					end = base + loc[2*g]
					break
				}
			}
		}
		if (p.pre != nil && !p.pre(s, start)) || (p.mid != nil && !p.mid(s, start)) {
			_, w := utf8.DecodeRuneInString(s[start:])
			if w == 0 {
				w = 1
			}
			return start + w, false
		}
		whole := s[start:end]
		if p.reject != nil && p.group > 0 && 2*p.group+1 < len(loc) && loc[2*p.group] >= 0 && p.reject(s[base+loc[2*p.group]:base+loc[2*p.group+1]]) {
			_, w := utf8.DecodeRuneInString(s[start:])
			if w == 0 {
				w = 1
			}
			return start + w, false
		}
		repl := whole
		if p.group == 0 {
			repl = "<REDACTED:" + name + ":" + fp(whole) + ">"
		} else if 2*p.group+1 < len(loc) && loc[2*p.group] >= 0 {
			if val := s[base+loc[2*p.group] : base+loc[2*p.group+1]]; val != "" {
				repl = strings.Replace(whole, val, "<REDACTED:"+name+":"+fp(val)+">", 1)
			}
		}
		b.WriteString(s[last:start])
		b.WriteString(repl)
		if counts != nil && repl != whole {
			counts[name]++
		}
		last = end
		return end, true // these patterns never match empty
	}
	if p.cands != nil {
		if cs, ok := p.cands(s); ok {
			for _, c := range cs {
				if c < pos {
					continue
				}
				if loc := p.anchRx().FindStringSubmatchIndex(s[c:]); loc != nil {
					if next, used := take(c, loc); used {
						pos = next
					}
				}
			}
			if last == 0 {
				return s
			}
			b.WriteString(s[last:])
			return b.String()
		}
	}
	for pos <= len(s) {
		loc := p.rx().FindStringSubmatchIndex(s[pos:])
		if loc == nil {
			break
		}
		pos, _ = take(pos, loc)
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// ---- layer 1: known secret values (a file of `sha256 label` lines, see docs/DESIGN.md)

const knownMinLen = 16

// pieceSplit is _PIECE_RX.split(tok): split on any of : / @ ? & # .
func pieceSplit(tok string) []string {
	return strings.FieldsFunc(tok, func(r rune) bool { return strings.ContainsRune(":/@?&#.", r) })
}

// tokenStop is the excluded set of _TOKEN_RX = [^\s"'`=,;()<>\[\]{}|\\]{16,}.
func tokenStop(r rune) bool {
	switch r {
	case '"', '\'', '`', '=', ',', ';', '(', ')', '<', '>', '[', ']', '{', '}', '|', '\\':
		return true
	}
	return pySpace(r)
}

// pySpace is Python's str.isspace().
func pySpace(r rune) bool {
	switch {
	case r >= 0x09 && r <= 0x0d, r >= 0x1c && r <= 0x20, r == 0x85, r == 0xa0, r == 0x1680,
		r >= 0x2000 && r <= 0x200a, r == 0x2028, r == 0x2029, r == 0x202f, r == 0x205f, r == 0x3000:
		return true
	}
	return false
}

// replaceTokens is _TOKEN_RX.sub(fn, s): every maximal run of >= 16
// non-stop runes goes through fn. (Invalid bytes count as one rune each,
// like RE2 does.)
func replaceTokens(s string, fn func(string) string) string {
	var b strings.Builder
	last, i := 0, 0
	for i < len(s) {
		r, w := utf8.DecodeRuneInString(s[i:])
		if tokenStop(r) {
			i += w
			continue
		}
		j, n := i, 0
		for j < len(s) {
			r, w := utf8.DecodeRuneInString(s[j:])
			if tokenStop(r) {
				break
			}
			j += w
			n++
		}
		if n >= knownMinLen {
			b.WriteString(s[last:i])
			b.WriteString(fn(s[i:j]))
			last = j
		}
		i = j
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func knownPath() string {
	if p, ok := os.LookupEnv("AI_HOOKS_KNOWN_HASHES"); ok {
		return p
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "ai-hooks", "known-hashes.txt")
	}
	return ""
}

func LoadKnown() map[string]string {
	known := map[string]string{}
	f, err := os.Open(knownPath())
	if err != nil {
		return known
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<24)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) >= 2 && utf8.RuneCountInString(parts[0]) == 64 {
			known[parts[0]] = parts[1]
		}
	}
	return known
}

// cleanLabel keeps a known-hash label from carrying characters that could break the marker.
func cleanLabel(id string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, id)
}

func sha(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])
}

func redactKnown(text string, known map[string]string, counts map[string]int) string {
	if len(known) == 0 {
		return text
	}
	return replaceTokens(text, func(tok string) string {
		if id, ok := known[sha(tok)]; ok {
			counts["known"]++
			return "<REDACTED:known-" + cleanLabel(id) + ":" + fp(tok) + ">"
		}
		for _, piece := range pieceSplit(tok) {
			if utf8.RuneCountInString(piece) >= knownMinLen {
				if id, ok := known[sha(piece)]; ok {
					counts["known"]++
					tok = strings.ReplaceAll(tok, piece, "<REDACTED:known-"+cleanLabel(id)+":"+fp(piece)+">")
				}
			}
		}
		return tok
	})
}

// Redact is the whole filter: by value first, then by shape.
func Redact(text string, known map[string]string) string {
	out, _ := RedactReport(text, known)
	return out
}

// RedactReport is Redact plus how many values of each type were replaced.
// The report never contains the values.
func RedactReport(text string, known map[string]string) (string, map[string]int) {
	if Parity {
		return redactCore(text, known)
	}
	// look through what hides a secret: ANSI colour codes, zero-width characters,
	// and \uXXXX / %XX escapes. Text with no finding is returned exactly as it came.
	norm := normalize(text)
	if out, counts := redactCore(norm, known); counts != nil {
		return out, counts
	}
	if dec := decodeEscapes(norm); dec != norm {
		if out, counts := redactCore(dec, known); counts != nil {
			return out, counts
		}
	}
	return text, nil
}

func redactCore(text string, known map[string]string) (string, map[string]int) {
	secretOnce.Do(func() {
		buildSecretPatterns()
		attachCands()
		buildExtras()
	})
	counts := map[string]int{}
	out := redactKnown(text, known, counts)
	if !Parity {
		for _, p := range extraPats {
			out = p.apply(out, counts)
		}
	}
	for _, p := range secretPatterns {
		out = p.apply(out, counts)
	}
	if !Parity {
		for _, p := range extraPatsB {
			out = p.apply(out, counts)
		}
		out = customPasses(out, counts)
	}
	if len(counts) == 0 {
		counts = nil
	}
	return out, counts
}

// Types lists the detector names (public names) in priority order; the
// optional credit-card detector is included last.
func Types() []string {
	secretOnce.Do(func() {
		buildSecretPatterns()
		attachCands()
		buildExtras()
	})
	var t []string
	if !Parity {
		for _, p := range extraPats {
			t = append(t, Display(p.kind))
		}
		for _, p := range extraPatsB {
			t = append(t, Display(p.kind))
		}
	}
	for _, p := range secretPatterns {
		t = append(t, Display(p.kind))
	}
	if !Parity {
		t = append(t, "env-high-entropy", "env-secret-short", "cookie-secret", "credit-card")
	}
	return t
}

// Limits of Stream, so memory stays bounded on hostile input.
const (
	maxLine  = 4 << 20 // a line longer than this is cut at whitespace and processed in pieces
	maxBlock = 1 << 20 // a private-key block longer than this is dropped from its start
)

// Stream filters r to w line by line (bounded memory, output as it arrives).
// A private-key block is held until its END line so it is never split; a block
// that never ends is replaced by a marker, never printed. A very long line is
// processed in pieces cut at whitespace. The one difference from Redact on a
// whole text: a match that spans two lines (for example "Bearer" at the end of
// one line and the token on the next) is not seen.
func Stream(r io.Reader, w io.Writer, known map[string]string, counts map[string]int) error {
	br := bufio.NewReaderSize(TextReader(r), 1<<16)
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	var pem strings.Builder
	inPEM, dropped := false, false
	endPEM := func() {
		inPEM, dropped = false, false
		pem.Reset()
	}
	flushUnterminated := func() {
		if !inPEM {
			return
		}
		v := pem.String()
		io.WriteString(bw, "<REDACTED:"+Display("pem")+":"+fp(v)+">\n")
		if counts != nil {
			counts[Display("pem")]++
		}
		endPEM()
	}
	for {
		line, err := readLine(&br)
		if line != "" {
			switch {
			case inPEM:
				if !dropped {
					pem.WriteString(line)
				}
				if pem.Len() > maxBlock && !dropped {
					dropped = true
				}
				if isPEMEnd(line) {
					if dropped {
						io.WriteString(bw, "<REDACTED:"+Display("pem")+":"+fp(pem.String())+">\n")
						if counts != nil {
							counts[Display("pem")]++
						}
						endPEM()
					} else {
						flush(bw, pem.String(), known, counts)
						endPEM()
					}
				}
			case strings.Contains(line, "-----BEGIN ") && strings.Contains(line, "PRIVATE KEY") && !strings.Contains(line, "-----END "):
				inPEM = true
				pem.WriteString(line)
			default:
				flush(bw, line, known, counts)
			}
			if !inPEM {
				_ = bw.Flush()
			}
		}
		if err != nil {
			flushUnterminated()
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// readLine returns one line (with its newline) or, for a line longer than
// maxLine, a piece cut at the last whitespace so a token is not split.
func readLine(brp **bufio.Reader) (string, error) {
	br := *brp
	var b strings.Builder
	for {
		chunk, err := br.ReadSlice('\n')
		b.Write(chunk)
		if err == bufio.ErrBufferFull {
			if b.Len() < maxLine {
				continue
			}
			s := b.String()
			cut := strings.LastIndexAny(s[len(s)-8192:], " \t,;") // look only at the tail
			if cut < 0 {
				return s, nil
			}
			cut += len(s) - 8192
			// push the remainder back by returning the head and keeping the tail for the next call
			*brp = bufio.NewReaderSize(io.MultiReader(strings.NewReader(s[cut+1:]), br), 1<<16)
			return s[:cut+1], nil
		}
		return b.String(), err
	}
}

// isPEMEnd: the line is an END armor line ("-----END ... -----"), not text that merely contains the words.
func isPEMEnd(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "-----END ") && strings.HasSuffix(t, "-----")
}

func flush(w io.Writer, s string, known map[string]string, counts map[string]int) {
	out, c := RedactReport(s, known)
	for k, v := range c {
		if counts != nil {
			counts[k] += v
		}
	}
	_, _ = io.WriteString(w, out)
}
