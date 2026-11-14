// Package corpus holds the bundled test corpus: FAKE secrets only.
//
// positive.jsonl lines: {"id","type","template"[, "known_miss":true,"note"]}
// negative.jsonl lines: {"id","text"[, "known_false_alarm":true,"note"]}
//
// A template marks the secret with [[...]] and may contain {{kind:N}} markers
// (alnum, b64url, b64, hexl, upper, digits) that expand to N deterministic
// pseudo-random characters, so no secret-shaped literal sits in the repository.
package corpus

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"hash/fnv"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
)

//go:embed positive.jsonl negative.jsonl
var files embed.FS

// Positive is a case that contains a secret.
type Positive struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Template  string `json:"template"`
	KnownMiss bool   `json:"known_miss"`
	Note      string `json:"note"`
	Text      string `json:"-"` // expanded, brackets removed
	Secret    string `json:"-"` // the part that must not survive
}

// Negative is a case that must come out unchanged.
type Negative struct {
	ID              string `json:"id"`
	Text            string `json:"text"`
	KnownFalseAlarm bool   `json:"known_false_alarm"`
	Note            string `json:"note"`
}

var marker = regexp.MustCompile(`\{\{(\w+):(\d+)\}\}`)

const (
	alnum   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b64url  = alnum + "_-"
	b64     = alnum + "+/"
	hexl    = "0123456789abcdef"
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	digits  = "0123456789"
	bech32u = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"
	base32  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

func expand(id, tpl string) string {
	h := fnv.New64a()
	h.Write([]byte(id))
	rng := rand.New(rand.NewSource(int64(h.Sum64())))
	return marker.ReplaceAllStringFunc(tpl, func(m string) string {
		sm := marker.FindStringSubmatch(m)
		n, _ := strconv.Atoi(sm[2])
		set := map[string]string{"alnum": alnum, "b64url": b64url, "b64": b64, "hexl": hexl, "upper": upper, "digits": digits, "bech32u": bech32u, "base32": base32}[sm[1]]
		b := make([]byte, n)
		for i := range b {
			b[i] = set[rng.Intn(len(set))]
		}
		return string(b)
	})
}

func lines(name string) [][]byte {
	data, _ := files.ReadFile(name)
	var out [][]byte
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) > 0 {
			out = append(out, append([]byte(nil), sc.Bytes()...))
		}
	}
	return out
}

// Positives returns the expanded positive cases.
func Positives() []Positive {
	var out []Positive
	for _, l := range lines("positive.jsonl") {
		var p Positive
		if json.Unmarshal(l, &p) != nil {
			continue
		}
		t := expand(p.ID, p.Template)
		a, b := strings.Index(t, "[["), strings.LastIndex(t, "]]")
		if a >= 0 && b > a {
			p.Secret = t[a+2 : b]
			p.Text = t[:a] + p.Secret + t[b+2:]
		} else {
			p.Text = t
		}
		out = append(out, p)
	}
	return out
}

// Negatives returns the negative cases.
func Negatives() []Negative {
	var out []Negative
	for _, l := range lines("negative.jsonl") {
		var n Negative
		if json.Unmarshal(l, &n) == nil {
			out = append(out, n)
		}
	}
	return out
}
