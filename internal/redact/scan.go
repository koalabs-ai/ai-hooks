package redact

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

// Finding is one detected secret: where, which detector, and the fingerprint.
// It never holds the value.
type Finding struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Line        int    `json:"line"`
	EndLine     int    `json:"end_line"`
}

var markerRe = regexp.MustCompile(`<REDACTED:([^:>]+):([0-9a-f]{8})>`)

// Scan reads r line by line (a private-key block is taken as one unit) and
// returns the findings. Lines longer than maxLine are still scanned.
func Scan(r io.Reader, known map[string]string) ([]Finding, error) {
	br := bufio.NewReaderSize(r, 1<<16)
	var out []Finding
	line := 0
	var block strings.Builder
	blockStart := 0
	inBlock := false
	handle := func(text string, start, end int) {
		red, counts := RedactReport(text, known)
		if counts == nil {
			return
		}
		for _, m := range markerRe.FindAllStringSubmatch(red, -1) {
			out = append(out, Finding{Type: m[1], Fingerprint: m[2], Line: start, EndLine: end})
		}
	}
	for {
		s, err := br.ReadString('\n')
		if s != "" {
			line++
			switch {
			case inBlock:
				block.WriteString(s)
				if isPEMEnd(s) {
					inBlock = false
					handle(block.String(), blockStart, line)
					block.Reset()
				}
			case strings.Contains(s, "-----BEGIN ") && strings.Contains(s, "PRIVATE KEY") && !strings.Contains(s, "-----END "):
				inBlock, blockStart = true, line
				block.WriteString(s)
			default:
				handle(s, line, line)
			}
		}
		if err != nil {
			if inBlock {
				handle(block.String(), blockStart, line)
			}
			if err == io.EOF {
				return out, nil
			}
			return out, err
		}
	}
}
