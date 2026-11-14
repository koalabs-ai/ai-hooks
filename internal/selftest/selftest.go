// Package selftest runs the bundled corpus and measures detection and false alarms.
package selftest

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/koalabs-ai/ai-hooks/corpus"
	"github.com/koalabs-ai/ai-hooks/internal/redact"
)

// Result is the outcome of one run.
type Result struct {
	Detected, Total  int
	ByType           map[string][2]int // type -> detected, total
	Missed           []string          // ids of positives not caught (not known misses)
	KnownMisses      []string          // "id: note" of expected misses that are indeed missed
	KnownMissCaught  []string          // known misses that are now caught (update the corpus)
	FalseAlarms      int
	NegTotal         int
	FalseAlarmIDs    []string // negatives altered, not known
	KnownFalseAlarms []string
	WrongType        []string // secret removed but reported under another type
}

// Run evaluates the corpus.
func Run() Result {
	prev := redact.EnableCards
	redact.EnableCards = true // the optional card detector is part of what the corpus measures
	defer func() { redact.EnableCards = prev }()
	r := Result{ByType: map[string][2]int{}}
	for _, p := range corpus.Positives() {
		out, rep := redact.RedactReport(p.Text, nil)
		removed := p.Secret != "" && !strings.Contains(out, p.Secret)
		if p.KnownMiss {
			if removed {
				r.KnownMissCaught = append(r.KnownMissCaught, p.ID)
			} else {
				r.KnownMisses = append(r.KnownMisses, p.ID+": "+p.Note)
			}
			continue
		}
		r.Total++
		bt := r.ByType[p.Type]
		bt[1]++
		if removed && rep[p.Type] > 0 {
			r.Detected++
			bt[0]++
		} else if removed {
			r.WrongType = append(r.WrongType, fmt.Sprintf("%s=%v", p.ID, rep))
			r.Detected++
			bt[0]++
		} else {
			r.Missed = append(r.Missed, p.ID)
		}
		r.ByType[p.Type] = bt
	}
	for _, n := range corpus.Negatives() {
		out := redact.Redact(n.Text, nil)
		if n.KnownFalseAlarm {
			if out != n.Text {
				r.KnownFalseAlarms = append(r.KnownFalseAlarms, n.ID+": "+n.Note)
			}
			continue
		}
		r.NegTotal++
		if out != n.Text {
			r.FalseAlarms++
			r.FalseAlarmIDs = append(r.FalseAlarmIDs, n.ID)
		}
	}
	return r
}

// Print writes the human report.
func (r Result) Print(w io.Writer) {
	fmt.Fprintf(w, "detection    %d/%d\n", r.Detected, r.Total)
	types := make([]string, 0, len(r.ByType))
	for t := range r.ByType {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		v := r.ByType[t]
		fmt.Fprintf(w, "  %-22s %d/%d\n", t, v[0], v[1])
	}
	fmt.Fprintf(w, "false alarms %d/%d", r.FalseAlarms, r.NegTotal)
	if len(r.FalseAlarmIDs) > 0 {
		fmt.Fprintf(w, "  (%s)", strings.Join(r.FalseAlarmIDs, ", "))
	}
	fmt.Fprintln(w)
	if len(r.Missed) > 0 {
		fmt.Fprintf(w, "MISSED       %s\n", strings.Join(r.Missed, ", "))
	}
	if len(r.WrongType) > 0 {
		fmt.Fprintf(w, "other type   %s\n", strings.Join(r.WrongType, ", "))
	}
	fmt.Fprintf(w, "known misses %d\n", len(r.KnownMisses))
	for _, m := range r.KnownMisses {
		fmt.Fprintf(w, "  - %s\n", m)
	}
	fmt.Fprintf(w, "known false alarms %d\n", len(r.KnownFalseAlarms))
	for _, m := range r.KnownFalseAlarms {
		fmt.Fprintf(w, "  - %s\n", m)
	}
	if len(r.KnownMissCaught) > 0 {
		fmt.Fprintf(w, "note: now caught, remove known_miss: %s\n", strings.Join(r.KnownMissCaught, ", "))
	}
}

// OK reports whether nothing unexpected happened.
func (r Result) OK() bool {
	return len(r.Missed) == 0 && r.FalseAlarms == 0 && len(r.KnownMissCaught) == 0
}

// Markdown writes the per-type table used in docs/DETECTION.md.
func (r Result) Markdown(w io.Writer) {
	fmt.Fprintf(w, "| Detector | Detected |\n|---|---|\n")
	types := make([]string, 0, len(r.ByType))
	for t := range r.ByType {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		v := r.ByType[t]
		fmt.Fprintf(w, "| `%s` | %d/%d |\n", t, v[0], v[1])
	}
	fmt.Fprintf(w, "| **all** | **%d/%d** |\n\n", r.Detected, r.Total)
	fmt.Fprintf(w, "False alarms: %d/%d clean samples touched.\n\n", r.FalseAlarms, r.NegTotal)
	fmt.Fprintf(w, "Known misses (%d):\n\n", len(r.KnownMisses))
	for _, m := range r.KnownMisses {
		fmt.Fprintf(w, "- %s\n", m)
	}
	fmt.Fprintf(w, "\nKnown false alarms (%d):\n\n", len(r.KnownFalseAlarms))
	for _, m := range r.KnownFalseAlarms {
		fmt.Fprintf(w, "- %s\n", m)
	}
}
