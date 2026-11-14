// Package report writes scan findings as text, JSON or SARIF 2.1.0. No format
// ever contains a secret value: only the detector, the location and the fingerprint.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/koalabs-ai/ai-hooks/internal/redact"
)

// File is the findings of one scanned input.
type File struct {
	Path     string
	Findings []redact.Finding
}

// Text prints "path:line: type fingerprint".
func Text(w io.Writer, files []File) {
	for _, f := range files {
		for _, x := range f.Findings {
			fmt.Fprintf(w, "%s:%d: %s %s\n", f.Path, x.Line, x.Type, x.Fingerprint)
		}
	}
}

// JSON prints {"findings":[...],"total":n,"by_type":{...}}.
func JSON(w io.Writer, files []File) error {
	type item struct {
		Path        string `json:"path"`
		Type        string `json:"type"`
		Fingerprint string `json:"fingerprint"`
		Line        int    `json:"line"`
		EndLine     int    `json:"end_line"`
	}
	items := []item{}
	by := map[string]int{}
	for _, f := range files {
		for _, x := range f.Findings {
			items = append(items, item{f.Path, x.Type, x.Fingerprint, x.Line, x.EndLine})
			by[x.Type]++
		}
	}
	return enc(w, map[string]any{"findings": items, "total": len(items), "by_type": by})
}

func enc(w io.Writer, v any) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(v)
}

// SARIF prints a SARIF 2.1.0 log (https://docs.oasis-open.org/sarif/sarif/v2.1.0/).
func SARIF(w io.Writer, files []File, version string) error {
	used := map[string]bool{}
	var results []any
	for _, f := range files {
		for _, x := range f.Findings {
			used[x.Type] = true
			region := map[string]any{"startLine": x.Line}
			if x.EndLine > x.Line {
				region["endLine"] = x.EndLine
			}
			results = append(results, map[string]any{
				"ruleId":  x.Type,
				"level":   "error",
				"message": map[string]any{"text": fmt.Sprintf("Secret-shaped value of type %s (fingerprint %s). The value is not included in this report.", x.Type, x.Fingerprint)},
				"locations": []any{map[string]any{"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": f.Path},
					"region":           region}}},
				"partialFingerprints": map[string]any{"primaryLocationLineHash": x.Fingerprint + ":1"},
			})
		}
	}
	var names []string
	for t := range used {
		names = append(names, t)
	}
	sort.Strings(names)
	rules := []any{}
	for _, t := range names {
		d, _ := redact.Explain(t)
		if d == "" {
			d = "Secret-shaped value of type " + t + "."
		}
		rules = append(rules, map[string]any{
			"id": t, "name": t,
			"shortDescription":     map[string]any{"text": "Secret of type " + t},
			"fullDescription":      map[string]any{"text": d},
			"helpUri":              "https://github.com/koalabs-ai/ai-hooks/blob/main/docs/DETECTORS.md",
			"defaultConfiguration": map[string]any{"level": "error"},
			"properties":           map[string]any{"tags": []string{"security", "secret"}},
		})
	}
	if results == nil {
		results = []any{}
	}
	return enc(w, map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "ai-hooks", "version": version, "informationUri": "https://github.com/koalabs-ai/ai-hooks", "rules": rules}},
			"results": results,
		}},
	})
}
