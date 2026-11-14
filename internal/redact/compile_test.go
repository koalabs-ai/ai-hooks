package redact

import "testing"

// Patterns compile lazily; make sure every one of them is valid.
func TestEveryPatternCompiles(t *testing.T) {
	secretOnce.Do(func() { buildSecretPatterns(); attachCands(); buildExtras() })
	for _, set := range [][]*secretPat{extraPats, extraPatsB, secretPatterns} {
		for _, p := range set {
			p.rx()
			if p.cands != nil {
				p.anchRx()
			}
		}
	}
}
