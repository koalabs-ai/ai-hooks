package selftest

import "testing"

// The bundled corpus is the contract: no missed secret, no unexpected false alarm.
func TestBundledCorpus(t *testing.T) {
	r := Run()
	if !r.OK() {
		t.Fatalf("missed=%v falseAlarms=%v knownMissCaught=%v", r.Missed, r.FalseAlarmIDs, r.KnownMissCaught)
	}
	if r.Total < 40 || r.NegTotal < 20 {
		t.Errorf("corpus too small: %d/%d", r.Total, r.NegTotal)
	}
}
