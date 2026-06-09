package fourfifths

import (
	"math"
	"testing"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// The canonical EEOC worked example: a reference group selected at 80% and a
// second group at 40% -> impact ratio 0.50, which fails the four-fifths rule.
func TestCanonicalEEOCExample(t *testing.T) {
	groups := []GroupOutcome{
		{Group: "reference", Applicants: 100, Selected: 80}, // rate 0.80
		{Group: "protected", Applicants: 100, Selected: 40}, // rate 0.40
	}
	ratios := ImpactRatios(groups)
	byName := map[string]GroupRatio{}
	for _, r := range ratios {
		byName[r.Group] = r
	}
	if !approx(byName["reference"].SelectionRate, 0.80) || !byName["reference"].IsReference {
		t.Errorf("reference: rate %v isRef %v", byName["reference"].SelectionRate, byName["reference"].IsReference)
	}
	if !approx(byName["reference"].ImpactRatio, 1.0) || byName["reference"].BelowFourFifths {
		t.Errorf("reference impact ratio should be 1.0 and not flagged")
	}
	if !approx(byName["protected"].ImpactRatio, 0.50) || !byName["protected"].BelowFourFifths {
		t.Errorf("protected: ratio %v below %v (want 0.50, true)", byName["protected"].ImpactRatio, byName["protected"].BelowFourFifths)
	}
	if got := BelowFourFifths(groups); len(got) != 1 || got[0] != "protected" {
		t.Errorf("BelowFourFifths = %v, want [protected]", got)
	}
}

func TestExactlyAtThresholdPasses(t *testing.T) {
	// 80 vs 64 of 100 -> 0.64/0.80 = 0.80 exactly -> NOT below (strict <).
	groups := []GroupOutcome{
		{Group: "ref", Applicants: 100, Selected: 80},
		{Group: "b", Applicants: 100, Selected: 64},
	}
	if got := BelowFourFifths(groups); len(got) != 0 {
		t.Errorf("ratio exactly 0.80 must pass, got flagged %v", got)
	}
}

func TestZeroApplicantsUndefined(t *testing.T) {
	groups := []GroupOutcome{
		{Group: "ref", Applicants: 50, Selected: 25}, // rate 0.50
		{Group: "empty", Applicants: 0, Selected: 0},  // undefined
	}
	ratios := ImpactRatios(groups)
	for _, r := range ratios {
		if r.Group == "empty" {
			if r.SelectionRate != -1 || r.ImpactRatio != -1 || r.BelowFourFifths {
				t.Errorf("empty group must be undefined and not flagged: %+v", r)
			}
		}
	}
	// the empty group must not become the reference (rate -1 is excluded)
	for _, r := range ratios {
		if r.Group == "ref" && !r.IsReference {
			t.Error("ref should be the reference despite the empty group")
		}
	}
}

func TestNoSelectionsAllUndefined(t *testing.T) {
	// nobody selected anywhere -> reference rate 0 -> ratios undefined, none flagged.
	groups := []GroupOutcome{
		{Group: "a", Applicants: 100, Selected: 0},
		{Group: "b", Applicants: 100, Selected: 0},
	}
	for _, r := range ImpactRatios(groups) {
		if r.ImpactRatio != -1 || r.BelowFourFifths {
			t.Errorf("no selections -> undefined ratio, got %+v", r)
		}
	}
}

func TestSummaryHashDeterministicAndOrderInvariant(t *testing.T) {
	a := []GroupOutcome{{Group: "x", Applicants: 10, Selected: 5}, {Group: "y", Applicants: 10, Selected: 2}}
	b := []GroupOutcome{{Group: "y", Applicants: 10, Selected: 2}, {Group: "x", Applicants: 10, Selected: 5}}
	if SummaryHash(a) != SummaryHash(b) {
		t.Error("SummaryHash must be order-invariant (rows sorted by group)")
	}
	if SummaryHash(a) == "" || len(SummaryHash(a)) != 64 {
		t.Errorf("SummaryHash should be 32-byte hex, got %q", SummaryHash(a))
	}
	// a changed outcome must change the hash
	c := []GroupOutcome{{Group: "x", Applicants: 10, Selected: 5}, {Group: "y", Applicants: 10, Selected: 3}}
	if SummaryHash(a) == SummaryHash(c) {
		t.Error("changing an outcome must change the SummaryHash")
	}
}
