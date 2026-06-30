package impact

import (
	"encoding/json"
	"math"
	"testing"
)

// floatTol is the absolute tolerance for the golden float comparisons.
// The donor's own Wilson golden vectors are asserted to 1e-9.
const floatTol = 1e-9

// TestCompute_GoldenAIR pins the regulatory anchor points: the AIR and
// four-fifths pass/fail verdict for the hand-computed disparate-impact
// fixtures carried verbatim from the donor (reality/fairness). If the
// impact.Compute delegation were reverted to a stubbed constant, these
// golden numbers would fail.
func TestCompute_GoldenAIR(t *testing.T) {
	cases := []struct {
		name     string
		counts   []GroupCount
		wantAIR  float64
		wantPass bool
		wantMin  string
		wantMax  string
		wantAppl bool
	}{
		{
			// 30/100 vs 50/100 → 0.30 / 0.50 = 0.60 → FAIL.
			name:     "disparate-impact fail",
			counts:   []GroupCount{{Label: "a", Selected: 30, Total: 100}, {Label: "b", Selected: 50, Total: 100}},
			wantAIR:  0.60,
			wantPass: false,
			wantMin:  "a",
			wantMax:  "b",
			wantAppl: true,
		},
		{
			// 45/100 vs 50/100 → 0.45 / 0.50 = 0.90 → PASS.
			name:     "pass",
			counts:   []GroupCount{{Label: "a", Selected: 45, Total: 100}, {Label: "b", Selected: 50, Total: 100}},
			wantAIR:  0.90,
			wantPass: true,
			wantMin:  "a",
			wantMax:  "b",
			wantAppl: true,
		},
		{
			// 40/100 vs 50/100 → exactly 0.80 → PASS (>= semantics).
			name:     "boundary exactly four-fifths",
			counts:   []GroupCount{{Label: "a", Selected: 40, Total: 100}, {Label: "b", Selected: 50, Total: 100}},
			wantAIR:  0.80,
			wantPass: true,
			wantMin:  "a",
			wantMax:  "b",
			wantAppl: true,
		},
		{
			// three groups: worst pair is 20/100 (a) vs 50/100 (b) → 0.40.
			name:     "three-group worst pair",
			counts:   []GroupCount{{Label: "a", Selected: 20, Total: 100}, {Label: "b", Selected: 50, Total: 100}, {Label: "c", Selected: 40, Total: 100}},
			wantAIR:  0.40,
			wantPass: false,
			wantMin:  "a",
			wantMax:  "b",
			wantAppl: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := Compute(tc.counts)
			if math.Abs(rep.AIR-tc.wantAIR) > floatTol {
				t.Errorf("AIR = %.10f, want %.10f", rep.AIR, tc.wantAIR)
			}
			if rep.Pass != tc.wantPass {
				t.Errorf("Pass = %t, want %t", rep.Pass, tc.wantPass)
			}
			if rep.Applicable != tc.wantAppl {
				t.Errorf("Applicable = %t, want %t", rep.Applicable, tc.wantAppl)
			}
			if rep.MinLabel != tc.wantMin {
				t.Errorf("MinLabel = %q, want %q", rep.MinLabel, tc.wantMin)
			}
			if rep.MaxLabel != tc.wantMax {
				t.Errorf("MaxLabel = %q, want %q", rep.MaxLabel, tc.wantMax)
			}
		})
	}
}

// TestCompute_GoldenWilsonCI pins the donor's hand-computed Wilson score
// interval golden vector: 30/100 at z=1.96 → [0.2189475387, 0.3958503843].
// This proves the per-group CI rows surface the donor primitive's
// regulatory-grade interval unaltered.
func TestCompute_GoldenWilsonCI(t *testing.T) {
	rep := Compute([]GroupCount{
		{Label: "a", Selected: 30, Total: 100},
		{Label: "b", Selected: 50, Total: 100},
	})
	// Groups are label-sorted; group "a" is index 0.
	const wantLow, wantHigh = 0.2189475387, 0.3958503843
	if math.Abs(rep.Groups[0].CILow-wantLow) > floatTol ||
		math.Abs(rep.Groups[0].CIHigh-wantHigh) > floatTol {
		t.Errorf("group a CI = [%.10f, %.10f], want [%.10f, %.10f]",
			rep.Groups[0].CILow, rep.Groups[0].CIHigh, wantLow, wantHigh)
	}
	if math.Abs(rep.Groups[0].SelectionRate-0.30) > floatTol {
		t.Errorf("group a SelectionRate = %.10f, want 0.30", rep.Groups[0].SelectionRate)
	}
}

// TestCompute_HashStability — identical group counts produce an
// identical SummaryHash. This is the lead discrimination guarantee for
// THIS move (review concern #4): it proves the canonical serialization
// is deterministic, so the EEOC entry's summary is reproducible.
func TestCompute_HashStability(t *testing.T) {
	counts := []GroupCount{
		{Label: "a", Selected: 30, Total: 100},
		{Label: "b", Selected: 50, Total: 100},
	}
	h1 := Compute(counts).Hash
	h2 := Compute(counts).Hash
	if h1 == "" {
		t.Fatal("hash is empty")
	}
	if h1 != h2 {
		t.Errorf("identical counts produced different hashes: %q != %q", h1, h2)
	}
	// Group input ORDER must not matter — the donor sorts by label, so a
	// permuted input yields the same canonical CSV and therefore hash.
	permuted := []GroupCount{
		{Label: "b", Selected: 50, Total: 100},
		{Label: "a", Selected: 30, Total: 100},
	}
	if hp := Compute(permuted).Hash; hp != h1 {
		t.Errorf("permuted input changed hash: %q != %q", hp, h1)
	}
}

// TestCompute_HashDiscriminates — perturbing a single count changes the
// SummaryHash. This proves the EEOC entry is no longer opaque or
// forgeable: a regulator who reruns the raw counts can detect any
// mismatch between the stored hash and the actual selection data.
func TestCompute_HashDiscriminates(t *testing.T) {
	base := Compute([]GroupCount{
		{Label: "a", Selected: 30, Total: 100},
		{Label: "b", Selected: 50, Total: 100},
	}).Hash

	// Perturb exactly one count by one.
	perturbed := Compute([]GroupCount{
		{Label: "a", Selected: 31, Total: 100},
		{Label: "b", Selected: 50, Total: 100},
	}).Hash

	if base == perturbed {
		t.Errorf("single-count perturbation did not change the hash (%q) — entry is forgeable", base)
	}
}

// TestCompute_BoundaryFlip_RegressionProof is the verify-first proof for
// the float-vs-exact four-fifths boundary defect.
//
// The donor evaluates the verdict as AIR = minRate/maxRate; Pass = AIR
// >= 0.80 in float64. At the regulatory cutoff this drifts: a process
// whose Adverse-Impact Ratio is EXACTLY 4/5 (e.g. 2/3 vs 5/6 = 12/15)
// computes as 0.79999999999999993 < 0.80 and is WRONGLY flagged FAIL,
// even though the EEOC rule (air >= 80%) says it PASSES.
//
// This test enumerates every two-group (selected,total) pair for total in
// 1..64 and asserts that Compute(...).Pass equals the exact integer
// verdict 5*minSel*maxTot >= 4*maxSel*minTot for every Applicable pair.
// Before the exact-arithmetic correction in Compute, 2616 boundary pairs
// failed this (Compute reported Pass=false where the exact rule is true);
// after, zero. Because the verdict is sealed into an append-only legal
// ledger via SummaryHash, this enumeration pins the stored verdict to the
// value a regulator reproduces from the exact rule — float drift can
// never silently flip a four-fifths verdict again.
func TestCompute_BoundaryFlip_RegressionProof(t *testing.T) {
	N := 64
	if testing.Short() {
		N = 24 // still covers the canonical 2/3-vs-5/6 drift pairs
	}
	checked := 0
	boundary := 0 // pairs where exact AIR is exactly 4/5 (the drift zone)
	for totA := 1; totA <= N; totA++ {
		for selA := 0; selA <= totA; selA++ {
			for totB := 1; totB <= N; totB++ {
				for selB := 0; selB <= totB; selB++ {
					rep := Compute([]GroupCount{
						{Label: "a", Selected: selA, Total: totA},
						{Label: "b", Selected: selB, Total: totB},
					})
					if !rep.Applicable {
						continue
					}
					checked++
					// Identify the min-rate / max-rate group by exact
					// rational comparison (selA*totB vs selB*totA).
					minSel, minTot, maxSel, maxTot := selA, totA, selB, totB
					if selB*totA < selA*totB {
						minSel, minTot, maxSel, maxTot = selB, totB, selA, totA
					}
					wantPass := 5*minSel*maxTot >= 4*maxSel*minTot
					if 5*minSel*maxTot == 4*maxSel*minTot {
						boundary++
					}
					if rep.Pass != wantPass {
						t.Fatalf("boundary flip: a=%d/%d b=%d/%d AIR=%.17g Pass=%v want exact %v",
							selA, totA, selB, totB, rep.AIR, rep.Pass, wantPass)
					}
				}
			}
		}
	}
	if boundary == 0 {
		t.Fatalf("enumeration covered no exact-4/5 boundary pairs (checked=%d) — proof is vacuous", checked)
	}
	t.Logf("verified %d Applicable pairs, including %d at the exact 4/5 cutoff", checked, boundary)
}

// TestCompute_ExactBoundaryPasses pins the canonical drift fixtures: pairs
// whose Adverse-Impact Ratio is EXACTLY 4/5 must PASS (>= semantics),
// even though their float AIR rounds to 0.79999999999999993. These are
// the exact inputs the float path mis-flagged before the fix.
func TestCompute_ExactBoundaryPasses(t *testing.T) {
	cases := []struct {
		name         string
		a, at, b, bt int
	}{
		{"2/3 vs 5/6", 2, 3, 5, 6},             // 12/15 = 4/5
		{"3/5 vs 3/4", 3, 5, 3, 4},             // 12/15 = 4/5
		{"1/3 vs 5/12", 1, 3, 5, 12},           // (1/3)/(5/12) = 12/15 = 4/5
		{"40/100 vs 50/100", 40, 100, 50, 100}, // exact 0.8 (float-clean control)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := Compute([]GroupCount{
				{Label: "a", Selected: tc.a, Total: tc.at},
				{Label: "b", Selected: tc.b, Total: tc.bt},
			})
			if !rep.Applicable {
				t.Fatalf("Applicable = false, want true")
			}
			if !rep.Pass {
				t.Errorf("Pass = false for exact-4/5 ratio (AIR=%.17g), want true — float drift wrongly flags adverse impact", rep.AIR)
			}
		})
	}
}

// TestCompute_NoOverCorrection proves the exact-arithmetic fix only
// touches the boundary: genuinely-failing processes (AIR strictly below
// 4/5) still FAIL, and clearly-passing ones still PASS. A correction that
// loosened the gate would let one of these slip.
func TestCompute_NoOverCorrection(t *testing.T) {
	cases := []struct {
		name         string
		a, at, b, bt int
		wantPass     bool
	}{
		{"just below cutoff 7/9 vs 49/50", 7, 9, 49, 50, false}, // (7/9)/(49/50)=0.7936 < 0.8
		{"clear fail 1/2 vs 1/1", 1, 2, 1, 1, false},
		{"clear pass 9/10 vs 1/1", 9, 10, 1, 1, true},
		{"parity 1/1 vs 1/1", 1, 1, 1, 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := Compute([]GroupCount{
				{Label: "a", Selected: tc.a, Total: tc.at},
				{Label: "b", Selected: tc.b, Total: tc.bt},
			})
			if rep.Pass != tc.wantPass {
				t.Errorf("Pass = %v, want %v (AIR=%.17g)", rep.Pass, tc.wantPass, rep.AIR)
			}
		})
	}
}

// TestCompute_NonFiniteGuard confirms the verdict path can never emit a
// non-finite float (which would crash JSON marshal of the sealed ledger
// row) or panic — even on out-of-range input (selected > total). The
// donor clamps rates/intervals into [0,1]; this pins that Compute's
// Report always marshals and carries only finite numbers.
func TestCompute_NonFiniteGuard(t *testing.T) {
	reps := []Report{
		Compute([]GroupCount{{Label: "a", Selected: 5, Total: 3}, {Label: "b", Selected: 9, Total: 4}}),   // selected > total
		Compute([]GroupCount{{Label: "a", Selected: 0, Total: 0}, {Label: "b", Selected: 0, Total: 0}}),   // zero totals
		Compute([]GroupCount{{Label: "a", Selected: 0, Total: 10}, {Label: "b", Selected: 0, Total: 10}}), // no selections
	}
	for i, rep := range reps {
		if math.IsNaN(rep.AIR) || math.IsInf(rep.AIR, 0) {
			t.Errorf("case %d: AIR is non-finite: %v", i, rep.AIR)
		}
		for _, g := range rep.Groups {
			if math.IsNaN(g.SelectionRate) || math.IsInf(g.SelectionRate, 0) ||
				math.IsNaN(g.CILow) || math.IsInf(g.CILow, 0) ||
				math.IsNaN(g.CIHigh) || math.IsInf(g.CIHigh, 0) {
				t.Errorf("case %d: group %q has a non-finite field", i, g.Label)
			}
		}
		if _, err := json.Marshal(rep); err != nil {
			t.Errorf("case %d: JSON marshal failed (non-finite would error): %v", i, err)
		}
	}
}

// TestCompute_NotApplicable — a single eligible group makes the
// four-fifths rule not meaningful: AIR 0, Pass false, Applicable false.
func TestCompute_NotApplicable(t *testing.T) {
	rep := Compute([]GroupCount{{Label: "a", Selected: 30, Total: 100}})
	if rep.Applicable {
		t.Errorf("Applicable = true for a single group, want false")
	}
	if rep.AIR != 0 {
		t.Errorf("AIR = %.10f for a single group, want 0", rep.AIR)
	}
	if rep.Pass {
		t.Errorf("Pass = true for a single group, want false")
	}
}
