package impact

import (
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
		name      string
		counts    []GroupCount
		wantAIR   float64
		wantPass  bool
		wantMin   string
		wantMax   string
		wantAppl  bool
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
