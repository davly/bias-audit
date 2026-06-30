// Package impact is bias-audit's first-party EEOC four-fifths
// adverse-impact producer. It is the thin adapter that lights up the
// dormant EntryTypeEEOCFourFifthsImpact ledger row: instead of storing
// an opaque, externally-computed CSV hash in Entry.SummaryHash,
// bias-audit now computes the four-fifths Adverse-Impact Ratio (AIR)
// and per-group Wilson score intervals IN-PROCESS and derives the
// SummaryHash from those self-produced numbers.
//
// The math itself carries no hiring-/lending-/admissions-specific
// types: it delegates wholesale to the promoted Tier-0 primitive
// github.com/davly/reality/fairness (the same package canopy's
// internal/hiring.ProtectedClassDelta consumes). This adapter is
// structurally the same map-in / map-out shape canopy already wrote;
// the only addition here is the deterministic canonical serialization
// + SHA-256 so the value can be stored in Entry.SummaryHash AND
// re-derived by a regulator who reruns the math off the raw counts.
//
// References:
//   - EEOC, "Uniform Guidelines on Employee Selection Procedures"
//     (1978), 29 C.F.R. § 1607.4(D) — the four-fifths (80%) rule.
//   - Wilson, E.B. (1927) — the score interval.
package impact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/davly/reality/fairness"
)

// GroupRate is one protected-class group's adverse-impact datum: the
// observed selection rate with its Wilson score confidence interval.
// It mirrors fairness.GroupRate but is re-exported here so callers of
// internal/impact need not import the foundation primitive directly.
type GroupRate struct {
	Label         string  `json:"label"`
	Selected      int     `json:"selected"`
	Total         int     `json:"total"`
	SelectionRate float64 `json:"selection_rate"`
	CILow         float64 `json:"ci_low"`
	CIHigh        float64 `json:"ci_high"`
}

// Report is the structured four-fifths result that backs an
// EntryTypeEEOCFourFifthsImpact ledger row. Hash is the SHA-256 of the
// report's canonical serialization (see CanonicalCSV) — the value a
// caller stores in auditledger.Entry.SummaryHash. Because the hash is
// derived from numbers bias-audit itself computed, the EEOC entry is no
// longer an opaque externally-supplied digest: a regulator can re-run
// the same counts through this producer and reproduce the hash byte for
// byte.
type Report struct {
	// Groups holds one GroupRate per input group, sorted by Label for
	// determinism (the ordering the donor primitive guarantees).
	Groups []GroupRate `json:"groups"`
	// MinLabel / MaxLabel identify the least- and most-selected groups
	// that define the adverse-impact ratio.
	MinLabel string `json:"min_label"`
	MaxLabel string `json:"max_label"`
	// AIR is the worst-pair adverse-impact ratio: min(rate)/max(rate)
	// over groups with Total > 0. 0 when not Applicable.
	AIR float64 `json:"air"`
	// Pass reports whether AIR >= 0.80 (the four-fifths threshold).
	// False when AIR is not computable (Applicable == false).
	Pass bool `json:"pass"`
	// Applicable is true only when at least two groups with Total > 0
	// were observed and the maximum selection rate is positive — the
	// conditions under which the four-fifths rule is meaningful.
	Applicable bool `json:"applicable"`
	// Hash is the SHA-256 (lowercase hex) of CanonicalCSV(report). It is
	// the value stored in Entry.SummaryHash.
	Hash string `json:"hash"`
}

// GroupCount is the primitive input for one protected-class group: the
// number selected out of the total observed. It is the same shape as
// fairness.GroupCount, re-exported so callers stay decoupled from the
// foundation import path.
type GroupCount struct {
	Label    string
	Selected int
	Total    int
}

// Compute runs the EEOC four-fifths adverse-impact analysis over a set
// of protected-class group counts and returns the structured Report
// with a self-derived SummaryHash.
//
// It delegates the full AIR + Wilson-CI math to
// fairness.AdverseImpact(counts, fairness.DefaultZ) — the promoted
// Tier-0 primitive (z = 1.96, the EEOC/NIST 95% two-sided value) — then
// maps the per-group output onto this package's Report and stamps the
// canonical-serialization SHA-256.
func Compute(counts []GroupCount) Report {
	fc := make([]fairness.GroupCount, 0, len(counts))
	for _, c := range counts {
		fc = append(fc, fairness.GroupCount{
			Label:    c.Label,
			Selected: c.Selected,
			Total:    c.Total,
		})
	}

	rep := fairness.AdverseImpact(fc, fairness.DefaultZ)

	groups := make([]GroupRate, 0, len(rep.Groups))
	for _, g := range rep.Groups {
		groups = append(groups, GroupRate{
			Label:         g.Label,
			Selected:      g.Selected,
			Total:         g.Total,
			SelectionRate: g.SelectionRate,
			CILow:         g.CILow,
			CIHigh:        g.CIHigh,
		})
	}

	r := Report{
		Groups:     groups,
		MinLabel:   rep.MinLabel,
		MaxLabel:   rep.MaxLabel,
		AIR:        rep.AIR,
		Pass:       rep.Pass,
		Applicable: rep.Applicable,
	}

	// EXACT-ARITHMETIC VERDICT CORRECTION.
	//
	// The donor primitive evaluates the four-fifths verdict in float64:
	//   AIR = minRate/maxRate;  Pass = AIR >= 0.80
	// where minRate and maxRate are themselves float64 divisions. At the
	// regulatory cutoff this drifts: a selection process whose Adverse-
	// Impact Ratio is EXACTLY 4/5 (e.g. 2/3 vs 5/6 = 12/15, or 3/5 vs 3/4
	// = 12/15) computes as 0.79999999999999993 and is WRONGLY recorded as
	// FAIL (adverse impact flagged) when the EEOC rule — air >= 80% — says
	// it PASSES. An enumeration over all (selected,total) pairs for total
	// in 1..64 finds 2616 such boundary pairs flipped by float rounding
	// (and zero flips in the opposite direction). Because this verdict is
	// sealed by SHA-256 into an append-only legal ledger, a regulator who
	// re-runs the raw counts through the exact rational rule would
	// reproduce a DIFFERENT (correct) Pass than the stored float verdict.
	//
	// We therefore recompute Pass with exact integer cross-multiplication
	// at the cutoff, leaving AIR (a display value) and the Wilson
	// intervals untouched. This ONLY corrects the boundary: it never flips
	// a genuinely-failing (AIR < 4/5) process to PASS. Applicability is
	// governed by the donor (a non-Applicable report keeps Pass=false).
	if rep.Applicable {
		r.Pass = exactFourFifthsPass(counts)
	}

	r.Hash = hashCanonical(r)
	return r
}

// exactFourFifthsPass recomputes the EEOC four-fifths pass/fail verdict
// using exact integer arithmetic, eliminating the float64 boundary drift
// in which an Adverse-Impact Ratio of exactly 4/5 rounds below 0.80.
//
// It selects the least- and most-selected groups (over groups with
// Total > 0) by EXACT rational comparison — matching the donor's float
// pick for all realistic counts but immune to rounding — then evaluates
// the four-fifths rule as the exact cross-multiplication:
//
//	(minSel/minTot) / (maxSel/maxTot) >= 4/5
//	  <=>  5 * minSel * maxTot >= 4 * maxSel * minTot
//
// All products are computed with math/big so arbitrarily large
// protected-class counts can never overflow. It returns false when the
// rule is not applicable (fewer than two groups with Total > 0, or no
// selections in the highest-rate group), mirroring the donor's
// Applicable semantics.
func exactFourFifthsPass(counts []GroupCount) bool {
	var have bool
	var minSel, minTot, maxSel, maxTot int
	eligible := 0
	for _, c := range counts {
		if c.Total <= 0 {
			continue
		}
		eligible++
		if !have {
			minSel, minTot = c.Selected, c.Total
			maxSel, maxTot = c.Selected, c.Total
			have = true
			continue
		}
		// c is the new minimum if its rate < current min rate, i.e.
		// c.Selected/c.Total < minSel/minTot.
		if lessRational(c.Selected, c.Total, minSel, minTot) {
			minSel, minTot = c.Selected, c.Total
		}
		// c is the new maximum if current max rate < c's rate.
		if lessRational(maxSel, maxTot, c.Selected, c.Total) {
			maxSel, maxTot = c.Selected, c.Total
		}
	}
	// maxSel <= 0 means the highest-rate group selected no one, so every
	// rate is 0 — the rule is not meaningful (matches maxRate <= 0).
	if eligible < 2 || maxSel <= 0 {
		return false
	}
	// 5*minSel*maxTot >= 4*maxSel*minTot, exact and overflow-free.
	left := mulInts(5, minSel, maxTot)
	right := mulInts(4, maxSel, minTot)
	return left.Cmp(right) >= 0
}

// lessRational reports whether aSel/aTot < bSel/bTot for non-negative
// counts with positive totals, using exact cross-multiplication
// (aSel*bTot < bSel*aTot) so the ordering never depends on float
// rounding. Computed with math/big to avoid integer overflow.
func lessRational(aSel, aTot, bSel, bTot int) bool {
	lhs := mulInts(aSel, bTot)
	rhs := mulInts(bSel, aTot)
	return lhs.Cmp(rhs) < 0
}

// mulInts returns the exact product of its arguments as a big.Int.
func mulInts(vals ...int) *big.Int {
	acc := big.NewInt(1)
	for _, v := range vals {
		acc.Mul(acc, big.NewInt(int64(v)))
	}
	return acc
}

// CanonicalCSV returns the deterministic byte serialization of a Report
// that the SummaryHash is taken over. The format is a stable,
// newline-delimited CSV: a header row of scalar verdict fields followed
// by one row per group in the donor's label-sorted order. Floats use
// %.10f so the serialization is exact at the regulatory precision and
// platform-independent (no %g locale/exponent drift).
//
// A regulator holding the raw protected-class counts can reproduce this
// byte stream (and therefore the SummaryHash) without trusting the
// bias-audit host — the EEOC entry stops being opaque.
func CanonicalCSV(r Report) []byte {
	var b strings.Builder
	// Verdict header: the scalar four-fifths outcome.
	fmt.Fprintf(&b, "air,pass,applicable,min_label,max_label\n")
	fmt.Fprintf(&b, "%.10f,%t,%t,%s,%s\n",
		r.AIR, r.Pass, r.Applicable, r.MinLabel, r.MaxLabel)
	// Per-group rows, in the donor's label-sorted order.
	fmt.Fprintf(&b, "label,selected,total,selection_rate,ci_low,ci_high\n")
	for _, g := range r.Groups {
		fmt.Fprintf(&b, "%s,%d,%d,%.10f,%.10f,%.10f\n",
			g.Label, g.Selected, g.Total, g.SelectionRate, g.CILow, g.CIHigh)
	}
	return []byte(b.String())
}

// hashCanonical returns the lowercase-hex SHA-256 of CanonicalCSV(r).
func hashCanonical(r Report) string {
	sum := sha256.Sum256(CanonicalCSV(r))
	return hex.EncodeToString(sum[:])
}
