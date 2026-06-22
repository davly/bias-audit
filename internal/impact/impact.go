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
	r.Hash = hashCanonical(r)
	return r
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
