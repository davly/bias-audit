// Package fourfifths computes the EEOC "four-fifths rule" adverse-impact ratio
// (29 C.F.R. § 1607.4(D)) for a selection procedure across protected-class
// groups. It activates the auditledger's EntryTypeEEOCFourFifthsImpact entry
// type + its SignoffNonApplicable / SummaryHash fields, which were declared and
// documented to record exactly this but had no calculator behind them.
//
// It produces a SIGNAL against the published EEOC rule — NOT a legal
// determination. A ratio below 0.80 flags a group for adverse-impact review;
// whether that constitutes unlawful discrimination is the deploying
// organisation's (and counsel's) call, per the repo's liability footer.
package fourfifths

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// FourFifthsThreshold is the EEOC 80% rule: a group's selection rate below
// four-fifths of the highest group's rate is an adverse-impact signal.
const FourFifthsThreshold = 0.80

// ratioEpsilon tolerates floating-point representation error so a ratio that is
// mathematically exactly 0.80 (e.g. 0.64/0.80, which evaluates to
// 0.7999999999999999 in float64) is NOT spuriously flagged. It is far larger
// than float64 error (~1e-16) and far smaller than any meaningful ratio gap.
const ratioEpsilon = 1e-9

// GroupOutcome is one protected-class group's outcome in a single selection
// procedure (e.g. an AEDT screening round): how many applied vs were selected.
type GroupOutcome struct {
	Group      string
	Applicants int
	Selected   int
}

// SelectionRate is Selected/Applicants, or -1 when Applicants <= 0 (undefined:
// you cannot rate a group nobody from applied).
func (g GroupOutcome) SelectionRate() float64 {
	if g.Applicants <= 0 {
		return -1
	}
	return float64(g.Selected) / float64(g.Applicants)
}

// GroupRatio is the computed four-fifths result for one group.
type GroupRatio struct {
	Group           string
	Applicants      int
	Selected        int
	SelectionRate   float64 // -1 if undefined (no applicants)
	ImpactRatio     float64 // rate / reference-group rate; -1 if undefined
	IsReference     bool    // the highest-selecting group (ratio 1.0 by definition)
	BelowFourFifths bool    // ImpactRatio < 0.80 -> adverse-impact signal
}

// ImpactRatios computes each group's selection rate and its EEOC four-fifths
// impact ratio against the REFERENCE group — the group with the highest
// selection rate (29 C.F.R. § 1607.4(D)). Groups with no applicants get
// undefined (-1) rate/ratio and are excluded from reference selection. When no
// group has a positive selection rate, all ratios are undefined.
func ImpactRatios(groups []GroupOutcome) []GroupRatio {
	refRate := -1.0
	for _, g := range groups {
		if r := g.SelectionRate(); r > refRate {
			refRate = r
		}
	}
	out := make([]GroupRatio, 0, len(groups))
	for _, g := range groups {
		rate := g.SelectionRate()
		gr := GroupRatio{
			Group: g.Group, Applicants: g.Applicants, Selected: g.Selected,
			SelectionRate: rate, ImpactRatio: -1,
		}
		if rate >= 0 && refRate > 0 {
			gr.ImpactRatio = rate / refRate
			gr.IsReference = rate == refRate
			gr.BelowFourFifths = gr.ImpactRatio < FourFifthsThreshold-ratioEpsilon
		}
		out = append(out, gr)
	}
	return out
}

// BelowFourFifths returns the names of groups flagged for adverse-impact review
// (impact ratio < 0.80), sorted for determinism.
func BelowFourFifths(groups []GroupOutcome) []string {
	var flagged []string
	for _, gr := range ImpactRatios(groups) {
		if gr.BelowFourFifths {
			flagged = append(flagged, gr.Group)
		}
	}
	sort.Strings(flagged)
	return flagged
}

// SummaryCSV renders the canonical four-fifths impact data as CSV — the document
// whose hash an auditledger Entry.SummaryHash records. Rows are sorted by group
// name so the CSV (and thus its hash) is deterministic.
func SummaryCSV(groups []GroupOutcome) string {
	rows := ImpactRatios(groups)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Group < rows[j].Group })
	var b strings.Builder
	b.WriteString("group,applicants,selected,selection_rate,impact_ratio,below_four_fifths\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%s,%d,%d,%.4f,%.4f,%t\n",
			r.Group, r.Applicants, r.Selected, r.SelectionRate, r.ImpactRatio, r.BelowFourFifths)
	}
	return b.String()
}

// SummaryHash is the sha256 hex of SummaryCSV — the value an auditledger
// Entry{EntryType: EntryTypeEEOCFourFifthsImpact} stores in SummaryHash.
func SummaryHash(groups []GroupOutcome) string {
	sum := sha256.Sum256([]byte(SummaryCSV(groups)))
	return hex.EncodeToString(sum[:])
}
