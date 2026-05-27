package manifest

import (
	"sort"
	"testing"
	"time"
)

// TestSeed_NonEmpty — sanity.
func TestSeed_NonEmpty(t *testing.T) {
	if len(Seed()) == 0 {
		t.Fatal("Seed returned empty manifest")
	}
}

// TestSeed_EntryCount — pins canonical entry count.
// 11 entries: 6 regulations + 3 cohort-rule pins + 1 parity + 1 R153.A.
func TestSeed_EntryCount(t *testing.T) {
	const expected = 11
	got := len(Seed())
	if got != expected {
		t.Fatalf("Seed entry count drift: got %d, want %d", got, expected)
	}
}

// TestSeed_AllEntriesHaveNonEmptyKey — non-empty Key.
func TestSeed_AllEntriesHaveNonEmptyKey(t *testing.T) {
	for i, e := range Seed() {
		if e.Key == "" {
			t.Errorf("Entry %d: empty Key", i)
		}
	}
}

// TestSeed_AllKeysUnique — unique Keys.
func TestSeed_AllKeysUnique(t *testing.T) {
	seen := map[string]int{}
	for i, e := range Seed() {
		if prev, ok := seen[e.Key]; ok {
			t.Errorf("Duplicate Key %q at indices %d and %d", e.Key, prev, i)
		}
		seen[e.Key] = i
	}
}

// TestSeed_AllSourceValuesCanonical — every Source in AllSources.
func TestSeed_AllSourceValuesCanonical(t *testing.T) {
	allowed := map[string]bool{}
	for _, s := range AllSources() {
		allowed[s] = true
	}
	for i, e := range Seed() {
		if !allowed[e.Source] {
			t.Errorf("Entry %d (%q): Source %q not in AllSources", i, e.Key, e.Source)
		}
	}
}

// TestSeed_AllReviewerClassesCanonical — every ReviewerClass in AllReviewerClasses.
func TestSeed_AllReviewerClassesCanonical(t *testing.T) {
	allowed := map[ReviewerClass]bool{}
	for _, r := range AllReviewerClasses() {
		allowed[r] = true
	}
	for i, e := range Seed() {
		if !allowed[e.ReviewerClass] {
			t.Errorf("Entry %d (%q): ReviewerClass %q not in AllReviewerClasses", i, e.Key, e.ReviewerClass)
		}
	}
}

// TestSeed_AllSchemaVersionsCurrent — every entry at SchemaVersion.
func TestSeed_AllSchemaVersionsCurrent(t *testing.T) {
	for i, e := range Seed() {
		if e.SchemaVersion != SchemaVersion {
			t.Errorf("Entry %d (%q): SchemaVersion %d, want %d", i, e.Key, e.SchemaVersion, SchemaVersion)
		}
	}
}

// TestSeed_AllReviewedByCounselFalse — R166 honest-default pin.
//
// Every seed entry MUST default to ReviewedByCounsel = false. Flipping
// any to true requires its own R145.B sibling-not-stacked branch +
// named counsel signoff per R166 anti-pattern (3).
func TestSeed_AllReviewedByCounselFalse(t *testing.T) {
	for i, e := range Seed() {
		if e.ReviewedByCounsel {
			t.Errorf("Entry %d (%q): ReviewedByCounsel = true (R166 honest-default violation)", i, e.Key)
		}
	}
}

// TestSeed_AllReviewerClassFounderDraft — R166 founder-draft baseline.
//
// Every seed entry MUST start at ReviewerClassFounder. Promoting an
// entry to a counsel ReviewerClass is a behaviour-changing event.
func TestSeed_AllReviewerClassFounderDraft(t *testing.T) {
	for i, e := range Seed() {
		if e.ReviewerClass != ReviewerClassFounder {
			t.Errorf("Entry %d (%q): ReviewerClass = %q (R166 founder-draft baseline violation)", i, e.Key, e.ReviewerClass)
		}
	}
}

// TestSeed_NYCLL144Citation — load-bearing NYC regulation entry.
func TestSeed_NYCLL144Citation(t *testing.T) {
	found := false
	for _, e := range Seed() {
		if e.Key == "regulation.nyc_local_law_144.aedt" {
			found = true
			if e.Jurisdiction != "US-NY" {
				t.Errorf("NYC LL144 entry: Jurisdiction = %q, want US-NY", e.Jurisdiction)
			}
			if e.Confidence != ConfidenceHigh {
				t.Errorf("NYC LL144 entry: Confidence = %d, want High (3)", e.Confidence)
			}
		}
	}
	if !found {
		t.Fatal("NYC LL144 entry missing from Seed()")
	}
}

// TestSeed_EUAIActCitation — load-bearing EU regulation entry.
func TestSeed_EUAIActCitation(t *testing.T) {
	found := false
	for _, e := range Seed() {
		if e.Key == "regulation.eu_ai_act.annex_iii_hr" {
			found = true
			if e.Jurisdiction != "EU" {
				t.Errorf("EU AI Act entry: Jurisdiction = %q, want EU", e.Jurisdiction)
			}
		}
	}
	if !found {
		t.Fatal("EU AI Act entry missing from Seed()")
	}
}

// TestSeed_EEOCFourFifthsCitation — load-bearing EEOC entry.
func TestSeed_EEOCFourFifthsCitation(t *testing.T) {
	found := false
	for _, e := range Seed() {
		if e.Key == "regulation.eeoc.uniform_guidelines_four_fifths" {
			found = true
			if e.Jurisdiction != "US" {
				t.Errorf("EEOC entry: Jurisdiction = %q, want US", e.Jurisdiction)
			}
		}
	}
	if !found {
		t.Fatal("EEOC entry missing from Seed()")
	}
}

// TestSeed_R153ASaturatorMarker — pins the 3rd-saturator claim.
func TestSeed_R153ASaturatorMarker(t *testing.T) {
	found := false
	for _, e := range Seed() {
		if e.Key == "cohort.r153a.audit_ledger_3rd_saturator" {
			found = true
		}
	}
	if !found {
		t.Fatal("R153.A 3rd-saturator marker entry missing — cohort claim is INDEX-LIE without it")
	}
}

// TestIsStale_MissingFreshAt_AlwaysTrue — sentinel branch.
func TestIsStale_MissingFreshAt_AlwaysTrue(t *testing.T) {
	e := Entry{
		Key:               "test",
		FreshAt:           FreshAtUnknown,
		Source:            SourceContextDoc,
		SchemaVersion:     SchemaVersion,
		Confidence:        ConfidenceLow,
		ReviewerClass:     ReviewerClassFounder,
		ReviewedByCounsel: false,
	}
	cases := []struct {
		now    time.Time
		maxAge time.Duration
	}{
		{time.Now(), time.Hour},
		{time.Now(), 100 * 365 * 24 * time.Hour},
		{FreshAtUnknown, time.Hour},
		{FreshAtUnknown.Add(time.Second), 24 * time.Hour},
	}
	for i, c := range cases {
		if !e.IsStale(c.now, c.maxAge) {
			t.Errorf("case %d: IsStale returned false", i)
		}
	}
}

// TestIsStale_FreshEntry_NotStale — recent FreshAt + generous maxAge.
func TestIsStale_FreshEntry_NotStale(t *testing.T) {
	now := time.Now()
	e := Entry{
		Key:               "test",
		FreshAt:           now.Add(-1 * time.Hour),
		Source:            SourceNYCLocalLaw144,
		SchemaVersion:     SchemaVersion,
		Confidence:        ConfidenceHigh,
		ReviewerClass:     ReviewerClassFounder,
		ReviewedByCounsel: false,
	}
	if e.IsStale(now, 24*time.Hour) {
		t.Error("recent-FreshAt entry incorrectly flagged stale")
	}
}

// TestSortedKeys_Deterministic — alphabetical output.
func TestSortedKeys_Deterministic(t *testing.T) {
	m := Seed()
	first := m.SortedKeys()
	if !sort.StringsAreSorted(first) {
		t.Fatal("SortedKeys output not sorted")
	}
	for i := 0; i < 5; i++ {
		got := m.SortedKeys()
		if len(got) != len(first) {
			t.Fatalf("iter %d: length drift", i)
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("iter %d index %d: drift", i, j)
			}
		}
	}
}

// TestAllSources_NonEmpty — non-empty AllSources.
func TestAllSources_NonEmpty(t *testing.T) {
	if len(AllSources()) == 0 {
		t.Fatal("AllSources returned empty list")
	}
	for i, s := range AllSources() {
		if s == "" {
			t.Errorf("AllSources[%d]: empty string", i)
		}
	}
}

// TestAllReviewerClasses_NonEmpty — non-empty AllReviewerClasses.
func TestAllReviewerClasses_NonEmpty(t *testing.T) {
	if len(AllReviewerClasses()) == 0 {
		t.Fatal("AllReviewerClasses returned empty list")
	}
	for i, r := range AllReviewerClasses() {
		if r == "" {
			t.Errorf("AllReviewerClasses[%d]: empty string", i)
		}
	}
}

// TestSchemaVersion_PinnedAtV1 — R150 schema version pin.
func TestSchemaVersion_PinnedAtV1(t *testing.T) {
	if SchemaVersion != 1 {
		t.Fatalf("SchemaVersion: got %d, want 1 (R150 v1)", SchemaVersion)
	}
}

// TestSeed_JurisdictionPopulatedForRegulations — every regulation entry
// carries a Jurisdiction.
func TestSeed_JurisdictionPopulatedForRegulations(t *testing.T) {
	for _, e := range Seed() {
		if e.Jurisdiction == "" {
			t.Errorf("Entry %q: empty Jurisdiction (R150 jurisdiction-axis pin)", e.Key)
		}
		if e.StatuteVersion == "" {
			t.Errorf("Entry %q: empty StatuteVersion (R150 version-axis pin)", e.Key)
		}
	}
}
