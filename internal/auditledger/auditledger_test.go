package auditledger

import (
	"crypto/sha256"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davly/bias-audit/internal/mirrormark"
)

// helper — fresh ledger seeded with the cohort-canonical KAT-1 inputs
// (corpus = zero / key = empty). The ledger's Mirror-Marks under this
// seed should byte-equal the corresponding cohort-canonical KAT-1
// mark when payload is empty.
func newKATLedger() *Ledger {
	var corpus [sha256.Size]byte
	return New(corpus, []byte{})
}

// helper — canonical fixture entry for an NYC LL144 annual audit.
func canonicalAnnualEntry(now time.Time) Entry {
	return Entry{
		TenantID:               "tenant_acme",
		AEDTSystemID:           "aedt_recruitor_v2",
		EntryType:              EntryTypeNYCLL144AnnualAudit,
		AuditPeriodStart:       now.AddDate(-1, 0, 0),
		AuditPeriodEnd:         now,
		IndependentAuditorName: "Acme Independent Bias Auditors LLP",
		SignoffStatus:          SignoffPending,
		SummaryHash:            "abc123",
		PublicPostingURL:       "",
	}
}

// TestAllEntryTypes_ClosedSet — R115 enum pin.
func TestAllEntryTypes_ClosedSet(t *testing.T) {
	got := AllEntryTypes()
	want := []EntryType{
		EntryTypeNYCLL144AnnualAudit,
		EntryTypeEUAIActConformityAssessment,
		EntryTypeEEOCFourFifthsImpact,
	}
	if len(got) != len(want) {
		t.Fatalf("AllEntryTypes count: got %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("AllEntryTypes[%d]: got %q, want %q", i, got[i], w)
		}
	}
}

// TestIsKnownEntryType_TrueForCanonical — closed-set membership.
func TestIsKnownEntryType_TrueForCanonical(t *testing.T) {
	for _, et := range AllEntryTypes() {
		if !IsKnownEntryType(et) {
			t.Errorf("IsKnownEntryType(%q): got false", et)
		}
	}
}

// TestIsKnownEntryType_FalseForUnknown — closed-set rejects garbage.
func TestIsKnownEntryType_FalseForUnknown(t *testing.T) {
	if IsKnownEntryType("garbage") {
		t.Error("IsKnownEntryType(garbage): got true, want false")
	}
	if IsKnownEntryType("") {
		t.Error("IsKnownEntryType(empty): got true, want false")
	}
}

// TestAllSignoffStatuses_ClosedSet — R115 enum pin.
func TestAllSignoffStatuses_ClosedSet(t *testing.T) {
	got := AllSignoffStatuses()
	want := []SignoffStatus{SignoffPending, SignoffAttested, SignoffNonApplicable}
	if len(got) != len(want) {
		t.Fatalf("AllSignoffStatuses count: got %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("AllSignoffStatuses[%d]: got %q, want %q", i, got[i], w)
		}
	}
}

// TestNew_FreshLedgerIsEmpty — Len = 0 on new ledger.
func TestNew_FreshLedgerIsEmpty(t *testing.T) {
	l := newKATLedger()
	if got := l.Len(); got != 0 {
		t.Fatalf("fresh ledger Len: got %d, want 0", got)
	}
	if all := l.All(); len(all) != 0 {
		t.Fatalf("fresh ledger All: got %d entries, want 0", len(all))
	}
}

// TestAppend_HappyPath_StampsMarkAndIncrementsLen — canonical append.
func TestAppend_HappyPath_StampsMarkAndIncrementsLen(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	got, err := l.Append(canonicalAnnualEntry(now), now)
	if err != nil {
		t.Fatalf("Append: unexpected err %v", err)
	}
	if got.Mark == "" {
		t.Error("Append: returned entry has empty Mark")
	}
	if !strings.HasPrefix(got.Mark, "lore@v1:") {
		t.Errorf("Append: Mark missing cohort prefix: %q", got.Mark)
	}
	if got.AppendedAt.IsZero() {
		t.Error("Append: returned entry has zero AppendedAt")
	}
	if l.Len() != 1 {
		t.Errorf("ledger Len after one Append: got %d, want 1", l.Len())
	}
}

// TestAppend_RejectsEmptyTenant — closed-set guard.
func TestAppend_RejectsEmptyTenant(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	e := canonicalAnnualEntry(now)
	e.TenantID = ""
	_, err := l.Append(e, now)
	if err != ErrEmptyTenant {
		t.Fatalf("empty TenantID: got %v, want ErrEmptyTenant", err)
	}
}

// TestAppend_RejectsEmptyAEDT — closed-set guard.
func TestAppend_RejectsEmptyAEDT(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	e := canonicalAnnualEntry(now)
	e.AEDTSystemID = ""
	_, err := l.Append(e, now)
	if err != ErrEmptyAEDTSystem {
		t.Fatalf("empty AEDTSystemID: got %v, want ErrEmptyAEDTSystem", err)
	}
}

// TestAppend_RejectsUnknownEntryType — closed-set guard.
func TestAppend_RejectsUnknownEntryType(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	e := canonicalAnnualEntry(now)
	e.EntryType = "garbage_type"
	_, err := l.Append(e, now)
	if err != ErrUnknownEntryType {
		t.Fatalf("unknown EntryType: got %v, want ErrUnknownEntryType", err)
	}
}

// TestAppend_RejectsUnknownSignoffStatus — closed-set guard.
func TestAppend_RejectsUnknownSignoffStatus(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	e := canonicalAnnualEntry(now)
	e.SignoffStatus = "approved"
	_, err := l.Append(e, now)
	if err != ErrUnknownSignoffStatus {
		t.Fatalf("unknown SignoffStatus: got %v, want ErrUnknownSignoffStatus", err)
	}
}

// TestAppend_RejectsInvertedPeriod — period sanity guard.
func TestAppend_RejectsInvertedPeriod(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	e := canonicalAnnualEntry(now)
	e.AuditPeriodStart, e.AuditPeriodEnd = e.AuditPeriodEnd, e.AuditPeriodStart
	_, err := l.Append(e, now)
	if err != ErrAuditPeriodInverted {
		t.Fatalf("inverted period: got %v, want ErrAuditPeriodInverted", err)
	}
}

// TestAppend_NYCLL144_RejectsNonAnnualPeriod — annual cadence pin.
func TestAppend_NYCLL144_RejectsNonAnnualPeriod(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	e := canonicalAnnualEntry(now)
	e.AuditPeriodEnd = e.AuditPeriodStart.Add(30 * 24 * time.Hour)
	_, err := l.Append(e, now)
	if err != ErrAuditPeriodNotAnnual {
		t.Fatalf("30-day period for NYC LL144: got %v, want ErrAuditPeriodNotAnnual", err)
	}
}

// TestAppend_NYCLL144_Accepts365DayPeriod — exact annual.
func TestAppend_NYCLL144_Accepts365DayPeriod(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	e := canonicalAnnualEntry(now)
	e.AuditPeriodEnd = e.AuditPeriodStart.Add(365 * 24 * time.Hour)
	_, err := l.Append(e, now)
	if err != nil {
		t.Fatalf("365-day period for NYC LL144: got %v, want nil", err)
	}
}

// TestAppend_EUAIAct_AcceptsNonAnnualPeriod — only NYC LL144 is
// annual-gated; EU AI Act conformity assessments are per-version.
func TestAppend_EUAIAct_AcceptsNonAnnualPeriod(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	e := canonicalAnnualEntry(now)
	e.EntryType = EntryTypeEUAIActConformityAssessment
	e.AuditPeriodEnd = e.AuditPeriodStart.Add(30 * 24 * time.Hour)
	_, err := l.Append(e, now)
	if err != nil {
		t.Fatalf("30-day period for EU AI Act: got %v, want nil", err)
	}
}

// TestAppend_AttestedWithoutSignoffDate — discipline guard.
func TestAppend_AttestedWithoutSignoffDate(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	e := canonicalAnnualEntry(now)
	e.SignoffStatus = SignoffAttested
	// SignoffDate left zero
	_, err := l.Append(e, now)
	if err != ErrAttestedWithoutSignoffDate {
		t.Fatalf("attested w/o date: got %v, want ErrAttestedWithoutSignoffDate", err)
	}
}

// TestAppend_AttestedWithoutAuditor — discipline guard.
func TestAppend_AttestedWithoutAuditor(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	e := canonicalAnnualEntry(now)
	e.SignoffStatus = SignoffAttested
	e.SignoffDate = now
	e.IndependentAuditorName = ""
	_, err := l.Append(e, now)
	if err != ErrAttestedWithoutAuditor {
		t.Fatalf("attested w/o auditor: got %v, want ErrAttestedWithoutAuditor", err)
	}
}

// TestAppend_AttestedHappyPath — full attestation flow.
func TestAppend_AttestedHappyPath(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	e := canonicalAnnualEntry(now)
	e.SignoffStatus = SignoffAttested
	e.SignoffDate = now
	got, err := l.Append(e, now)
	if err != nil {
		t.Fatalf("attested happy path: unexpected err %v", err)
	}
	if got.SignoffStatus != SignoffAttested {
		t.Errorf("SignoffStatus: got %q, want attested", got.SignoffStatus)
	}
}

// TestVerifyEntry_RoundtripsAcrossAppend — Mark cold-verify.
func TestVerifyEntry_RoundtripsAcrossAppend(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	got, err := l.Append(canonicalAnnualEntry(now), now)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := l.VerifyEntry(got); err != nil {
		t.Fatalf("VerifyEntry: got %v, want nil (cohort cold-verify)", err)
	}
}

// TestVerifyEntry_RejectsTamperedSummaryHash — payload mutation.
func TestVerifyEntry_RejectsTamperedSummaryHash(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	got, err := l.Append(canonicalAnnualEntry(now), now)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	tampered := got
	tampered.SummaryHash = "modified_after_signing"
	err = l.VerifyEntry(tampered)
	if err != mirrormark.ErrSignatureMismatch {
		t.Fatalf("tampered payload: got %v, want ErrSignatureMismatch", err)
	}
}

// TestByType_FiltersToRequestedType — filter discipline.
func TestByType_FiltersToRequestedType(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	annual := canonicalAnnualEntry(now)
	conformity := canonicalAnnualEntry(now)
	conformity.EntryType = EntryTypeEUAIActConformityAssessment
	conformity.AuditPeriodEnd = conformity.AuditPeriodStart.Add(30 * 24 * time.Hour)
	if _, err := l.Append(annual, now); err != nil {
		t.Fatalf("Append annual: %v", err)
	}
	if _, err := l.Append(conformity, now); err != nil {
		t.Fatalf("Append conformity: %v", err)
	}
	annuals := l.ByType(EntryTypeNYCLL144AnnualAudit)
	if len(annuals) != 1 {
		t.Errorf("ByType annual: got %d, want 1", len(annuals))
	}
	confs := l.ByType(EntryTypeEUAIActConformityAssessment)
	if len(confs) != 1 {
		t.Errorf("ByType conformity: got %d, want 1", len(confs))
	}
}

// TestByTenant_FiltersToRequestedTenant — multi-tenant separation.
func TestByTenant_FiltersToRequestedTenant(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	a := canonicalAnnualEntry(now)
	a.TenantID = "tenant_alpha"
	b := canonicalAnnualEntry(now)
	b.TenantID = "tenant_beta"
	if _, err := l.Append(a, now); err != nil {
		t.Fatalf("Append alpha: %v", err)
	}
	if _, err := l.Append(b, now); err != nil {
		t.Fatalf("Append beta: %v", err)
	}
	alphas := l.ByTenant("tenant_alpha")
	if len(alphas) != 1 || alphas[0].TenantID != "tenant_alpha" {
		t.Errorf("ByTenant alpha: got %d entries (first=%v), want 1 with tenant_alpha", len(alphas), alphas)
	}
}

// TestAnnualCadenceCompliance_PartitionsCoveredAndUncovered — R153.A.
func TestAnnualCadenceCompliance_PartitionsCoveredAndUncovered(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	// covered: tenant_acme has a 2026-04-01-ending annual audit, < 1y old.
	covered := canonicalAnnualEntry(now)
	covered.TenantID = "tenant_acme"
	covered.AuditPeriodEnd = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	covered.AuditPeriodStart = covered.AuditPeriodEnd.AddDate(-1, 0, 0)
	if _, err := l.Append(covered, now); err != nil {
		t.Fatalf("Append covered: %v", err)
	}

	// uncovered: tenant_widget has a non-annual conformity entry only.
	uncoveredE := canonicalAnnualEntry(now)
	uncoveredE.TenantID = "tenant_widget"
	uncoveredE.EntryType = EntryTypeEUAIActConformityAssessment
	uncoveredE.AuditPeriodStart = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	uncoveredE.AuditPeriodEnd = time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	if _, err := l.Append(uncoveredE, now); err != nil {
		t.Fatalf("Append uncovered: %v", err)
	}

	gotCovered, gotUncovered := l.AnnualCadenceCompliance(now)
	if len(gotCovered) != 1 || gotCovered[0].TenantID != "tenant_acme" {
		t.Errorf("covered: got %v, want [tenant_acme/aedt_recruitor_v2]", gotCovered)
	}
	if len(gotUncovered) != 1 || gotUncovered[0].TenantID != "tenant_widget" {
		t.Errorf("uncovered: got %v, want [tenant_widget/aedt_recruitor_v2]", gotUncovered)
	}
}

// TestAnnualCadenceCompliance_StaleAnnualUncovered — > 1y means uncovered.
func TestAnnualCadenceCompliance_StaleAnnualUncovered(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	stale := canonicalAnnualEntry(now)
	stale.TenantID = "tenant_stale"
	stale.AuditPeriodEnd = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	stale.AuditPeriodStart = stale.AuditPeriodEnd.AddDate(-1, 0, 0)
	if _, err := l.Append(stale, now); err != nil {
		t.Fatalf("Append stale: %v", err)
	}

	_, gotUncovered := l.AnnualCadenceCompliance(now)
	if len(gotUncovered) != 1 || gotUncovered[0].TenantID != "tenant_stale" {
		t.Errorf("stale annual: got uncovered=%v, want [tenant_stale/...]", gotUncovered)
	}
}

// TestAll_ReturnsDefensiveCopy — caller mutation does not affect ledger.
func TestAll_ReturnsDefensiveCopy(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if _, err := l.Append(canonicalAnnualEntry(now), now); err != nil {
		t.Fatalf("Append: %v", err)
	}
	copy1 := l.All()
	copy1[0].TenantID = "mutated"
	copy2 := l.All()
	if copy2[0].TenantID == "mutated" {
		t.Error("All() did not return a defensive copy — caller mutation leaked into ledger")
	}
}

// TestAppend_GoroutineSafeWithMixedOperations — sync.RWMutex correctness.
func TestAppend_GoroutineSafeWithMixedOperations(t *testing.T) {
	l := newKATLedger()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = l.Append(canonicalAnnualEntry(now), now)
		}()
	}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = l.All()
			_ = l.Len()
		}()
	}
	wg.Wait()
	if got := l.Len(); got != 50 {
		t.Errorf("after 50 concurrent appends, Len: got %d, want 50", got)
	}
}

// TestCanonicalPayload_DeterministicAcrossCalls — same entry, same bytes.
func TestCanonicalPayload_DeterministicAcrossCalls(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	e := canonicalAnnualEntry(now)
	e.AppendedAt = now
	first := CanonicalPayload(e)
	for i := 0; i < 32; i++ {
		got := CanonicalPayload(e)
		if string(got) != string(first) {
			t.Fatalf("iter %d: non-deterministic CanonicalPayload:\n  first: %q\n  iter:  %q", i, first, got)
		}
	}
}

// TestCanonicalPayload_ContainsKeyFields — payload format pin.
func TestCanonicalPayload_ContainsKeyFields(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	e := canonicalAnnualEntry(now)
	e.AppendedAt = now
	payload := string(CanonicalPayload(e))
	requiredFields := []string{
		"tenant:", "aedt:", "type:", "period:",
		"auditor:", "signoff:", "summary:", "posting:", "appended:",
	}
	for _, f := range requiredFields {
		if !strings.Contains(payload, f) {
			t.Errorf("CanonicalPayload missing field %q:\n%s", f, payload)
		}
	}
}

// TestSelfCheck_GreenAndDeterministic pins the SelfCheck contract used
// by Stele spine anchoring: a healthy ledger self-checks green, and
// the canonical run serialization is deterministic — the same entries
// in the same order produce the same digest across independent
// ledgers, and append ORDER is load-bearing.
func TestSelfCheck_GreenAndDeterministic(t *testing.T) {
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	entryA := canonicalAnnualEntry(now)
	entryB := Entry{
		TenantID:               "tenant_beta",
		AEDTSystemID:           "aedt_screener_v1",
		EntryType:              EntryTypeEUAIActConformityAssessment,
		AuditPeriodStart:       now.AddDate(0, -2, 0),
		AuditPeriodEnd:         now,
		IndependentAuditorName: "EU Notified Body 1234",
		SignoffStatus:          SignoffPending,
		SummaryHash:            "conformity_hash",
	}

	build := func(entries ...Entry) *Ledger {
		l := newKATLedger()
		for _, e := range entries {
			if _, err := l.Append(e, now); err != nil {
				t.Fatalf("Append: %v", err)
			}
		}
		return l
	}

	l1 := build(entryA, entryB)
	n1, d1, err := l1.SelfCheck()
	if err != nil {
		t.Fatalf("SelfCheck on healthy ledger: %v", err)
	}
	if n1 != 2 {
		t.Errorf("SelfCheck count: got %d, want 2", n1)
	}
	var zero [sha256.Size]byte
	if d1 == zero {
		t.Errorf("SelfCheck digest is zero for a non-empty ledger")
	}

	// Determinism: an independent ledger with the same entries
	// appended at the same now produces the same digest.
	_, d2, err := build(entryA, entryB).SelfCheck()
	if err != nil {
		t.Fatalf("SelfCheck on second ledger: %v", err)
	}
	if d1 != d2 {
		t.Errorf("SelfCheck digest non-deterministic: %x vs %x", d1, d2)
	}

	// Order-sensitivity: append order is load-bearing for an
	// append-only ledger — swapping entries MUST change the digest.
	_, d3, err := build(entryB, entryA).SelfCheck()
	if err != nil {
		t.Fatalf("SelfCheck on swapped ledger: %v", err)
	}
	if d3 == d1 {
		t.Errorf("SelfCheck digest insensitive to entry order: %x", d3)
	}
}

// TestSelfCheck_DetectsTamper pins the integrity half of SelfCheck:
// post-Append mutation of entry content or carried mark MUST fail the
// self-check (this is the gate that keeps a tampered ledger from
// being anchored LIT into the Stele spine).
func TestSelfCheck_DetectsTamper(t *testing.T) {
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)

	// Tampered entry content (direct slice mutation — the documented
	// antipattern the self-check exists to surface).
	l := newKATLedger()
	if _, err := l.Append(canonicalAnnualEntry(now), now); err != nil {
		t.Fatalf("Append: %v", err)
	}
	l.entries[0].SummaryHash = "tampered_hash"
	if _, _, err := l.SelfCheck(); err == nil {
		t.Errorf("SelfCheck accepted a tampered SummaryHash, want failure")
	}

	// Tampered mark (still cohort-prefixed so the prefix gate alone
	// cannot catch it).
	l2 := newKATLedger()
	stamped, err := l2.Append(canonicalAnnualEntry(now), now)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	l2.entries[0].Mark = stamped.Mark[:len(stamped.Mark)-2] + "xx"
	if _, _, err := l2.SelfCheck(); err == nil {
		t.Errorf("SelfCheck accepted a tampered mark, want failure")
	}

	// Mark missing the cohort prefix entirely.
	l3 := newKATLedger()
	if _, err := l3.Append(canonicalAnnualEntry(now), now); err != nil {
		t.Fatalf("Append: %v", err)
	}
	l3.entries[0].Mark = "not-a-mark"
	if _, _, err := l3.SelfCheck(); err == nil {
		t.Errorf("SelfCheck accepted a prefix-less mark, want failure")
	}
}

// TestSelfCheck_DetectsClosedSetMutation pins the cheap structural
// re-validation: an entry whose closed-set enum fields were mutated
// post-Append out of the R115 closed sets fails the self-check.
func TestSelfCheck_DetectsClosedSetMutation(t *testing.T) {
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)

	l := newKATLedger()
	if _, err := l.Append(canonicalAnnualEntry(now), now); err != nil {
		t.Fatalf("Append: %v", err)
	}
	l.entries[0].EntryType = "garbage_type"
	if _, _, err := l.SelfCheck(); err == nil {
		t.Errorf("SelfCheck accepted an out-of-enum EntryType, want failure")
	}

	l2 := newKATLedger()
	if _, err := l2.Append(canonicalAnnualEntry(now), now); err != nil {
		t.Fatalf("Append: %v", err)
	}
	l2.entries[0].SignoffStatus = "garbage_status"
	if _, _, err := l2.SelfCheck(); err == nil {
		t.Errorf("SelfCheck accepted an out-of-enum SignoffStatus, want failure")
	}
}

// TestSelfCheck_EmptyLedger pins the empty-ledger shape: zero entries
// is not an integrity failure (count 0, the sha256 of the empty
// stream, nil error).
func TestSelfCheck_EmptyLedger(t *testing.T) {
	n, d, err := newKATLedger().SelfCheck()
	if err != nil {
		t.Fatalf("SelfCheck on empty ledger: %v", err)
	}
	if n != 0 {
		t.Errorf("SelfCheck count on empty ledger: got %d, want 0", n)
	}
	if want := sha256.Sum256(nil); d != want {
		t.Errorf("SelfCheck digest on empty ledger: got %x, want sha256 of empty stream %x", d, want)
	}
}
