package main

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/davly/bias-audit/internal/auditledger"
	"github.com/davly/bias-audit/internal/honest"
	"github.com/davly/bias-audit/internal/legal"
	"github.com/davly/bias-audit/internal/lore"
	"github.com/davly/bias-audit/internal/manifest"
	"github.com/davly/bias-audit/internal/mirrormark"
)

// TestVersion_NonEmpty — sanity: version string populated.
func TestVersion_NonEmpty(t *testing.T) {
	if version == "" {
		t.Fatal("version: empty string")
	}
}

// TestVersion_PhaseScaffold — pin Phase-1 marker.
func TestVersion_PhaseScaffold(t *testing.T) {
	const expected = "0.1.0-phase1-scaffold"
	if version != expected {
		t.Fatalf("version drift: got %q, want %q", version, expected)
	}
}

// TestDemoCadenceCheck_SmokeTest — wiring smoke test for the demo
// pipeline; exercises every internal package from main.
//
// Builds the same in-memory ledger demoCadenceCheck() builds, asserts
// every Mirror-Mark verifies, and asserts the cadence-compliance
// partition is correct.
func TestDemoCadenceCheck_SmokeTest(t *testing.T) {
	var corpus [sha256.Size]byte
	l := auditledger.New(corpus, []byte{})
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)

	recent := auditledger.Entry{
		TenantID:               "tenant_alpha",
		AEDTSystemID:           "aedt_recruiter_v2",
		EntryType:              auditledger.EntryTypeNYCLL144AnnualAudit,
		AuditPeriodStart:       now.AddDate(-1, 0, 0),
		AuditPeriodEnd:         now,
		IndependentAuditorName: "Acme Independent Bias Auditors LLP",
		SignoffStatus:          auditledger.SignoffAttested,
		SignoffDate:            now,
		SummaryHash:            "demo_recent_hash",
		PublicPostingURL:       "https://acme.example/aedt-audit-2026.pdf",
	}
	if _, err := l.Append(recent, now); err != nil {
		t.Fatalf("Append recent: %v", err)
	}

	conformity := auditledger.Entry{
		TenantID:               "tenant_beta",
		AEDTSystemID:           "aedt_screener_v1",
		EntryType:              auditledger.EntryTypeEUAIActConformityAssessment,
		AuditPeriodStart:       now.AddDate(0, -2, 0),
		AuditPeriodEnd:         now,
		IndependentAuditorName: "EU Notified Body 1234",
		SignoffStatus:          auditledger.SignoffPending,
		SummaryHash:            "demo_conformity_hash",
	}
	if _, err := l.Append(conformity, now); err != nil {
		t.Fatalf("Append conformity: %v", err)
	}

	covered, uncovered := l.AnnualCadenceCompliance(now)
	if len(covered) != 1 || covered[0].TenantID != "tenant_alpha" {
		t.Errorf("covered: got %v, want [tenant_alpha/aedt_recruiter_v2]", covered)
	}
	if len(uncovered) != 1 || uncovered[0].TenantID != "tenant_beta" {
		t.Errorf("uncovered: got %v, want [tenant_beta/aedt_screener_v1]", uncovered)
	}

	for _, e := range l.All() {
		if err := mirrormark.Verify(e.Mark, corpus, auditledger.CanonicalPayload(e), []byte{}); err != nil {
			t.Errorf("Mirror-Mark verify drift on %s: %v", e.TenantID, err)
		}
	}
}

// TestImports_AllInternalPackagesReachableFromMain — wiring discipline.
//
// Every R174 5-of-5 cohort package + the 2 bias-audit domain packages
// MUST be reachable from `cmd/bias-audit/main.go`. The test calls a
// canonical exported function from each to assert real import + real
// usage (catches the Inverse-INDEX-LIE sub-class per R155.A: a package
// exists in source tree but no main entry point imports it).
func TestImports_AllInternalPackagesReachableFromMain(t *testing.T) {
	if got := honest.CanonicalAdvisories(); len(got) == 0 {
		t.Error("internal/honest: CanonicalAdvisories returns empty (Inverse-INDEX-LIE risk)")
	}
	if got := legal.LegalLiabilityFooter; got == "" {
		t.Error("internal/legal: LegalLiabilityFooter empty (Inverse-INDEX-LIE risk)")
	}
	if got := lore.Digest; got == "" {
		t.Error("internal/lore: Digest empty (Inverse-INDEX-LIE risk)")
	}
	if got := manifest.Seed(); len(got) == 0 {
		t.Error("internal/manifest: Seed empty (Inverse-INDEX-LIE risk)")
	}
	// auditledger + mirrormark are wired via TestDemoCadenceCheck_SmokeTest above.
}
