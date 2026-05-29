// Additive `.evidence`-bundle export tests (2026-05-29).
//
// These are the "bias-audit is a REAL consumer, not a library" proof,
// mirroring Folio's handlers_audit_evidence_test.go. The load-bearing test
// (TestExportEvidence_EndToEnd_FullVerifyPasses) takes REAL ledger data →
// exports a .evidence bundle via the production path → runs the
// limitless-evidence-bundle repo's OWN full verify chain (KAT-1 +
// content-hash + Mirror-Mark) over it → asserts PASS. That round trip is
// exactly the Phase-2 acceptance test SPEC.md §10 names for a consumer.
//
// They also pin the additive contract: placeholder corpus → refuse (a
// .evidence bundle has no meaningful unsigned form); the export is read-only
// over the ledger; and the existing per-row ledger behaviour (CanonicalPayload
// / Append / VerifyEntry wire format) is byte-for-byte unchanged.

package auditledger

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/davly/bias-audit/internal/mirrormark"
	"github.com/davly/limitless-evidence-bundle/pkg/evidence"
)

// realCorpusKey returns a deterministic NON-ZERO corpus + key so the emitted
// bundle cold-verifies (the zero corpus is rejected by design). The 0xC4 fill
// matches the value Folio's auditMarkerForTest uses, keeping the harness
// recognisable across the two consumers.
func realCorpusKey() ([sha256.Size]byte, []byte) {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = 0xC4
	}
	return corpus, []byte("iik_test_BIAS_AUDIT_evidence")
}

// signedLedger returns a ledger seeded with a real (non-zero) corpus + key
// and a couple of representative rows, so the exported bundle covers real
// data (not an empty ledger).
func signedLedger(t *testing.T) (*Ledger, [sha256.Size]byte, []byte, time.Time) {
	t.Helper()
	corpus, key := realCorpusKey()
	l := New(corpus, key)
	now := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)

	annual := canonicalAnnualEntry(now)
	annual.TenantID = "tenant_acme"
	annual.SignoffStatus = SignoffAttested
	annual.SignoffDate = now
	if _, err := l.Append(annual, now); err != nil {
		t.Fatalf("seed annual: %v", err)
	}

	conformity := canonicalAnnualEntry(now)
	conformity.TenantID = "tenant_acme"
	conformity.EntryType = EntryTypeEUAIActConformityAssessment
	conformity.AuditPeriodEnd = conformity.AuditPeriodStart.Add(30 * 24 * time.Hour)
	if _, err := l.Append(conformity, now); err != nil {
		t.Fatalf("seed conformity: %v", err)
	}

	beta := canonicalAnnualEntry(now)
	beta.TenantID = "tenant_beta"
	if _, err := l.Append(beta, now); err != nil {
		t.Fatalf("seed beta: %v", err)
	}

	return l, corpus, key, now
}

// TestExportEvidence_EndToEnd_FullVerifyPasses is the load-bearing proof.
// Real ledger rows → production export path → bundle → evidence-repo ModeFull
// verify (KAT + content-hash + Mirror-Mark) → PASS.
func TestExportEvidence_EndToEnd_FullVerifyPasses(t *testing.T) {
	l, _, key, now := signedLedger(t)

	export, err := l.ExportEvidenceSnapshot(EvidenceScope{}, now)
	if err != nil {
		t.Fatalf("ExportEvidenceSnapshot: %v", err)
	}
	if len(export.Bundle) == 0 {
		t.Fatal("empty bundle in export")
	}
	if !strings.HasPrefix(string(export.Bundle), "LIMITLESS-EVIDENCE-v1\n") {
		head := string(export.Bundle)
		if len(head) > 40 {
			head = head[:40]
		}
		t.Fatalf("bundle missing v1 magic header; got %q", head)
	}

	// THE PROOF: run the evidence-bundle repo's own full verify chain over the
	// produced bundle, using the exact payload bytes the export carried and the
	// key the ledger signed under. This is the cold-verify a regulator runs.
	res := evidence.Verify(export.Bundle, evidence.ModeFull, export.PayloadBytes, key)
	if res.Class != "PASS" {
		t.Fatalf("evidence full-verify did NOT pass: class=%s verdict=%s failures=%v",
			res.Class, res.Verdict, res.Failures)
	}
	if !res.KAT1Verified || !res.ContentHashVerified || !res.MirrorMarkVerified {
		t.Fatalf("not all chain steps verified: %+v", res)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit_code 0 on PASS, got %d", res.ExitCode)
	}
	if res.Domain != evidenceDomain {
		t.Fatalf("bundle domain = %q, want %q", res.Domain, evidenceDomain)
	}

	// The payload must actually carry the seeded rows (not an empty export).
	var payload LedgerEvidencePayload
	if err := json.Unmarshal(export.PayloadBytes, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Count != 3 {
		t.Fatalf("expected 3 exported rows (3 seeded), got %d", payload.Count)
	}
	if payload.Count != len(payload.Entries) {
		t.Fatalf("Count (%d) != len(Entries) (%d)", payload.Count, len(payload.Entries))
	}
	if payload.PayloadVersion != EvidencePayloadVersion {
		t.Fatalf("payload version = %q, want %q", payload.PayloadVersion, EvidencePayloadVersion)
	}
	// Each exported row must still carry its per-row Mirror-Mark — the bundle
	// envelope does not replace per-row cold-verify.
	for i, e := range payload.Entries {
		if e.Mark == "" {
			t.Fatalf("exported row %d has empty per-row Mark", i)
		}
	}
}

// TestExportEvidence_PayloadBytesAreByteExact pins the byte-determinism
// contract: the export's payload bytes are the EXACT input the content-hash +
// mark were derived over. Verifying with those bytes passes; we additionally
// confirm the envelope-level Mark re-derives over them with the ledger's own
// (corpus, key).
func TestExportEvidence_PayloadBytesAreByteExact(t *testing.T) {
	l, corpus, key, now := signedLedger(t)

	export, err := l.ExportEvidenceSnapshot(EvidenceScope{}, now)
	if err != nil {
		t.Fatalf("ExportEvidenceSnapshot: %v", err)
	}

	res := evidence.Verify(export.Bundle, evidence.ModeFull, export.PayloadBytes, key)
	if res.Class != "PASS" {
		t.Fatalf("verify with export payload bytes failed: %s/%s", res.Class, res.Verdict)
	}

	// Independently re-derive the envelope-level Mirror-Mark over the export's
	// payload bytes with a fresh mirrormark.Verify against (corpus, payload,
	// key). It must match export.Mark — proving the served payload bytes are
	// exactly what was signed.
	if verr := mirrormark.Verify(export.Mark, corpus, export.PayloadBytes, key); verr != nil {
		t.Fatalf("envelope mark does not re-derive over export payload bytes: %v", verr)
	}
	// Sanity: corpus the ledger is bound to is non-zero so this isn't a
	// placeholder-corpus pass.
	if corpus == ([sha256.Size]byte{}) {
		t.Fatal("test ledger corpus is zero — would not be a meaningful verify")
	}
}

// TestExportEvidence_DetectsPayloadTamper — editing the exported payload
// breaks the content-hash step. The forensic property that makes the bundle
// worth emitting.
func TestExportEvidence_DetectsPayloadTamper(t *testing.T) {
	l, _, key, now := signedLedger(t)

	export, err := l.ExportEvidenceSnapshot(EvidenceScope{}, now)
	if err != nil {
		t.Fatalf("ExportEvidenceSnapshot: %v", err)
	}

	// Tamper: flip a stable field in the payload bytes.
	tampered := strings.Replace(string(export.PayloadBytes), `"payloadVersion":"v1"`, `"payloadVersion":"v2"`, 1)
	if tampered == string(export.PayloadBytes) {
		t.Fatal("test setup: could not tamper payload")
	}

	res := evidence.Verify(export.Bundle, evidence.ModeFull, []byte(tampered), key)
	if res.Class != "FAIL" {
		t.Fatalf("expected FAIL for tampered payload, got %s", res.Class)
	}
	if res.Verdict != "ErrContentHashMismatch" {
		t.Fatalf("expected ErrContentHashMismatch, got %s", res.Verdict)
	}
}

// TestExportEvidence_DetectsWrongKey — a regulator holding the wrong key sees
// the Mirror-Mark step fail (content-hash still passes, since the payload is
// unmodified). Confirms the bundle binds bias-audit's specific signing key.
func TestExportEvidence_DetectsWrongKey(t *testing.T) {
	l, _, _, now := signedLedger(t)

	export, err := l.ExportEvidenceSnapshot(EvidenceScope{}, now)
	if err != nil {
		t.Fatalf("ExportEvidenceSnapshot: %v", err)
	}

	res := evidence.Verify(export.Bundle, evidence.ModeFull, export.PayloadBytes, []byte("iik_test_WRONG_KEY"))
	if res.Class != "FAIL" {
		t.Fatalf("expected FAIL for wrong key, got %s (verdict=%s)", res.Class, res.Verdict)
	}
	if res.ContentHashVerified != true {
		t.Fatalf("content-hash should still verify (payload unchanged); got %v", res.ContentHashVerified)
	}
	if res.MirrorMarkVerified {
		t.Fatal("Mirror-Mark must NOT verify under the wrong key")
	}
}

// TestExportEvidence_PlaceholderCorpus_Refuses — the additive contract.
// A ledger with the placeholder (all-zero) corpus refuses to export (a
// .evidence bundle has no meaningful unsigned form). Mirrors Folio's
// no-marker → 503.
func TestExportEvidence_PlaceholderCorpus_Refuses(t *testing.T) {
	// newKATLedger uses the zero corpus + empty key (cohort KAT inputs).
	l := newKATLedger()
	now := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)
	if _, err := l.Append(canonicalAnnualEntry(now), now); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err := l.ExportEvidenceSnapshot(EvidenceScope{}, now)
	if err != ErrEvidenceNoCorpus {
		t.Fatalf("placeholder corpus: got %v, want ErrEvidenceNoCorpus", err)
	}
}

// TestExportEvidence_ScopeFilters — the scope narrows the export to a tenant
// and/or type, the subject reflects it, and the filtered bundle still
// cold-verifies.
func TestExportEvidence_ScopeFilters(t *testing.T) {
	l, _, key, now := signedLedger(t)

	// Tenant scope: only tenant_acme rows (2 of the 3 seeded).
	export, err := l.ExportEvidenceSnapshot(EvidenceScope{Tenant: "tenant_acme"}, now)
	if err != nil {
		t.Fatalf("ExportEvidenceSnapshot tenant: %v", err)
	}
	var payload LedgerEvidencePayload
	if err := json.Unmarshal(export.PayloadBytes, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Count != 2 {
		t.Fatalf("tenant_acme scope: got %d rows, want 2", payload.Count)
	}
	for _, e := range payload.Entries {
		if e.TenantID != "tenant_acme" {
			t.Fatalf("tenant scope leaked a non-acme row: %q", e.TenantID)
		}
	}
	if payload.TenantFilter != "tenant_acme" {
		t.Fatalf("payload TenantFilter = %q, want tenant_acme", payload.TenantFilter)
	}
	if !strings.Contains(payload.Subject, "tenant=tenant_acme") {
		t.Fatalf("subject does not reflect tenant filter: %q", payload.Subject)
	}
	if res := evidence.Verify(export.Bundle, evidence.ModeFull, export.PayloadBytes, key); res.Class != "PASS" {
		t.Fatalf("tenant-scoped bundle verify failed: %s/%s", res.Class, res.Verdict)
	}

	// Tenant + Type intersection: tenant_acme AND NYC LL144 annual (1 row).
	export2, err := l.ExportEvidenceSnapshot(EvidenceScope{Tenant: "tenant_acme", Type: EntryTypeNYCLL144AnnualAudit}, now)
	if err != nil {
		t.Fatalf("ExportEvidenceSnapshot tenant+type: %v", err)
	}
	var payload2 LedgerEvidencePayload
	if err := json.Unmarshal(export2.PayloadBytes, &payload2); err != nil {
		t.Fatalf("decode payload2: %v", err)
	}
	if payload2.Count != 1 {
		t.Fatalf("tenant+type scope: got %d rows, want 1", payload2.Count)
	}
	if payload2.Entries[0].EntryType != EntryTypeNYCLL144AnnualAudit {
		t.Fatalf("tenant+type scope wrong type: %q", payload2.Entries[0].EntryType)
	}
	if !strings.Contains(payload2.Subject, "type="+string(EntryTypeNYCLL144AnnualAudit)) {
		t.Fatalf("subject does not reflect type filter: %q", payload2.Subject)
	}
	if res := evidence.Verify(export2.Bundle, evidence.ModeFull, export2.PayloadBytes, key); res.Class != "PASS" {
		t.Fatalf("tenant+type-scoped bundle verify failed: %s/%s", res.Class, res.Verdict)
	}
}

// TestExportEvidence_EmptyLedgerVerifies — an export over a ledger with a real
// corpus but no rows still produces a valid (empty-slice) bundle. The JSON
// must carry `[]`, not `null`, so a regulator re-marshalling reproduces
// identical bytes.
func TestExportEvidence_EmptyLedgerVerifies(t *testing.T) {
	corpus, key := realCorpusKey()
	l := New(corpus, key)
	now := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)

	export, err := l.ExportEvidenceSnapshot(EvidenceScope{}, now)
	if err != nil {
		t.Fatalf("ExportEvidenceSnapshot empty: %v", err)
	}
	if !strings.Contains(string(export.PayloadBytes), `"entries":[]`) {
		t.Fatalf("empty ledger payload must carry entries:[] not null; got %s", export.PayloadBytes)
	}
	if res := evidence.Verify(export.Bundle, evidence.ModeFull, export.PayloadBytes, key); res.Class != "PASS" {
		t.Fatalf("empty-ledger bundle verify failed: %s/%s", res.Class, res.Verdict)
	}
}

// TestExportEvidence_Deterministic — the same ledger + scope + timestamp
// yields byte-identical bundles + payloads across calls (the property a
// regulator relies on to reproduce the cold-verify input).
func TestExportEvidence_Deterministic(t *testing.T) {
	l, _, _, now := signedLedger(t)

	first, err := l.ExportEvidenceSnapshot(EvidenceScope{}, now)
	if err != nil {
		t.Fatalf("first export: %v", err)
	}
	for i := 0; i < 16; i++ {
		got, err := l.ExportEvidenceSnapshot(EvidenceScope{}, now)
		if err != nil {
			t.Fatalf("iter %d export: %v", i, err)
		}
		if string(got.Bundle) != string(first.Bundle) {
			t.Fatalf("iter %d: non-deterministic bundle bytes", i)
		}
		if string(got.PayloadBytes) != string(first.PayloadBytes) {
			t.Fatalf("iter %d: non-deterministic payload bytes", i)
		}
		if got.Mark != first.Mark {
			t.Fatalf("iter %d: non-deterministic mark", i)
		}
	}
}

// TestExportEvidence_ExistingLedgerBehaviourUnchanged — the additive
// guarantee. The evidence-export path must NOT perturb the pre-existing
// per-row ledger behaviour: an export over the ledger leaves the ledger's
// observable state (length, rows, per-row Marks, VerifyEntry) byte-for-byte
// unchanged, and the per-row CanonicalPayload + Mirror-Mark wire format is
// independent of the envelope the bundle binds.
func TestExportEvidence_ExistingLedgerBehaviourUnchanged(t *testing.T) {
	l, corpus, key, now := signedLedger(t)

	// Snapshot the ledger's observable state BEFORE the export.
	lenBefore := l.Len()
	rowsBefore := l.All()
	marksBefore := make([]string, len(rowsBefore))
	payloadsBefore := make([]string, len(rowsBefore))
	for i, e := range rowsBefore {
		marksBefore[i] = e.Mark
		payloadsBefore[i] = string(CanonicalPayload(e))
		// Each row's pre-existing per-row cold-verify must pass (unchanged).
		if err := l.VerifyEntry(e); err != nil {
			t.Fatalf("pre-export VerifyEntry row %d: %v", i, err)
		}
	}

	// Run the export.
	if _, err := l.ExportEvidenceSnapshot(EvidenceScope{}, now); err != nil {
		t.Fatalf("ExportEvidenceSnapshot: %v", err)
	}

	// AFTER: length, rows, marks, payloads, and per-row verify all unchanged.
	if l.Len() != lenBefore {
		t.Fatalf("ledger Len changed by export: %d -> %d", lenBefore, l.Len())
	}
	rowsAfter := l.All()
	if len(rowsAfter) != len(rowsBefore) {
		t.Fatalf("row count changed by export: %d -> %d", len(rowsBefore), len(rowsAfter))
	}
	for i, e := range rowsAfter {
		if e.Mark != marksBefore[i] {
			t.Fatalf("row %d per-row Mark changed by export:\n  before: %q\n  after:  %q", i, marksBefore[i], e.Mark)
		}
		if got := string(CanonicalPayload(e)); got != payloadsBefore[i] {
			t.Fatalf("row %d CanonicalPayload changed by export:\n  before: %q\n  after:  %q", i, payloadsBefore[i], got)
		}
		if err := l.VerifyEntry(e); err != nil {
			t.Fatalf("post-export VerifyEntry row %d: %v (per-row wire format must be unchanged)", i, err)
		}
		// And the per-row Mark must still independently re-derive via the
		// package-level mirrormark.Verify with the ledger's (corpus, key) —
		// the envelope-level mark must not have disturbed the per-row format.
		if err := mirrormark.Verify(e.Mark, corpus, CanonicalPayload(e), key); err != nil {
			t.Fatalf("post-export per-row mirrormark.Verify row %d: %v", i, err)
		}
	}
}
