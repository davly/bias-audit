// Additive `.evidence`-bundle export path (2026-05-29).
//
// What this file is
// -----------------
// The SECOND production wire-in of the limitless-evidence-bundle SPEC v1
// format (apps/limitless-evidence-bundle), after Folio. It makes bias-audit
// the second real consumer of the regulator-readable `.evidence` artefact:
// a read-only export that streams a snapshot of the append-only annual-audit
// ledger as a single cold-verifiable `.evidence` bundle (KAT-1 anchor +
// content-hash + L43 Mirror-Mark over the exported rows).
//
// Why this is purely ADDITIVE (R145-strict / no-silent-behaviour-changes)
// ----------------------------------------------------------------------
//   - It adds NO method that mutates ledger state. ExportEvidenceSnapshot
//     reads via the existing defensive-copy accessors (All / ByType /
//     ByTenant) and never appends, deletes, or re-stamps a row.
//   - It does NOT change CanonicalPayload, Append, Sign, or VerifyEntry —
//     the per-row Mirror-Mark wire format is byte-for-byte unchanged
//     (pinned by TestExportEvidence_ExistingLedgerBehaviourUnchanged and
//     the pre-existing auditledger_test.go suite).
//   - The bundle binds a SEPARATE envelope (LedgerEvidencePayload) whose
//     bytes are distinct from any single row's CanonicalPayload; existing
//     per-row cold-verify is untouched.
//
// Canonical Phase-2 path (SPEC.md §10): bias-audit computes the MIRROR_MARK
// with its OWN in-process signer (the ledger's mirrormark.Sign over the
// ledger's bound corpus + key) and hands it to the public
// evidence.PackWithMark — the evidence-bundle repo never sees bias-audit's
// HMAC key, so its stdlib-only verifier stays the independent cold-verify
// path. This mirrors Folio's conduit.MirrorMarker → evidence.PackWithMark
// flow exactly; bias-audit's signer happens to be the Ledger itself (it is
// the object that owns the corpus + key).
//
// Byte-determinism (load-bearing)
// -------------------------------
// The envelope is marshalled EXACTLY ONCE (buildLedgerEvidencePayload) and
// the resulting bytes feed BOTH mirrormark.Sign() AND
// evidence.PackWithMark (whose CONTENT_HASH = SHA-256 of those same bytes).
// A regulator reproduces the bytes by json.Marshal-ing the same envelope
// shape (Go's encoding/json is field-declaration-order deterministic). The
// returned EvidenceExport carries the bundle AND those exact payload bytes
// so the cold-verify input is reproduced verbatim — no re-marshal, no
// field-ordering risk.
//
// Self-check before return (SPEC.md §10 self-check contract)
// ----------------------------------------------------------
// ExportEvidenceSnapshot self-verifies the freshly-packed bundle in two
// parts that together cover the full chain, WITHOUT exposing the key:
//
//	(1) evidence.Verify(ModeOffline) — the evidence-repo verifier's
//	    structural-integrity + KAT-1 anchor checks (no key needed).
//	(2) the ledger's own mirrormark.Verify over the canonical payload with
//	    the ledger's (corpus, key) — proves the mark binds the exported
//	    bytes + corpus. CONTENT_HASH is SHA-256(payload) set by
//	    PackWithMark from these same bytes, so a passing mark over the same
//	    payload pins the content-hash too.
//
// A bundle that does not self-verify is never returned (the caller gets an
// error instead) — a malformed/non-verifying artefact never escapes.
//
// Stdlib-only beyond the evidence-bundle module: crypto/sha256 +
// encoding/json + time, plus the existing internal/mirrormark and the
// public github.com/davly/limitless-evidence-bundle/pkg/evidence.
package auditledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/davly/bias-audit/internal/mirrormark"
	"github.com/davly/limitless-evidence-bundle/pkg/evidence"
)

// EvidencePayloadVersion is the wire-format tag for the LedgerEvidencePayload
// envelope this path signs. Bumping it signals a backwards-incompatible
// payload shape to downstream verifiers (who compare on string equality, so
// an unknown version fails closed). Distinct from the bundle's own
// LIMITLESS-EVIDENCE-v1 wire tag — this versions the bias-audit payload
// shape INSIDE the bundle.
const EvidencePayloadVersion = "v1"

// evidenceDomain is the closed METADATA domain label for bias-audit ledger
// evidence bundles. A regulator portal can branch on this without parsing
// the payload.
const evidenceDomain = "bias-audit.ledger"

// ErrEvidenceNoCorpus is returned by ExportEvidenceSnapshot when the ledger
// was constructed with a placeholder (all-zero) corpus SHA. A `.evidence`
// bundle's whole value is that it cold-verifies against a real lore corpus;
// emitting one stamped with a placeholder corpus would yield an artefact
// that CANNOT cold-verify (worse than honest silence), so the export refuses.
// This mirrors Folio's marker-absent → 503 contract (a `.evidence` bundle
// has no meaningful degraded form). Production hosts inject a non-zero corpus
// via New(corpus, key); dev/KAT ledgers using the zero corpus get this error.
var ErrEvidenceNoCorpus = errors.New("auditledger: cannot export .evidence bundle with placeholder (all-zero) corpus SHA")

// LedgerEvidencePayload is the canonical envelope whose JSON bytes the
// `.evidence` bundle binds (CONTENT_HASH + MIRROR_MARK). It is
// self-describing about the slice of the ledger it covers so a regulator
// holding only the bundle + payload knows WHAT was exported, not just that
// SOMETHING was.
//
// Field order is load-bearing: Go's encoding/json marshals struct fields in
// declaration order, and the cold-verify recipe re-marshals this exact
// shape. Adding a field later is wire-additive only if it sits at the end
// AND uses omitempty (so previously-issued payloads re-marshal to identical
// bytes).
type LedgerEvidencePayload struct {
	// PayloadVersion lets a recipient branch on shape before anything else.
	PayloadVersion string `json:"payloadVersion"`
	// Subject identifies what this evidence covers (the ledger slice).
	Subject string `json:"subject"`
	// ExportedAt is the UTC instant the export was produced.
	ExportedAt time.Time `json:"exportedAt"`
	// TenantFilter echoes the tenant scope applied (empty = all tenants).
	TenantFilter string `json:"tenantFilter"`
	// TypeFilter echoes the EntryType scope applied (empty = all types).
	TypeFilter EntryType `json:"typeFilter"`
	// Count is len(Entries) — a cheap completeness cross-check for the
	// auditor that does not require counting the array.
	Count int `json:"count"`
	// Entries is the exported ledger rows, in append order (the same order
	// the ledger's All / ByType / ByTenant accessors return). Each row
	// still carries its per-row Mirror-Mark (the Entry.Mark field), so a
	// regulator can ALSO cold-verify each row individually via VerifyEntry,
	// independent of this bundle's envelope-level mark.
	Entries []Entry `json:"entries"`
}

// EvidenceExport pairs the cold-verify artefact (Bundle) with the exact
// bytes it binds (PayloadBytes) so a consumer can verify offline without
// re-deriving the payload. Mirrors Folio's AuditEvidenceResponse shape.
type EvidenceExport struct {
	// Bundle is the `.evidence` bundle text (LIMITLESS-EVIDENCE-v1 wire
	// format): KAT-1 anchor + content-hash + Mirror-Mark over PayloadBytes.
	Bundle []byte
	// PayloadBytes is the EXACT canonical JSON of the LedgerEvidencePayload
	// the bundle binds, emitted verbatim so the consumer's cold-verify input
	// is byte-identical to what bias-audit signed.
	PayloadBytes []byte
	// Mark is the envelope-level v1 Mirror-Mark bias-audit computed over
	// PayloadBytes with the ledger's own (corpus, key). Returned so a caller
	// can self-check the Mirror-Mark step without the HMAC key ever leaving
	// the ledger; also the value the bundle's MIRROR_MARK section carries.
	Mark string
}

// EvidenceScope selects which ledger rows the export covers. The zero value
// (both fields empty) exports the entire ledger. A non-empty Tenant scopes
// to one tenant; a non-empty Type scopes to one EntryType; both narrow to
// the intersection. Scoping is read-only — it reuses the existing
// defensive-copy accessors and never mutates the ledger.
type EvidenceScope struct {
	// Tenant, when non-empty, restricts the export to rows for this tenant.
	Tenant string
	// Type, when non-empty, restricts the export to rows of this EntryType.
	Type EntryType
}

// ExportEvidenceSnapshot builds a regulator-readable `.evidence` bundle from
// a read-only snapshot of the ledger, scoped by `scope`. It is the canonical
// Phase-2 consumer path (SPEC.md §10): bias-audit signs the envelope with
// its OWN in-process signer and hands the mark to evidence.PackWithMark, so
// the evidence-bundle repo never sees the ledger's key.
//
// `now` is the export timestamp stamped into the envelope (injected for
// deterministic tests; production passes time.Now().UTC()).
//
// Returns ErrEvidenceNoCorpus when the ledger has a placeholder corpus (a
// bundle would not cold-verify — fail loud rather than emit an unverifiable
// artefact). Returns a wrapped error if pack or the pre-emit self-check
// fails. On success the returned bundle is guaranteed to pass
// evidence.Verify(ModeFull, PayloadBytes, key) for the ledger's own key.
//
// READ-ONLY: this method appends/deletes/re-stamps nothing. It reads through
// the existing defensive-copy accessors, so a concurrent Append is safe and
// the ledger's observable state is unchanged by an export.
func (l *Ledger) ExportEvidenceSnapshot(scope EvidenceScope, now time.Time) (EvidenceExport, error) {
	// A placeholder (all-zero) corpus cannot produce a cold-verifiable
	// bundle. Refuse rather than emit an artefact that fails a regulator's
	// re-verify (Folio's marker-absent → 503 analogue).
	corpus := l.corpusSHA()
	if corpus == ([sha256.Size]byte{}) {
		return EvidenceExport{}, ErrEvidenceNoCorpus
	}

	entries := l.snapshotForScope(scope)

	payload, payloadBytes, err := buildLedgerEvidencePayload(scope, entries, now)
	if err != nil {
		// json.Marshal on the fixed envelope shape is structurally
		// unreachable; wrapped for forward-compat.
		return EvidenceExport{}, fmt.Errorf("auditledger: evidence payload marshal: %w", err)
	}

	// MIRROR_MARK via bias-audit's OWN in-process signer over the canonical
	// bytes (the canonical Phase-2 path). evidence.PackWithMark takes this
	// mark verbatim — the evidence-bundle repo never sees the ledger's key.
	mark := l.signEvidence(payloadBytes)

	in := evidence.PackInput{
		CorpusSHAHex: hex.EncodeToString(corpus[:]),
		Payload:      payloadBytes,
		Meta: evidence.Metadata{
			CreatedAt:   payload.ExportedAt.Format(time.RFC3339),
			Creator:     "bias-audit auditledger evidence " + EvidencePayloadVersion,
			Subject:     payload.Subject,
			Domain:      evidenceDomain,
			CorpusLabel: "infrastructure/lore (bias-audit-bound corpus)",
		},
	}
	raw, err := evidence.PackWithMark(in, mark)
	if err != nil {
		return EvidenceExport{}, fmt.Errorf("auditledger: evidence pack: %w", err)
	}

	// Self-check before return (SPEC.md §10), in two parts covering the full
	// chain without exposing the key:
	//   (1) structural-integrity + KAT-1 anchor (no key needed)
	offline := evidence.Verify(raw, evidence.ModeOffline, nil, nil)
	if offline.Class != "PASS" {
		return EvidenceExport{}, fmt.Errorf("auditledger: evidence self-verify (offline) did not pass: verdict=%s failures=%v", offline.Verdict, offline.Failures)
	}
	//   (2) Mirror-Mark over the canonical payload, via the ledger's own
	//       (corpus, key) — re-derives the mark, pinning content + corpus.
	if verr := l.verifyEvidenceMark(mark, payloadBytes); verr != nil {
		return EvidenceExport{}, fmt.Errorf("auditledger: evidence self-verify (mark) did not pass: %w", verr)
	}

	return EvidenceExport{
		Bundle:       raw,
		PayloadBytes: payloadBytes,
		Mark:         mark,
	}, nil
}

// snapshotForScope returns a read-only, defensively-copied slice of ledger
// rows matching scope, reusing the existing accessors so no new read path is
// introduced. Both-empty scope = the whole ledger.
func (l *Ledger) snapshotForScope(scope EvidenceScope) []Entry {
	switch {
	case scope.Tenant != "" && scope.Type != "":
		// Intersection: tenant rows filtered to the requested type. Reuses
		// ByTenant's defensive copy, then narrows in-slice (the copy is
		// already detached from the ledger).
		var out []Entry
		for _, e := range l.ByTenant(scope.Tenant) {
			if e.EntryType == scope.Type {
				out = append(out, e)
			}
		}
		return out
	case scope.Tenant != "":
		return l.ByTenant(scope.Tenant)
	case scope.Type != "":
		return l.ByType(scope.Type)
	default:
		return l.All()
	}
}

// buildLedgerEvidencePayload assembles the envelope and marshals it ONCE.
// Returns (envelope, canonicalBytes, err). The canonical bytes are the
// single source of truth for both the Mirror-Mark and the bundle's
// CONTENT_HASH — they MUST NOT be re-marshalled separately downstream.
//
// Pure over its inputs (no ledger reads — the caller passes the already-read
// entries), so it is unit-testable in isolation.
func buildLedgerEvidencePayload(scope EvidenceScope, entries []Entry, now time.Time) (LedgerEvidencePayload, []byte, error) {
	// Normalise a nil slice to an empty slice so the JSON is `[]` not
	// `null` — a regulator re-marshalling the same envelope must reproduce
	// identical bytes regardless of whether the slice happened to be empty.
	if entries == nil {
		entries = []Entry{}
	}
	payload := LedgerEvidencePayload{
		PayloadVersion: EvidencePayloadVersion,
		Subject:        evidenceSubject(scope),
		ExportedAt:     now.UTC(),
		TenantFilter:   scope.Tenant,
		TypeFilter:     scope.Type,
		Count:          len(entries),
		Entries:        entries,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return LedgerEvidencePayload{}, nil, err
	}
	return payload, b, nil
}

// evidenceSubject builds the bundle subject string from the scope, so the
// bundle is self-describing about which slice it covers.
func evidenceSubject(scope EvidenceScope) string {
	switch {
	case scope.Tenant != "" && scope.Type != "":
		return "bias-audit:ledger:tenant=" + scope.Tenant + ":type=" + string(scope.Type)
	case scope.Tenant != "":
		return "bias-audit:ledger:tenant=" + scope.Tenant
	case scope.Type != "":
		return "bias-audit:ledger:type=" + string(scope.Type)
	default:
		return "bias-audit:ledger:all"
	}
}

// corpusSHA returns the ledger's bound corpus SHA. Read-only, goroutine-safe
// (corpus is immutable after New). Lower-cased name keeps it package-private:
// the evidence path needs the corpus to fill the bundle's CORPUS_SHA section
// with the SAME corpus the MIRROR_MARK was computed against.
func (l *Ledger) corpusSHA() [sha256.Size]byte {
	return l.corpus
}

// signEvidence stamps a v1 Mirror-Mark over payload with the ledger's bound
// (corpus, key) — the SAME signer Append uses for per-row marks, so the
// envelope-level mark is byte-compatible with the cohort wire format. Thin
// wrapper that keeps the key inside the ledger; the evidence path hands the
// resulting string to evidence.PackWithMark verbatim.
func (l *Ledger) signEvidence(payload []byte) string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return mirrormark.Sign(l.corpus, payload, l.key)
}

// verifyEvidenceMark cold-checks an envelope-level mark against the ledger's
// bound (corpus, key) over payload. Returns nil on match; a mirrormark
// sentinel error otherwise. Used for the pre-emit self-check without the key
// leaving the ledger.
func (l *Ledger) verifyEvidenceMark(mark string, payload []byte) error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return mirrormark.Verify(mark, l.corpus, payload, l.key)
}
