// Package auditledger implements the append-only annual-bias-audit
// ledger primitive that turns bias-audit into the canonical 3rd
// saturator for R153.A REGULATORY-ESCAPE-INVARIANT-WITH-AUDIT-LEDGER.
//
// R153.A status pre-bias-audit (per ECOSYSTEM_QUALITY_STANDARD.md Part
// XII, R153 row): R153.A REGULATORY-ESCAPE-INVARIANT-WITH-AUDIT-LEDGER
// sub-clause was sitting at 1/3 (canopy NYC LL144 annual-audit alone)
// — promotion deferred until 2 more saturators ship. Memory cited the
// cheapest 3rd as "FCA SYSC 4.5 annual-review OR HIPAA §164.312(b)
// audit-log review." bias-audit promotes a different cheapest 3rd: a
// dedicated annual-cadence audit-ledger primitive where the cadence
// + the independent-auditor sign-off slot are themselves load-bearing
// runtime artefacts (not just doc-comment claims). With bias-audit
// shipping, R153.A saturates 3/3.
//
// Three R153.A role profiles populated by this package's ledger:
//
//   - **NYC LL144 § 20-871(a) — Annual independent bias audit**.
//     One BiasAuditEntry per calendar year, signed off by a qualified
//     independent auditor with no interest in the AEDT's outcome. The
//     IndependentAuditorSignoff slot is FALSE by default + flippable
//     only via an attested signoff path; the canonical R166 sentinel
//     applied to a non-counsel reviewer class.
//   - **EU AI Act 2024/1689 Article 43 — Conformity assessment**.
//     One ConformityAssessmentEntry per (deployer × AI-system × major
//     version) tuple, attested by a notified body. The
//     NotifiedBodySignoff slot is FALSE by default.
//   - **EEOC 29 C.F.R. § 1607 — Uniform Guidelines four-fifths rule**.
//     One FourFifthsImpactEntry per (selection-procedure × time-window)
//     tuple recording the impact ratio per protected class. NO signoff
//     gate — the four-fifths rule is computational, not adjudicative;
//     the entry is a record-keeping artefact.
//
// The ledger is **append-only** at the API layer — there is no public
// `Delete` or `Update` method. Tampering (e.g. via direct slice
// mutation in tests) is structurally possible but is the antipattern;
// production hosts deploying bias-audit MUST persist the ledger to
// a write-once-read-many backing store (S3 Object Lock / Postgres
// append-only schema with INSERT-only role).
//
// Each entry carries a Mirror-Mark stamped at append-time; a regulator
// receiving the entry can cold-verify the Mirror-Mark via OpenSSL
// without trusting the bias-audit host (per R175 R-MIRROR-MARK-LOAD-
// BEARING-IN-PRODUCTION criterion 2).
package auditledger

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/davly/bias-audit/internal/mirrormark"
)

// EntryType — closed-set R115 enum of audit-ledger entry classes.
type EntryType string

const (
	// EntryTypeNYCLL144AnnualAudit — NYC LL144 § 20-871(a) annual
	// independent bias audit.
	EntryTypeNYCLL144AnnualAudit EntryType = "nyc_ll144_annual_audit"

	// EntryTypeEUAIActConformityAssessment — EU AI Act 2024/1689
	// Article 43 conformity assessment.
	EntryTypeEUAIActConformityAssessment EntryType = "eu_ai_act_conformity_assessment"

	// EntryTypeEEOCFourFifthsImpact — EEOC 29 C.F.R. § 1607 four-
	// fifths-rule impact ratio record.
	EntryTypeEEOCFourFifthsImpact EntryType = "eeoc_four_fifths_impact"
)

// AllEntryTypes returns the closed-set R115 enum slice.
func AllEntryTypes() []EntryType {
	return []EntryType{
		EntryTypeNYCLL144AnnualAudit,
		EntryTypeEUAIActConformityAssessment,
		EntryTypeEEOCFourFifthsImpact,
	}
}

// IsKnownEntryType returns true if t is a closed-set member.
func IsKnownEntryType(t EntryType) bool {
	for _, et := range AllEntryTypes() {
		if et == t {
			return true
		}
	}
	return false
}

// SignoffStatus — closed-set R115 enum capturing the independent-
// auditor or notified-body sign-off state.
type SignoffStatus string

const (
	// SignoffPending — initial state. Honest baseline.
	SignoffPending SignoffStatus = "pending"
	// SignoffAttested — the named independent auditor / notified body
	// has signed off. Flipping into this state requires a sibling
	// commit per R145.B; bias-audit does not perform the attestation
	// itself (LIBRARY-RECOMMENDS-HOST-ACTS).
	SignoffAttested SignoffStatus = "attested"
	// SignoffNonApplicable — used only by EEOC four-fifths entries
	// where no adjudicative sign-off applies.
	SignoffNonApplicable SignoffStatus = "non_applicable"
)

// AllSignoffStatuses returns the closed-set R115 enum slice.
func AllSignoffStatuses() []SignoffStatus {
	return []SignoffStatus{
		SignoffPending,
		SignoffAttested,
		SignoffNonApplicable,
	}
}

// Entry — single audit-ledger row.
//
// All fields are scalar / pre-canonicalised to keep the append-time
// HMAC over a deterministic byte representation.
type Entry struct {
	// TenantID — opaque tenant identifier. bias-audit does NOT
	// validate tenant identity; the deploying host must.
	TenantID string

	// AEDTSystemID — opaque AEDT identifier. Per NYC LL144 the
	// "automated employment decision tool" is the audited unit.
	AEDTSystemID string

	// EntryType — closed-set R115 enum.
	EntryType EntryType

	// AuditPeriodStart / AuditPeriodEnd — UTC. The annual cadence
	// requirement (NYC LL144) is enforced via the AuditPeriodEnd -
	// AuditPeriodStart spread = ~365 days (validated in Append).
	AuditPeriodStart time.Time
	AuditPeriodEnd   time.Time

	// IndependentAuditorName — string identifier of the independent
	// auditor (NYC LL144) or notified body (EU AI Act). For EEOC
	// entries this is the deploying employer's compliance contact.
	IndependentAuditorName string

	// SignoffStatus — closed-set R115 enum.
	SignoffStatus SignoffStatus

	// SignoffDate — UTC. Zero-valued when SignoffStatus = pending.
	SignoffDate time.Time

	// SummaryHash — opaque hash of the audit summary document (the
	// independent auditor's report, the notified body's certificate,
	// or the four-fifths impact data CSV). bias-audit does not store
	// the document body — only the SHA-256 of it.
	SummaryHash string

	// PublicPostingURL — required by NYC LL144 § 20-871(c) for the
	// annual audit summary results. Empty string is honest absence
	// (R120 nullable-additive-telemetry-migration — empty != absent
	// at the database layer; here in-memory empty IS honest).
	PublicPostingURL string

	// AppendedAt — UTC stamp at Append time. Set by Append; do not
	// pre-populate.
	AppendedAt time.Time

	// Mark — Mirror-Mark stamped at Append time over the canonical
	// byte representation of the entry. Cold-verifiable by a
	// regulator with the corpus SHA + the tenant's signing key.
	Mark string
}

// Ledger is the in-memory append-only audit-ledger.
//
// Concurrency: safe for concurrent Append + Read. Production hosts
// MUST persist to a write-once-read-many backing store.
type Ledger struct {
	mu      sync.RWMutex
	entries []Entry
	corpus  [sha256.Size]byte
	key     []byte
}

// New returns a fresh empty Ledger seeded with the corpus + key used
// to stamp Mirror-Marks at Append time.
//
// corpus = 32-byte SHA-256 of the tenant's lore-corpus body. key =
// HMAC key (typically the tenant's per-environment audit-ledger
// signing key). The zero-value of both is acceptable for development
// + test (the cohort-canonical KAT-1 inputs); production hosts MUST
// inject non-zero values + emit a boot-time R143 LOUD-ONCE-WARN
// advisory when the zero-value is detected (per R175 criterion 3 —
// the warn is emitted by package honest, not here).
func New(corpus [sha256.Size]byte, key []byte) *Ledger {
	return &Ledger{
		corpus: corpus,
		key:    append([]byte(nil), key...),
	}
}

// CanonicalPayload returns the byte representation HMAC'd at Append
// time. Exported for cold-verify purposes — a regulator can re-derive
// the exact payload from a returned Entry + the OpenSSL one-liner.
//
// Format (UTF-8, deterministic field-ordering, newline-delimited):
//
//	tenant: <tenant_id>
//	aedt: <aedt_system_id>
//	type: <entry_type>
//	period: <auditPeriodStart_RFC3339> .. <auditPeriodEnd_RFC3339>
//	auditor: <independent_auditor_name>
//	signoff: <signoff_status>@<signoff_date_RFC3339_or_empty>
//	summary: <summary_hash>
//	posting: <public_posting_url>
//	appended: <appended_at_RFC3339>
//
// Field-ordering is alphabetical-stable; new fields added in a future
// schema version MUST bump the package-level version constant + the
// Mark format prefix in a coordinated R145.B sibling-not-stacked
// branch.
func CanonicalPayload(e Entry) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "tenant: %s\n", e.TenantID)
	fmt.Fprintf(&b, "aedt: %s\n", e.AEDTSystemID)
	fmt.Fprintf(&b, "type: %s\n", e.EntryType)
	fmt.Fprintf(&b, "period: %s .. %s\n",
		e.AuditPeriodStart.UTC().Format(time.RFC3339),
		e.AuditPeriodEnd.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "auditor: %s\n", e.IndependentAuditorName)
	signoffDate := ""
	if !e.SignoffDate.IsZero() {
		signoffDate = e.SignoffDate.UTC().Format(time.RFC3339)
	}
	fmt.Fprintf(&b, "signoff: %s@%s\n", e.SignoffStatus, signoffDate)
	fmt.Fprintf(&b, "summary: %s\n", e.SummaryHash)
	fmt.Fprintf(&b, "posting: %s\n", e.PublicPostingURL)
	fmt.Fprintf(&b, "appended: %s\n", e.AppendedAt.UTC().Format(time.RFC3339))
	return []byte(b.String())
}

// ErrUnknownEntryType — Append received a non-closed-set EntryType.
var ErrUnknownEntryType = errors.New("auditledger: unknown EntryType (not in closed-set R115 enum)")

// ErrUnknownSignoffStatus — Append received a non-closed-set status.
var ErrUnknownSignoffStatus = errors.New("auditledger: unknown SignoffStatus (not in closed-set R115 enum)")

// ErrEmptyTenant — TenantID is empty.
var ErrEmptyTenant = errors.New("auditledger: TenantID required")

// ErrEmptyAEDTSystem — AEDTSystemID is empty.
var ErrEmptyAEDTSystem = errors.New("auditledger: AEDTSystemID required")

// ErrAuditPeriodInverted — AuditPeriodEnd <= AuditPeriodStart.
var ErrAuditPeriodInverted = errors.New("auditledger: AuditPeriodEnd must be after AuditPeriodStart")

// ErrAuditPeriodNotAnnual — for NYC LL144 entries, the period must
// span approximately one calendar year (≥ 360 days, ≤ 370 days).
var ErrAuditPeriodNotAnnual = errors.New("auditledger: NYC LL144 audit period must span ~1 year (360-370 days)")

// ErrAttestedWithoutSignoffDate — SignoffStatus=attested but
// SignoffDate is zero.
var ErrAttestedWithoutSignoffDate = errors.New("auditledger: SignoffStatus=attested requires a non-zero SignoffDate")

// ErrAttestedWithoutAuditor — SignoffStatus=attested but
// IndependentAuditorName is empty.
var ErrAttestedWithoutAuditor = errors.New("auditledger: SignoffStatus=attested requires a non-empty IndependentAuditorName")

// Append validates + stamps + appends an Entry, returning the
// stamped entry. The Mark + AppendedAt fields are set by Append; do
// not pre-populate (Append overwrites both).
//
// Validation is closed-set + structural — bias-audit refuses to
// admit a malformed entry rather than silently ledger-poison.
func (l *Ledger) Append(e Entry, now time.Time) (Entry, error) {
	if e.TenantID == "" {
		return Entry{}, ErrEmptyTenant
	}
	if e.AEDTSystemID == "" {
		return Entry{}, ErrEmptyAEDTSystem
	}
	if !IsKnownEntryType(e.EntryType) {
		return Entry{}, ErrUnknownEntryType
	}
	if !isKnownSignoffStatus(e.SignoffStatus) {
		return Entry{}, ErrUnknownSignoffStatus
	}
	if !e.AuditPeriodEnd.After(e.AuditPeriodStart) {
		return Entry{}, ErrAuditPeriodInverted
	}
	if e.EntryType == EntryTypeNYCLL144AnnualAudit {
		days := e.AuditPeriodEnd.Sub(e.AuditPeriodStart).Hours() / 24
		if days < 360 || days > 370 {
			return Entry{}, ErrAuditPeriodNotAnnual
		}
	}
	if e.SignoffStatus == SignoffAttested {
		if e.SignoffDate.IsZero() {
			return Entry{}, ErrAttestedWithoutSignoffDate
		}
		if e.IndependentAuditorName == "" {
			return Entry{}, ErrAttestedWithoutAuditor
		}
	}

	e.AppendedAt = now.UTC()
	payload := CanonicalPayload(e)
	e.Mark = mirrormark.Sign(l.corpus, payload, l.key)

	l.mu.Lock()
	l.entries = append(l.entries, e)
	l.mu.Unlock()
	return e, nil
}

func isKnownSignoffStatus(s SignoffStatus) bool {
	for _, ks := range AllSignoffStatuses() {
		if ks == s {
			return true
		}
	}
	return false
}

// Len returns the current ledger length (R143 surface for monitoring).
func (l *Ledger) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

// All returns a defensive copy of the ledger entries in append order.
// Mutating the returned slice does NOT affect the ledger.
func (l *Ledger) All() []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Entry, len(l.entries))
	copy(out, l.entries)
	return out
}

// ByType returns a defensive copy of entries matching t, in append
// order.
func (l *Ledger) ByType(t EntryType) []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var out []Entry
	for _, e := range l.entries {
		if e.EntryType == t {
			out = append(out, e)
		}
	}
	return out
}

// ByTenant returns a defensive copy of entries matching tenantID, in
// append order.
func (l *Ledger) ByTenant(tenantID string) []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var out []Entry
	for _, e := range l.entries {
		if e.TenantID == tenantID {
			out = append(out, e)
		}
	}
	return out
}

// VerifyEntry cold-checks the Mirror-Mark on a returned entry against
// the ledger's corpus + key. Returns nil on match; one of the
// mirrormark sentinel errors on failure.
//
// Used by a regulator-facing audit-export endpoint to confirm that
// every exported row was stamped by THIS ledger (not a downstream
// substitution attack).
func (l *Ledger) VerifyEntry(e Entry) error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return mirrormark.Verify(e.Mark, l.corpus, CanonicalPayload(e), l.key)
}

// SelfCheck re-derives every entry's Mirror-Mark from its canonical
// payload via the ledger's OWN corpus + key, and re-runs the cheap
// closed-set structural checks (EntryType + SignoffStatus). On
// success it returns the entry count plus the ledger digest; on the
// first failure it returns a non-nil error and a zero digest
// (callers MUST NOT anchor/attest a ledger whose self-check failed —
// this is the gate internal/stele.AnchorRun enforces before sealing
// a LIT run-anchor into the Stele spine).
//
// LEDGER DIGEST — canonical run serialization (documented contract):
// sha256 over, for each Entry in append order,
//
//	json.Marshal(Entry) || '\n'
//
// Go's encoding/json marshals struct fields in declaration order
// (TenantID, AEDTSystemID, EntryType, AuditPeriodStart,
// AuditPeriodEnd, IndependentAuditorName, SignoffStatus, SignoffDate,
// SummaryHash, PublicPostingURL, AppendedAt, Mark) and time.Time
// marshals as RFC 3339, so the byte stream is deterministic:
// identical entries in identical order produce an identical digest,
// and any change to entry content, mark, or ORDER changes it. The
// ledger is not hash-chained (Phase-1 in-memory scaffold), so this
// digest is the canonical binding for a Stele spine anchor's
// subject_hash.
//
// HONESTY: this is a SELF-check — the same corpus + key that stamped
// the entries re-derives the marks. It surfaces post-Append tampering
// of in-memory entries, but it is NOT an independent oracle and does
// NOT prove the signing key is production-grade (the zero-value
// dev/test seed self-checks green). Downstream consumers describing
// this check MUST label it self-check, not gauntlet.
func (l *Ledger) SelfCheck() (int, [sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	snap := l.All() // RLock-guarded defensive copy; corpus + key are set at New and never mutated
	h := sha256.New()
	for i, e := range snap {
		if !IsKnownEntryType(e.EntryType) {
			return 0, digest, fmt.Errorf("auditledger: self-check failed: entry %d EntryType %q not in closed-set R115 enum", i, e.EntryType)
		}
		if !isKnownSignoffStatus(e.SignoffStatus) {
			return 0, digest, fmt.Errorf("auditledger: self-check failed: entry %d SignoffStatus %q not in closed-set R115 enum", i, e.SignoffStatus)
		}
		if !strings.HasPrefix(e.Mark, mirrormark.MarkPrefix) {
			return 0, digest, fmt.Errorf("auditledger: self-check failed: entry %d mark missing cohort-canonical prefix %q", i, mirrormark.MarkPrefix)
		}
		if mirrormark.Sign(l.corpus, CanonicalPayload(e), l.key) != e.Mark {
			return 0, digest, fmt.Errorf("auditledger: self-check failed: entry %d mark does not re-derive from canonical payload (entry or mark tampered)", i)
		}
		line, err := json.Marshal(e)
		if err != nil {
			return 0, digest, fmt.Errorf("auditledger: self-check failed: entry %d serialization: %w", i, err)
		}
		h.Write(line)
		h.Write([]byte{'\n'})
	}
	copy(digest[:], h.Sum(nil))
	return len(snap), digest, nil
}

// AnnualCadenceCompliance returns the set of (tenantID, AEDTSystemID)
// pairs that have at least one NYC LL144 annual audit entry covering
// the year ending at refTime, and the complement set.
//
// The NYC LL144 § 20-871(a) annual cadence requirement is most easily
// audited by asking: for every tenant+AEDT pair this ledger has ever
// recorded an entry for, did the ledger record a NYC LL144 annual
// audit within the year ending refTime? Pairs missing from the
// covered set are honest delinquency signals; bias-audit reports
// them, the deploying host acts.
func (l *Ledger) AnnualCadenceCompliance(refTime time.Time) (covered, uncovered []TenantAEDTPair) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	yearAgo := refTime.Add(-365 * 24 * time.Hour)
	all := map[TenantAEDTPair]bool{}
	withRecent := map[TenantAEDTPair]bool{}
	for _, e := range l.entries {
		pair := TenantAEDTPair{TenantID: e.TenantID, AEDTSystemID: e.AEDTSystemID}
		all[pair] = true
		if e.EntryType == EntryTypeNYCLL144AnnualAudit &&
			!e.AuditPeriodEnd.Before(yearAgo) {
			withRecent[pair] = true
		}
	}
	for pair := range all {
		if withRecent[pair] {
			covered = append(covered, pair)
		} else {
			uncovered = append(uncovered, pair)
		}
	}
	sort.Slice(covered, func(i, j int) bool {
		return pairLess(covered[i], covered[j])
	})
	sort.Slice(uncovered, func(i, j int) bool {
		return pairLess(uncovered[i], uncovered[j])
	})
	return covered, uncovered
}

// TenantAEDTPair — composite key for AnnualCadenceCompliance output.
type TenantAEDTPair struct {
	TenantID     string
	AEDTSystemID string
}

func pairLess(a, b TenantAEDTPair) bool {
	if a.TenantID != b.TenantID {
		return a.TenantID < b.TenantID
	}
	return a.AEDTSystemID < b.AEDTSystemID
}
