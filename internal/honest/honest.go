// Package honest implements the cohort R143 LOUD-ONCE-WARNING-FLAG
// discipline for bias-audit, with R157 substrate-native idiom (Go's
// `sync.Once`), R153 R-DOMAIN-ESCAPE-INVARIANT explicit advisories,
// and R153.A REGULATORY-ESCAPE-INVARIANT-WITH-AUDIT-LEDGER cadence
// advisories.
//
// bias-audit operates in TWO regulated HR-employment domains
// simultaneously:
//
//   - NYC Local Law 144 (Automated Employment Decision Tool, effective
//     2023-07-05) — annual independent bias audit + candidate notice
//     ≥10 business days + public posting of audit summary.
//   - EU AI Act 2024/1689 (Annex III §1 high-risk HR/employment AI
//     systems) — conformity assessment + risk-management system +
//     human-oversight + technical documentation.
//
// Five canonical advisories — three Error (R153.A regulator-strict-
// liability surfaces) + two Warn (R153.A cadence/notice advisories
// per the severity-discriminator clause):
//
//  1. EEOC_REGULATED_ROLE_ESCAPE_INVARIANT — R153 / Error. Inherited
//     from the canopy cohort sibling. Any candidate matching the EEOC
//     regulated-role taxonomy MUST short-circuit to qualified HR +
//     legal review.
//  2. NYC_LL144_AEDT_BIAS_AUDIT_REQUIRED — R153.A / Warn. Cadence
//     advisory. The annual independent audit is the deploying
//     tenant's responsibility; bias-audit orchestrates the ledger but
//     does NOT itself perform the independent audit.
//  3. BIAS_AUDIT_INDEPENDENT_AUDITOR_REQUIRED — R153 / Error. The
//     auditor MUST be a person or organisation not involved in the
//     AEDT's development + with no interest in the outcome (NYC LL144
//     § 20-871(a)). bias-audit refuses to record an attested signoff
//     without an IndependentAuditorName + SignoffDate.
//  4. BIAS_AUDIT_CANDIDATE_NOTICE_10_BUSINESS_DAYS — R153 / Warn.
//     NYC LL144 § 20-871(b) requires ≥10 business days notice to
//     candidates prior to AEDT-mediated assessment. bias-audit
//     generates the notice template; the deploying employer is
//     responsible for the actual delivery + cadence.
//  5. BIAS_AUDIT_PUBLIC_POSTING_REQUIRED — R153 / Warn. NYC LL144
//     § 20-871(c) requires public posting of annual audit summary
//     on the deploying employer's website. bias-audit produces the
//     summary; the employer is responsible for posting.
//
// R157 substrate-native: bias-audit uses Go's `sync.Once` for the
// once-fire mechanism (not a Go-ported foreign idiom).
package honest

import (
	"fmt"
	"io"
	"sync"
)

const LoudOncePrefix = "[LOUD-ONCE-WARNING]"

type Severity string

const (
	SeverityInfo  Severity = "INFO"
	SeverityWarn  Severity = "WARN"
	SeverityError Severity = "ERROR"
)

type Advisory struct {
	Code     string
	Severity Severity
	Message  string
	DocLink  string
}

var canonicalAdvisories = []Advisory{
	{
		Code:     "EEOC_REGULATED_ROLE_ESCAPE_INVARIANT",
		Severity: SeverityError,
		Message:  "R153 R-DOMAIN-ESCAPE-INVARIANT: any candidate matching the EEOC regulated-role taxonomy (director / executive / safety_critical / protected_class_sensitive per EEOC 29 C.F.R. § 1607) MUST short-circuit to qualified HR + legal review. bias-audit does NOT itself perform the screening; it orchestrates the annual audit ledger that records the AEDT's compliance with the four-fifths rule. The deploying tenant's AEDT must wire the R74 EEOC escape gate (see canopy cohort sibling).",
		DocLink:  "SECURITY.md",
	},
	{
		Code:     "NYC_LL144_AEDT_BIAS_AUDIT_REQUIRED",
		Severity: SeverityWarn,
		Message:  "NYC Local Law 144 (AEDT, effective 2023-07-05) requires (a) annual independent bias audit, (b) candidate notice ≥10 business days prior, (c) public posting of summary results. R153.A R-REGULATORY-ESCAPE-INVARIANT-WITH-AUDIT-LEDGER: the annual cadence is the deploying tenant's responsibility; bias-audit's auditledger primitive orchestrates the record but does NOT itself perform the independent audit. Use auditledger.Ledger.AnnualCadenceCompliance to surface tenant-AEDT pairs missing recent annual coverage.",
		DocLink:  "SECURITY.md",
	},
	{
		Code:     "BIAS_AUDIT_INDEPENDENT_AUDITOR_REQUIRED",
		Severity: SeverityError,
		Message:  "R153 R-DOMAIN-ESCAPE-INVARIANT: per NYC LL144 § 20-871(a) the bias audit MUST be performed by a person or organisation NOT involved in the development of the AEDT AND with no interest in the outcome of the audit. bias-audit refuses to record an attested signoff without IndependentAuditorName + non-zero SignoffDate (see auditledger.ErrAttestedWithoutAuditor + ErrAttestedWithoutSignoffDate). The independent-auditor identity is the load-bearing regulator-facing field.",
		DocLink:  "SECURITY.md",
	},
	{
		Code:     "BIAS_AUDIT_CANDIDATE_NOTICE_10_BUSINESS_DAYS",
		Severity: SeverityWarn,
		Message:  "R153 candidate-notice cadence per NYC LL144 § 20-871(b) — the deploying employer MUST notify candidates ≥10 business days prior to AEDT-mediated assessment. bias-audit generates the canonical candidate-notice template via legal.CandidateNoticeFooter; the deploying employer is responsible for the actual notice delivery + cadence + alternative-selection-process offer.",
		DocLink:  "CONTEXT.md",
	},
	{
		Code:     "BIAS_AUDIT_PUBLIC_POSTING_REQUIRED",
		Severity: SeverityWarn,
		Message:  "R153 public-posting requirement per NYC LL144 § 20-871(c) — the deploying employer MUST publicly post the annual audit summary results on its website. bias-audit produces the summary via auditledger.Entry.SummaryHash + PublicPostingURL slot; the deploying employer is responsible for the actual public posting + URL stability. An empty PublicPostingURL on an attested annual entry is an honest delinquency signal (R120 nullable-additive — empty != absent at the database layer; here in-memory empty IS honest).",
		DocLink:  "CONTEXT.md",
	},
}

var (
	registryMu sync.RWMutex
	registry   = map[string]*sync.Once{}
)

func LoudOnce(adv Advisory, w io.Writer) {
	registryMu.RLock()
	once, ok := registry[adv.Code]
	registryMu.RUnlock()
	if !ok {
		registryMu.Lock()
		once, ok = registry[adv.Code]
		if !ok {
			once = &sync.Once{}
			registry[adv.Code] = once
		}
		registryMu.Unlock()
	}
	once.Do(func() {
		_, _ = fmt.Fprintf(w, "%s %s %s: %s (see %s)\n",
			LoudOncePrefix, adv.Severity, adv.Code, adv.Message, adv.DocLink)
	})
}

func Reset() {
	registryMu.Lock()
	registry = map[string]*sync.Once{}
	registryMu.Unlock()
}

func CanonicalAdvisories() []Advisory {
	out := make([]Advisory, len(canonicalAdvisories))
	copy(out, canonicalAdvisories)
	return out
}

func FindAdvisory(code string) (Advisory, bool) {
	for _, a := range canonicalAdvisories {
		if a.Code == code {
			return a, true
		}
	}
	return Advisory{}, false
}
