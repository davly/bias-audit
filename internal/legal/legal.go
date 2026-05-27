// Package legal pins bias-audit's founder-drafted disclaimer text + the
// R166 ReviewedByCounsel honest-default sentinel.
//
// Why this package exists (R166 R-LIABILITY-FOOTER-CONST + REVIEWED-BY-
// COUNSEL-FALSE, promoted 2026-05-27 at 10/3 — strongest single
// godfather-session payoff):
//
// bias-audit is the SaaS productisation of NYC LL144 AEDT + EU AI Act
// HR-bias-audit. Every consumer-touching string (terms-of-use shown
// at tenant onboarding / privacy-notice surfaced at candidate-notice
// time / library-disclaimer rendered into the audit-ledger header)
// MUST satisfy R166's 3-element discipline:
//
//  1. The disclaimer body is a typed constant in domain code (this
//     file's `LegalLiabilityFooter` constant), NEVER a string literal
//     inlined at the call site. The named constant is grep-discoverable
//     and version-controlled.
//  2. A paired `ReviewedByCounsel: bool = false` module-level honest-
//     default sentinel. False is the load-bearing default. Flipping to
//     True requires its own R145.B sibling-not-stacked additive branch
//     + a named counsel signoff commit-message.
//  3. CONTEXT.md / SECURITY.md document the founder-authored boundary
//     explicitly with LIBRARY-RECOMMENDS-HOST-ACTS language — the
//     tenant is responsible for counsel review before flipping the
//     sentinel to True.
//
// Cohort siblings (founder-drafted legal-document cohort at 10/3):
//
//   - forgefit (Go) — FORGEFIT_NOT_MEDICAL_DEVICE Warning advisory
//   - tidepool (Go) — founder-drafted disclaimers per cohort doc
//   - paradox (Go) — founder-drafted disclaimers per cohort doc
//   - casino (Go) — ReviewedByCounsel sentinel
//   - ledger (Go) — ReviewedByCounsel sentinel
//   - haven (Python) — DEFAULT_REVIEWED_BY_COUNSEL = False
//   - dreamcatcher (Python) — REVIEWED_BY_COUNSEL: bool = False
//   - diagnosis (Prolog) — legal_document/3 facts
//   - arbiter-legal (Go) — NOT_LEGAL_ADVICE warning advisory
//   - catala-forge (Python) — NOT_LEGAL_ADVICE Error-severity advisory
//
// bias-audit joins as the 11th instance, further over-saturating the
// R166 cohort. Distinguishing trait: bias-audit's disclaimer surface
// is **regulator-facing** (NYC DCWP independent auditors will read it)
// AND **candidate-facing** (R153.A candidate-notice ≥10 business days
// requirement under NYC LL144 § 20-871(b)) — dual-audience structure
// not present in single-audience cohort siblings.
package legal

// LegalDocumentVersion — bumping requires paired R145.B sibling branch.
const LegalDocumentVersion = "v1"

// EffectiveDate — pinned at module load. ISO 8601.
const EffectiveDate = "2026-05-27"

// ReviewedByCounsel is the R166 honest-default sentinel.
//
// FALSE is the load-bearing default. Flipping to True is a
// behaviour-changing event that:
//
//   - MUST land on its own R145.B sibling-not-stacked branch
//     (named `legal-counsel-review-v1-2026-MM-DD-bias-audit`).
//   - MUST cite the qualified counsel by name + admission jurisdiction
//     (NYC bar admission for the NYC LL144 surface; EU member-state
//     bar admission for the EU AI Act surface) in the commit message.
//   - MUST land paired with a regression test asserting the new value.
//
// Bundling a False→True flip into a feature commit defeats audit-trail
// and is the canonical R166 antipattern (4).
const ReviewedByCounsel bool = false

// LegalLiabilityFooter is the canonical founder-drafted liability
// footer rendered into every audit-ledger row header + every
// candidate-notice email + every tenant-facing terms-of-use page.
//
// Grep-discoverable single source of truth — NEVER inline this body
// at a call site (R166 antipattern 1).
const LegalLiabilityFooter = `=== bias-audit v1 Legal Liability Footer ===

bias-audit is software that orchestrates the annual independent bias
audit required by NYC Local Law 144 (Automated Employment Decision
Tool, effective 2023-07-05) and the conformity-assessment artefacts
required by EU AI Act 2024/1689 Annex III §1 (high-risk HR/employment
AI systems). bias-audit does NOT itself constitute, replace, or
substitute for:

  1. The annual independent bias audit performed by a qualified
     independent auditor as required by NYC LL144 § 20-871(a). The
     independent auditor MUST be a person or organisation that has
     not been involved in the development of the AEDT and has no
     interest in the outcome of the audit.
  2. Legal advice from counsel admitted to the New York State bar or
     to a relevant EU member-state bar. The disclaimer bodies in this
     software were founder-drafted; ReviewedByCounsel = false is the
     honest baseline. Until that constant is flipped to true (on its
     own R145.B sibling-not-stacked branch with a named counsel
     signoff commit), every body in this package is a founder draft.
  3. A conformity assessment under EU AI Act 2024/1689 Article 43.
     bias-audit produces evidence rows the conformity assessment may
     reference; the assessment itself is performed by a notified body
     listed in the EU AI Act conformity-assessment register.
  4. Compliance with EEOC 29 C.F.R. § 1607 Uniform Guidelines on
     Employee Selection Procedures (1978). bias-audit reports impact
     ratios under the four-fifths rule; the underlying selection
     procedure compliance is the deploying organisation's
     responsibility.

LIBRARY-RECOMMENDS-HOST-ACTS — bias-audit advises; the deploying
tenant + the independent auditor + counsel act.
=== End Footer ===`

// CandidateNoticeFooter — appended to the canonical candidate-notice
// email body sent ≥10 business days prior to an AEDT-mediated
// employment decision per NYC LL144 § 20-871(b).
const CandidateNoticeFooter = `=== Candidate Notice Footer (NYC LL144 § 20-871(b)) ===

Under New York City Local Law 144 (Automated Employment Decision Tool
regulation, effective 2023-07-05), you have the right to:

  1. Receive notice that an automated employment decision tool (AEDT)
     will be used in your assessment, NO LATER than 10 business days
     prior to its use.
  2. Request an alternative selection process or reasonable
     accommodation. The deploying employer is required to provide
     instructions for how to make such a request.
  3. Review the annual independent bias audit summary results, which
     the deploying employer is required to publicly post on its
     website per NYC LL144 § 20-871(c).

This notice is generated by bias-audit, an orchestration tool.
bias-audit does NOT itself perform the AEDT assessment. Questions
about the assessment, alternative selection processes, or reasonable
accommodations should be directed to the deploying employer.
=== End Footer ===`

// TermsOfUseFooter — rendered at tenant-onboarding time.
const TermsOfUseFooter = `=== bias-audit Tenant Terms-of-Use Footer (Founder Draft) ===

This software is provided AS-IS without warranty of any kind. The
tenant is responsible for:

  1. Engaging a qualified independent auditor (NYC LL144 § 20-871(a))
     to perform the annual bias audit. bias-audit produces the audit
     evidence ledger; the independent auditor produces the audit
     opinion.
  2. Counsel review of all founder-drafted disclaimer bodies BEFORE
     deployment to production. ReviewedByCounsel = false is the
     honest baseline.
  3. Compliance with applicable jurisdictional regulations beyond
     NYC LL144 + EU AI Act (e.g. Illinois AI Video Interview Act
     820 ILCS 42/, Colorado SB 21-169, Maryland HB 1202).
  4. Tenant-level data protection compliance — GDPR Article 22
     (automated decision-making) requires a lawful basis for AEDT use
     that bias-audit does NOT itself establish.
=== End Footer ===`
