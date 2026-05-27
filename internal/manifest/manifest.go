// Package manifest implements the R150 cohort-canonical schematised-
// knowledge envelope for bias-audit's regulatory + jurisdictional
// content surfaces.
//
// Why bias-audit consumes this today (cohort-port from inception per
// R174 5-of-5 strict + R150 R-PARALLEL-MAP-R144-REVIEW-METADATA-
// SIBLING):
//
//   - bias-audit's domain content includes:
//     - NYC Local Law 144 AEDT regulation (§ 20-870 / 20-871 / 20-872)
//     - EU AI Act 2024/1689 Annex III §1 high-risk HR/employment AI
//     - EEOC 29 C.F.R. § 1607 Uniform Guidelines (four-fifths rule)
//     - Illinois AI Video Interview Act 820 ILCS 42/
//     - Colorado SB 21-169
//     - Maryland HB 1202
//   - The R150 envelope pins each regulatory citation with FreshAt +
//     a cite-able authoritative source so a regulator-facing audit can
//     detect drift between a recorded confidence claim and updated
//     regulation. R144 jurisdiction-version anchored (jurisdiction
//     axis + statute axis = 2-axis composite key per R150 sub-clause).
//   - ReviewedByCounsel honest-default per R166 — every regulatory
//     entry carries `ReviewedByCounsel = false` until counsel signs
//     off on its own R145.B sibling-not-stacked branch.
package manifest

import (
	"sort"
	"time"
)

const SchemaVersion = 1

var FreshAtUnknown = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)

const (
	SourceNYCLocalLaw144                  = "NYC Local Law 144 AEDT (Automated Employment Decision Tool, effective 2023-07-05) § 20-870 / 20-871 / 20-872"
	SourceEUAIAct                         = "EU AI Act Regulation (EU) 2024/1689 (entered into force 2024-08-01) Annex III §1 high-risk HR/employment AI"
	SourceEEOCUniformGuidelines           = "EEOC 29 C.F.R. § 1607 Uniform Guidelines on Employee Selection Procedures (1978) — four-fifths rule"
	SourceIllinoisAIVideoInterviewAct     = "Illinois AI Video Interview Act 820 ILCS 42/ (effective 2020-01-01)"
	SourceColoradoSB21169                 = "Colorado SB 21-169 (Protecting Consumers from Unfair Discrimination in Insurance Practices, signed 2021)"
	SourceMarylandHB1202                  = "Maryland HB 1202 (Labor and Employment - Use of Facial Recognition Services, effective 2020-10-01)"
	SourceR74CanopyEEOCEscape             = "Canopy R74 second-gate eeoc_regulated_role_gate (cohort sibling implementation reference)"
	SourceR166FounderDraftedLegalCohort   = "R166 R-LIABILITY-FOOTER-CONST + REVIEWED-BY-COUNSEL-FALSE founder-drafted legal-document cohort"
	SourceR175MirrorMarkLoadBearingCohort = "R175 R-MIRROR-MARK-LOAD-BEARING-IN-PRODUCTION cohort wire posture"
	SourceContextDoc                      = "bias-audit CONTEXT.md"
	SourceR85ParityMarker                 = "R85 CLEAN-PARITY between code + CONTEXT.md"
)

type Confidence int

const (
	ConfidenceHigh   Confidence = 3
	ConfidenceMedium Confidence = 2
	ConfidenceLow    Confidence = 1
)

// ReviewerClass — R150 review-metadata reviewer-class axis per R150.E
// REVIEWER-CLASS-EXTENSION-FIELD.
type ReviewerClass string

const (
	// ReviewerClassNYCEmploymentCounsel — NYC bar admitted counsel
	// reviewing the NYC LL144 AEDT surface.
	ReviewerClassNYCEmploymentCounsel ReviewerClass = "nyc_employment_counsel"
	// ReviewerClassEUEmploymentCounsel — EU member-state bar admitted
	// counsel reviewing the EU AI Act + GDPR Art-22 surface.
	ReviewerClassEUEmploymentCounsel ReviewerClass = "eu_employment_counsel"
	// ReviewerClassUSFederalEmploymentCounsel — US federal employment
	// law counsel reviewing the EEOC / Title VII surface.
	ReviewerClassUSFederalEmploymentCounsel ReviewerClass = "us_federal_employment_counsel"
	// ReviewerClassIndependentBiasAuditor — independent bias auditor
	// per NYC LL144 § 20-871(a). Distinct from counsel — the bias
	// auditor is a quantitative reviewer, not a legal reviewer.
	ReviewerClassIndependentBiasAuditor ReviewerClass = "independent_bias_auditor"
	// ReviewerClassFounder — founder draft (R166 baseline; honest
	// default). Flipping to a counsel ReviewerClass requires its own
	// R145.B sibling-not-stacked branch + named counsel signoff.
	ReviewerClassFounder ReviewerClass = "founder_draft"
)

type Entry struct {
	Key                string
	Description        string
	FreshAt            time.Time
	Source             string
	SchemaVersion      int
	Confidence         Confidence
	ReviewerClass      ReviewerClass
	ReviewedByCounsel  bool
	Jurisdiction       string // ISO 3166-2 region code OR "EU" / "GLOBAL" / etc.
	StatuteVersion     string // statute citation including version / amendment
}

func (e Entry) IsStale(now time.Time, maxAge time.Duration) bool {
	if e.FreshAt.Equal(FreshAtUnknown) {
		return true
	}
	return now.Sub(e.FreshAt) > maxAge
}

type Manifest []Entry

func (m Manifest) SortedKeys() []string {
	keys := make([]string, 0, len(m))
	for _, e := range m {
		keys = append(keys, e.Key)
	}
	sort.Strings(keys)
	return keys
}

func (m Manifest) StaleEntries(now time.Time, maxAge time.Duration) []Entry {
	var out []Entry
	for _, e := range m {
		if e.IsStale(now, maxAge) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func AllSources() []string {
	return []string{
		SourceNYCLocalLaw144,
		SourceEUAIAct,
		SourceEEOCUniformGuidelines,
		SourceIllinoisAIVideoInterviewAct,
		SourceColoradoSB21169,
		SourceMarylandHB1202,
		SourceR74CanopyEEOCEscape,
		SourceR166FounderDraftedLegalCohort,
		SourceR175MirrorMarkLoadBearingCohort,
		SourceContextDoc,
		SourceR85ParityMarker,
	}
}

func AllReviewerClasses() []ReviewerClass {
	return []ReviewerClass{
		ReviewerClassNYCEmploymentCounsel,
		ReviewerClassEUEmploymentCounsel,
		ReviewerClassUSFederalEmploymentCounsel,
		ReviewerClassIndependentBiasAuditor,
		ReviewerClassFounder,
	}
}

// Seed returns the canonical R150 manifest for bias-audit.
//
// 11 entries: 6 regulation citations + 3 cohort-rule pins + 1 parity
// + 1 founder-drafted legal cohort marker.
func Seed() Manifest {
	regCheck := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
	parity := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)

	return Manifest{
		// 6 regulation citations (R150 parallel-map shape).
		{
			Key:               "regulation.nyc_local_law_144.aedt",
			Description:       "NYC Local Law 144 (Automated Employment Decision Tool) effective 2023-07-05 — annual independent bias audit + candidate notice ≥10 business days + public posting of summary results. § 20-870 (definitions), § 20-871(a) (annual audit), § 20-871(b) (candidate notice), § 20-871(c) (public posting), § 20-872 (penalties).",
			FreshAt:           regCheck,
			Source:            SourceNYCLocalLaw144,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewerClass:     ReviewerClassFounder,
			ReviewedByCounsel: false,
			Jurisdiction:      "US-NY",
			StatuteVersion:    "NYC Local Law 144 (2021) effective 2023-07-05",
		},
		{
			Key:               "regulation.eu_ai_act.annex_iii_hr",
			Description:       "EU AI Act Regulation (EU) 2024/1689 Annex III §1 high-risk AI systems in HR/employment. Article 6 (classification), Article 16 (provider obligations), Article 43 (conformity assessment), Article 50 (transparency obligations), Annex IV (technical documentation), Annex V (EU declaration of conformity).",
			FreshAt:           regCheck,
			Source:            SourceEUAIAct,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewerClass:     ReviewerClassFounder,
			ReviewedByCounsel: false,
			Jurisdiction:      "EU",
			StatuteVersion:    "EU AI Act 2024/1689 (in force 2024-08-01; HR Annex III applies from 2026-08-02)",
		},
		{
			Key:               "regulation.eeoc.uniform_guidelines_four_fifths",
			Description:       "EEOC 29 C.F.R. § 1607 Uniform Guidelines on Employee Selection Procedures (1978) — four-fifths rule for adverse impact analysis. Section 4D states that a selection rate for any group less than 4/5ths the rate for the highest group will generally be regarded as evidence of adverse impact.",
			FreshAt:           regCheck,
			Source:            SourceEEOCUniformGuidelines,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewerClass:     ReviewerClassFounder,
			ReviewedByCounsel: false,
			Jurisdiction:      "US",
			StatuteVersion:    "29 C.F.R. § 1607 Uniform Guidelines (1978)",
		},
		{
			Key:               "regulation.illinois.ai_video_interview_act",
			Description:       "Illinois AI Video Interview Act 820 ILCS 42/ (effective 2020-01-01) — employer notice + consent + race/ethnicity reporting for AI-analysed video interviews of Illinois applicants.",
			FreshAt:           regCheck,
			Source:            SourceIllinoisAIVideoInterviewAct,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceMedium,
			ReviewerClass:     ReviewerClassFounder,
			ReviewedByCounsel: false,
			Jurisdiction:      "US-IL",
			StatuteVersion:    "820 ILCS 42/ (2019) effective 2020-01-01",
		},
		{
			Key:               "regulation.colorado.sb_21_169",
			Description:       "Colorado SB 21-169 (Protecting Consumers from Unfair Discrimination in Insurance Practices, signed 2021) — restrictions on external consumer data and algorithms in insurance underwriting. Adjacent to HR-AEDT class.",
			FreshAt:           regCheck,
			Source:            SourceColoradoSB21169,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceMedium,
			ReviewerClass:     ReviewerClassFounder,
			ReviewedByCounsel: false,
			Jurisdiction:      "US-CO",
			StatuteVersion:    "Colorado SB 21-169 (2021)",
		},
		{
			Key:               "regulation.maryland.hb_1202_facial_recognition",
			Description:       "Maryland HB 1202 (Labor and Employment - Use of Facial Recognition Services, effective 2020-10-01) — restrictions on facial-recognition use in pre-employment interviews.",
			FreshAt:           regCheck,
			Source:            SourceMarylandHB1202,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceMedium,
			ReviewerClass:     ReviewerClassFounder,
			ReviewedByCounsel: false,
			Jurisdiction:      "US-MD",
			StatuteVersion:    "Maryland HB 1202 (2020) effective 2020-10-01",
		},
		// 3 cohort-rule pins.
		{
			Key:               "cohort.r74.canopy_eeoc_escape_reference",
			Description:       "R74 second-gate eeoc_regulated_role_gate as implemented in canopy cohort sibling — bias-audit references canopy's runtime EEOC escape as the in-code enforcement layer; bias-audit's auditledger primitive records compliance with the escape per audit cycle.",
			FreshAt:           parity,
			Source:            SourceR74CanopyEEOCEscape,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewerClass:     ReviewerClassFounder,
			ReviewedByCounsel: false,
			Jurisdiction:      "GLOBAL",
			StatuteVersion:    "canopy R74 second-gate (cohort reference)",
		},
		{
			Key:               "cohort.r166.founder_drafted_legal_cohort",
			Description:       "R166 R-LIABILITY-FOOTER-CONST + REVIEWED-BY-COUNSEL-FALSE — 10/3 cohort spanning forgefit / tidepool / paradox / casino / ledger / haven / dreamcatcher / diagnosis / arbiter-legal / catala-forge. bias-audit joins as the 11th instance.",
			FreshAt:           parity,
			Source:            SourceR166FounderDraftedLegalCohort,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewerClass:     ReviewerClassFounder,
			ReviewedByCounsel: false,
			Jurisdiction:      "GLOBAL",
			StatuteVersion:    "R166 catalogue (promoted 2026-05-27)",
		},
		{
			Key:               "cohort.r175.mirrormark_load_bearing_in_production",
			Description:       "R175 R-MIRROR-MARK-LOAD-BEARING-IN-PRODUCTION — bias-audit qualifies via auditledger.Ledger.Append stamping a Mirror-Mark on every annual-audit row + boot-time R143 LOUD-ONCE-WARN when key is placeholder + KAT-1 hex pinned in lore.go.",
			FreshAt:           parity,
			Source:            SourceR175MirrorMarkLoadBearingCohort,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewerClass:     ReviewerClassFounder,
			ReviewedByCounsel: false,
			Jurisdiction:      "GLOBAL",
			StatuteVersion:    "R175 catalogue (promoted 2026-05-27)",
		},
		// 1 parity + 1 r153.a saturator marker.
		{
			Key:               "r85.parity.code_vs_context",
			Description:       "R85 CLEAN-PARITY anchor — CONTEXT.md status row vs runtime ground truth.",
			FreshAt:           parity,
			Source:            SourceR85ParityMarker,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewerClass:     ReviewerClassFounder,
			ReviewedByCounsel: false,
			Jurisdiction:      "GLOBAL",
			StatuteVersion:    "R85 (internal)",
		},
		{
			Key:               "cohort.r153a.audit_ledger_3rd_saturator",
			Description:       "R153.A REGULATORY-ESCAPE-INVARIANT-WITH-AUDIT-LEDGER — bias-audit is the 3rd saturator (1/3 pre: canopy NYC LL144 annual-audit alone; 2/3 cheapest: FCA SYSC 4.5 or HIPAA §164.312(b)); bias-audit ships the annual-cadence audit-ledger as a load-bearing runtime artefact via internal/auditledger, promoting R153.A to 3/3 saturation.",
			FreshAt:           parity,
			Source:            SourceR175MirrorMarkLoadBearingCohort,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewerClass:     ReviewerClassFounder,
			ReviewedByCounsel: false,
			Jurisdiction:      "GLOBAL",
			StatuteVersion:    "R153.A catalogue (promoted 2026-05-26, 3rd saturator 2026-05-27)",
		},
	}
}
