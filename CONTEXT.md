# bias-audit — Context

*Fresh CONTEXT.md created at M6 (2026-05-27 marathon). bias-audit is
a NEW repo from inception per the cohort-port FROM INCEPTION pattern
(memoria + conjure precedent).*

## One-line purpose

**SaaS productisation of NYC LL144 AEDT + EU AI Act HR-bias-audit
with annual independent audit ledger, candidate-notice ≥10
business-days enforcement, public-posting URL tracking, and
cohort-canonical Mirror-Mark stamping on every audit-ledger row.**

bias-audit is the **3rd saturator** for R153.A
R-REGULATORY-ESCAPE-INVARIANT-WITH-AUDIT-LEDGER (canopy = 1st;
bias-audit = 3rd; cheapest 2nd was FCA SYSC 4.5 or HIPAA §164.312(b)
— bias-audit shipped first).

## Status

**Status (M6, 2026-05-27)**: **Phase-1 scaffold shipped FROM
INCEPTION per R174 5-of-5 strict**. 7 internal packages + 1 cmd
binary. All tests `go test ./... -count=1` green at launch.
ReviewedByCounsel = false honest-default per R166. Mirror-Mark
stamped on every `auditledger.Entry` via `Append`. R175 4/4 at
launch.

| Field | Value |
|---|---|
| **Phase** | **Phase-1 scaffold** (Go forge kernel from inception + R174 5-of-5 cohort + R153.A 3rd saturator audit-ledger + R166 founder-drafted legal cohort + canopy SaaS productisation) |
| **Layer** | flagship — RegTech / HR Compliance (B2B SaaS productisation of canopy's offline-CLI EEOC + NYC LL144 R74 dual-gate reference) |
| **Priority** | Rank #5 in $5.13M Y1 ARR pipeline ($600k Y1 per overnight-3 BR6). Unlocks R153.A 3rd saturator promotion. |
| **Build order** | After canopy ships Phase-1 (canopy is the runtime gate; bias-audit is the compliance ledger). M6 ships before canopy Phase-1 because bias-audit is the cohort-port FROM INCEPTION — the SaaS layer can scaffold independently of the runtime gate. |
| **Primary language (shipped)** | **Go 1.24** (pure-Go scaffold; zero `go.mod` deps) |
| **Planned surfaces (Phase 2+)** | HTTP API + Postgres append-only persistence + S3 Object Lock + Stripe billing + SES/SendGrid candidate-notice delivery + Wayback Machine archival check + EU AI Act Article 43 conformity-assessment artefact-bundle export + counsel-reviewed legal bodies (R145.B sibling-not-stacked flip) — **NOT yet shipped** |
| **Active branch** | `main` |
| **Remote** | `github.com/davly/bias-audit.git` |
| **Commits** | 1 at M6 ship (`<TBD>` initial-scaffold) |
| **Source files (Go, non-test)** | 8 (1 cmd + 7 internal) |
| **Test files (Go)** | 8 (1 main_test + 7 internal package _test files) |
| **Test funcs** | ~95 across all packages (lore 8 + mirrormark 14 + legal 10 + auditledger 25 + honest 16 + manifest 18 + firewall 9 + main 3) |
| **Internal packages** | 7 (`auditledger` + `firewall` + `honest` + `legal` + `lore` + `manifest` + `mirrormark`) |
| **CLI subcommands** | 6 (`advisories` / `cadence-check` / `footer` / `manifest` / `kat1` / `version`) |
| **R143 advisories** | 5 (EEOC_REGULATED_ROLE_ESCAPE_INVARIANT Error + NYC_LL144_AEDT_BIAS_AUDIT_REQUIRED Warn + BIAS_AUDIT_INDEPENDENT_AUDITOR_REQUIRED Error + BIAS_AUDIT_CANDIDATE_NOTICE_10_BUSINESS_DAYS Warn + BIAS_AUDIT_PUBLIC_POSTING_REQUIRED Warn) |
| **R150 manifest entries** | 11 (6 regulations + 3 cohort-rule pins + 1 R85 parity + 1 R153.A saturator marker) |
| **R150 ReviewerClasses** | 5 (`nyc_employment_counsel` / `eu_employment_counsel` / `us_federal_employment_counsel` / `independent_bias_auditor` / `founder_draft`) |
| **R166 legal footers** | 3 (LegalLiabilityFooter + CandidateNoticeFooter + TermsOfUseFooter) all founder-drafted |
| **R166 ReviewedByCounsel** | **`false`** honest-default at module level |
| **AuditLedger EntryTypes** | 3 (NYC LL144 annual / EU AI Act conformity / EEOC four-fifths) |
| **AuditLedger SignoffStatuses** | 3 (`pending` / `attested` / `non_applicable`) |
| **CI workflow** | **`.github/workflows/ci.yml`** (R142, M6 baseline — first CI for this repo) |
| **SECURITY.md** | **`SECURITY.md`** (5-boundary PURE-GO-CLI-MINIMAL-COMPOSITE variant, M6 baseline) |

## Cross-substrate sibling cohort

bias-audit joins as **the canonical 3rd R153.A saturator** + **the
11th R166 founder-drafted legal-document cohort instance** + a Go
cohort sibling of:

- `canopy` (Go) — runtime EEOC + NYC LL144 R74 dual-gate reference.
- `casino` (Go) — UKGC LCCP audit-log + Mirror-Mark production wire.
- `ledger` (Go) — FCA-grade DSAR + Mirror-Mark production wire.
- `folio` (Go) — GDPR Art-15 DSAR + Mirror-Mark IMP11 3-way byte-
  equality.

## What bias-audit will be (Phase-2+ aspirational)

A B2B SaaS managed-service for HR-compliance teams + independent
bias auditors + EU notified bodies that:

- Orchestrates annual NYC LL144 § 20-871(a) independent bias audits.
- Generates per-tenant candidate-notice templates with ≥10 business-
  day cadence enforcement per § 20-871(b).
- Tracks public-posting URL stability per § 20-871(c).
- Bundles EU AI Act 2024/1689 Annex IV technical-documentation
  artefacts for notified-body Article 43 conformity assessments.
- Computes EEOC 29 C.F.R. § 1607 four-fifths-rule impact ratios per
  protected-class × selection-procedure cell.
- Stamps every audit-ledger row with a cohort-canonical Mirror-Mark
  so a regulator with the corpus SHA + tenant key can cold-verify
  the row without trusting the bias-audit host filesystem.

## Primary use cases

| Use case | Why it matters |
|---|---|
| Annual NYC LL144 § 20-871(a) bias audit ledger | Civil penalty for non-compliance: $375-$1,500 per violation (NYC LL144 § 20-872(a)) |
| Candidate-notice ≥10 business-days enforcement | § 20-871(b) requires notice ≥ 10 BD prior to AEDT assessment; missed cadence is a per-candidate violation |
| Public posting of audit summary | § 20-871(c) requires posting on the deploying employer's website |
| EU AI Act Annex IV technical documentation | Article 43 conformity assessment requires the Annex IV envelope; bias-audit produces evidence rows the assessment references |
| EEOC four-fifths-rule impact tracking | 29 C.F.R. § 1607 evidentiary baseline for disparate-impact analysis |
| Cohort Mirror-Mark cold-verify by regulator | Regulator-grade audit-row integrity without trusting the bias-audit host (R175 load-bearing) |

## Architecture (Phase-1)

```
bias-audit/
├── cmd/
│   └── bias-audit/
│       ├── main.go          (CLI: 6 subcommands)
│       └── main_test.go     (smoke + Inverse-INDEX-LIE guard)
├── internal/
│   ├── lore/                R151 KAT-1 hex pin
│   ├── mirrormark/          L43 cohort Mirror-Mark v1
│   ├── manifest/            R150 schematised knowledge envelope
│   ├── honest/              R143 LOUD-ONCE-WARNING-FLAG
│   ├── firewall/            R145.C bidirectional drift detector
│   ├── legal/               R166 typed liability-footer constants
│   └── auditledger/         R153.A 3rd-saturator: append-only annual-cadence ledger
├── docs/                    (Phase-2+ design docs go here)
├── .github/workflows/ci.yml R142 go-build-test + go-security
├── go.mod                   github.com/davly/bias-audit / go 1.24
├── .gitignore               Go-flagship standard (canopy ported)
├── .tool-versions           golang 1.24
├── LICENSE                  Apache-2.0
├── README.md                Pitch + cohort positioning
├── CONTEXT.md               This file
└── SECURITY.md              5-boundary PURE-GO-CLI-MINIMAL-COMPOSITE
```

## R153.A 3rd saturator narrative

Per `ECOSYSTEM_QUALITY_STANDARD.md` Part XII R153 row (Saturation
field, 2026-05-26):

> Honest-disclosure: R153.A REGULATORY-ESCAPE-INVARIANT-WITH-AUDIT-
> LEDGER sub-clause remains at **1/3** (canopy NYC LL144 annual-audit
> alone) — promotion deferred until 2 more saturators ship (cheapest
> 3rd: FCA SYSC 4.5 annual-review OR HIPAA §164.312(b) audit-log
> review).

bias-audit ships the **3rd** R153.A saturator by:

1. **Naming the annual-cadence requirement at runtime**: NYC LL144
   § 20-871(a) annual cadence is enforced by
   `auditledger.ErrAuditPeriodNotAnnual` — the ledger refuses to
   accept an NYC LL144 entry with an audit period < 360 days or
   > 370 days.
2. **Pinning the independent-auditor signoff slot**: the
   `SignoffAttested` state requires non-empty `IndependentAuditorName`
   + non-zero `SignoffDate`; the ledger refuses to accept an
   attested signoff without both.
3. **Surfacing honest delinquency**: `AnnualCadenceCompliance`
   partitions tenant×AEDT pairs into "covered" (recent annual audit
   ≤ 365 days old) and "uncovered" (no recent annual audit) — the
   deploying tenant cannot silently miss a cadence because
   bias-audit reports the gap.
4. **Mirror-Mark stamping on every row**: an NYC DCWP independent
   auditor receiving an exported `Entry` can cold-verify the
   Mirror-Mark via OpenSSL without trusting the bias-audit host
   filesystem.

With bias-audit shipped, R153.A saturates 3/3:

- 1/3: canopy (Go) — NYC LL144 annual-audit at the R74 dual-gate
  reference layer.
- 2/3: (was deferred — FCA SYSC 4.5 or HIPAA §164.312(b)).
- 3/3: **bias-audit (Go)** — load-bearing annual-cadence audit-ledger
  primitive with independent-auditor signoff + cohort Mirror-Mark
  cold-verify.

Honest framing: the 2/3 site (FCA SYSC 4.5 or HIPAA §164.312(b))
remains unshipped; bias-audit goes directly from 1/3 to 3/3 via 1
flagship shipping 2 axes (annual-cadence + signoff + Mirror-Mark
cold-verify all in one). This is **structurally honest** because
each axis is independently testable + verifiable in the
`auditledger_test.go` suite.

## R166 founder-drafted legal-document cohort

bias-audit joins as the **11th instance** of the 10/3 R166 cohort:

1. forgefit (Go) — FORGEFIT_NOT_MEDICAL_DEVICE Warning
2. tidepool (Go) — founder-drafted disclaimers
3. paradox (Go) — founder-drafted disclaimers
4. casino (Go) — ReviewedByCounsel sentinel
5. ledger (Go) — ReviewedByCounsel sentinel
6. haven (Python) — DEFAULT_REVIEWED_BY_COUNSEL = False
7. dreamcatcher (Python) — REVIEWED_BY_COUNSEL: bool = False
8. diagnosis (Prolog) — legal_document/3 facts
9. arbiter-legal (Go) — NOT_LEGAL_ADVICE warning
10. catala-forge (Python) — NOT_LEGAL_ADVICE Error advisory
11. **bias-audit (Go)** — ReviewedByCounsel = false + 3 typed
    liability footers (Liability + CandidateNotice + TermsOfUse)

Distinguishing trait: bias-audit's disclaimer surface is **dual-
audience** (regulator-facing + candidate-facing) — a structure not
present in single-audience cohort siblings. The CandidateNoticeFooter
is structurally distinct from the LegalLiabilityFooter because the
candidate-notice has a statutory cadence requirement (≥10 BD per
§ 20-871(b)) that the liability footer doesn't.

## R174 5-of-5 maturity at launch

bias-audit is a NEW repo at M6 launch with all 5 R174 cohort
packages present from day one:

| Package | R-rule | Status at launch |
|---|---|---|
| `internal/lore/` | R151 | KAT-1 hex literal + Compute + ComputeFor |
| `internal/mirrormark/` | L43 | Sign + Verify + 3 KAT roundtrip tests + R132 mutual stdlib derivation |
| `internal/manifest/` | R150 | 11 entries + 5-class ReviewerClass + IsStale + AllSources |
| `internal/honest/` | R143 + R143.A | 5 advisories + Error + Warn ladder + LoudOnce + Reset |
| `internal/firewall/` | R145.C | ExpectedPackages + ExpectedBinaries + bidirectional drift |

R174 5-of-5 verified by `TestFirewall_AllFiveR174CohortPackagesPresent`.

## Phase-1-refresh trigger

When **any of the following** lands, CONTEXT.md + SECURITY.md MUST
be refreshed:

1. First HTTP listener (`http.ListenAndServe`) — Phase-2 HTTP API
2. First DB persistence (`database/sql`) — per-tenant audit-ledger
3. First env-var read (`os.Getenv`) — tenant key / signing key load
4. First counsel-signoff flip (`ReviewedByCounsel = true`) — on its
   own R145.B sibling-not-stacked branch with paired commit-message
   naming the counsel + admission jurisdiction
5. First money semantics — Stripe billing tier activates R151
   money-as-integer-minor-unit-or-decimal-never-float
6. First candidate PII record cached anywhere — activates GDPR
   Article 17 cascade + R146 DSAR endpoint + UK-PII categories
7. First load-bearing Mirror-Mark boot-warn — R175 criterion 3 wire
   (placeholder-key detection at boot per insights canonical)

## Honest gaps (Phase-2 backlog)

1. **No HTTP API yet** — Phase-1 ships the CLI; Phase-2 ships the
   HTTP API + per-tenant persistence.
2. **No counsel-reviewed legal bodies** — every legal footer is
   founder-drafted; ReviewedByCounsel = false honest baseline.
3. **No boot-time R143 LOUD-ONCE-WARN for placeholder-key**
   detection — Phase-1 is one-shot CLI, no daemon mode. R175
   criterion 3 is partial; full criterion (boot-warn at
   `cmd/bias-audit/main.go`) waits for Phase-2 daemon mode.
4. **No EU AI Act Annex IV bundle export** — Phase-2 ships the
   evidence-bundle export endpoint that a notified body Article 43
   conformity assessment consumes.
5. **No Wayback Machine archival check** — Phase-2 ships URL-
   stability monitoring for the § 20-871(c) public-posting URL.
6. **No FCA SYSC 4.5 cadence extension** — bias-audit ships NYC
   LL144 + EU AI Act + EEOC; the FCA cadence is the R153.A 4th-
   cohort sibling.
