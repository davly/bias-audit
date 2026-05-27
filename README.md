# bias-audit

**One-line:** SaaS productisation of NYC LL144 AEDT + EU AI Act
HR-bias-audit — an append-only annual-cadence audit ledger primitive
with independent-auditor signoff slots, cohort-canonical Mirror-Mark
receipts, and founder-drafted (counsel-pending) candidate-notice + 
public-posting + terms-of-use bodies.

**Category:** B2B Enterprise | RegTech / HR Compliance
**Target Market:** Enterprise HR departments deploying AEDTs in
NYC (NYC LL144 § 20-871(a) coverage) and EU member states (EU AI Act
2024/1689 Annex III §1), independent bias auditors per NYC DCWP rule
§ 5-300, EU notified bodies performing Article 43 conformity
assessments.

**Status:** Phase-1 scaffold (M6, 2026-05-27). Cohort-port FROM
INCEPTION per R174 5-of-5 strict — bias-audit ships the 5-of-5
cohort packages on day one (lore + mirrormark + manifest + honest +
firewall) PLUS the two bias-audit-domain packages (legal +
auditledger). All packages `go test ./... -count=1` green at launch.

---

## Why bias-audit (cohort positioning)

Canopy (cohort sibling) ships the offline-CLI single-tenant reference
for the R74 EEOC + NYC LL144 dual-gate. **bias-audit is canopy's
SaaS productisation**: multi-tenant managed annual-audit ledger +
candidate-notice + public-posting orchestration plane.

- canopy is the runtime gate; bias-audit is the **compliance ledger**.
- canopy refuses to render a verdict on regulated-role candidates;
  bias-audit records the annual independent audit confirming canopy's
  refusal is being honoured + audits the per-decision four-fifths
  impact ratio per NYC LL144 § 20-871(a) + EEOC 29 C.F.R. § 1607.
- canopy's `R69b REGULATORY ESCAPE` tag flows into bias-audit's
  ledger as an audit-row.

bias-audit is **the canonical 3rd saturator** for R153.A
R-REGULATORY-ESCAPE-INVARIANT-WITH-AUDIT-LEDGER. Pre-bias-audit
the sub-clause sat at 1/3 (canopy NYC LL144 alone); bias-audit ships
the annual-cadence audit-ledger as a load-bearing runtime artefact
via `internal/auditledger`, promoting R153.A to **3/3 saturation**.

## Phase-1 scope (M6 ship)

What ships today (~120 min single-session scaffold):

1. **`internal/lore/`** — R151 KAT-1 hex pin (`239a7d0d…`) +
   OpenSSL one-liner cold-verify recipe. Byte-identical to every
   cohort Go port.
2. **`internal/mirrormark/`** — L43 cohort-canonical Mirror-Mark
   v1 (62-char `lore@v1:…` receipt). 3 KAT pins (KAT-1 / KAT-6 /
   KAT-7) plus R132 mutual-cross-validation parity check.
3. **`internal/manifest/`** — R150 schematised-knowledge envelope
   with 11 entries (6 regulation citations + 3 cohort-rule pins +
   1 R85 parity + 1 R153.A 3rd-saturator marker). R166
   ReviewedByCounsel = false honest-default on every entry.
4. **`internal/honest/`** — R143 LOUD-ONCE-WARNING-FLAG with 5
   canonical advisories spanning R143.A's Error + Warn severity
   tiers.
5. **`internal/firewall/`** — R145.C FIREWALL-TEST-DISCIPLINE
   bidirectional drift detector (`ExpectedPackages` ↔ on-disk
   `internal/`).
6. **`internal/legal/`** — R166 R-LIABILITY-FOOTER-CONST +
   REVIEWED-BY-COUNSEL-FALSE — bias-audit joins the 10/3 founder-
   drafted legal-document cohort as the 11th instance. Three
   typed footer constants (Liability + CandidateNotice +
   TermsOfUse).
7. **`internal/auditledger/`** — the load-bearing R153.A 3rd
   saturator. Append-only annual-cadence audit ledger with
   independent-auditor signoff slots + Mirror-Mark stamping at
   append time + AnnualCadenceCompliance partition function.
8. **`cmd/bias-audit/`** — Go CLI with 6 subcommands (advisories /
   cadence-check / footer / manifest / kat1 / version).

## Phase-2+ (future work; NOT in scope today)

- HTTP API + per-tenant persistence (Postgres append-only / S3
  Object Lock).
- Independent-auditor signoff workflow (multi-party signing +
  attestation upload).
- Public-posting URL stability check + Wayback Machine archival
  integration.
- Candidate-notice email delivery (SES / SendGrid integration).
- Tenant onboarding + Stripe billing (the 4-CRITICAL Folio
  launch-blocker pattern applies — gate behind GDPR-DSAR + Stripe
  signed-webhook).
- Counsel review of the founder-drafted legal bodies (flipping
  `ReviewedByCounsel = false` → `true` is an R145.B sibling-not-
  stacked event with a named counsel signoff commit-message).
- EU AI Act Article 43 conformity-assessment artefact bundle (the
  ledger records evidence; the bundle export produces the
  Annex IV technical-documentation envelope a notified body
  consumes).
- FCA SYSC 4.5 cadence extension (R153.A 4th-cohort sibling).

## Regulatory anchors (R150 manifest)

| Regulation | Citation | Coverage |
|---|---|---|
| NYC Local Law 144 AEDT | § 20-870 / 20-871 / 20-872 | Annual audit + candidate notice + public posting |
| EU AI Act | Reg (EU) 2024/1689 Annex III §1 | High-risk HR/employment AI conformity assessment |
| EEOC Uniform Guidelines | 29 C.F.R. § 1607 | Four-fifths-rule adverse-impact analysis |
| Illinois AI Video Interview Act | 820 ILCS 42/ | Adjacent — Illinois applicant notice |
| Colorado SB 21-169 | (signed 2021) | Adjacent — insurance algorithm discrimination |
| Maryland HB 1202 | (effective 2020-10-01) | Adjacent — facial recognition in interviews |

## R-rule cohort coverage

| R-rule | Status | Notes |
|---|---|---|
| R115 SINGLE-ENUM-REJECTION-OUTCOME | Present | `EntryType` + `SignoffStatus` + `ReviewerClass` + `Severity` 4 enums |
| R132 MUTUAL-CROSS-VALIDATION-IN-PARITY-TEST | Present | `TestSign_InlineStdlibReDerivation_AgreesWithSign` |
| R143 LOUD-ONCE-WARNING-FLAG | Present | 5 advisories in `internal/honest/` |
| R143.A SEVERITY-LADDER-CONVENTION | Present | 2 Error + 3 Warn (no Info) |
| R145 strict additive | Present | NEW repo; no pre-existing surface to modify |
| R145.B SIBLING-NOT-STACKED | Pending | Future R145.B events: counsel-signoff flip, EU AI Act in-force date |
| R145.C FIREWALL-TEST-DISCIPLINE | Present | `internal/firewall/firewall.go` + bidirectional test |
| R150 PARALLEL-MAP-R144-REVIEW-METADATA | Present | 11-entry manifest + 5-class ReviewerClass enum |
| R150.E REVIEWER-CLASS-EXTENSION-FIELD | Present | `ReviewerClass` field on every Entry |
| R151 KAT-AS-COHORT-INVARIANT-CROSS-SUBSTRATE-PIN | Present | KAT-1 hex pinned at `internal/lore/lore.go:Digest` |
| R153 R-DOMAIN-ESCAPE-INVARIANT | Present | `EEOC_REGULATED_ROLE_ESCAPE_INVARIANT` Error + 4 cadence advisories |
| R153.A REGULATORY-ESCAPE-INVARIANT-WITH-AUDIT-LEDGER | **3rd saturator** | `internal/auditledger/` load-bearing — promotes R153.A from 1/3 to 3/3 |
| R155 R-VERDICT-REQUIRES-COMMIT-SHA-AND-TEST-RECEIPT | Present | Impl log at `MARATHON_2026-05-27/impl/M6_bias_audit_new_flagship.md` |
| R166 R-LIABILITY-FOOTER-CONST + REVIEWED-BY-COUNSEL-FALSE | Present | `internal/legal/` typed constants + `ReviewedByCounsel = false` default |
| R174 R-COHORT-5-OF-5-MATURITY | Present (5/5) | Cohort-port FROM INCEPTION — lore + mirrormark + manifest + honest + firewall on day one |
| R175 R-MIRROR-MARK-LOAD-BEARING-IN-PRODUCTION | Present (4/4) | `auditledger.Append` stamps Mirror-Mark on every row; KAT-1 hex pinned; OpenSSL recipe in `lore.go`; R143 advisory documented (boot-warn wire-in deferred to Phase-2 daemon mode) |

## License

Apache-2.0. See `LICENSE`.

## Security

See `SECURITY.md`. Phase-1 has no network listener, no env-var
reads, no persistence, no auth surface. Phase-2+ will introduce
each of these and refresh the threat model accordingly.

## Contact

Maintainer: David Carson — david@vocala.co
