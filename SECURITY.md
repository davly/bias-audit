# bias-audit — Security & Threat Model

**Status**: pure-Go library + offline CLI (Phase-1 scaffold, M6) —
SaaS-productisation of canopy's R74 EEOC + NYC LL144 dual-gate via
an append-only annual-cadence audit-ledger primitive in
`internal/auditledger/` plus the 5-of-5 R174 cohort packages (lore /
mirrormark / manifest / honest / firewall) plus the R166 founder-
drafted legal-document package (`internal/legal/`). **No HTTP
listener, no HTTP client, no daemon, no auth surface, no PII at
runtime, no DB.** The CLI reads no environment variables and writes
no files. This file documents the trust boundaries that DO exist so
future agents can verify what is and is not part of the threat model.

## Substrate context

- **Primary language**: Go 1.24; `cmd/bias-audit` is an offline CLI
  for the Phase-1 scaffold. No HTTP listener, no auth, no daemon
  mode; reads no environment variables; no filesystem reads beyond
  Go's own module imports.
- **Planned languages / surfaces (Phase 2+)**: HTTP API + Postgres
  append-only persistence + S3 Object Lock for audit-ledger row
  immutability + SES/SendGrid for candidate-notice delivery +
  Stripe for billing + EU AI Act Annex IV bundle export endpoint +
  Wayback Machine URL-stability check. **Not in this threat
  model.** Phase 2 will require an explicit refresh of this file
  before merging.
- **Go dependencies**: zero (verified by `cat go.mod` — only `module
  github.com/davly/bias-audit` + `go 1.24`; no `require` block, no
  `go.sum`).
- **Shape**: pure library — `internal/` packages are deterministic
  pure functions of their inputs; `cmd/bias-audit` is a one-shot
  CLI reading `os.Args` only.
- **Domain audience**: enterprise HR-compliance teams deploying
  AEDTs in NYC + EU + US-federal jurisdictions, independent bias
  auditors per NYC DCWP rule § 5-300, EU notified bodies performing
  Article 43 conformity assessments. **The audit-ledger is load-
  bearing**: the `Append` method validates annual cadence + signoff
  status + closed-set EntryType + closed-set SignoffStatus +
  non-empty TenantID + AEDTSystemID + audit-period sanity BEFORE
  appending; tampering attempts surface as one of the 7 typed
  sentinel errors. Distinct from sibling `flagships/canopy` (the
  runtime EEOC gate); bias-audit is the **compliance ledger**
  recording canopy's escape decisions.

## Threat model summary

Three structural disclaimers up front:

1. **No actuator** — bias-audit never executes a host-system
   action, never makes a hiring decision on the user's behalf,
   never edits an ATS or HRIS record, never sends an offer letter,
   never controls a network socket. The CLI prints audit-ledger
   summaries + advisory texts + KAT-1 hex + footer bodies, and the
   human (independent auditor + HR compliance team + counsel)
   decides whether to act. The library advises, the host acts.
   (Shared boundary with sibling `flagships/canopy` +
   `flagships/casino` + `flagships/ledger` + `flagships/folio` —
   `LIBRARY-RECOMMENDS-HOST-ACTS` R-pattern saturated cohort-wide.)

2. **No PII / no operational intelligence (shipped scaffold)** —
   tenant identifiers (`tenant_alpha`, `tenant_beta`), AEDT system
   identifiers (`aedt_recruiter_v2`, `aedt_screener_v1`),
   independent-auditor names (`Acme Independent Bias Auditors
   LLP`), and summary-hash strings (`demo_recent_hash`) in the
   demo + test fixtures are demonstration fixtures, not real
   tenants. **Real candidate data NEVER lands in this scaffold's
   ledger** — Phase-1 is structurally pure-function over deterministic
   inputs.

3. **Closed-set vocabulary is a security control** — `EntryType` ∈
   3-element closed set (`nyc_ll144_annual_audit` /
   `eu_ai_act_conformity_assessment` / `eeoc_four_fifths_impact`);
   `SignoffStatus` ∈ 3-element closed set (`pending` / `attested` /
   `non_applicable`); `ReviewerClass` ∈ 5-element closed set
   (`nyc_employment_counsel` / `eu_employment_counsel` /
   `us_federal_employment_counsel` / `independent_bias_auditor` /
   `founder_draft`); `Severity` ∈ 3-element closed set (`INFO` /
   `WARN` / `ERROR`); R143 advisory codes ∈ 5-element closed set.
   No free-form strings escape the CLI: every label printed on
   stdout is sourced from a closed-set enum + a manifest literal +
   the human-readable advisory message + the legal footer bodies.

## Trust boundaries

| # | Boundary | Owner | Guarantee | Falsifier |
|---|---|---|---|---|
| 1 | CLI argv → forge runtime | cmd/bias-audit/main.go | Input is parsed by stdlib `flag.NewFlagSet`; unknown commands print usage + exit 2; unknown footer kinds exit 2 with the closed-set list. Subcommand surface is fixed (`advisories` / `cadence-check` / `footer` / `manifest` / `kat1` / `version` / `help`) — no dynamic command discovery, no plugin loading. | `cmd/bias-audit/main_test.go` 3 smoke tests pin the version literal + the demo-cadence-check pipeline + the Inverse-INDEX-LIE guard ensuring every internal/ package is actually reachable from main. |
| 2 | Audit-ledger Append → in-memory storage | internal/auditledger/auditledger.go | `Append` validates: non-empty TenantID + AEDTSystemID; closed-set EntryType + SignoffStatus; AuditPeriodEnd > AuditPeriodStart; for NYC LL144 entries, 360 ≤ period ≤ 370 days; for SignoffAttested, non-zero SignoffDate + non-empty IndependentAuditorName. 7 typed sentinel errors. Mirror-Mark stamped at append time via the seeded corpus + key. | `internal/auditledger/auditledger_test.go` 25 tests pin every validation path + Mirror-Mark roundtrip + AnnualCadenceCompliance partition + defensive-copy + goroutine-safe concurrent appends + canonical-payload determinism. |
| 3 | Closed-set vocabulary + R150 manifest | internal/manifest/manifest.go + internal/auditledger/auditledger.go + internal/honest/honest.go + internal/legal/legal.go | `Severity` ∈ 3-element closed set; `EntryType` ∈ 3-element; `SignoffStatus` ∈ 3-element; `ReviewerClass` ∈ 5-element; R143 advisory codes ∈ 5-element closed set; R150 manifest sources ∈ 11-element closed set; legal footers ∈ 3-element closed-set typed-constants (R166). | `internal/manifest/manifest_test.go` 18 tests pin the 11-entry seed + uniqueness + R166 ReviewedByCounsel=false default + jurisdiction populated + sources canonical. `internal/honest/honest_test.go` 16 tests pin advisory count + severity ladder + LoudOnce gate + goroutine safety. `internal/legal/legal_test.go` 10 tests pin ReviewedByCounsel=false + every regulatory citation present in footers. `internal/auditledger/auditledger_test.go` 25 tests pin EntryType / SignoffStatus closed-set guards. |
| 4 | HMAC-SHA256 cohort cold-verify | internal/lore/lore.go + internal/mirrormark/mirrormark.go | KAT-1 hex `239a7d0d…` byte-identical across cohort (R151); `lore@v1:` 62-char mark format byte-identical to foundation/pkg/mirrormark (L43); HMAC + base64url use Go stdlib `crypto/hmac` + `crypto/sha256` + `encoding/base64` (R157 substrate-native idiom). All comparisons use `hmac.Equal` (constant-time). | `internal/lore/lore_test.go` 8 tests pin Compute → Digest equality + 33-byte canonical input shape + empty-key invariant + deterministic-roundtrip + single-bit-perturbation difference + OpenSSL recipe-literal present. `internal/mirrormark/mirrormark_test.go` 14 tests pin Sign roundtrip + KAT-1/6/7 mark literals + R132 mutual-stdlib derivation + 4 typed sentinel errors + fixed-62-character length. |
| 5 | Zero-emit / zero-network / zero-DB library surface | (whole repo) | No `http.ListenAndServe`, no `net/http`, no `database/sql`, no `os.Getenv`, no `os.LookupEnv`, no `bcrypt`, no `password`, no `JWT`, no `crypto/tls`, no `crypto/rand` in production paths (only in `mirrormark_test.go::TestSign_RoundtripVerify` to generate test fixtures), no goroutine in production paths (only in `auditledger_test.go::TestAppend_GoroutineSafeWithMixedOperations` to exercise the `sync.RWMutex`), no `time.Now()` in production paths (callers pass `now time.Time` per R-pattern). No filesystem writes; no temp files; no panic recoveries; no signal handlers. CLI exits with non-zero code on error per stdlib `flag.ExitOnError`. | Grep-verified at M6: `grep -rn "net/http\|os.Getenv\|os.LookupEnv\|database/sql\|crypto/tls\|JWT\|jwt\|password\|bcrypt\|secret" cmd/ internal/` → **0 hits**. `grep -rn "http.ListenAndServe\|net.Listen" cmd/ internal/` → 0 hits. R142 CI workflow `go-build-test` + `go-security` (gosec + govulncheck) re-asserts on every PR. |

## R-pattern coverage matrix

| R | Pattern | Status |
|---|---|---|
| R115 | SINGLE-ENUM-REJECTION-OUTCOME | **Present (strong)** — 4 closed-set enums (`EntryType` 3-state + `SignoffStatus` 3-state + `ReviewerClass` 5-state + `Severity` 3-state) close every output vocabulary path. |
| R132 | MUTUAL-CROSS-VALIDATION-IN-PARITY-TEST | **Present** — `mirrormark_test.go::TestSign_InlineStdlibReDerivation_AgreesWithSign` re-derives the mark via inline `crypto/hmac` + `crypto/sha256` calls and asserts byte-equality with `Sign()`. |
| R143 | LOUD-ONCE-WARNING-FLAG | **Present** — `internal/honest/honest.go` ships 5 canonical advisories with `sync.Once`-gated emission + Reset + FindAdvisory + CanonicalAdvisories APIs. |
| R143.A | SEVERITY-LADDER-CONVENTION | **Present** — 2 Error severities + 3 Warn severities; no Info. The Error tier covers EEOC regulated-role escape + independent-auditor required (R153 strict-liability surfaces); the Warn tier covers cadence advisories (NYC LL144 annual / candidate notice / public posting). |
| R145 | strict additive | **Present (NEW repo)** — bias-audit is a NEW flagship repo from inception; no pre-existing surface to modify. R145 strict additive holds trivially. |
| R145.B | SIBLING-NOT-STACKED | **Pending — but doc-noted** — counsel-signoff flip (`ReviewedByCounsel = false → true`) MUST land on its own R145.B sibling-not-stacked branch. This file documents the trigger. |
| R145.C | FIREWALL-TEST-DISCIPLINE | **Present** — `internal/firewall/firewall.go` + `firewall_test.go` ships the canonical bidirectional drift detector covering all 7 internal packages + 1 cmd binary. R174 5-of-5 verified by `TestFirewall_AllFiveR174CohortPackagesPresent`. |
| R150 | PARALLEL-MAP-R144-REVIEW-METADATA-SIBLING | **Present** — 11-entry R150 manifest in `internal/manifest/manifest.go` with `ReviewerClass` 5-class enum + Jurisdiction + StatuteVersion + ReviewedByCounsel + Confidence + FreshAt + Source + Description + Key fields. |
| R150.E | REVIEWER-CLASS-EXTENSION-FIELD | **Present** — `ReviewerClass` field on every Entry; `ReviewerClassFounder` is the honest baseline. |
| R151 | KAT-AS-COHORT-INVARIANT-CROSS-SUBSTRATE-PIN | **Present** — KAT-1 hex `239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca` pinned at `internal/lore/lore.go:Digest`; OpenSSL one-liner cold-verify recipe in doc-comment + `kat1` CLI subcommand. |
| R153 | R-DOMAIN-ESCAPE-INVARIANT | **Present** — `EEOC_REGULATED_ROLE_ESCAPE_INVARIANT` (Error) + 4 cadence advisories cover the 2-jurisdiction (NYC + EU) HR-employment regulated decision-making surface. |
| R153.A | REGULATORY-ESCAPE-INVARIANT-WITH-AUDIT-LEDGER | **Present (3rd saturator)** — `internal/auditledger/` ships load-bearing annual-cadence + independent-auditor signoff slots + Mirror-Mark cold-verify. Promotes R153.A from 1/3 → 3/3 saturation. |
| R155 | R-VERDICT-REQUIRES-COMMIT-SHA-AND-TEST-RECEIPT | **Present** — impl log at `reviews/MARATHON_2026-05-27/impl/M6_bias_audit_new_flagship.md` cites the launch commit SHA + `go test ./... -count=1` receipt. |
| R157 | R-SUBSTRATE-NATIVE-IDIOM-OVER-LITERAL-TRANSLATION | **Present** — `sync.Once` for LoudOnce gate (Go-native); `crypto/hmac` + `crypto/sha256` (Go-stdlib); `encoding/base64.RawURLEncoding` (Go-stdlib); `sync.RWMutex` for ledger concurrency (Go-native). |
| R166 | R-LIABILITY-FOOTER-CONST + REVIEWED-BY-COUNSEL-FALSE | **Present** — `internal/legal/legal.go` ships 3 typed liability-footer constants + `ReviewedByCounsel = false` module-level honest-default sentinel. 11th instance of the 10/3 R166 cohort. |
| R174 | R-COHORT-5-OF-5-MATURITY | **Present (5/5 from inception)** — bias-audit ships all 5 cohort packages on day one (lore + mirrormark + manifest + honest + firewall) plus 2 domain packages (legal + auditledger). |
| R175 | R-MIRROR-MARK-LOAD-BEARING-IN-PRODUCTION | **Present (4/4)** — (1) `auditledger.Append` stamps Mirror-Mark on every row via `marker.Sign()` (production-traffic emit path); (2) OpenSSL one-liner cold-verify recipe in `lore.go` doc-comment + `kat1` CLI subcommand; (3) boot-time R143 LOUD-ONCE-WARN — partial (Phase-1 is one-shot CLI; full boot-warn waits for Phase-2 daemon mode); (4) KAT-1 hex pinned in `lore.go` + test surface. |

## Patterns intentionally absent

1. **No PII categories** — tenant identifiers + AEDT system
   identifiers + auditor names are demonstration fixtures; no real
   tenant data, no UK-PII, no candidate-PII. **Phase 2 multi-tenant
   persistence WILL introduce real PII** — at that point the 9
   UK-PII categories become directly applicable + GDPR Article 17
   cascade activates.
2. **No `[AiDataClassificationAttribute]` analog** — no AI
   execution path exists in the shipped scaffold; bias-audit is a
   pure deterministic compliance ledger.
3. **No GDPR Article 17 cascade** — no persistence in-repo; the
   ledger is in-memory only. **Phase 2 per-tenant persistence WILL
   require** the FK-safe cascade pattern.
4. **No 2FA / no user authentication** — no users in the threat
   model; bias-audit Phase-1 is a single-machine offline CLI.
5. **No SQL guard layers** — no SQL anywhere.
6. **No Idempotency key** — the ledger is append-only at the API
   layer; the same Append call with identical inputs produces
   distinct rows (distinct AppendedAt timestamps). Production
   hosts MUST de-duplicate by composite (TenantID, AEDTSystemID,
   EntryType, AuditPeriodStart, AuditPeriodEnd) at the persistence
   layer.
7. **No money semantics in shipped scaffold** — no currency / value
   transfer; Phase 2 Stripe billing introduces these but they're
   not yet present.
8. **No env var reads** — `grep -rn "os.Getenv\|os.LookupEnv"`
   across `cmd/` + `internal/` returns 0 hits at M6.
9. **No HTTP listener / no HTTP client** — `grep -rn
   "net/http\|http.Get\|http.ListenAndServe"` across `cmd/` +
   `internal/` returns 0 hits at M6.
10. **No daemon mode** — `cmd/bias-audit` is a one-shot CLI; argv
    → output → exit. Phase-2 daemon mode activates R175 criterion
    3 boot-time R143 LOUD-ONCE-WARN.
11. **No counsel-reviewed legal bodies** — every legal footer is
    founder-drafted; ReviewedByCounsel = false honest baseline per
    R166.

## Out of scope

1. **MFA / per-user 2FA** — no users in Phase-1.
2. **GDPR DSAR endpoint** — no personal data shipped in Phase-1.
3. **R117 5-layer-defense** — no AI execution layer; no SQL; LLM
   not in the loop in the shipped surface.
4. **R118 deterministic-first-AI-last** — N/A in active shape (no
   AI surface at all in shipped scaffold).
5. **RUNBOOK.md** — pure library + offline CLI, no multi-vendor
   failure modes, no operator surface.
6. **R151 money-as-integer-or-decimal** — not yet load-bearing
   (no money in shipped scaffold); Phase-2 Stripe billing
   activates.
7. **Counsel review of founder-drafted legal bodies** — Phase-2+
   per R166 R145.B sibling-not-stacked branch event.

## Phase-1-refresh trigger

When **any of the following** lands, this SECURITY.md MUST be
refreshed before merging:

1. First HTTP listener (`http.ListenAndServe`) — Phase-2 HTTP API.
2. First DB persistence (`database/sql` or sqlite) — per-tenant
   audit-ledger.
3. First env-var read (`os.Getenv`) — tenant signing key load /
   Stripe API key / SES/SendGrid API key.
4. First counsel-signoff flip (`ReviewedByCounsel = true`) — on its
   own R145.B sibling-not-stacked branch with paired commit-message.
5. First money semantics — Phase-2 Stripe billing activates R151.
6. First candidate PII record cached anywhere — activates GDPR
   Article 17 + R146 DSAR + UK-PII categories.
7. First boot-time R143 LOUD-ONCE-WARN — Phase-2 daemon mode
   activates R175 criterion 3 full compliance.

## Escalation

Email: **david@vocala.co**. Out-of-bounds findings (KAT-1 hex
drift, Mirror-Mark format drift, annual-cadence guard bypass,
independent-auditor signoff slot bypass, R143 once-gate defeat,
R166 ReviewedByCounsel silent-flip, R150 manifest entry tampering)
should escalate to David directly; he is the sole maintainer at M6
baseline.
