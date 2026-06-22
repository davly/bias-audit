// Command bias-audit — SaaS productisation of NYC LL144 AEDT + EU AI
// Act HR-bias-audit + annual independent audit ledger CLI.
//
// Where canopy (cohort sibling) is the single-tenant offline-CLI
// reference for the R74 EEOC + NYC LL144 dual-gate, bias-audit is the
// multi-tenant managed annual-audit ledger + candidate-notice + public-
// posting orchestration plane. Phase-1 ships the in-process append-only
// ledger CLI; Phase-2+ ships the HTTP API + per-tenant persistence +
// independent-auditor signoff workflow.
//
// Subcommands:
//
//	advisories               List the 5 canonical R143 honest advisories
//	cadence-check            Report annual-cadence compliance per tenant×AEDT
//	eeoc-impact              Compute a first-party EEOC four-fifths impact entry
//	footer                   Print a named legal footer body
//	manifest                 Print R150 manifest entries
//	kat1                     Print KAT-1 cohort hex + OpenSSL recipe
//	version                  Print bias-audit version
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/davly/bias-audit/internal/auditledger"
	"github.com/davly/bias-audit/internal/honest"
	"github.com/davly/bias-audit/internal/impact"
	"github.com/davly/bias-audit/internal/legal"
	"github.com/davly/bias-audit/internal/lore"
	"github.com/davly/bias-audit/internal/manifest"
	"github.com/davly/bias-audit/internal/mirrormark"
	"github.com/davly/bias-audit/internal/stele"
)

const version = "0.1.0-phase1-scaffold"

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: bias-audit <command> [flags]

Commands:
  advisories                  List the 5 canonical R143 honest advisories
  cadence-check               Report annual-cadence compliance (demo, in-memory)
  eeoc-impact                 Compute a first-party EEOC four-fifths impact entry (demo, in-memory)
  footer <kind>               Print a named legal footer body
                              kind ∈ {liability, candidate-notice, terms-of-use}
  manifest                    Print R150 manifest entries
  kat1                        Print KAT-1 cohort hex + OpenSSL one-liner
  version                     Print bias-audit version
  help                        Print this help

R153.A R-REGULATORY-ESCAPE-INVARIANT-WITH-AUDIT-LEDGER:
  bias-audit is the canonical 3rd saturator. The audit-ledger primitive
  in internal/auditledger ships annual-cadence + independent-auditor
  signoff + Mirror-Mark-stamped append-only rows.

R166 founder-drafted legal-document cohort: bias-audit's legal package
  ships ReviewedByCounsel = false honest-default. Flipping requires its
  own R145.B sibling-not-stacked branch with named counsel signoff.

Stele spine anchoring (opt-in, off by default):
  Set BIASAUDIT_STELE_URL (e.g. http://localhost:8097) to anchor each
  ledger-writing command's run into the Stele verified-trust spine.
  The ledger must pass its own SelfCheck first; a requested anchor
  that fails (self-check, network, non-201) prints to stderr and
  exits non-zero. Unset/empty = disabled: no network, no new output.

Examples:
  bias-audit advisories
  bias-audit footer liability
  bias-audit kat1
  bias-audit cadence-check`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	rest := os.Args[2:]

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)

	switch cmd {
	case "version", "--version", "-V":
		fmt.Printf("bias-audit %s\n", version)

	case "advisories":
		_ = fs.Parse(rest)
		advisories := honest.CanonicalAdvisories()
		fmt.Printf("bias-audit canonical R143 advisories (%d):\n\n", len(advisories))
		for _, a := range advisories {
			fmt.Printf("  [%s] %s\n", a.Severity, a.Code)
			fmt.Printf("      %s\n", a.Message)
			fmt.Printf("      (see %s)\n\n", a.DocLink)
		}

	case "cadence-check":
		_ = fs.Parse(rest)
		demoCadenceCheck()

	case "eeoc-impact":
		_ = fs.Parse(rest)
		demoEEOCImpact()

	case "footer":
		_ = fs.Parse(rest)
		args := fs.Args()
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "error: 'footer' requires a kind: liability | candidate-notice | terms-of-use")
			os.Exit(2)
		}
		switch args[0] {
		case "liability":
			fmt.Println(legal.LegalLiabilityFooter)
		case "candidate-notice":
			fmt.Println(legal.CandidateNoticeFooter)
		case "terms-of-use":
			fmt.Println(legal.TermsOfUseFooter)
		default:
			fmt.Fprintf(os.Stderr, "error: unknown footer kind %q (want liability | candidate-notice | terms-of-use)\n", args[0])
			os.Exit(2)
		}

	case "manifest":
		_ = fs.Parse(rest)
		m := manifest.Seed()
		fmt.Printf("bias-audit R150 manifest (%d entries):\n\n", len(m))
		for _, e := range m {
			counselMark := "[founder-draft]"
			if e.ReviewedByCounsel {
				counselMark = "[counsel-reviewed]"
			}
			fmt.Printf("  %s  %s\n", counselMark, e.Key)
			fmt.Printf("      jurisdiction: %s\n", e.Jurisdiction)
			fmt.Printf("      source:       %s\n", e.Source)
			fmt.Printf("      reviewer:     %s\n", e.ReviewerClass)
			fmt.Printf("      fresh-at:     %s\n\n", e.FreshAt.Format("2006-01-02"))
		}

	case "kat1":
		_ = fs.Parse(rest)
		fmt.Println("bias-audit KAT-1 cohort firewall pin (R151)")
		fmt.Println()
		fmt.Printf("  Cohort canonical hex (HMAC-SHA256 of 0x01||32×0x00 with empty key):\n")
		fmt.Printf("    %s\n\n", lore.Digest)
		fmt.Printf("  Recomputed here on this machine via Go crypto/hmac:\n")
		fmt.Printf("    %s\n\n", lore.Compute())
		if lore.Digest != lore.Compute() {
			fmt.Fprintln(os.Stderr, "R151 FIREWALL DRIFT: cohort hex != recomputed hex")
			os.Exit(3)
		}
		fmt.Println("  Cold-verify via OpenSSL (no Go toolchain required):")
		fmt.Println(`    printf '\x01' > /tmp/kat1.bin`)
		fmt.Print(`    printf '\x00`)
		fmt.Print("%")
		fmt.Println(`.0s' {1..32} >> /tmp/kat1.bin`)
		fmt.Println(`    openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin`)
		fmt.Println()
		fmt.Println("  PASS: bias-audit KAT-1 matches cohort canonical hex.")

	case "--help", "-h", "help":
		usage()

	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}
}

// demoCadenceCheck — illustrate the annual-cadence compliance report
// over a small in-memory ledger. Production hosts will replace the
// in-memory ledger with a persistent backing store.
func demoCadenceCheck() {
	var corpus [sha256.Size]byte
	l := auditledger.New(corpus, []byte{})
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)

	// Tenant alpha: ships a recent annual audit.
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
		fmt.Fprintf(os.Stderr, "demo Append recent: %v\n", err)
		os.Exit(3)
	}

	// Tenant beta: has only a non-NYC-LL144 EU AI Act conformity entry.
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
		fmt.Fprintf(os.Stderr, "demo Append conformity: %v\n", err)
		os.Exit(3)
	}

	covered, uncovered := l.AnnualCadenceCompliance(now)
	fmt.Printf("R153.A REGULATORY-ESCAPE-INVARIANT-WITH-AUDIT-LEDGER demo\n\n")
	fmt.Printf("Ledger length: %d entries\n\n", l.Len())
	fmt.Printf("Tenant×AEDT pairs WITH recent NYC LL144 annual audit (≤365d):\n")
	if len(covered) == 0 {
		fmt.Println("  (none)")
	}
	for _, p := range covered {
		fmt.Printf("  + %s / %s\n", p.TenantID, p.AEDTSystemID)
	}
	fmt.Println()
	fmt.Printf("Tenant×AEDT pairs MISSING recent NYC LL144 annual audit (honest delinquency):\n")
	if len(uncovered) == 0 {
		fmt.Println("  (none)")
	}
	for _, p := range uncovered {
		fmt.Printf("  - %s / %s\n", p.TenantID, p.AEDTSystemID)
	}
	fmt.Println()
	fmt.Println("Each ledger row is stamped with a cohort Mirror-Mark; verify via VerifyEntry().")

	// Demonstrate Mirror-Mark roundtrip on the first entry.
	for _, e := range l.All() {
		if err := mirrormark.Verify(e.Mark, corpus, auditledger.CanonicalPayload(e), []byte{}); err != nil {
			fmt.Fprintf(os.Stderr, "Mirror-Mark verify drift on %s: %v\n", e.TenantID, err)
			os.Exit(3)
		}
	}
	fmt.Println("Mirror-Mark verify: PASS for all ledger entries.")

	maybeAnchorToStele(l, "cadence-check")
}

// demoEEOCImpact — illustrate the first-party EEOC four-fifths
// adverse-impact producer. Before this wiring the
// EntryTypeEEOCFourFifthsImpact ledger row had NO producer: the
// SummaryHash could only ever be an opaque externally-computed CSV
// hash. Now bias-audit computes the AIR + per-group Wilson intervals
// in-process (delegating the math to reality/fairness) and derives the
// SummaryHash from those self-produced numbers, so the EEOC entry is
// self-reproducible by a regulator who reruns the raw counts.
//
// The Entry deliberately sets every field Append requires for a
// non-NYC-LL144 row: non-empty TenantID + AEDTSystemID and a
// non-inverted audit period (AuditPeriodStart < AuditPeriodEnd). EEOC
// entries use SignoffNonApplicable — the four-fifths rule is
// computational, not adjudicative — so no SignoffDate/auditor is
// required.
func demoEEOCImpact() {
	var corpus [sha256.Size]byte
	l := auditledger.New(corpus, []byte{})
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)

	// Raw protected-class selection counts for one selection procedure.
	// A disparate-impact example: group_a selects at 30% vs group_b at
	// 50% → AIR 0.60 < 0.80 → four-fifths FAILS.
	counts := []impact.GroupCount{
		{Label: "group_a", Selected: 30, Total: 100},
		{Label: "group_b", Selected: 50, Total: 100},
	}
	rep := impact.Compute(counts)

	fmt.Printf("EEOC 29 C.F.R. § 1607 four-fifths impact (first-party producer)\n\n")
	fmt.Printf("Adverse-Impact Ratio (AIR): %.4f  (%s vs %s)\n",
		rep.AIR, rep.MinLabel, rep.MaxLabel)
	fmt.Printf("Four-fifths pass (AIR >= 0.80): %t\n", rep.Pass)
	fmt.Printf("Applicable: %t\n\n", rep.Applicable)
	fmt.Printf("Per-group selection rates (95%% Wilson score interval):\n")
	for _, g := range rep.Groups {
		fmt.Printf("  %s: %d/%d = %.4f  CI [%.4f, %.4f]\n",
			g.Label, g.Selected, g.Total, g.SelectionRate, g.CILow, g.CIHigh)
	}
	fmt.Printf("\nSelf-derived SummaryHash (SHA-256 of canonical impact CSV):\n  %s\n\n", rep.Hash)

	// Append the EEOC entry. The SummaryHash is now derived in-process
	// from numbers bias-audit itself computed — not an opaque off-system
	// digest. Concern #1 from the adversarial review: Append requires a
	// non-empty TenantID + AEDTSystemID and a non-inverted audit period.
	e := auditledger.Entry{
		TenantID:               "tenant_alpha",
		AEDTSystemID:           "aedt_recruiter_v2",
		EntryType:              auditledger.EntryTypeEEOCFourFifthsImpact,
		AuditPeriodStart:       now.AddDate(0, -3, 0),
		AuditPeriodEnd:         now,
		IndependentAuditorName: "Acme Compliance Contact",
		SignoffStatus:          auditledger.SignoffNonApplicable,
		SummaryHash:            rep.Hash,
	}
	stamped, err := l.Append(e, now)
	if err != nil {
		fmt.Fprintf(os.Stderr, "demo Append EEOC impact: %v\n", err)
		os.Exit(3)
	}

	fmt.Printf("Appended EEOC four-fifths ledger row:\n")
	fmt.Printf("  type:    %s\n", stamped.EntryType)
	fmt.Printf("  signoff: %s\n", stamped.SignoffStatus)
	fmt.Printf("  summary: %s\n", stamped.SummaryHash)
	fmt.Printf("  mark:    %s\n\n", stamped.Mark)

	if err := mirrormark.Verify(stamped.Mark, corpus,
		auditledger.CanonicalPayload(stamped), []byte{}); err != nil {
		fmt.Fprintf(os.Stderr, "Mirror-Mark verify drift on EEOC entry: %v\n", err)
		os.Exit(3)
	}
	fmt.Println("Mirror-Mark verify: PASS. The four-fifths entry's summary is self-reproducible.")

	maybeAnchorToStele(l, "eeoc-impact")
}

// maybeAnchorToStele anchors the command's audit ledger into the
// Stele spine when BIASAUDIT_STELE_URL is set. Unset/empty =
// disabled: no self-check, no HTTP, no output — behavior identical
// to a non-anchoring run. This is bias-audit's ONLY env read (R145.B
// stele-anchor confinement pin in internal/firewall/).
//
// Honesty rules (load-bearing):
//   - the sealed line prints ONLY after the spine returned
//     201 + entry_hash (stele.AnchorRun enforces this);
//   - a requested anchor that fails — ledger self-check, network,
//     non-201 — prints to stderr and exits non-zero, so a missing
//     anchor can never look like success.
func maybeAnchorToStele(ledger *auditledger.Ledger, command string) {
	rcpt, anchored, err := stele.AnchorRun(os.Getenv(stele.EnvURL), command, ledger, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(os.Stderr, "stele anchor FAILED (%s set, anchor requested but NOT sealed): %v\n", stele.EnvURL, err)
		os.Exit(1)
	}
	if !anchored {
		return
	}
	fmt.Printf("stele anchor: sealed seq=%d entry_hash=%s\n", rcpt.Seq, rcpt.EntryHash)
}
