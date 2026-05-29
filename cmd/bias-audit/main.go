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
//	evidence                 Export the audit ledger as a .evidence bundle
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
	"github.com/davly/bias-audit/internal/legal"
	"github.com/davly/bias-audit/internal/lore"
	"github.com/davly/bias-audit/internal/manifest"
	"github.com/davly/bias-audit/internal/mirrormark"
	"github.com/davly/limitless-evidence-bundle/pkg/evidence"
)

const version = "0.1.0-phase1-scaffold"

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: bias-audit <command> [flags]

Commands:
  advisories                  List the 5 canonical R143 honest advisories
  cadence-check               Report annual-cadence compliance (demo, in-memory)
  evidence                    Export the audit ledger as a regulator-readable
                              .evidence bundle (demo, in-memory)
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

Examples:
  bias-audit advisories
  bias-audit footer liability
  bias-audit kat1
  bias-audit cadence-check
  bias-audit evidence`)
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

	case "evidence":
		_ = fs.Parse(rest)
		if err := demoEvidenceExport(); err != nil {
			fmt.Fprintf(os.Stderr, "evidence export failed: %v\n", err)
			os.Exit(3)
		}

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
}

// demoEvidenceExport — illustrate the additive `.evidence`-bundle export
// path over a small in-memory ledger. bias-audit is the SECOND flagship
// consumer of the limitless-evidence-bundle SPEC v1 format (Folio was the
// first). The export is read-only over the ledger; production hosts will
// run it over a persistent backing store.
//
// Unlike demoCadenceCheck (which uses the zero/KAT corpus), this demo MUST
// use a NON-ZERO corpus — a `.evidence` bundle's whole value is that it
// cold-verifies, and ExportEvidenceSnapshot refuses a placeholder corpus
// (ErrEvidenceNoCorpus). We seed a deterministic non-zero corpus + key so
// the printed bundle re-verifies on any machine.
func demoEvidenceExport() error {
	// Deterministic non-zero demo corpus + key. NOT production secrets — the
	// loud `_NOT_FOR_PRODUCTION` token makes any leaked-to-prod use grep-loud.
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = 0xC4
	}
	key := []byte("iik_demo_BIAS_AUDIT_NOT_FOR_PRODUCTION")
	now := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)

	l := auditledger.New(corpus, key)

	annual := auditledger.Entry{
		TenantID:               "tenant_acme",
		AEDTSystemID:           "aedt_recruiter_v2",
		EntryType:              auditledger.EntryTypeNYCLL144AnnualAudit,
		AuditPeriodStart:       now.AddDate(-1, 0, 0),
		AuditPeriodEnd:         now,
		IndependentAuditorName: "Acme Independent Bias Auditors LLP",
		SignoffStatus:          auditledger.SignoffAttested,
		SignoffDate:            now,
		SummaryHash:            "demo_summary_hash",
		PublicPostingURL:       "https://acme.example/aedt-audit-2026.pdf",
	}
	if _, err := l.Append(annual, now); err != nil {
		return fmt.Errorf("append annual: %w", err)
	}

	conformity := auditledger.Entry{
		TenantID:               "tenant_acme",
		AEDTSystemID:           "aedt_recruiter_v2",
		EntryType:              auditledger.EntryTypeEUAIActConformityAssessment,
		AuditPeriodStart:       now.AddDate(0, -2, 0),
		AuditPeriodEnd:         now,
		IndependentAuditorName: "EU Notified Body 1234",
		SignoffStatus:          auditledger.SignoffPending,
		SummaryHash:            "demo_conformity_hash",
	}
	if _, err := l.Append(conformity, now); err != nil {
		return fmt.Errorf("append conformity: %w", err)
	}

	export, err := l.ExportEvidenceSnapshot(auditledger.EvidenceScope{}, now)
	if err != nil {
		return err
	}

	// Independent cold-verify via the evidence-bundle repo's OWN full chain
	// (KAT-1 + content-hash + Mirror-Mark) — exactly what a regulator runs.
	res := evidence.Verify(export.Bundle, evidence.ModeFull, export.PayloadBytes, key)

	fmt.Println("bias-audit .evidence-bundle export demo (SPEC v1 consumer #2)")
	fmt.Println()
	fmt.Printf("Ledger length:  %d entries\n", l.Len())
	fmt.Printf("Bundle bytes:   %d\n", len(export.Bundle))
	fmt.Printf("Payload bytes:  %d\n", len(export.PayloadBytes))
	fmt.Printf("Verify class:   %s (verdict=%s exit=%d)\n", res.Class, res.Verdict, res.ExitCode)
	fmt.Printf("  KAT-1:        %v\n", res.KAT1Verified)
	fmt.Printf("  content-hash: %v\n", res.ContentHashVerified)
	fmt.Printf("  Mirror-Mark:  %v\n", res.MirrorMarkVerified)
	if res.Class != "PASS" {
		return fmt.Errorf("self full-verify did not PASS: class=%s verdict=%s failures=%v", res.Class, res.Verdict, res.Failures)
	}
	fmt.Println()
	fmt.Println("---BEGIN .evidence BUNDLE---")
	fmt.Print(string(export.Bundle))
	if len(export.Bundle) > 0 && export.Bundle[len(export.Bundle)-1] != '\n' {
		fmt.Println()
	}
	fmt.Println("---END .evidence BUNDLE---")
	fmt.Println()
	fmt.Println("PASS: bias-audit emitted a cold-verifiable .evidence bundle and the")
	fmt.Println("      evidence-bundle repo's own ModeFull verifier accepts it.")
	return nil
}
