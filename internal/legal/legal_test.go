package legal

import (
	"strings"
	"testing"
)

// TestReviewedByCounsel_HonestDefaultFalse — R166 honest-default sentinel.
//
// Flipping this to true is a behaviour-changing event that MUST land on
// its own R145.B sibling-not-stacked branch with a named counsel
// signoff in the commit message. Any sweep agent flipping this in a
// feature commit is in R166 antipattern (3) violation.
func TestReviewedByCounsel_HonestDefaultFalse(t *testing.T) {
	if ReviewedByCounsel {
		t.Fatalf("R166 honest-default drift: ReviewedByCounsel = %v, want false (honest baseline)", ReviewedByCounsel)
	}
}

// TestLegalDocumentVersion_PinnedAtV1 — version literal pin.
func TestLegalDocumentVersion_PinnedAtV1(t *testing.T) {
	const expected = "v1"
	if LegalDocumentVersion != expected {
		t.Fatalf("LegalDocumentVersion drift: got %q, want %q", LegalDocumentVersion, expected)
	}
}

// TestEffectiveDate_ISO8601Shape — date literal sanity.
func TestEffectiveDate_ISO8601Shape(t *testing.T) {
	if len(EffectiveDate) != 10 {
		t.Fatalf("EffectiveDate length: got %d, want 10 (ISO 8601 YYYY-MM-DD)", len(EffectiveDate))
	}
	if EffectiveDate[4] != '-' || EffectiveDate[7] != '-' {
		t.Fatalf("EffectiveDate shape: got %q, want YYYY-MM-DD", EffectiveDate)
	}
}

// TestLegalLiabilityFooter_NamesNYCLL144 — regulator-citation pin.
func TestLegalLiabilityFooter_NamesNYCLL144(t *testing.T) {
	if !strings.Contains(LegalLiabilityFooter, "NYC Local Law 144") {
		t.Errorf("LegalLiabilityFooter missing NYC LL144 citation")
	}
	if !strings.Contains(LegalLiabilityFooter, "§ 20-871") {
		t.Errorf("LegalLiabilityFooter missing § 20-871 citation")
	}
	if !strings.Contains(LegalLiabilityFooter, "2023-07-05") {
		t.Errorf("LegalLiabilityFooter missing NYC LL144 effective date 2023-07-05")
	}
}

// TestLegalLiabilityFooter_NamesEUAIAct — second-regulator citation pin.
func TestLegalLiabilityFooter_NamesEUAIAct(t *testing.T) {
	if !strings.Contains(LegalLiabilityFooter, "EU AI Act 2024/1689") {
		t.Errorf("LegalLiabilityFooter missing EU AI Act 2024/1689 citation")
	}
	if !strings.Contains(LegalLiabilityFooter, "Annex III") {
		t.Errorf("LegalLiabilityFooter missing Annex III citation")
	}
}

// TestLegalLiabilityFooter_NamesEEOC — third-regulator citation pin.
func TestLegalLiabilityFooter_NamesEEOC(t *testing.T) {
	if !strings.Contains(LegalLiabilityFooter, "EEOC 29 C.F.R. § 1607") {
		t.Errorf("LegalLiabilityFooter missing EEOC 29 C.F.R. § 1607 citation")
	}
}

// TestLegalLiabilityFooter_LibraryRecommendsHostActs — cohort literal.
func TestLegalLiabilityFooter_LibraryRecommendsHostActs(t *testing.T) {
	if !strings.Contains(LegalLiabilityFooter, "LIBRARY-RECOMMENDS-HOST-ACTS") {
		t.Errorf("LegalLiabilityFooter missing LIBRARY-RECOMMENDS-HOST-ACTS cohort literal")
	}
}

// TestCandidateNoticeFooter_NamesTenBusinessDays — NYC LL144 § 20-871(b).
func TestCandidateNoticeFooter_NamesTenBusinessDays(t *testing.T) {
	if !strings.Contains(CandidateNoticeFooter, "10 business days") {
		t.Errorf("CandidateNoticeFooter missing 10 business days requirement")
	}
	if !strings.Contains(CandidateNoticeFooter, "§ 20-871(b)") {
		t.Errorf("CandidateNoticeFooter missing § 20-871(b) section citation")
	}
}

// TestCandidateNoticeFooter_NamesPublicPosting — NYC LL144 § 20-871(c).
func TestCandidateNoticeFooter_NamesPublicPosting(t *testing.T) {
	if !strings.Contains(CandidateNoticeFooter, "publicly post") {
		t.Errorf("CandidateNoticeFooter missing public posting requirement")
	}
	if !strings.Contains(CandidateNoticeFooter, "§ 20-871(c)") {
		t.Errorf("CandidateNoticeFooter missing § 20-871(c) section citation")
	}
}

// TestTermsOfUseFooter_NamesFounderDraft — honest-default disclosure.
func TestTermsOfUseFooter_NamesFounderDraft(t *testing.T) {
	if !strings.Contains(TermsOfUseFooter, "Founder Draft") {
		t.Errorf("TermsOfUseFooter missing Founder Draft disclosure")
	}
	if !strings.Contains(TermsOfUseFooter, "ReviewedByCounsel = false") {
		t.Errorf("TermsOfUseFooter missing ReviewedByCounsel = false honest baseline")
	}
}

// TestAllFootersNonEmpty — sanity sweep.
func TestAllFootersNonEmpty(t *testing.T) {
	footers := map[string]string{
		"LegalLiabilityFooter":  LegalLiabilityFooter,
		"CandidateNoticeFooter": CandidateNoticeFooter,
		"TermsOfUseFooter":      TermsOfUseFooter,
	}
	for name, body := range footers {
		if body == "" {
			t.Errorf("%s: empty body", name)
		}
		if len(body) < 200 {
			t.Errorf("%s: body length %d below 200-byte sanity floor", name, len(body))
		}
	}
}
