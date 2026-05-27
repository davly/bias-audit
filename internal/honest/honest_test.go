package honest

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

// TestLoudOncePrefix_PinnedAtCohortLiteral — canonical literal pin.
func TestLoudOncePrefix_PinnedAtCohortLiteral(t *testing.T) {
	const expected = "[LOUD-ONCE-WARNING]"
	if LoudOncePrefix != expected {
		t.Fatalf("LoudOncePrefix drift: got %q, want %q", LoudOncePrefix, expected)
	}
}

// TestLoudOnce_EmitsOnFirstCall — first call emits.
func TestLoudOnce_EmitsOnFirstCall(t *testing.T) {
	Reset()
	var buf bytes.Buffer
	adv := Advisory{
		Code:     "TEST_FIRST_CALL",
		Severity: SeverityInfo,
		Message:  "first emit",
		DocLink:  "test.md",
	}
	LoudOnce(adv, &buf)
	out := buf.String()
	if !strings.Contains(out, LoudOncePrefix) {
		t.Errorf("output missing LoudOncePrefix: %q", out)
	}
	if !strings.Contains(out, "TEST_FIRST_CALL") {
		t.Errorf("output missing Code: %q", out)
	}
	if !strings.Contains(out, "first emit") {
		t.Errorf("output missing Message: %q", out)
	}
	if !strings.Contains(out, "test.md") {
		t.Errorf("output missing DocLink: %q", out)
	}
}

// TestLoudOnce_SilentOnSubsequentCalls — once-gated.
func TestLoudOnce_SilentOnSubsequentCalls(t *testing.T) {
	Reset()
	var buf bytes.Buffer
	adv := Advisory{
		Code:     "TEST_ONCE_GATE",
		Severity: SeverityInfo,
		Message:  "once-gated",
		DocLink:  "test.md",
	}
	LoudOnce(adv, &buf)
	if buf.Len() == 0 {
		t.Fatal("first LoudOnce emitted nothing")
	}
	buf.Reset()
	LoudOnce(adv, &buf)
	LoudOnce(adv, &buf)
	LoudOnce(adv, &buf)
	if buf.Len() != 0 {
		t.Fatalf("subsequent LoudOnce calls leaked output: %q", buf.String())
	}
}

// TestLoudOnce_DistinctCodesEmitIndependently — separate gates.
func TestLoudOnce_DistinctCodesEmitIndependently(t *testing.T) {
	Reset()
	var buf bytes.Buffer
	for _, code := range []string{"CODE_A", "CODE_B", "CODE_C"} {
		LoudOnce(Advisory{
			Code:     code,
			Severity: SeverityInfo,
			Message:  "msg " + code,
			DocLink:  "doc.md",
		}, &buf)
	}
	out := buf.String()
	for _, code := range []string{"CODE_A", "CODE_B", "CODE_C"} {
		if !strings.Contains(out, code) {
			t.Errorf("output missing Code %q: %q", code, out)
		}
	}
}

// TestLoudOnce_GoroutineSafe — concurrent calls = exactly one emit.
func TestLoudOnce_GoroutineSafe(t *testing.T) {
	Reset()
	var buf bytes.Buffer
	var mu sync.Mutex
	guarded := &syncedWriter{buf: &buf, mu: &mu}
	adv := Advisory{
		Code:     "CONCURRENT",
		Severity: SeverityInfo,
		Message:  "concurrent emit",
		DocLink:  "test.md",
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			LoudOnce(adv, guarded)
		}()
	}
	wg.Wait()
	count := strings.Count(buf.String(), LoudOncePrefix)
	if count != 1 {
		t.Fatalf("concurrent LoudOnce emitted %d times, want 1", count)
	}
}

type syncedWriter struct {
	buf *bytes.Buffer
	mu  *sync.Mutex
}

func (w *syncedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

// TestCanonicalAdvisories_Count — pin 5-advisory count.
func TestCanonicalAdvisories_Count(t *testing.T) {
	const expected = 5
	got := len(CanonicalAdvisories())
	if got != expected {
		t.Fatalf("CanonicalAdvisories count: got %d, want %d", got, expected)
	}
}

// TestCanonicalAdvisories_AllFieldsNonEmpty — non-empty fields.
func TestCanonicalAdvisories_AllFieldsNonEmpty(t *testing.T) {
	for i, a := range CanonicalAdvisories() {
		if a.Code == "" {
			t.Errorf("advisory %d: empty Code", i)
		}
		if a.Severity == "" {
			t.Errorf("advisory %d (%q): empty Severity", i, a.Code)
		}
		if a.Message == "" {
			t.Errorf("advisory %d (%q): empty Message", i, a.Code)
		}
		if a.DocLink == "" {
			t.Errorf("advisory %d (%q): empty DocLink", i, a.Code)
		}
	}
}

// TestCanonicalAdvisories_UniqueCodes — unique Codes.
func TestCanonicalAdvisories_UniqueCodes(t *testing.T) {
	seen := map[string]int{}
	for i, a := range CanonicalAdvisories() {
		if prev, ok := seen[a.Code]; ok {
			t.Errorf("Duplicate Code %q at indices %d and %d", a.Code, prev, i)
		}
		seen[a.Code] = i
	}
}

// TestCanonicalAdvisories_AllSeveritiesCanonical — canonical severities.
func TestCanonicalAdvisories_AllSeveritiesCanonical(t *testing.T) {
	allowed := map[Severity]bool{SeverityInfo: true, SeverityWarn: true, SeverityError: true}
	for i, a := range CanonicalAdvisories() {
		if !allowed[a.Severity] {
			t.Errorf("advisory %d (%q): non-canonical Severity %q", i, a.Code, a.Severity)
		}
	}
}

// TestFindAdvisory_ByCanonicalCode — every code retrievable.
func TestFindAdvisory_ByCanonicalCode(t *testing.T) {
	for _, expected := range CanonicalAdvisories() {
		got, ok := FindAdvisory(expected.Code)
		if !ok {
			t.Errorf("FindAdvisory(%q): not found", expected.Code)
			continue
		}
		if got.Code != expected.Code || got.Message != expected.Message {
			t.Errorf("FindAdvisory(%q): drift", expected.Code)
		}
	}
}

// TestFindAdvisory_UnknownCode — unknown returns false.
func TestFindAdvisory_UnknownCode(t *testing.T) {
	_, ok := FindAdvisory("DOES_NOT_EXIST_999")
	if ok {
		t.Fatal("FindAdvisory(unknown): ok=true")
	}
}

// TestReset_ClearsRegistry — Reset re-emits.
func TestReset_ClearsRegistry(t *testing.T) {
	Reset()
	var buf bytes.Buffer
	adv := Advisory{Code: "RESET_TEST", Severity: SeverityInfo, Message: "msg", DocLink: "d"}
	LoudOnce(adv, &buf)
	first := buf.String()
	buf.Reset()
	LoudOnce(adv, &buf)
	if buf.Len() != 0 {
		t.Fatal("expected silent on second call before Reset")
	}
	Reset()
	LoudOnce(adv, &buf)
	if buf.String() != first {
		t.Errorf("post-Reset emission drift:\n  got:  %q\n  want: %q", buf.String(), first)
	}
}

// TestLoudOnce_EmissionShape — canonical emission shape.
func TestLoudOnce_EmissionShape(t *testing.T) {
	Reset()
	var buf bytes.Buffer
	adv := Advisory{
		Code:     "SHAPE_TEST",
		Severity: SeverityWarn,
		Message:  "shape body",
		DocLink:  "shape.md",
	}
	LoudOnce(adv, &buf)
	expected := "[LOUD-ONCE-WARNING] WARN SHAPE_TEST: shape body (see shape.md)\n"
	if buf.String() != expected {
		t.Fatalf("emission shape drift:\n  got:  %q\n  want: %q", buf.String(), expected)
	}
}

// TestCanonicalAdvisories_EEOCRegulatedRoleAtError — R153 strict-liability.
func TestCanonicalAdvisories_EEOCRegulatedRoleAtError(t *testing.T) {
	got, ok := FindAdvisory("EEOC_REGULATED_ROLE_ESCAPE_INVARIANT")
	if !ok {
		t.Fatal("EEOC_REGULATED_ROLE_ESCAPE_INVARIANT missing")
	}
	if got.Severity != SeverityError {
		t.Errorf("EEOC_REGULATED_ROLE_ESCAPE_INVARIANT severity: got %q, want Error", got.Severity)
	}
}

// TestCanonicalAdvisories_NYCLL144AtWarn — R153.A cadence advisory.
func TestCanonicalAdvisories_NYCLL144AtWarn(t *testing.T) {
	got, ok := FindAdvisory("NYC_LL144_AEDT_BIAS_AUDIT_REQUIRED")
	if !ok {
		t.Fatal("NYC_LL144_AEDT_BIAS_AUDIT_REQUIRED missing")
	}
	if got.Severity != SeverityWarn {
		t.Errorf("NYC_LL144_AEDT_BIAS_AUDIT_REQUIRED severity: got %q, want Warn", got.Severity)
	}
}

// TestCanonicalAdvisories_IndependentAuditorAtError — R153 strict-liability.
func TestCanonicalAdvisories_IndependentAuditorAtError(t *testing.T) {
	got, ok := FindAdvisory("BIAS_AUDIT_INDEPENDENT_AUDITOR_REQUIRED")
	if !ok {
		t.Fatal("BIAS_AUDIT_INDEPENDENT_AUDITOR_REQUIRED missing")
	}
	if got.Severity != SeverityError {
		t.Errorf("BIAS_AUDIT_INDEPENDENT_AUDITOR_REQUIRED severity: got %q, want Error", got.Severity)
	}
}

// TestCanonicalAdvisories_CandidateNoticeAtWarn — R153 cadence advisory.
func TestCanonicalAdvisories_CandidateNoticeAtWarn(t *testing.T) {
	got, ok := FindAdvisory("BIAS_AUDIT_CANDIDATE_NOTICE_10_BUSINESS_DAYS")
	if !ok {
		t.Fatal("BIAS_AUDIT_CANDIDATE_NOTICE_10_BUSINESS_DAYS missing")
	}
	if got.Severity != SeverityWarn {
		t.Errorf("BIAS_AUDIT_CANDIDATE_NOTICE_10_BUSINESS_DAYS severity: got %q, want Warn", got.Severity)
	}
}

// TestCanonicalAdvisories_PublicPostingAtWarn — R153 cadence advisory.
func TestCanonicalAdvisories_PublicPostingAtWarn(t *testing.T) {
	got, ok := FindAdvisory("BIAS_AUDIT_PUBLIC_POSTING_REQUIRED")
	if !ok {
		t.Fatal("BIAS_AUDIT_PUBLIC_POSTING_REQUIRED missing")
	}
	if got.Severity != SeverityWarn {
		t.Errorf("BIAS_AUDIT_PUBLIC_POSTING_REQUIRED severity: got %q, want Warn", got.Severity)
	}
}

// TestCanonicalAdvisories_SeverityLadderPopulated — R143.A 3-tier ladder.
//
// R143.A REQUIRES the canonical advisory set populate both Error AND
// Warn severities. Info is optional. This test pins bias-audit at 3
// Error severities + 3 Warn severities → wait, that's wrong, double-check:
// EEOC=Error, IndependentAuditor=Error, NYCLL144/CandidateNotice/PublicPosting=Warn.
// So 2 Error + 3 Warn. The pin asserts both tiers populated.
func TestCanonicalAdvisories_SeverityLadderPopulated(t *testing.T) {
	hasError, hasWarn := false, false
	for _, a := range CanonicalAdvisories() {
		switch a.Severity {
		case SeverityError:
			hasError = true
		case SeverityWarn:
			hasWarn = true
		}
	}
	if !hasError {
		t.Error("Severity ladder missing Error tier — R143.A regulator-strict-liability surface absent")
	}
	if !hasWarn {
		t.Error("Severity ladder missing Warn tier — R143.A cadence-advisory surface absent")
	}
}
