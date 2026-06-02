package mcpserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/davly/bias-audit/internal/auditledger"
	"github.com/davly/bias-audit/internal/legal"
	"github.com/davly/bias-audit/internal/mirrormark"
)

const (
	testToken  = "svc-tok-7c9f"
	testTenant = "user_acme_42"
)

// fixedNow gives every test a deterministic clock.
func fixedNow() time.Time { return time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC) }

// nonZeroCorpusKey returns a deterministic non-zero corpus + key so emitted
// Mirror-Marks are production-shaped (and re-verify) rather than dev/KAT.
func nonZeroCorpusKey() ([sha256.Size]byte, []byte) {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = 0xC4
	}
	return corpus, []byte("iik_test_BIAS_AUDIT_NOT_FOR_PRODUCTION")
}

// newTestServer builds a configured (token set, non-zero signer) server.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	corpus, key := nonZeroCorpusKey()
	return New(Config{
		ServiceToken: testToken,
		Corpus:       corpus,
		Key:          key,
		Now:          fixedNow,
	}, io.Discard)
}

// do issues a request through the full Handler (gate + router) and returns the
// recorder.
func do(t *testing.T, s *Server, method, path, token, userID, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if token != "" {
		req.Header.Set(headerServiceToken, token)
	}
	if userID != "" {
		req.Header.Set(headerUserID, userID)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// decodeEnvelope unwraps an executionEnvelope from a 200 tool response.
func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder) (content json.RawMessage, isError bool, errMsg string) {
	t.Helper()
	var env struct {
		Content      json.RawMessage `json:"content"`
		IsError      bool            `json:"is_error"`
		ErrorMessage string          `json:"error_message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v (body=%s)", err, rec.Body.String())
	}
	return env.Content, env.IsError, env.ErrorMessage
}

// ---------------------------------------------------------------------------
// REACHABILITY — the surface answers from a cookieless, service-token-only
// caller (exactly how Nexus calls). No 302/redirect, no auth-cookie path.
// ---------------------------------------------------------------------------

func TestManifest_ReachableWithToken(t *testing.T) {
	s := newTestServer(t)
	rec := do(t, s, http.MethodGet, "/mcp/tools/", testToken, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("manifest: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var env struct {
		Tools []struct {
			Name             string `json:"name"`
			ApprovalRequired bool   `json:"approval_required"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	// The TOP capability must be present and approval-gated.
	var foundTop, foundCadence, foundFooter bool
	for _, tl := range env.Tools {
		switch tl.Name {
		case ToolComplianceAuditLedger:
			foundTop = true
			if !tl.ApprovalRequired {
				t.Errorf("%s must be approval_required (it mutates a regulatory record)", ToolComplianceAuditLedger)
			}
		case ToolCadenceReport:
			foundCadence = true
		case ToolGetLegalFooter:
			foundFooter = true
		}
	}
	if !foundTop || !foundCadence || !foundFooter {
		t.Fatalf("manifest missing tools: top=%v cadence=%v footer=%v", foundTop, foundCadence, foundFooter)
	}
}

func TestInvoke_ReachableWithTokenAndProvenance(t *testing.T) {
	s := newTestServer(t)
	rec := do(t, s, http.MethodPost, "/mcp/tools/"+ToolCadenceReport, testToken, testTenant, "{}")
	if rec.Code != http.StatusOK {
		t.Fatalf("cadence invoke: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	_, isErr, msg := decodeEnvelope(t, rec)
	if isErr {
		t.Fatalf("cadence invoke unexpectedly is_error: %s", msg)
	}
}

// ---------------------------------------------------------------------------
// STEP-1.5 — FAIL-CLOSED service-token gate. The load-bearing case: an UNSET
// token env returns 401 for EVERYTHING, even with a token header present.
// ---------------------------------------------------------------------------

func TestGate_UnsetTokenFailsClosed_Manifest(t *testing.T) {
	// Server constructed with an EMPTY service token (env unset).
	corpus, key := nonZeroCorpusKey()
	s := New(Config{ServiceToken: "", Corpus: corpus, Key: key, Now: fixedNow}, io.Discard)

	// Even WITH a token header, an unconfigured server must 401 (never fail open).
	rec := do(t, s, http.MethodGet, "/mcp/tools/", "any-token-the-caller-sends", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unset-token manifest: want 401 (fail closed), got %d", rec.Code)
	}
}

func TestGate_UnsetTokenFailsClosed_Invoke(t *testing.T) {
	corpus, key := nonZeroCorpusKey()
	s := New(Config{ServiceToken: "", Corpus: corpus, Key: key, Now: fixedNow}, io.Discard)

	rec := do(t, s, http.MethodPost, "/mcp/tools/"+ToolComplianceAuditLedger, "any-token", testTenant, validAppendBody())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unset-token invoke: want 401 (fail closed), got %d", rec.Code)
	}
}

func TestGate_NoTokenHeader_401(t *testing.T) {
	s := newTestServer(t)
	rec := do(t, s, http.MethodGet, "/mcp/tools/", "", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: want 401, got %d", rec.Code)
	}
}

func TestGate_WrongToken_401(t *testing.T) {
	s := newTestServer(t)
	rec := do(t, s, http.MethodGet, "/mcp/tools/", "wrong-"+testToken, "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: want 401, got %d", rec.Code)
	}
}

func TestGate_AppliesToEveryRoute(t *testing.T) {
	s := newTestServer(t)
	// Both the manifest and a tool invocation must be gated.
	for _, tc := range []struct {
		name, method, path, body string
	}{
		{"manifest", http.MethodGet, "/mcp/tools/", ""},
		{"append", http.MethodPost, "/mcp/tools/" + ToolComplianceAuditLedger, validAppendBody()},
		{"cadence", http.MethodPost, "/mcp/tools/" + ToolCadenceReport, "{}"},
		{"footer", http.MethodPost, "/mcp/tools/" + ToolGetLegalFooter, `{"kind":"liability"}`},
	} {
		rec := do(t, s, tc.method, tc.path, "", testTenant, tc.body)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without token: want 401, got %d", tc.name, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// PROVENANCE — X-User-Id mandatory on tool invocations; bound as tenant.
// ---------------------------------------------------------------------------

func TestInvoke_MissingUserID_400(t *testing.T) {
	s := newTestServer(t)
	// Valid token, but NO X-User-Id => 400 on a tenant-scoped tool.
	for _, tc := range []struct{ name, path, body string }{
		{"append", "/mcp/tools/" + ToolComplianceAuditLedger, validAppendBody()},
		{"cadence", "/mcp/tools/" + ToolCadenceReport, "{}"},
	} {
		rec := do(t, s, http.MethodPost, tc.path, testToken, "", tc.body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s missing X-User-Id: want 400, got %d (body=%s)", tc.name, rec.Code, rec.Body.String())
		}
	}
}

func TestInvoke_BodyCannotOverrideTenant(t *testing.T) {
	s := newTestServer(t)
	// Smuggle a tenant_id in the body — strict decoding must reject the unknown
	// field with a 400, so a caller can never write into another tenant's ledger.
	body := `{"tenant_id":"victim","aedt_system_id":"aedt_x","entry_type":"eeoc_four_fifths_impact",` +
		`"audit_period_start":"2026-01-01T00:00:00Z","audit_period_end":"2026-02-01T00:00:00Z",` +
		`"signoff_status":"non_applicable","summary_hash":"h"}`
	rec := do(t, s, http.MethodPost, "/mcp/tools/"+ToolComplianceAuditLedger, testToken, testTenant, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("smuggled tenant_id: want 400 (unknown field rejected), got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// REAL ENGINE — the append path produces a Mirror-Mark the REAL mirrormark /
// auditledger verifier accepts; tenant isolation holds; cadence + typed errors
// route through the genuine engine, not a stub.
// ---------------------------------------------------------------------------

func validAppendBody() string {
	return `{"aedt_system_id":"aedt_recruiter_v2",` +
		`"entry_type":"nyc_ll144_annual_audit",` +
		`"audit_period_start":"2025-05-27T12:00:00Z",` +
		`"audit_period_end":"2026-05-27T12:00:00Z",` +
		`"independent_auditor_name":"Acme Independent Bias Auditors LLP",` +
		`"signoff_status":"attested",` +
		`"signoff_date":"2026-05-27T12:00:00Z",` +
		`"summary_hash":"sha256:deadbeef",` +
		`"public_posting_url":"https://acme.example/aedt-audit-2026.pdf"}`
}

func TestAppend_RealEngine_MirrorMarkColdVerifies(t *testing.T) {
	s := newTestServer(t)
	rec := do(t, s, http.MethodPost, "/mcp/tools/"+ToolComplianceAuditLedger, testToken, testTenant, validAppendBody())
	if rec.Code != http.StatusOK {
		t.Fatalf("append: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	content, isErr, msg := decodeEnvelope(t, rec)
	if isErr {
		t.Fatalf("append unexpectedly is_error: %s", msg)
	}
	var res struct {
		AppendedAt string `json:"appended_at"`
		MirrorMark string `json:"mirror_mark"`
		Entry      struct {
			TenantID         string `json:"tenant_id"`
			AEDTSystemID     string `json:"aedt_system_id"`
			EntryType        string `json:"entry_type"`
			AuditPeriodStart string `json:"audit_period_start"`
			AuditPeriodEnd   string `json:"audit_period_end"`
			IndependentName  string `json:"independent_auditor_name"`
			SignoffStatus    string `json:"signoff_status"`
			SignoffDate      string `json:"signoff_date"`
			SummaryHash      string `json:"summary_hash"`
			PublicPostingURL string `json:"public_posting_url"`
		} `json:"entry"`
	}
	if err := json.Unmarshal(content, &res); err != nil {
		t.Fatalf("decode append content: %v", err)
	}

	// Provenance binding: the tenant came from X-User-Id, not the body.
	if res.Entry.TenantID != testTenant {
		t.Fatalf("tenant binding: want %q, got %q", testTenant, res.Entry.TenantID)
	}
	if !strings.HasPrefix(res.MirrorMark, mirrormark.MarkPrefix) {
		t.Fatalf("mirror_mark missing canonical prefix %q: %q", mirrormark.MarkPrefix, res.MirrorMark)
	}

	// COLD-VERIFY the returned mark with the REAL engine, exactly as a regulator
	// would: re-derive the canonical payload from the returned entry and check
	// the Mirror-Mark against the server's (corpus, key). This proves the
	// producer wrapped the genuine signer, not a fake.
	corpus, key := nonZeroCorpusKey()
	start, _ := time.Parse(time.RFC3339, res.Entry.AuditPeriodStart)
	end, _ := time.Parse(time.RFC3339, res.Entry.AuditPeriodEnd)
	signoff, _ := time.Parse(time.RFC3339, res.Entry.SignoffDate)
	appended, _ := time.Parse(time.RFC3339, res.AppendedAt)
	reconstructed := auditledger.Entry{
		TenantID:               res.Entry.TenantID,
		AEDTSystemID:           res.Entry.AEDTSystemID,
		EntryType:              auditledger.EntryType(res.Entry.EntryType),
		AuditPeriodStart:       start,
		AuditPeriodEnd:         end,
		IndependentAuditorName: res.Entry.IndependentName,
		SignoffStatus:          auditledger.SignoffStatus(res.Entry.SignoffStatus),
		SignoffDate:            signoff,
		SummaryHash:            res.Entry.SummaryHash,
		PublicPostingURL:       res.Entry.PublicPostingURL,
		AppendedAt:             appended,
	}
	payload := auditledger.CanonicalPayload(reconstructed)
	if err := mirrormark.Verify(res.MirrorMark, corpus, payload, key); err != nil {
		t.Fatalf("REAL-engine cold-verify of returned Mirror-Mark failed: %v", err)
	}
}

func TestAppend_TenantIsolation(t *testing.T) {
	s := newTestServer(t)
	// Tenant A appends one NYC-LL144 row; tenant B appends none.
	recA := do(t, s, http.MethodPost, "/mcp/tools/"+ToolComplianceAuditLedger, testToken, "tenant_A", validAppendBody())
	if recA.Code != http.StatusOK {
		t.Fatalf("tenant_A append: want 200, got %d (%s)", recA.Code, recA.Body.String())
	}

	// Tenant B's cadence report must see ZERO pairs — A's row must not leak.
	recB := do(t, s, http.MethodPost, "/mcp/tools/"+ToolCadenceReport, testToken, "tenant_B", "{}")
	contentB, isErr, msg := decodeEnvelope(t, recB)
	if isErr {
		t.Fatalf("tenant_B cadence is_error: %s", msg)
	}
	var resB struct {
		Covered   []map[string]string `json:"covered"`
		Uncovered []map[string]string `json:"uncovered"`
	}
	if err := json.Unmarshal(contentB, &resB); err != nil {
		t.Fatalf("decode cadence B: %v", err)
	}
	if len(resB.Covered) != 0 || len(resB.Uncovered) != 0 {
		t.Fatalf("tenant isolation breach: tenant_B sees covered=%v uncovered=%v", resB.Covered, resB.Uncovered)
	}

	// Tenant A's cadence report must show the row as COVERED (recent annual audit).
	recA2 := do(t, s, http.MethodPost, "/mcp/tools/"+ToolCadenceReport, testToken, "tenant_A", "{}")
	contentA, _, _ := decodeEnvelope(t, recA2)
	var resA struct {
		Covered []struct {
			TenantID     string `json:"tenant_id"`
			AEDTSystemID string `json:"aedt_system_id"`
		} `json:"covered"`
	}
	if err := json.Unmarshal(contentA, &resA); err != nil {
		t.Fatalf("decode cadence A: %v", err)
	}
	if len(resA.Covered) != 1 || resA.Covered[0].TenantID != "tenant_A" {
		t.Fatalf("tenant_A cadence: want 1 covered pair for tenant_A, got %+v", resA.Covered)
	}
}

func TestAppend_TypedValidationError_IsToolError(t *testing.T) {
	s := newTestServer(t)
	// NYC-LL144 entry whose period is NOT ~annual (1 month) => the engine's
	// ErrAuditPeriodNotAnnual must surface as a tool-level error (is_error:true)
	// at HTTP 200, NOT an HTTP 4xx — the request was well-formed.
	body := `{"aedt_system_id":"aedt_x","entry_type":"nyc_ll144_annual_audit",` +
		`"audit_period_start":"2026-01-01T00:00:00Z","audit_period_end":"2026-02-01T00:00:00Z",` +
		`"signoff_status":"pending","summary_hash":"h"}`
	rec := do(t, s, http.MethodPost, "/mcp/tools/"+ToolComplianceAuditLedger, testToken, testTenant, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("typed validation: want HTTP 200 with tool error, got %d", rec.Code)
	}
	_, isErr, msg := decodeEnvelope(t, rec)
	if !isErr {
		t.Fatalf("typed validation: want is_error:true, got is_error:false")
	}
	if !strings.Contains(msg, "~1 year") && !strings.Contains(msg, "360-370") {
		t.Fatalf("typed validation: error message not the engine's ErrAuditPeriodNotAnnual: %q", msg)
	}
}

func TestLegalFooter_RealText(t *testing.T) {
	s := newTestServer(t)
	rec := do(t, s, http.MethodPost, "/mcp/tools/"+ToolGetLegalFooter, testToken, "", `{"kind":"liability"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("footer: want 200, got %d", rec.Code)
	}
	content, isErr, msg := decodeEnvelope(t, rec)
	if isErr {
		t.Fatalf("footer is_error: %s", msg)
	}
	var res struct {
		Body              string `json:"body"`
		ReviewedByCounsel bool   `json:"reviewed_by_counsel"`
	}
	if err := json.Unmarshal(content, &res); err != nil {
		t.Fatalf("decode footer: %v", err)
	}
	if res.Body != legal.LegalLiabilityFooter {
		t.Fatalf("footer body is not the real legal.LegalLiabilityFooter")
	}
	if res.ReviewedByCounsel != legal.ReviewedByCounsel {
		t.Fatalf("footer reviewed_by_counsel must mirror the honest sentinel (%v)", legal.ReviewedByCounsel)
	}
}

func TestLegalFooter_UnknownKind_ToolError(t *testing.T) {
	s := newTestServer(t)
	rec := do(t, s, http.MethodPost, "/mcp/tools/"+ToolGetLegalFooter, testToken, "", `{"kind":"bogus"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("unknown footer kind: want HTTP 200 tool error, got %d", rec.Code)
	}
	_, isErr, _ := decodeEnvelope(t, rec)
	if !isErr {
		t.Fatalf("unknown footer kind: want is_error:true")
	}
}

// ---------------------------------------------------------------------------
// METHOD / ROUTING hygiene
// ---------------------------------------------------------------------------

func TestManifest_WrongMethod_405(t *testing.T) {
	s := newTestServer(t)
	rec := do(t, s, http.MethodPost, "/mcp/tools/", testToken, "", "{}")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST manifest: want 405, got %d", rec.Code)
	}
}

func TestInvoke_UnknownTool_404(t *testing.T) {
	s := newTestServer(t)
	rec := do(t, s, http.MethodPost, "/mcp/tools/bias-audit.does_not_exist", testToken, testTenant, "{}")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown tool: want 404, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// LOUD-ONCE-WARN — zero-signer boot warning fires (honest persistence posture).
// ---------------------------------------------------------------------------

func TestNew_ZeroSigner_EmitsLoudOnceWarn(t *testing.T) {
	var buf bytes.Buffer
	_ = New(Config{ServiceToken: testToken}, &buf) // zero corpus + nil key
	out := buf.String()
	if !strings.Contains(out, "[LOUD-ONCE-WARNING]") {
		t.Fatalf("zero-signer New must emit a LOUD-ONCE-WARN; got %q", out)
	}
}

// NewFromEnv smoke: an empty env yields a fail-closed server (no token) — the
// secure default for an unconfigured deploy.
func TestNewFromEnv_EmptyEnvFailsClosed(t *testing.T) {
	t.Setenv(serviceTokenEnv, "")
	t.Setenv("BIAS_AUDIT_CORPUS_SHA256", "")
	t.Setenv("BIAS_AUDIT_SIGNING_KEY", "")
	s := NewFromEnv(io.Discard)
	rec := do(t, s, http.MethodGet, "/mcp/tools/", "whatever", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("empty-env server must fail closed (401), got %d", rec.Code)
	}
}

// Guard: the producer must not accidentally expose a route outside /mcp/tools/.
func TestHandler_NoUngatedRoutes(t *testing.T) {
	s := newTestServer(t)
	// A path outside the gated tree should 404 (mux has no other handler) and
	// certainly never 200 without a token.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("unexpected ungated 200 at /: body=%s", rec.Body.String())
	}
}
