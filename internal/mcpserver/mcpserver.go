// Package mcpserver is the additive Nexus-facing MCP-tool producer for
// bias-audit. It exposes the existing internal/auditledger engine as a
// Nexus-routable capability over the standard /mcp/tools wire shape, with
// ZERO change to any existing file (purely additive per R145-strict).
//
// Why this exists
// ---------------
// Per ADR-001 (capability-hub): consumer apps integrate ONLY with Nexus;
// Nexus routes to producers BY CAPABILITY. bias-audit's load-bearing
// capability is `compliance_audit_ledger` — an append-only, Mirror-Mark-
// stamped regulated-AI audit record (NYC LL144 / EU AI Act / EEOC). This
// package is the producer surface Nexus's FlagshipToolLoader fetches +
// forwards to. The tool NAME (`bias-audit.compliance_audit_ledger`) IS the
// routing key — no Nexus-side code change is needed (one
// FLAGSHIP_TOOL_PROVIDERS env entry).
//
// The wire contract (verified against the Nexus consumer code in
// infrastructure/nexus/.../internal/services/flagship_tool_loader.go on
// 2026-06-02):
//
//	GET  /mcp/tools/        -> {"tools":[{name,description,input_schema,approval_required}]}
//	POST /mcp/tools/{name}  -> body = tool input JSON;
//	                           reply {"content":<any-json>,"is_error":bool,"error_message":string}
//
// Trust boundary (STEP-1.5, the gap the 2026-06-01 wave caught)
// -------------------------------------------------------------
// EVERY /mcp/tools request passes a FAIL-CLOSED service-token gate before
// any handler runs:
//
//   - X-Nexus-Service-Token must constant-time-equal the configured secret.
//   - If the configured secret is EMPTY/UNSET, EVERY request is 401 — the
//     server NEVER fails open. (A P0 of exactly this class — fail-open on an
//     unset token — was found in the last exposure wave.)
//
// This server is a single net/http.ServeMux with NO app-wide auth group, so
// (unlike the RubberDuck ASP.NET exemplar) there is no global default-deny
// policy to opt out of — the token gate IS the only boundary, applied
// uniformly in the mux handler. STEP-1.5 here = "the token gate wraps the
// whole /mcp/tools surface and fails closed", proven by the unset-token-401
// test.
//
// Provenance (who originated the request)
// ---------------------------------------
// X-User-Id is mandatory on every TOOL INVOCATION (POST) and is bound as the
// auditledger TenantID. A consumer can NEVER write into another tenant's
// ledger by passing a tenant id in the body — the body carries no tenant
// field and the handler ignores any attempt. Absent X-User-Id => 400. (The
// GET manifest is provenance-free — it lists tools, touches no tenant data.)
//
// Persistence honesty
// -------------------
// The underlying auditledger.Ledger is in-memory (sync.RWMutex + []Entry),
// exactly as documented on main. This producer keeps ONE ledger per tenant
// in a process-lifetime map; rows are lost on restart. That is the engine's
// documented Phase-1 posture, surfaced loudly: a LOUD-ONCE-WARN fires at
// boot when the signing corpus/key are the zero-value (dev/KAT inputs), and
// the README/runbook state the WORM-backing-store requirement for production.
// This wraps the REAL engine — it is not a stub.
package mcpserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/davly/bias-audit/internal/auditledger"
	"github.com/davly/bias-audit/internal/honest"
	"github.com/davly/bias-audit/internal/legal"
)

// Tool name constants. The {project}.{verb_noun} convention; the name is the
// Nexus routing key. The TOP capability uses the capability code itself per
// the exposure task spec.
const (
	// ToolComplianceAuditLedger is the TOP capability: append one regulated-AI
	// audit row and get back a cold-verifiable Mirror-Mark receipt. Mutates a
	// regulatory record => approval_required.
	ToolComplianceAuditLedger = "bias-audit.compliance_audit_ledger"

	// ToolCadenceReport reports tenant×AEDT pairs missing a recent NYC-LL144
	// annual audit (honest delinquency). Read-only.
	ToolCadenceReport = "bias-audit.cadence_report"

	// ToolGetLegalFooter returns a founder-drafted (counsel-pending) legal
	// footer body. Static text; read-only; free.
	ToolGetLegalFooter = "bias-audit.get_legal_footer"
)

// serviceTokenEnv is the env var holding the shared machine-trust secret. Its
// value must equal the token field of the Nexus FLAGSHIP_TOOL_PROVIDERS entry.
const serviceTokenEnv = "BIAS_AUDIT_NEXUS_SERVICE_TOKEN"

const (
	headerServiceToken = "X-Nexus-Service-Token"
	headerUserID       = "X-User-Id"

	// maxBodyBytes caps a tool-invocation request body. Audit rows are small
	// scalar records; 1 MiB is generous and bounds memory.
	maxBodyBytes = 1 << 20
)

// Server is the bias-audit MCP producer. It owns a per-tenant in-memory
// ledger map and the fail-closed token gate.
type Server struct {
	// serviceToken is the configured shared secret. Empty => fail closed
	// (every request 401). Captured at construction from the env.
	serviceToken string

	// corpus + key sign every ledger row's Mirror-Mark. Production hosts MUST
	// inject non-zero values (see New); the zero-value is dev/KAT only and
	// triggers a LOUD-ONCE-WARN at boot.
	corpus [sha256.Size]byte
	key    []byte

	// now is injected for deterministic tests; defaults to time.Now.
	now func() time.Time

	mu      sync.Mutex
	ledgers map[string]*auditledger.Ledger // keyed by tenant id (X-User-Id)
}

// Config configures a Server.
type Config struct {
	// ServiceToken is the shared machine-trust secret. Empty => fail closed.
	ServiceToken string
	// Corpus is the 32-byte SHA-256 of the tenant lore-corpus body used to
	// stamp Mirror-Marks. Zero-value is dev/KAT only.
	Corpus [sha256.Size]byte
	// Key is the HMAC signing key. Zero/empty is dev/KAT only.
	Key []byte
	// Now overrides the clock for tests. nil => time.Now.
	Now func() time.Time
}

// New builds a Server from cfg. When cfg.ServiceToken is empty the server
// fails closed (every request 401) and that is the SECURE default — never an
// accident. When the signing corpus + key are both zero-value a LOUD-ONCE-WARN
// is written to w (typically os.Stderr) because such a server can only emit
// dev/KAT-grade marks, not production receipts.
func New(cfg Config, w io.Writer) *Server {
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	s := &Server{
		serviceToken: cfg.ServiceToken,
		corpus:       cfg.Corpus,
		key:          append([]byte(nil), cfg.Key...),
		now:          nowFn,
		ledgers:      make(map[string]*auditledger.Ledger),
	}
	if cfg.Corpus == ([sha256.Size]byte{}) && len(cfg.Key) == 0 && w != nil {
		// R143 LOUD-ONCE-WARN: a zero-corpus/zero-key signer is dev/KAT only.
		// Reuse the canonical advisory taxonomy rather than inventing a string.
		honest.LoudOnce(honest.Advisory{
			Code:     "BIAS_AUDIT_MCP_ZERO_SIGNER",
			Severity: honest.SeverityWarn,
			Message: "MCP producer started with a zero-value Mirror-Mark corpus + key — " +
				"every receipt it stamps is dev/KAT-grade and will NOT cold-verify against a " +
				"real lore corpus. Production hosts MUST inject a non-zero corpus + key " +
				"(BIAS_AUDIT_CORPUS_SHA256 / BIAS_AUDIT_SIGNING_KEY) and persist the ledger to " +
				"a write-once-read-many store; the in-memory ledger is lost on restart.",
			DocLink: "SECURITY.md",
		}, w)
	}
	return s
}

// NewFromEnv builds a Server from the process environment. The service token
// is read from BIAS_AUDIT_NEXUS_SERVICE_TOKEN (empty => fail closed). The
// signing corpus + key are read from BIAS_AUDIT_CORPUS_SHA256 (64-hex) +
// BIAS_AUDIT_SIGNING_KEY; absent/invalid => zero-value (dev/KAT, warned).
func NewFromEnv(w io.Writer) *Server {
	var corpus [sha256.Size]byte
	if h := strings.TrimSpace(os.Getenv("BIAS_AUDIT_CORPUS_SHA256")); h != "" {
		if b, err := decodeHex32(h); err == nil {
			corpus = b
		}
	}
	return New(Config{
		ServiceToken: os.Getenv(serviceTokenEnv),
		Corpus:       corpus,
		Key:          []byte(os.Getenv("BIAS_AUDIT_SIGNING_KEY")),
	}, w)
}

// Handler returns the http.Handler serving the /mcp/tools surface. The
// returned mux has NO routes outside the token-gated /mcp/tools tree, so the
// fail-closed gate is the sole trust boundary (STEP-1.5).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// One gated entry point covering the whole surface. The leading "/mcp/tools/"
	// pattern matches both the trailing-slash manifest and the per-tool path.
	mux.HandleFunc("/mcp/tools/", s.gate(s.routeMcpTools))
	return mux
}

// gate is the FAIL-CLOSED service-token middleware. It runs BEFORE any
// handler. An empty configured secret => 401 for everything (never fail
// open). A present-but-wrong (or missing) header => 401. Comparison is
// constant-time.
func (s *Server) gate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authOK(r.Header.Get(headerServiceToken)) {
			writeStatusJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "unauthorized: invalid or missing " + headerServiceToken,
			})
			return
		}
		next(w, r)
	}
}

// authOK constant-time-compares the presented token to the configured secret.
// An empty configured secret can never match (we return false up front) — the
// server FAILS CLOSED when unconfigured rather than authorising everyone.
func (s *Server) authOK(presented string) bool {
	if s.serviceToken == "" {
		return false // fail closed: unset secret authorises nobody
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.serviceToken)) == 1
}

// routeMcpTools dispatches inside the gated /mcp/tools tree. GET on the
// trailing-slash root returns the manifest; POST on /mcp/tools/{name} invokes
// a tool. Anything else is 404/405.
func (s *Server) routeMcpTools(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/mcp/tools/")
	if rest == "" {
		if r.Method != http.MethodGet {
			writeStatusJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "manifest is GET-only"})
			return
		}
		s.handleManifest(w, r)
		return
	}
	if r.Method != http.MethodPost {
		writeStatusJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "tool invocation is POST-only"})
		return
	}
	s.handleInvoke(w, r, rest)
}

// manifestTool is the per-tool manifest entry shape Nexus parses.
type manifestTool struct {
	Name             string         `json:"name"`
	Description      string         `json:"description"`
	InputSchema      map[string]any `json:"input_schema"`
	ApprovalRequired bool           `json:"approval_required"`
}

// handleManifest returns the static tool manifest. No tenant data is touched,
// so no X-User-Id is required here (only the service-token gate, already
// passed).
func (s *Server) handleManifest(w http.ResponseWriter, _ *http.Request) {
	writeStatusJSON(w, http.StatusOK, map[string]any{"tools": manifest()})
}

// manifest is the canonical tool list. Factored out so tests can pin it.
func manifest() []manifestTool {
	return []manifestTool{
		{
			Name: ToolComplianceAuditLedger,
			Description: "Append one regulated-AI bias-audit row (NYC LL144 / EU AI Act / EEOC) to the " +
				"calling tenant's append-only ledger; returns a cold-verifiable Mirror-Mark receipt.",
			ApprovalRequired: true, // mutates a regulatory record
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"aedt_system_id": map[string]any{"type": "string"},
					"entry_type": map[string]any{
						"type": "string",
						"enum": []string{
							string(auditledger.EntryTypeNYCLL144AnnualAudit),
							string(auditledger.EntryTypeEUAIActConformityAssessment),
							string(auditledger.EntryTypeEEOCFourFifthsImpact),
						},
					},
					"audit_period_start":       map[string]any{"type": "string", "format": "date-time"},
					"audit_period_end":         map[string]any{"type": "string", "format": "date-time"},
					"independent_auditor_name": map[string]any{"type": "string"},
					"signoff_status": map[string]any{
						"type": "string",
						"enum": []string{
							string(auditledger.SignoffPending),
							string(auditledger.SignoffAttested),
							string(auditledger.SignoffNonApplicable),
						},
					},
					"signoff_date":       map[string]any{"type": "string", "format": "date-time"},
					"summary_hash":       map[string]any{"type": "string"},
					"public_posting_url": map[string]any{"type": "string"},
				},
				"required": []string{
					"aedt_system_id", "entry_type", "audit_period_start",
					"audit_period_end", "signoff_status", "summary_hash",
				},
			},
		},
		{
			Name:             ToolCadenceReport,
			Description:      "Report tenant×AEDT pairs missing a recent (≤365d) NYC-LL144 annual audit (honest delinquency).",
			ApprovalRequired: false,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"ref_time": map[string]any{"type": "string", "format": "date-time"},
				},
			},
		},
		{
			Name:             ToolGetLegalFooter,
			Description:      "Return a founder-drafted (counsel-pending) legal footer body.",
			ApprovalRequired: false,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"kind": map[string]any{
						"type": "string",
						"enum": []string{"liability", "candidate-notice", "terms-of-use"},
					},
				},
				"required": []string{"kind"},
			},
		},
	}
}

// handleInvoke runs one tool. The service-token gate has already passed. For
// tools that touch tenant data, X-User-Id is required and bound as TenantID.
func (s *Server) handleInvoke(w http.ResponseWriter, r *http.Request, name string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		writeStatusJSON(w, http.StatusBadRequest, map[string]string{"error": "could not read request body"})
		return
	}

	switch name {
	case ToolComplianceAuditLedger:
		s.invokeAppend(w, r, body)
	case ToolCadenceReport:
		s.invokeCadence(w, r, body)
	case ToolGetLegalFooter:
		s.invokeLegalFooter(w, body) // static text — provenance not required
	default:
		// Unknown tool: 404 (Nexus only forwards manifest-listed tools, but be
		// strict in case of a stale registry).
		writeStatusJSON(w, http.StatusNotFound, map[string]string{"error": "unknown tool: " + name})
	}
}

// appendInput is the wire body for ToolComplianceAuditLedger. NOTE: there is
// deliberately NO tenant_id field — the tenant is the X-User-Id provenance
// header, never client-supplied. aedt_system_id is the audited unit.
type appendInput struct {
	AEDTSystemID           string `json:"aedt_system_id"`
	EntryType              string `json:"entry_type"`
	AuditPeriodStart       string `json:"audit_period_start"`
	AuditPeriodEnd         string `json:"audit_period_end"`
	IndependentAuditorName string `json:"independent_auditor_name"`
	SignoffStatus          string `json:"signoff_status"`
	SignoffDate            string `json:"signoff_date"`
	SummaryHash            string `json:"summary_hash"`
	PublicPostingURL       string `json:"public_posting_url"`
}

// appendResult is the content payload returned on a successful append.
type appendResult struct {
	AppendedAt string          `json:"appended_at"`
	MirrorMark string          `json:"mirror_mark"`
	Entry      appendEntryEcho `json:"entry"`
}

// appendEntryEcho echoes the stamped entry back to the caller in a stable,
// decoupled JSON shape (NOT auditledger.Entry's field serialisation, so the
// wire contract does not pin the engine's exported field names).
type appendEntryEcho struct {
	TenantID               string `json:"tenant_id"`
	AEDTSystemID           string `json:"aedt_system_id"`
	EntryType              string `json:"entry_type"`
	AuditPeriodStart       string `json:"audit_period_start"`
	AuditPeriodEnd         string `json:"audit_period_end"`
	IndependentAuditorName string `json:"independent_auditor_name,omitempty"`
	SignoffStatus          string `json:"signoff_status"`
	SignoffDate            string `json:"signoff_date,omitempty"`
	SummaryHash            string `json:"summary_hash"`
	PublicPostingURL       string `json:"public_posting_url,omitempty"`
}

func (s *Server) invokeAppend(w http.ResponseWriter, r *http.Request, body []byte) {
	tenant, ok := requireUserID(w, r)
	if !ok {
		return
	}
	var in appendInput
	if err := unmarshalStrict(body, &in); err != nil {
		writeStatusJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body: " + err.Error()})
		return
	}

	start, err := parseTime(in.AuditPeriodStart)
	if err != nil {
		writeToolError(w, "audit_period_start must be RFC3339 date-time")
		return
	}
	end, err := parseTime(in.AuditPeriodEnd)
	if err != nil {
		writeToolError(w, "audit_period_end must be RFC3339 date-time")
		return
	}
	var signoffDate time.Time
	if strings.TrimSpace(in.SignoffDate) != "" {
		signoffDate, err = parseTime(in.SignoffDate)
		if err != nil {
			writeToolError(w, "signoff_date must be RFC3339 date-time")
			return
		}
	}

	entry := auditledger.Entry{
		TenantID:               tenant, // provenance-bound; body cannot override
		AEDTSystemID:           in.AEDTSystemID,
		EntryType:              auditledger.EntryType(in.EntryType),
		AuditPeriodStart:       start,
		AuditPeriodEnd:         end,
		IndependentAuditorName: in.IndependentAuditorName,
		SignoffStatus:          auditledger.SignoffStatus(in.SignoffStatus),
		SignoffDate:            signoffDate,
		SummaryHash:            in.SummaryHash,
		PublicPostingURL:       in.PublicPostingURL,
	}

	stamped, aerr := s.ledgerFor(tenant).Append(entry, s.now())
	if aerr != nil {
		// Typed validation errors (ErrAuditPeriodNotAnnual, ErrAttestedWithoutAuditor, …)
		// map to a tool-level error, NOT an HTTP error — the request was well-formed.
		writeToolError(w, aerr.Error())
		return
	}

	writeContent(w, appendResult{
		AppendedAt: stamped.AppendedAt.UTC().Format(time.RFC3339),
		MirrorMark: stamped.Mark,
		Entry:      echoEntry(stamped),
	})
}

// cadenceInput is the wire body for ToolCadenceReport. ref_time is optional;
// absent => now. There is NO tenant field — the report is scoped to the
// calling tenant's ledger via X-User-Id.
type cadenceInput struct {
	RefTime string `json:"ref_time"`
}

type cadencePair struct {
	TenantID     string `json:"tenant_id"`
	AEDTSystemID string `json:"aedt_system_id"`
}

type cadenceResult struct {
	RefTime   string        `json:"ref_time"`
	Covered   []cadencePair `json:"covered"`
	Uncovered []cadencePair `json:"uncovered"`
}

func (s *Server) invokeCadence(w http.ResponseWriter, r *http.Request, body []byte) {
	tenant, ok := requireUserID(w, r)
	if !ok {
		return
	}
	var in cadenceInput
	if err := unmarshalStrict(body, &in); err != nil {
		writeStatusJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body: " + err.Error()})
		return
	}
	ref := s.now()
	if strings.TrimSpace(in.RefTime) != "" {
		var err error
		ref, err = parseTime(in.RefTime)
		if err != nil {
			writeToolError(w, "ref_time must be RFC3339 date-time")
			return
		}
	}
	covered, uncovered := s.ledgerFor(tenant).AnnualCadenceCompliance(ref)
	writeContent(w, cadenceResult{
		RefTime:   ref.UTC().Format(time.RFC3339),
		Covered:   toCadencePairs(covered),
		Uncovered: toCadencePairs(uncovered),
	})
}

// legalFooterInput is the wire body for ToolGetLegalFooter.
type legalFooterInput struct {
	Kind string `json:"kind"`
}

type legalFooterResult struct {
	Kind              string `json:"kind"`
	Body              string `json:"body"`
	ReviewedByCounsel bool   `json:"reviewed_by_counsel"`
	Version           string `json:"version"`
}

func (s *Server) invokeLegalFooter(w http.ResponseWriter, body []byte) {
	var in legalFooterInput
	if err := unmarshalStrict(body, &in); err != nil {
		writeStatusJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body: " + err.Error()})
		return
	}
	var text string
	switch in.Kind {
	case "liability":
		text = legal.LegalLiabilityFooter
	case "candidate-notice":
		text = legal.CandidateNoticeFooter
	case "terms-of-use":
		text = legal.TermsOfUseFooter
	default:
		writeToolError(w, "unknown footer kind (want liability | candidate-notice | terms-of-use)")
		return
	}
	writeContent(w, legalFooterResult{
		Kind:              in.Kind,
		Body:              text,
		ReviewedByCounsel: legal.ReviewedByCounsel, // honest sentinel, surfaced
		Version:           legal.LegalDocumentVersion,
	})
}

// ledgerFor returns (creating if needed) the in-memory ledger for tenant. All
// ledgers share the process signer (corpus + key); rows are scoped by tenant.
func (s *Server) ledgerFor(tenant string) *auditledger.Ledger {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.ledgers[tenant]
	if !ok {
		l = auditledger.New(s.corpus, s.key)
		s.ledgers[tenant] = l
	}
	return l
}

// --- small helpers -------------------------------------------------------

// requireUserID enforces provenance: a non-empty X-User-Id header. On absence
// it writes a 400 and returns ok=false. The returned id is the tenant key.
func requireUserID(w http.ResponseWriter, r *http.Request) (string, bool) {
	uid := strings.TrimSpace(r.Header.Get(headerUserID))
	if uid == "" {
		writeStatusJSON(w, http.StatusBadRequest, map[string]string{
			"error": "missing " + headerUserID + " (provenance required)",
		})
		return "", false
	}
	return uid, true
}

func toCadencePairs(in []auditledger.TenantAEDTPair) []cadencePair {
	out := make([]cadencePair, 0, len(in))
	for _, p := range in {
		out = append(out, cadencePair{TenantID: p.TenantID, AEDTSystemID: p.AEDTSystemID})
	}
	return out
}

func echoEntry(e auditledger.Entry) appendEntryEcho {
	out := appendEntryEcho{
		TenantID:               e.TenantID,
		AEDTSystemID:           e.AEDTSystemID,
		EntryType:              string(e.EntryType),
		AuditPeriodStart:       e.AuditPeriodStart.UTC().Format(time.RFC3339),
		AuditPeriodEnd:         e.AuditPeriodEnd.UTC().Format(time.RFC3339),
		IndependentAuditorName: e.IndependentAuditorName,
		SignoffStatus:          string(e.SignoffStatus),
		SummaryHash:            e.SummaryHash,
		PublicPostingURL:       e.PublicPostingURL,
	}
	if !e.SignoffDate.IsZero() {
		out.SignoffDate = e.SignoffDate.UTC().Format(time.RFC3339)
	}
	return out
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, strings.TrimSpace(s))
}

// unmarshalStrict decodes JSON, rejecting unknown fields so a caller cannot
// smuggle e.g. a tenant_id field that the handler silently ignores — an
// unknown field is a loud 400 instead. An empty body decodes to the zero
// struct (Nexus sends "{}" for no-arg tools).
func unmarshalStrict(body []byte, v any) error {
	if len(body) == 0 {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

func decodeHex32(h string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	if len(h) != sha256.Size*2 {
		return out, errors.New("corpus hex must be 64 chars")
	}
	for i := 0; i < sha256.Size; i++ {
		var b byte
		for j := 0; j < 2; j++ {
			c := h[i*2+j]
			var nib byte
			switch {
			case c >= '0' && c <= '9':
				nib = c - '0'
			case c >= 'a' && c <= 'f':
				nib = c - 'a' + 10
			case c >= 'A' && c <= 'F':
				nib = c - 'A' + 10
			default:
				return out, errors.New("corpus hex has non-hex char")
			}
			b = b<<4 | nib
		}
		out[i] = b
	}
	return out, nil
}

// executionEnvelope mirrors the {content,is_error,error_message} shape Nexus's
// FlagshipToolLoader unwraps.
type executionEnvelope struct {
	Content      any    `json:"content"`
	IsError      bool   `json:"is_error"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// writeContent writes a successful tool result (is_error:false) at HTTP 200.
func writeContent(w http.ResponseWriter, content any) {
	writeStatusJSON(w, http.StatusOK, executionEnvelope{Content: content, IsError: false})
}

// writeToolError writes a tool-level error (is_error:true) at HTTP 200 — the
// request reached the handler and was well-formed; the FAILURE is in the tool
// semantics (a validation error). This matches the Nexus loader which inspects
// is_error, not the HTTP status, for tool-level failures.
func writeToolError(w http.ResponseWriter, msg string) {
	writeStatusJSON(w, http.StatusOK, executionEnvelope{IsError: true, ErrorMessage: msg})
}

// writeStatusJSON writes v as JSON with the given status.
func writeStatusJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
