// Command bias-audit-server is the Nexus-facing MCP-tool producer binary for
// bias-audit. It exposes the existing internal/auditledger engine over the
// standard /mcp/tools wire shape so Nexus can route the
// `bias-audit.compliance_audit_ledger` capability to it.
//
// This is additive to the existing `bias-audit` CLI (cmd/bias-audit) — that
// CLI is unchanged; this is a second, separate binary.
//
// Trust boundary (fail-closed): every /mcp/tools request must carry a valid
// X-Nexus-Service-Token (constant-time compared to BIAS_AUDIT_NEXUS_SERVICE_TOKEN);
// an UNSET token env => 401 for everything (never fail open). Tool invocations
// additionally require X-User-Id provenance (=> 400 if absent), bound as the
// per-tenant ledger key.
//
// Environment:
//
//	BIAS_AUDIT_NEXUS_SERVICE_TOKEN  shared machine-trust secret (REQUIRED to be
//	                                non-empty for the server to authorise any
//	                                request; empty => fail closed)
//	BIAS_AUDIT_CORPUS_SHA256        64-hex Mirror-Mark corpus SHA (optional; zero
//	                                => dev/KAT signer, LOUD-ONCE warned)
//	BIAS_AUDIT_SIGNING_KEY          Mirror-Mark HMAC key (optional; empty => dev/KAT)
//	BIAS_AUDIT_LISTEN_ADDR          listen address (optional; default ":8080")
//
// Persistence honesty: the ledger is in-memory (engine's documented Phase-1
// posture); rows are lost on restart. Production hosts MUST persist to a WORM
// store (Postgres INSERT-only role / S3 Object Lock) — see SECURITY.md.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/davly/bias-audit/internal/mcpserver"
)

func main() {
	srv := mcpserver.NewFromEnv(os.Stderr)

	addr := os.Getenv("BIAS_AUDIT_LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	fmt.Fprintf(os.Stderr, "bias-audit-server: MCP producer listening on %s (capability bias-audit.compliance_audit_ledger)\n", addr)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "bias-audit-server: %v\n", err)
		os.Exit(1)
	}
}
