// Package lore pins the ecosystem-canonical KAT-1 HMAC-SHA256 invariant
// for the R151 ECOSYSTEM_QUALITY_STANDARD.md Part XII cross-substrate
// pin.
//
// KAT-1 = the foundation-anchor Known Answer Test. The cohort
// computes HMAC-SHA256 over a canonical 33-byte input with an empty
// key; the hex output is pinned byte-identical across every cohort
// flagship + substrate (Go × N, Rust, Python, Haskell, Solidity,
// Idris 2, Gleam, Java, Swift, Ruby, C#, Zig, etc.). When the hex
// literal drifts, the cohort firewall (the test pin in this package)
// catches the drift on every CI run BEFORE the artefact reaches a
// regulator (in bias-audit's case, an NYC DCWP independent auditor,
// an EU AI Act notified body, or an HR-tenant compliance officer
// reviewing the annual independent bias audit).
//
// Why bias-audit consumes this today:
//
//   - bias-audit is the SaaS productisation of canopy's NYC LL144 +
//     EEOC R74 dual-gate. Where canopy is a single-tenant offline-CLI
//     reference, bias-audit is the multi-tenant managed annual-audit
//     ledger + candidate-notice + public-posting orchestration plane.
//   - The Mirror-Mark stamped on every audit-ledger row (per
//     R175 R-MIRROR-MARK-LOAD-BEARING-IN-PRODUCTION) MUST be cold-
//     verifiable by an NYC DCWP independent auditor without trusting
//     bias-audit's filesystem. KAT-1 byte-identity is the FIPS-
//     anchored proof that the HMAC-SHA256 substrate is correct.
//   - Pure-stdlib `crypto/hmac` + `crypto/sha256` — no module
//     dependencies (matches bias-audit's zero-`go.mod`-requires
//     discipline from inception per R174).
//
// Cold-verify recipe (OpenSSL one-liner — no Go toolchain involved):
//
//	# KAT-1 input: 0x01 || 32×0x00 (33 bytes); HMAC key: empty
//	printf '\x01' > /tmp/kat1.bin
//	printf '\x00%.0s' {1..32} >> /tmp/kat1.bin
//	openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin
//	# → HMAC-SHA256(stdin) = 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
//
// A regulator with `openssl dgst` and this hex string can reproduce
// the digest from canonical inputs WITHOUT any Limitless toolchain.
// The property is bedded in FIPS PUB 180-4 + RFC 2104 + RFC 4648 —
// not in bias-audit source.
package lore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Digest is the cohort-canonical KAT-1 HMAC-SHA256 digest, hex-encoded.
// Pinned byte-identical to foundation/pkg/mirrormark.KAT1Digest and to
// every cohort port (canopy / pulse / baseline / oracle / iris / foundry
// / folio / nexus / dipstick / pigeonhole / howler / ouroboros / casino
// / ledger / FW-Torque).
const Digest = "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"

// InputLen is the canonical KAT-1 input length: 1 byte version tag +
// 32 bytes zero corpus = 33 bytes.
const InputLen = 33

// VersionTag is the v1 1-byte tag prefix. Bumping this byte to v2 is
// a cohort-wide migration that invalidates every mark in flight.
const VersionTag byte = 0x01

// CanonicalInput returns the cohort-canonical 33-byte KAT-1 input
// (0x01 || 32×0x00). Pure: no runtime state; safe to call from a
// cold-verify regulator binary.
func CanonicalInput() []byte {
	out := make([]byte, InputLen)
	out[0] = VersionTag
	// indices 1..32 already zero-valued
	return out
}

// CanonicalKey returns the cohort-canonical KAT-1 HMAC key: empty
// (zero bytes). The empty-key form is intentional — KAT-1 is the
// substrate-parity oracle, not a tenant-secret-keyed receipt.
func CanonicalKey() []byte {
	return []byte{}
}

// Compute returns the HMAC-SHA256 hex digest for the cohort-canonical
// KAT-1 input + key. MUST byte-equal Digest. The test pin in
// lore_test.go is the bias-audit-side firewall.
//
// Pure stdlib; no heap allocs beyond the hex string. Safe to call in
// any hot path.
func Compute() string {
	mac := hmac.New(sha256.New, CanonicalKey())
	_, _ = mac.Write(CanonicalInput())
	return hex.EncodeToString(mac.Sum(nil))
}

// ComputeFor returns the HMAC-SHA256 hex digest for an arbitrary
// (input, key) pair. Used by callers (e.g. annual-audit row stamp
// fingerprinting, future SaaS tenant-key parity verification) to
// confirm byte-parity for non-KAT inputs.
func ComputeFor(input []byte, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(input)
	return hex.EncodeToString(mac.Sum(nil))
}
