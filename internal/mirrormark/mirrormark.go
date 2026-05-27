// Package mirrormark implements the cohort L43 Mirror-Mark v1 receipt
// algorithm — byte-identical to foundation/pkg/mirrormark and to every
// cohort Go port (canopy / casino / ledger / folio / pulse / baseline /
// etc.).
//
// A Mirror-Mark is a 62-character receipt stamped on a canonical
// payload that proves: (a) which lore corpus signed it (8-byte
// prefix), (b) the payload was unmodified since signing
// (HMAC-SHA256 with corpus-prefixed input). The cohort uses
// Mirror-Marks to gate regulator-grade-AI artefacts: any output that
// crosses a trust boundary carries a Mark, and any consumer with the
// corpus SHA + the key can cold-verify the receipt without trusting
// the upstream.
//
// Why bias-audit consumes this today (R175 R-MIRROR-MARK-LOAD-BEARING-
// IN-PRODUCTION canonical wire):
//
//   - bias-audit is the SaaS productisation of NYC LL144 AEDT + EU AI
//     Act HR-bias-audit. Every annual-audit-ledger row that an NYC
//     DCWP independent auditor or EU notified body downloads MUST
//     carry a Mirror-Mark — the regulator can cold-verify the row was
//     not modified between bias-audit generation and regulator
//     receipt, without trusting the tenant's filesystem.
//   - Byte-identical algorithm to canopy/internal/mirrormark and to
//     foundation/pkg/mirrormark — the N-of-N byte-identical
//     implementation IS the cohort firewall. A future R145-strict
//     additive sweep can replace this package with
//     `import "github.com/davly/foundation/pkg/mirrormark"`;
//     today the local implementation lets bias-audit stay
//     zero-`go.mod`-requires from inception per R174.
//   - Cohort-port FROM INCEPTION per R174 5-of-5 strict (memoria +
//     conjure precedent) — bias-audit lands the 5-package shape on
//     day one, not as a later uplift.
//
// Mark format (byte-identical to foundation/pkg/mirrormark):
//
//	"lore@v1:" + base64url( corpusSHA[:8] || hmacSHA256(0x01 || corpusSHA || payload, key) )
//
// Resulting in a fixed 62-character string: `lore@v1:` prefix (8
// chars) + 54-char base64url body (40 raw bytes encoded).
package mirrormark

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// MarkVersion is the 1-byte tag prefixing the HMAC input.
const MarkVersion byte = 0x01

// MarkPrefix is the documented header-value prefix.
const MarkPrefix = "lore@v1:"

// MarkCorpusPrefixLen is the corpus-SHA prefix length (8 bytes).
const MarkCorpusPrefixLen = 8

// MarkBodyLen is the unencoded length of the mark body (40 bytes).
// Base64URL-encoded, this becomes the fixed 54-character suffix.
const MarkBodyLen = MarkCorpusPrefixLen + sha256.Size

// ErrUnknownMarkVersion — mark missing canonical prefix.
var ErrUnknownMarkVersion = errors.New("mirrormark: unknown mark version (missing 'lore@v1:' prefix)")

// ErrMalformedMark — base64url decode failed or wrong body length.
var ErrMalformedMark = errors.New("mirrormark: malformed mark (base64url decode failed or wrong body length)")

// ErrCorpusMismatch — corpus prefix in mark != supplied corpus SHA.
var ErrCorpusMismatch = errors.New("mirrormark: corpus prefix mismatch (mark signed by different corpus)")

// ErrSignatureMismatch — HMAC digest mismatch (payload or key wrong).
var ErrSignatureMismatch = errors.New("mirrormark: HMAC signature mismatch (payload tampered or wrong key)")

// Sign returns the canonical Mirror-Mark string for the given payload.
//
// Byte-identical to foundation/pkg/mirrormark.Sign — the test pin
// `TestVerify_KAT*Mark` confirms parity.
func Sign(corpusSHA [sha256.Size]byte, payload []byte, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte{MarkVersion})
	_, _ = mac.Write(corpusSHA[:])
	_, _ = mac.Write(payload)
	digest := mac.Sum(nil)

	body := make([]byte, 0, MarkBodyLen)
	body = append(body, corpusSHA[:MarkCorpusPrefixLen]...)
	body = append(body, digest...)

	return MarkPrefix + base64.RawURLEncoding.EncodeToString(body)
}

// Verify cold-checks a Mirror-Mark against the caller's (corpus,
// payload, key) triple. Returns nil on match; one of the typed
// sentinel errors on any failure.
//
// Both byte-comparisons use hmac.Equal (constant-time) — timing-safe.
func Verify(mark string, corpusSHA [sha256.Size]byte, payload []byte, key []byte) error {
	if len(mark) < len(MarkPrefix) || mark[:len(MarkPrefix)] != MarkPrefix {
		return ErrUnknownMarkVersion
	}
	body, err := base64.RawURLEncoding.DecodeString(mark[len(MarkPrefix):])
	if err != nil {
		return ErrMalformedMark
	}
	if len(body) != MarkBodyLen {
		return ErrMalformedMark
	}
	corpusPrefix := body[:MarkCorpusPrefixLen]
	digest := body[MarkCorpusPrefixLen:]
	if !hmac.Equal(corpusPrefix, corpusSHA[:MarkCorpusPrefixLen]) {
		return ErrCorpusMismatch
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte{MarkVersion})
	_, _ = mac.Write(corpusSHA[:])
	_, _ = mac.Write(payload)
	want := mac.Sum(nil)
	if !hmac.Equal(digest, want) {
		return ErrSignatureMismatch
	}
	return nil
}
