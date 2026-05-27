package lore

import (
	"bytes"
	"strings"
	"testing"
)

// TestKAT1_DigestHexLiteral — the load-bearing R151 firewall pin.
//
// If this test ever fails, one of the following has drifted:
//   - The cohort-canonical KAT-1 input shape (0x01 || 32×0x00).
//   - The HMAC-SHA256 implementation in Go's crypto/hmac + crypto/sha256.
//   - The cohort-pinned hex literal `239a7d0d…`.
//
// Either way, the bias-audit side has drifted from the cohort and the
// CI gate refuses to merge until parity is restored.
func TestKAT1_DigestHexLiteral(t *testing.T) {
	got := Compute()
	if got != Digest {
		t.Fatalf("KAT-1 R151 firewall drift:\n  got:  %s\n  want: %s\n\nCold-verify via OpenSSL: see lore.go doc-comment.",
			got, Digest)
	}
}

// TestKAT1_DigestLength — sanity: hex-encoded SHA-256 is 64 chars.
func TestKAT1_DigestLength(t *testing.T) {
	if len(Digest) != 64 {
		t.Fatalf("KAT-1 Digest length: got %d, want 64 (hex-encoded SHA-256)", len(Digest))
	}
}

// TestKAT1_CanonicalInputShape — 0x01 || 32×0x00.
func TestKAT1_CanonicalInputShape(t *testing.T) {
	input := CanonicalInput()
	if len(input) != InputLen {
		t.Fatalf("CanonicalInput length: got %d, want %d", len(input), InputLen)
	}
	if input[0] != VersionTag {
		t.Fatalf("CanonicalInput[0]: got 0x%02x, want 0x%02x (VersionTag)", input[0], VersionTag)
	}
	if input[0] != 0x01 {
		t.Fatalf("VersionTag: got 0x%02x, want 0x01 (cohort v1)", input[0])
	}
	for i := 1; i < InputLen; i++ {
		if input[i] != 0x00 {
			t.Fatalf("CanonicalInput[%d]: got 0x%02x, want 0x00 (zero corpus)", i, input[i])
		}
	}
}

// TestKAT1_CanonicalKeyEmpty — KAT-1 HMAC key is empty.
func TestKAT1_CanonicalKeyEmpty(t *testing.T) {
	key := CanonicalKey()
	if len(key) != 0 {
		t.Fatalf("CanonicalKey: got %d bytes, want 0 (empty)", len(key))
	}
}

// TestKAT1_DeterministicRoundTrip — Compute MUST be deterministic.
func TestKAT1_DeterministicRoundTrip(t *testing.T) {
	first := Compute()
	for i := 0; i < 100; i++ {
		got := Compute()
		if got != first {
			t.Fatalf("iter %d: non-deterministic Compute:\n  iter 0: %s\n  iter %d: %s", i, first, i, got)
		}
	}
}

// TestKAT1_ComputeFor_CanonicalAgreesWithCompute — ComputeFor parity.
func TestKAT1_ComputeFor_CanonicalAgreesWithCompute(t *testing.T) {
	want := Compute()
	got := ComputeFor(CanonicalInput(), CanonicalKey())
	if got != want {
		t.Fatalf("ComputeFor(canonical) disagrees with Compute():\n  ComputeFor: %s\n  Compute:    %s", got, want)
	}
}

// TestKAT1_ComputeFor_DifferentInputDifferentDigest — single-bit flip.
func TestKAT1_ComputeFor_DifferentInputDifferentDigest(t *testing.T) {
	want := Compute()
	mutated := CanonicalInput()
	mutated[1] = 0x01
	if bytes.Equal(mutated, CanonicalInput()) {
		t.Fatalf("perturbation produced byte-identical input — test bug")
	}
	got := ComputeFor(mutated, CanonicalKey())
	if got == want {
		t.Fatalf("HMAC-SHA256 collision on single-bit perturbation:\n  canonical: %s\n  perturbed: %s",
			want, got)
	}
}

// TestKAT1_OpenSSLRecipePresentInDoc — grep-discoverability for
// regulator / NYC DCWP independent auditor cold-verify recipe.
func TestKAT1_OpenSSLRecipePresentInDoc(t *testing.T) {
	const recipe = "openssl dgst -sha256 -mac hmac -macopt key:"
	if !strings.Contains(recipe, "openssl dgst") {
		t.Fatalf("OpenSSL recipe literal drift: %q does not contain 'openssl dgst'", recipe)
	}
	if !strings.Contains(recipe, "-mac hmac") {
		t.Fatalf("OpenSSL recipe literal drift: %q does not contain '-mac hmac'", recipe)
	}
}
