package mirrormark

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// Cohort-canonical KAT-1 mark literal. Byte-identical to every cohort
// Go port (canopy / casino / ledger / pulse / baseline / foundry /
// oracle / iris / nexus / folio / ouroboros / etc.).
const kat1Mark = "lore@v1:AAAAAAAAAAAjmn0NPxu-Opiu3gHirYGMLbYLcXfALi8BUDWytbfbyg"

// Cohort-canonical KAT-6 mark literal.
const kat6Mark = "lore@v1:MzMzMzMzMzNDXUcWs_KJVkPQfl3-ykizfhchYGxWCw-IoxKxgijBOw"

// Cohort-canonical KAT-7 mark literal.
const kat7Mark = "lore@v1:AAECAwQFBgdXSiwQoZ5vwuA9nIqeZ_2v8tfAsQWV2ow_OiE34Pud_w"

// KAT-1 HMAC-SHA256 digest hex (same hex as internal/lore.Digest).
const kat1DigestHex = "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"

// TestSign_RoundtripVerify — happy-path: signed mark round-trips.
func TestSign_RoundtripVerify(t *testing.T) {
	for i := 0; i < 32; i++ {
		var corpus [sha256.Size]byte
		if _, err := rand.Read(corpus[:]); err != nil {
			t.Fatalf("iter %d: rand corpus: %v", i, err)
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatalf("iter %d: rand key: %v", i, err)
		}
		payload := make([]byte, 64)
		if _, err := rand.Read(payload); err != nil {
			t.Fatalf("iter %d: rand payload: %v", i, err)
		}
		mark := Sign(corpus, payload, key)
		if !strings.HasPrefix(mark, MarkPrefix) {
			t.Fatalf("iter %d: missing prefix: %q", i, mark)
		}
		if err := Verify(mark, corpus, payload, key); err != nil {
			t.Fatalf("iter %d: Verify rejected fresh mark: %v", i, err)
		}
	}
}

// TestVerify_KAT1Mark — cohort substrate-parity oracle.
func TestVerify_KAT1Mark(t *testing.T) {
	var zeroCorpus [sha256.Size]byte
	if err := Verify(kat1Mark, zeroCorpus, []byte{}, []byte{}); err != nil {
		t.Fatalf("KAT-1 cohort literal failed Verify: %v\n\nThe bias-audit mirrormark algorithm has drifted from the cohort.", err)
	}
}

// TestVerify_KAT6Mark — 0x33 corpus + "hello world" + "iik_hello".
func TestVerify_KAT6Mark(t *testing.T) {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = 0x33
	}
	if err := Verify(kat6Mark, corpus, []byte("hello world"), []byte("iik_hello")); err != nil {
		t.Fatalf("KAT-6 cohort literal failed Verify: %v", err)
	}
}

// TestVerify_KAT7Mark — identity corpus + pulse JSON + pulse key.
func TestVerify_KAT7Mark(t *testing.T) {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = byte(i)
	}
	payload := []byte(`{"probeId":"https-google","verdict":"red","ms":5000,"error":"connection-timeout"}`)
	key := []byte("iik_pulse_kat_probe_failure")
	if err := Verify(kat7Mark, corpus, payload, key); err != nil {
		t.Fatalf("KAT-7 cohort literal failed Verify: %v", err)
	}
}

// TestSign_ProducesKAT1Mark — Sign reproduces published literal.
func TestSign_ProducesKAT1Mark(t *testing.T) {
	var zeroCorpus [sha256.Size]byte
	got := Sign(zeroCorpus, []byte{}, []byte{})
	if got != kat1Mark {
		t.Fatalf("Sign for KAT-1 input drift:\n  got:  %q\n  want: %q", got, kat1Mark)
	}
}

// TestSign_ProducesKAT6Mark — KAT-6 inputs reproduce literal.
func TestSign_ProducesKAT6Mark(t *testing.T) {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = 0x33
	}
	got := Sign(corpus, []byte("hello world"), []byte("iik_hello"))
	if got != kat6Mark {
		t.Fatalf("Sign for KAT-6 input drift:\n  got:  %q\n  want: %q", got, kat6Mark)
	}
}

// TestSign_ProducesKAT7Mark — KAT-7 inputs reproduce literal.
func TestSign_ProducesKAT7Mark(t *testing.T) {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = byte(i)
	}
	payload := []byte(`{"probeId":"https-google","verdict":"red","ms":5000,"error":"connection-timeout"}`)
	key := []byte("iik_pulse_kat_probe_failure")
	got := Sign(corpus, payload, key)
	if got != kat7Mark {
		t.Fatalf("Sign for KAT-7 input drift:\n  got:  %q\n  want: %q", got, kat7Mark)
	}
}

// TestKAT1Digest_EmbeddedInKAT1Mark — connects mark literal → OpenSSL.
func TestKAT1Digest_EmbeddedInKAT1Mark(t *testing.T) {
	encoded := strings.TrimPrefix(kat1Mark, MarkPrefix)
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("KAT-1 mark body not valid base64.RawURLEncoding: %v", err)
	}
	if len(body) != MarkBodyLen {
		t.Fatalf("KAT-1 body length: got %d want %d", len(body), MarkBodyLen)
	}
	gotDigestHex := hex.EncodeToString(body[MarkCorpusPrefixLen:])
	if gotDigestHex != kat1DigestHex {
		t.Fatalf("KAT-1 embedded-digest drift:\n  got:      %s\n  expected: %s", gotDigestHex, kat1DigestHex)
	}
}

// TestSign_InlineStdlibReDerivation_AgreesWithSign — R132 mutual.
func TestSign_InlineStdlibReDerivation_AgreesWithSign(t *testing.T) {
	var corpus [sha256.Size]byte
	copy(corpus[:], bytes.Repeat([]byte{0x77}, sha256.Size))
	key := []byte("bias_audit_internal_test_key")
	payload := []byte(`{"id":"test","data":"bias-audit"}`)

	pathSign := Sign(corpus, payload, key)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte{0x01})
	mac.Write(corpus[:])
	mac.Write(payload)
	digest := mac.Sum(nil)
	body := make([]byte, 0, MarkBodyLen)
	body = append(body, corpus[:MarkCorpusPrefixLen]...)
	body = append(body, digest...)
	pathInline := "lore@v1:" + base64.RawURLEncoding.EncodeToString(body)

	if pathSign != pathInline {
		t.Fatalf("Sign vs inline stdlib drift:\n  Sign:   %q\n  inline: %q", pathSign, pathInline)
	}
}

// TestVerify_RejectsMissingPrefix — non-Mirror-Mark string.
func TestVerify_RejectsMissingPrefix(t *testing.T) {
	var corpus [sha256.Size]byte
	err := Verify("not-a-mark", corpus, []byte{}, []byte("k"))
	if err != ErrUnknownMarkVersion {
		t.Fatalf("missing-prefix: got %v, want ErrUnknownMarkVersion", err)
	}
}

// TestVerify_RejectsMalformedBase64 — invalid base64 body.
func TestVerify_RejectsMalformedBase64(t *testing.T) {
	var corpus [sha256.Size]byte
	err := Verify("lore@v1:!!!not-base64!!!", corpus, []byte{}, []byte("k"))
	if err != ErrMalformedMark {
		t.Fatalf("malformed-base64: got %v, want ErrMalformedMark", err)
	}
}

// TestVerify_RejectsWrongCorpus — corpus A signed, corpus B passed.
func TestVerify_RejectsWrongCorpus(t *testing.T) {
	var corpusA, corpusB [sha256.Size]byte
	for i := range corpusA {
		corpusA[i] = 0x11
		corpusB[i] = 0x22
	}
	key := []byte("k")
	payload := []byte("p")
	markA := Sign(corpusA, payload, key)
	err := Verify(markA, corpusB, payload, key)
	if err != ErrCorpusMismatch {
		t.Fatalf("wrong-corpus: got %v, want ErrCorpusMismatch", err)
	}
}

// TestVerify_RejectsTamperedPayload — payload mutation.
func TestVerify_RejectsTamperedPayload(t *testing.T) {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = 0x44
	}
	key := []byte("k")
	payloadA := []byte("original audit-row")
	payloadB := []byte("tampered audit-row")
	markA := Sign(corpus, payloadA, key)
	err := Verify(markA, corpus, payloadB, key)
	if err != ErrSignatureMismatch {
		t.Fatalf("tampered-payload: got %v, want ErrSignatureMismatch", err)
	}
}

// TestVerify_RejectsTamperedKey — key mutation.
func TestVerify_RejectsTamperedKey(t *testing.T) {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = 0x55
	}
	payload := []byte("p")
	keyA := []byte("alice")
	keyB := []byte("bob")
	markA := Sign(corpus, payload, keyA)
	err := Verify(markA, corpus, payload, keyB)
	if err != ErrSignatureMismatch {
		t.Fatalf("tampered-key: got %v, want ErrSignatureMismatch", err)
	}
}

// TestMarkLength_FixedAt62 — every Mirror-Mark v1 is 62 chars.
func TestMarkLength_FixedAt62(t *testing.T) {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = byte(i * 3)
	}
	mark := Sign(corpus, []byte("anything"), []byte("k"))
	if len(mark) != 62 {
		t.Fatalf("Mark length: got %d, want 62 (8 prefix + 54 body)", len(mark))
	}
	if len(MarkPrefix) != 8 {
		t.Fatalf("MarkPrefix length: got %d, want 8", len(MarkPrefix))
	}
}
