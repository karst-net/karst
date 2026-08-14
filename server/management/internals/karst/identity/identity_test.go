// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package identity

import (
	"bytes"
	"testing"
)

func TestSizesMatchTheSpec(t *testing.T) {
	// PLAN.md §2 quotes these; if circl ever disagrees, the netmap and the
	// handshake budget are both wrong and it should fail here first.
	if PublicKeySize != 1952 {
		t.Errorf("public key: got %d want 1952", PublicKeySize)
	}
	if SignatureSize != 3309 {
		t.Errorf("signature: got %d want 3309", SignatureSize)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	msg := []byte("transcript")
	sig, err := k.Sign([]byte(ControlContext), msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("signature length: got %d want %d", len(sig), SignatureSize)
	}
	if !Verify(k.Public(), []byte(ControlContext), msg, sig) {
		t.Fatal("valid signature did not verify")
	}
}

// The context string is the whole point of ControlContext: a signature made
// for the control channel must not verify anywhere else.
func TestContextSeparatesDomains(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	msg := []byte("same bytes, different purpose")
	sig, err := k.Sign([]byte(ControlContext), msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if Verify(k.Public(), []byte("karst-bedrock-v1"), msg, sig) {
		t.Fatal("a control-channel signature verified under a different context")
	}
	if Verify(k.Public(), nil, msg, sig) {
		t.Fatal("a control-channel signature verified with no context")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	msg := []byte("m")
	sig, err := a.Sign([]byte(ControlContext), msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if Verify(b.Public(), []byte(ControlContext), msg, sig) {
		t.Fatal("signature verified under the wrong public key")
	}
}

func TestTamperedMessageAndSignatureRejected(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	msg := []byte("original")
	sig, err := k.Sign([]byte(ControlContext), msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if Verify(k.Public(), []byte(ControlContext), []byte("tampered"), sig) {
		t.Fatal("signature verified over a different message")
	}
	bad := bytes.Clone(sig)
	bad[0] ^= 0xFF
	if Verify(k.Public(), []byte(ControlContext), msg, bad) {
		t.Fatal("tampered signature verified")
	}
}

// Verify must not panic or misbehave on attacker-supplied garbage: every call
// is in the middle of authenticating an unauthenticated message.
func TestVerifyRejectsMalformedInputs(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	msg := []byte("m")
	sig, err := k.Sign([]byte(ControlContext), msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	cases := []struct {
		name string
		pub  []byte
		sig  []byte
		ctx  []byte
	}{
		{"nil public key", nil, sig, []byte(ControlContext)},
		{"empty public key", []byte{}, sig, []byte(ControlContext)},
		{"short public key", k.Public()[:10], sig, []byte(ControlContext)},
		{"long public key", append(bytes.Clone(k.Public()), 0), sig, []byte(ControlContext)},
		{"nil signature", k.Public(), nil, []byte(ControlContext)},
		{"short signature", k.Public(), sig[:10], []byte(ControlContext)},
		{"oversized context", k.Public(), sig, bytes.Repeat([]byte{'x'}, 256)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if Verify(tc.pub, tc.ctx, msg, tc.sig) {
				t.Fatal("verified")
			}
		})
	}
}

func TestSeedDeterminism(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, SeedSize)
	a, err := FromSeed(seed)
	if err != nil {
		t.Fatalf("from seed: %v", err)
	}
	b, err := FromSeed(seed)
	if err != nil {
		t.Fatalf("from seed: %v", err)
	}
	if !bytes.Equal(a.Public(), b.Public()) {
		t.Fatal("the same seed produced two different identities")
	}

	other, err := FromSeed(bytes.Repeat([]byte{8}, SeedSize))
	if err != nil {
		t.Fatalf("from seed: %v", err)
	}
	if bytes.Equal(a.Public(), other.Public()) {
		t.Fatal("different seeds produced the same identity")
	}
}

func TestFromSeedRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 1, SeedSize - 1, SeedSize + 1} {
		if _, err := FromSeed(bytes.Repeat([]byte{1}, n)); err == nil {
			t.Fatalf("seed of %d bytes was accepted", n)
		}
	}
}

// Hedged signing means two signatures over the same message differ. Both must
// verify; a deterministic scheme would be a change worth noticing.
func TestSigningIsHedged(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	msg := []byte("m")
	first, err := k.Sign([]byte(ControlContext), msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	second, err := k.Sign([]byte(ControlContext), msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two signatures over the same message were identical: signing is not hedged")
	}
	if !Verify(k.Public(), []byte(ControlContext), msg, first) ||
		!Verify(k.Public(), []byte(ControlContext), msg, second) {
		t.Fatal("a hedged signature failed to verify")
	}
}

func TestOversizedContextRefusedOnSign(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := k.Sign(bytes.Repeat([]byte{'x'}, 256), []byte("m")); err != ErrContext {
		t.Fatalf("got %v want %v", err, ErrContext)
	}
}
