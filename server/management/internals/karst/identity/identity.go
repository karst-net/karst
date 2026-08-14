// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package identity implements Karst node identities: ML-DSA-65 signing keys
// per ADR-0001 and PLAN.md §2.
//
// # Why not the standard library
//
// Go 1.26 *does* implement ML-DSA-44/65/87, in crypto/internal/fips140/mldsa,
// ACVP-tested — but only there. There is no public crypto/mldsa, and internal
// packages cannot be imported from outside the standard library. The pattern
// is the one ML-KEM followed: crypto/mlkem is a thin public wrapper over
// crypto/internal/fips140/mlkem, and it arrived in 1.24 after the internal
// implementation landed first. ML-DSA has done the internal half.
//
// So this package wraps cloudflare/circl, and is written to be deleted: it is
// deliberately a thin shim over one dependency, and channel.Signer /
// channel.Verifier are interfaces so that nothing above this layer knows which
// implementation is underneath. When crypto/mldsa ships, the swap is this file.
//
// circl is not merely a stopgap, though. Bedrock needs SLH-DSA-SHA2-192s
// (ADR-0001), and the standard library has no SLH-DSA at all — not even
// internally. circl has both, so it is a dependency either way.
package identity

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	// PublicKeySize is 1952 bytes.
	PublicKeySize = mldsa65.PublicKeySize
	// SignatureSize is 3309 bytes.
	SignatureSize = mldsa65.SignatureSize
	// SeedSize is 32 bytes; the seed is the thing worth protecting.
	SeedSize = mldsa65.SeedSize
)

// ControlContext domain-separates control-channel signatures from every other
// use of the same identity key.
//
// FIPS 204 gives signatures a context string, and it costs nothing to use it.
// Without one, a signature produced for the control channel would be a valid
// signature over the same bytes anywhere else the key is used — Bedrock
// countersignatures, audit-log entries, future protocols. That is only a
// theoretical problem until the day two transcripts collide, at which point it
// is not.
const ControlContext = "karst-control-v1"

var (
	ErrKeySize = errors.New("identity: wrong key size")
	ErrContext = errors.New("identity: context string exceeds 255 bytes")
)

// Key is a node's ML-DSA-65 identity keypair.
type Key struct {
	pub  *mldsa65.PublicKey
	priv *mldsa65.PrivateKey
}

// Generate creates a new identity from the system CSPRNG.
func Generate() (*Key, error) { return GenerateFrom(rand.Reader) }

// GenerateFrom creates one from a caller-supplied source, for tests.
func GenerateFrom(r io.Reader) (*Key, error) {
	pub, priv, err := mldsa65.GenerateKey(r)
	if err != nil {
		return nil, fmt.Errorf("identity: generate: %w", err)
	}
	return &Key{pub: pub, priv: priv}, nil
}

// FromSeed deterministically derives an identity from a 32-byte seed, so a
// node can re-derive its identity from sealed storage without persisting the
// expanded private key.
func FromSeed(seed []byte) (*Key, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("%w: seed is %d bytes, want %d", ErrKeySize, len(seed), SeedSize)
	}
	var s [SeedSize]byte
	copy(s[:], seed)
	pub, priv := mldsa65.NewKeyFromSeed(&s)
	return &Key{pub: pub, priv: priv}, nil
}

// Public returns the 1952-byte public key.
func (k *Key) Public() []byte { return k.pub.Bytes() }

// Sign produces a signature over msg under the given context string.
//
// Signing is *hedged* (randomized): FIPS 204 permits both, and the randomized
// form is the one that does not hand a fault-injection attacker a repeatable
// target. It costs one call to the CSPRNG.
func (k *Key) Sign(ctx, msg []byte) ([]byte, error) {
	if len(ctx) > 255 {
		return nil, ErrContext
	}
	sig := make([]byte, SignatureSize)
	if err := mldsa65.SignTo(k.priv, msg, ctx, true, sig); err != nil {
		return nil, fmt.Errorf("identity: sign: %w", err)
	}
	return sig, nil
}

// Verify checks a signature against a serialised public key.
//
// It returns false rather than an error on a malformed key, because every
// caller is in the middle of authenticating an attacker-supplied message and
// there is exactly one useful outcome.
func Verify(publicKey, ctx, msg, sig []byte) bool {
	if len(publicKey) != PublicKeySize || len(sig) != SignatureSize || len(ctx) > 255 {
		return false
	}
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(publicKey); err != nil {
		return false
	}
	return mldsa65.Verify(&pk, msg, ctx, sig)
}

// ControlSigner adapts a Key to channel.Signer, binding the control-channel
// context so a caller cannot forget it.
type ControlSigner struct{ Key *Key }

func (s ControlSigner) Sign(msg []byte) ([]byte, error) {
	return s.Key.Sign([]byte(ControlContext), msg)
}

func (s ControlSigner) PublicKey() []byte { return s.Key.Public() }

// ControlVerifier adapts to channel.Verifier with the same binding.
type ControlVerifier struct{}

func (ControlVerifier) Verify(publicKey, msg, sig []byte) bool {
	return Verify(publicKey, []byte(ControlContext), msg, sig)
}
