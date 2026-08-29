// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package identity implements Karst node identities: ML-DSA-87 signing keys
// per ADR-0015 and PLAN.md §2.
//
// **ML-DSA-87, not the ML-DSA-65 ADR-0001 originally specified.** CNSA 2.0 is
// Category 5 throughout (ADR-0015), and this key is a signature key, so it
// moved with everything else. The change is not cosmetic: a node handle is a
// hash of this key, so every handle in a deployment changes with it. That was
// affordable exactly once — before anything shipped — and this is that once.
//
// # This package was written to be deleted, and most of it now has been
//
// Until Go 1.27 there was no public crypto/mldsa. Go 1.26 implemented
// ML-DSA-44/65/87 in crypto/internal/fips140/mldsa, ACVP-tested — but only
// there, and internal packages cannot be imported from outside the standard
// library. So this package wrapped cloudflare/circl behind channel.Signer and
// channel.Verifier, deliberately thin, so that the swap would be one file.
//
// Go 1.27 shipped crypto/mldsa and this is that swap. It removes circl from the
// module entirely: nothing else imported it. **It will come back for Bedrock**,
// which needs SLH-DSA-SHA2-192s (ADR-0001) and which the standard library has
// no implementation of, internal or otherwise — so this is a dependency
// deferred to Phase 5 rather than one avoided.
//
// # The swap was checked for byte-compatibility, not assumed
//
// Both libraries implement FIPS 204, which is a strong argument that a seed
// derives the same key under each and not a proof. It matters more than usual
// here: a node's handle is a hash of its public key, so a disagreement would
// silently re-identify every enrolled node rather than fail. TestSeedIsStable
// pins the value produced by circl before the migration.
//
// # crypto/mldsa is unavailable under FIPS 140-3 module v1.0.0
//
// In that mode every constructor here returns an error rather than a key, which
// surfaces at startup as a failure to load an identity. That is the right
// failure: a build that cannot do ML-DSA cannot run Karst's control plane at
// all, and the alternative to failing loudly would be a node that enrolls with
// no post-quantum authentication.
package identity

import (
	"crypto/mldsa"
	"errors"
	"fmt"
)

const (
	// PublicKeySize is 2592 bytes.
	PublicKeySize = mldsa.MLDSA87PublicKeySize
	// SignatureSize is 4627 bytes.
	SignatureSize = mldsa.MLDSA87SignatureSize
	// SeedSize is 32 bytes; the seed is the thing worth protecting.
	//
	// crypto/mldsa calls this PrivateKeySize, because a seed is the only
	// private key it will serialize — the expanded form never leaves the
	// package. The name here stays SeedSize because that is what the rest of
	// Karst calls it and because it is the more honest of the two.
	SeedSize = mldsa.PrivateKeySize
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
	priv *mldsa.PrivateKey
}

// Generate creates a new identity.
//
// The randomness comes from the FIPS module rather than from a caller-supplied
// reader: crypto/mldsa takes none, and the io.Reader parameter this package
// used to expose existed only so a test could pass rand.Reader explicitly.
// Nothing depended on it.
func Generate() (*Key, error) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		return nil, fmt.Errorf("identity: generate: %w", err)
	}
	return &Key{priv: priv}, nil
}

// FromSeed deterministically derives an identity from a 32-byte seed, so a
// node can re-derive its identity from sealed storage without persisting the
// expanded private key.
func FromSeed(seed []byte) (*Key, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("%w: seed is %d bytes, want %d", ErrKeySize, len(seed), SeedSize)
	}
	priv, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), seed)
	if err != nil {
		return nil, fmt.Errorf("identity: from seed: %w", err)
	}
	return &Key{priv: priv}, nil
}

// Public returns the 2592-byte public key.
func (k *Key) Public() []byte { return k.priv.PublicKey().Bytes() }

// Sign produces a signature over msg under the given context string.
//
// Signing is *hedged* (randomized): FIPS 204 permits both, and the randomized
// form is the one that does not hand a fault-injection attacker a repeatable
// target. crypto/mldsa spells the two apart as Sign and SignDeterministic, so
// the choice is now visible at the call site rather than a boolean argument —
// which is an improvement, because the boolean was easy to read backwards.
//
// The io.Reader argument is ignored by crypto/mldsa; the module supplies its
// own randomness. Passing nil is what the standard library's own examples do.
func (k *Key) Sign(ctx, msg []byte) ([]byte, error) {
	if len(ctx) > 255 {
		return nil, ErrContext
	}
	sig, err := k.priv.Sign(nil, msg, &mldsa.Options{Context: string(ctx)})
	if err != nil {
		return nil, fmt.Errorf("identity: sign: %w", err)
	}
	return sig, nil
}

// Verify checks a signature against a serialized public key.
//
// It returns false rather than an error on a malformed key, because every
// caller is in the middle of authenticating an attacker-supplied message and
// there is exactly one useful outcome.
func Verify(publicKey, ctx, msg, sig []byte) bool {
	if len(publicKey) != PublicKeySize || len(sig) != SignatureSize || len(ctx) > 255 {
		return false
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA87(), publicKey)
	if err != nil {
		return false
	}
	return mldsa.Verify(pk, msg, sig, &mldsa.Options{Context: string(ctx)}) == nil
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
