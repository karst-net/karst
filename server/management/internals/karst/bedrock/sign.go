// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Bedrock's two signature tiers — ADR-0015's Option A, ADR-0014 tiering.
//
// # Both tiers are ML-DSA-87, and that is a loss recorded on purpose
//
// The root was SLH-DSA-SHA2-192s, chosen by ADR-0001 *because it is not
// lattice-based*: if lattice cryptography falls it takes ML-KEM and ML-DSA
// together, and the ability to re-key the network was meant to survive that.
// ADR-0014 built the two-tier hierarchy on exactly that property.
//
// CNSA 2.0 excludes SLH-DSA — "not approved for any use in NSS" — and NSA does
// not plan to admit future NIST PQC standards. ADR-0015 records the decision to
// take ML-DSA-87 rather than the stateful LMS, and records what it costs:
// **there is no longer an assumption-diversity hedge above the authority tier.**
// A lattice break now takes the whole hierarchy, recovery path included.
//
// The tiers are therefore distinguished only by their context strings and by
// which key list they index into. ADR-0014 anticipated this in as many words —
// "a root signature must never be a valid authority signature and vice versa,
// **even though the algorithms differ today**, because the whole point of the
// rotatable authority tier is that they will not always differ." They no longer
// differ, and that separation is now the only thing keeping the tiers apart.
//
// circl is gone again. identity.go predicted it would "come back for Bedrock,
// which needs SLH-DSA-SHA2-192s"; Bedrock no longer needs it, so the module
// carries no post-quantum signature dependency outside the standard library.
//
// # Signing here is deterministic, and on the control channel it is not
//
// identity.go signs hedged (randomized) because a deterministic signature hands
// a fault-injection attacker a repeatable target. Bedrock signs
// deterministically, and the difference is deliberate.
//
// A control-channel key signs continuously on a networked server, where faults
// can be induced without holding the machine. A Bedrock key signs a handful of
// times during a deliberate ceremony on a machine that has no network interface
// at all — so a fault attack requires physical possession, at which point the
// key itself is available and the fault buys nothing.
//
// What determinism buys instead is reproducibility: a second admin can re-run a
// ceremony and get byte-identical output, which is the only practical check
// that the bundle an admin signed is the bundle they were shown. It is also
// what lets spec/vectors/bedrock-v1.json pin exact signature bytes rather than
// merely asserting that both implementations verify.
package bedrock

import (
	"crypto/mldsa"
	"errors"
	"fmt"
)

// Sizes, fixed by ADR-0015 (Category 5 throughout) and asserted in log_test.go.
const (
	// RootPublicKeySize is 2592 bytes (ML-DSA-87).
	RootPublicKeySize = mldsa.MLDSA87PublicKeySize
	// RootSignatureSize is 4627 bytes.
	//
	// Smaller than the 16 224 bytes SLH-DSA-192s produced, which is the one
	// consolation in ADR-0015's Option A: a thousand-node log shrinks rather
	// than grows.
	RootSignatureSize = mldsa.MLDSA87SignatureSize
	// RootSeedSize is 32 bytes. ML-DSA expands a seed, so unlike the FIPS 205
	// key this replaces there is a short form worth protecting and nothing
	// longer to store.
	RootSeedSize = mldsa.PrivateKeySize

	// AuthorityPublicKeySize is 2592 bytes (ML-DSA-87).
	AuthorityPublicKeySize = mldsa.MLDSA87PublicKeySize
	// AuthoritySignatureSize is 4627 bytes.
	AuthoritySignatureSize = mldsa.MLDSA87SignatureSize
	// AuthoritySeedSize is 32 bytes.
	AuthoritySeedSize = mldsa.PrivateKeySize

	// NodeIdentityKeySize is 2592 bytes — the ML-DSA-87 control-channel key a
	// node-sign covers.
	//
	// Numerically equal to AuthorityPublicKeySize now that ADR-0015 item 5 has
	// moved node identity to Category 5 as well. Kept as its own constant
	// because the two are different things that happen to share a size, and a
	// future tier split should not have to rediscover which call sites meant
	// which.
	NodeIdentityKeySize = mldsa.MLDSA87PublicKeySize
)

// Context strings. A root signature must never be a valid authority signature
// and vice versa, **even though the algorithms differ today** — ADR-0014 makes
// the authority tier rotatable, and the day it rotates this stops being
// guaranteed by the algorithm split alone.
//
// These follow identity.ControlContext's precedent, and deliberately share its
// "karst-…-v1" shape so that a reader who has seen one recognizes the other.
const (
	RootContext      = "karst-bedrock-v1 root"
	AuthorityContext = "karst-bedrock-v1 authority"
)

var (
	// ErrKeySize is returned when key material is the wrong length.
	ErrKeySize = errors.New("bedrock: wrong key size")
	// ErrSign is returned when the signature operation itself fails.
	ErrSign = errors.New("bedrock: signing failed")
)

// rootParams is the single place the root parameter set is named. Changing it
// is a wire-format change and an ADR amendment, not a tuning decision.
func rootParams() mldsa.Parameters { return mldsa.MLDSA87() }

// ── root tier ───────────────────────────────────────────────────────────────

// RootKey is an offline root signing key.
//
// In the intended deployment this type is only ever constructed on a machine
// with no network interface. Nothing on the coordination server holds one, and
// bedrock.Store deliberately has no column that could store one.
type RootKey struct {
	priv *mldsa.PrivateKey
}

// GenerateRoot creates a new root key.
func GenerateRoot() (*RootKey, error) {
	priv, err := mldsa.GenerateKey(rootParams())
	if err != nil {
		return nil, fmt.Errorf("bedrock: generate root: %w", err)
	}
	return &RootKey{priv: priv}, nil
}

// RootFromSeed derives a root key from its 32-byte seed.
func RootFromSeed(seed []byte) (*RootKey, error) {
	if len(seed) != RootSeedSize {
		return nil, fmt.Errorf("%w: root seed is %d bytes, want %d", ErrKeySize, len(seed), RootSeedSize)
	}
	priv, err := mldsa.NewPrivateKey(rootParams(), seed)
	if err != nil {
		return nil, fmt.Errorf("bedrock: root from seed: %w", err)
	}
	return &RootKey{priv: priv}, nil
}

// Seed returns the 32-byte seed, for writing to offline media.
//
// The seed is the whole secret: ML-DSA expands it deterministically, and the
// expanded form never needs to leave this process. That is a smaller thing to
// carry to an offline machine than the 96-byte FIPS 205 key it replaces, and a
// smaller thing to print as a paper backup.
func (k *RootKey) Seed() []byte { return k.priv.Bytes() }

// Public returns the 2592-byte public key.
func (k *RootKey) Public() []byte { return k.priv.PublicKey().Bytes() }

// Sign produces a deterministic signature over msg under RootContext.
func (k *RootKey) Sign(msg []byte) ([]byte, error) {
	sig, err := k.priv.SignDeterministic(msg, &mldsa.Options{Context: RootContext})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSign, err)
	}
	return sig, nil
}

// VerifyRoot checks a root signature under RootContext.
//
// It returns false rather than an error on malformed input, because every
// caller is in the middle of authenticating attacker-supplied bytes and there
// is exactly one useful outcome — the same convention as identity.Verify.
func VerifyRoot(publicKey, msg, sig []byte) bool {
	if len(publicKey) != RootPublicKeySize || len(sig) != RootSignatureSize {
		return false
	}
	pk, err := mldsa.NewPublicKey(rootParams(), publicKey)
	if err != nil {
		return false
	}
	return mldsa.Verify(pk, msg, sig, &mldsa.Options{Context: RootContext}) == nil
}

// ── authority tier ──────────────────────────────────────────────────────────

// AuthorityKey is an ML-DSA-65 authority signing key. It lives on an admin
// device, a subset of them offline.
type AuthorityKey struct {
	priv *mldsa.PrivateKey
}

// GenerateAuthority creates a new authority key.
func GenerateAuthority() (*AuthorityKey, error) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		return nil, fmt.Errorf("bedrock: generate authority: %w", err)
	}
	return &AuthorityKey{priv: priv}, nil
}

// AuthorityFromSeed derives an authority key from its 32-byte seed.
func AuthorityFromSeed(seed []byte) (*AuthorityKey, error) {
	if len(seed) != AuthoritySeedSize {
		return nil, fmt.Errorf("%w: authority seed is %d bytes, want %d", ErrKeySize, len(seed), AuthoritySeedSize)
	}
	priv, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), seed)
	if err != nil {
		return nil, fmt.Errorf("bedrock: authority from seed: %w", err)
	}
	return &AuthorityKey{priv: priv}, nil
}

// Public returns the 2592-byte public key.
func (k *AuthorityKey) Public() []byte { return k.priv.PublicKey().Bytes() }

// Sign produces a deterministic signature over msg under AuthorityContext.
func (k *AuthorityKey) Sign(msg []byte) ([]byte, error) {
	sig, err := k.priv.SignDeterministic(msg, &mldsa.Options{Context: AuthorityContext})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSign, err)
	}
	return sig, nil
}

// VerifyAuthority checks an authority signature under AuthorityContext.
func VerifyAuthority(publicKey, msg, sig []byte) bool {
	if len(publicKey) != AuthorityPublicKeySize || len(sig) != AuthoritySignatureSize {
		return false
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA87(), publicKey)
	if err != nil {
		return false
	}
	return mldsa.Verify(pk, msg, sig, &mldsa.Options{Context: AuthorityContext}) == nil
}
