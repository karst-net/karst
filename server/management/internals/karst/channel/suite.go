// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Control-channel cipher suites — ADR-0015 item 4.
//
// # One number gates both the format and the algorithms, on purpose
//
// `karst-control-v1.md` §3 has always said "suite negotiation is **not** in v1;
// the suite is implied by the protocol version". This file is that sentence
// made executable. The version in ChannelHello, ChannelInit and KarstEnvelope
// selects an entry here, and an entry names every algorithm the channel uses.
//
// **The point is that an algorithm cannot change without the version
// changing.** That is not hypothetical: ADR-0015 item 5 moved this channel's
// signature from ML-DSA-65 to ML-DSA-87, and because the version was a bare
// constant with no registry behind it, nothing objected. Nothing was deployed
// so nothing broke, but the same edit against a live fleet would have produced
// handshakes failing with `ErrSignature` and no indication why. A registry
// makes the omission visible: adding an algorithm means adding a row.
//
// # There is no negotiation here, and that is the design
//
// The data plane negotiates (ADR-0006) because two nodes configured by
// different people must agree. A control channel is one operator's node talking
// to the same operator's server, so there is nothing to discover — and a
// negotiation nobody needs is a downgrade surface nobody needs either.
//
// What replaces it is smaller and stronger:
//
//   - The server states its version. The node checks it against what it
//     implements *and* against a local floor, so a server cannot talk a node
//     down to a weaker suite. That is ADR-0006's rule — "a compromised
//     coordination server can raise the floor but cannot lower it" — applied
//     to the one channel ADR-0006 did not cover.
//   - A mismatch is legible. "This build does not implement version 2 (the
//     CNSA 2.0 suite)" is actionable; "unsupported version" is not, and a
//     silent handshake failure is worse than either.
//
// # Pin sizes come from the suite
//
// A node pins its server's static KEM key and verification key out of band, and
// **those keys carry the algorithm in their length**. A 1 184-byte pin is
// ML-KEM-768 and cannot be anything else. So the suite fixes the expected pin
// sizes, and a deployment configured for one version with pins from another
// fails at startup with a sentence naming both — rather than at the handshake,
// where the symptom is a node that cannot enroll for no visible reason.
package channel

import (
	"errors"
	"fmt"
)

// Suite is everything the control channel's cryptography is made of.
type Suite struct {
	// Version is the number on the wire.
	Version uint32
	// Name is for logs and errors, never for matching.
	Name string
	// KEMPublicKeySize is the size of the server's static ML-KEM key, which is
	// what a node pins.
	KEMPublicKeySize int
	// KEMCiphertextSize is the encapsulation size.
	KEMCiphertextSize int
	// SignaturePublicKeySize and SignatureSize describe the server and node
	// identity algorithm.
	SignaturePublicKeySize int
	SignatureSize          int
	// AEAD and Hash name the symmetric halves. Strings because nothing
	// dispatches on them yet — the implemented suite hardcodes both, and a
	// second suite is what turns these into a switch.
	AEAD string
	Hash string
	// Implemented reports whether this build can actually speak it. A known
	// version that is not implemented is a different failure from an unknown
	// one, and saying so is the difference between an actionable error and a
	// mystery.
	Implemented bool
}

var (
	// ErrUnknownVersion is returned for a version this build has never heard
	// of — a peer newer than this one, or a corrupted field.
	ErrUnknownVersion = errors.New("channel: unknown protocol version")
	// ErrNotImplemented is returned for a version this build knows about and
	// cannot speak.
	ErrNotImplemented = errors.New("channel: protocol version not implemented by this build")
	// ErrBelowMinimum is returned when a server offers a suite weaker than the
	// node's configured floor.
	ErrBelowMinimum = errors.New("channel: server offered a suite below this node's minimum")
)

// suiteV1 is the shipping suite.
//
// ML-DSA-87 rather than the ML-DSA-65 ADR-0011 originally specified: ADR-0015
// made CNSA 2.0 a mandate and Category 5 applies to every signature, so the
// change landed here before this registry existed to record it.
var suiteV1 = Suite{
	Version:                1,
	Name:                   "KARST_CONTROL_1_MLKEM768_MLDSA87_CHACHA20_SHA512",
	KEMPublicKeySize:       1184,
	KEMCiphertextSize:      1088,
	SignaturePublicKeySize: 2592,
	SignatureSize:          4627,
	AEAD:                   "ChaCha20-Poly1305",
	Hash:                   "SHA-512",
	Implemented:            true,
}

// suiteV2 is the CNSA 2.0 profile, reserved and not implemented.
//
// **Reserved rather than omitted.** A deployment under the mandate needs
// ML-KEM-1024 and AES-256-GCM here (ADR-0015 items 2 and 3); ChaCha20-Poly1305
// is not a NIST algorithm at all. Naming the version now means the failure is
// "this build does not implement version 2" rather than "unknown version 2",
// and it means the floor below is something an operator can already set and
// have refused honestly.
//
// **Both primitives now exist and this row is still not implemented**, which
// is the honest state: `crypto/mlkem` has carried ML-KEM-1024 all along and
// items 2 and 3 confirmed it against the standard's own constants, but
// `channel.go` names `mlkem.DecapsulationKey768` and ChaCha20-Poly1305
// directly, so speaking v2 is a matter of dispatching there. Flipping this
// flag before that happens would make the handshake advertise a suite it does
// not run — the exact defect FINDINGS 53 recorded on the data plane.
//
// **The data plane finished that dispatch on 2026-08-25** (ADR-0015 item 1),
// and item 7 then removed ChaCha20-Poly1305 from it outright. Both remaining
// PHREATIC suites are AES-256-GCM, which makes this channel the only place in
// the tree a CNSA 2.0 or FIPS 140-3 deployment is non-conformant. The work is
// the same shape and smaller — the control channel has no negotiation, no
// fragmentation and one hash — but it is work, and until it is done this flag
// stays false.
var suiteV2 = Suite{
	Version:                2,
	Name:                   "KARST_CONTROL_2_MLKEM1024_MLDSA87_AES256GCM_SHA512",
	KEMPublicKeySize:       1568,
	KEMCiphertextSize:      1568,
	SignaturePublicKeySize: 2592,
	SignatureSize:          4627,
	AEAD:                   "AES-256-GCM",
	Hash:                   "SHA-512",
	Implemented:            false,
}

// Suites is the complete registry. Adding an algorithm means adding a row;
// there is no other way to change what the channel does.
var Suites = []Suite{suiteV1, suiteV2}

// SuiteFor returns the suite a version selects.
func SuiteFor(version uint32) (Suite, error) {
	for _, s := range Suites {
		if s.Version == version {
			if !s.Implemented {
				return s, fmt.Errorf("%w: version %d is %s", ErrNotImplemented, version, s.Name)
			}
			return s, nil
		}
	}
	return Suite{}, fmt.Errorf("%w: %d", ErrUnknownVersion, version)
}

// Negotiate resolves the version a server offered against what this node will
// accept.
//
// `minimum` is the node's floor. A server offering below it is refused even
// though this build could speak it, which is the whole point: an operator who
// has configured a CNSA deployment must not be silently served the weaker
// suite by a server that has been compromised or misconfigured.
func Negotiate(offered, minimum uint32) (Suite, error) {
	if offered < minimum {
		return Suite{}, fmt.Errorf("%w: offered %d, minimum %d", ErrBelowMinimum, offered, minimum)
	}
	return SuiteFor(offered)
}

// CheckPins reports whether pinned server keys match the suite's algorithms.
//
// The pin lengths *are* the algorithm — a 1 184-byte key is ML-KEM-768 and
// nothing else — so this catches a deployment configured for one version with
// pins from another, at startup, with both numbers named. The alternative is a
// handshake that fails with a signature or decapsulation error and sends
// somebody looking in the wrong place entirely.
func (s Suite) CheckPins(staticKEM, verifyKey []byte) error {
	if len(staticKEM) != s.KEMPublicKeySize {
		return fmt.Errorf(
			"channel: server_kem_pin is %d bytes, but version %d (%s) uses a %d-byte key",
			len(staticKEM), s.Version, s.Name, s.KEMPublicKeySize)
	}
	if len(verifyKey) != s.SignaturePublicKeySize {
		return fmt.Errorf(
			"channel: server_verify_pin is %d bytes, but version %d (%s) uses a %d-byte key",
			len(verifyKey), s.Version, s.Name, s.SignaturePublicKeySize)
	}
	return nil
}
