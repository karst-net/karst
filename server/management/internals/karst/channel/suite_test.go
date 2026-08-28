// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package channel

import (
	"crypto/mlkem"
	"errors"
	"strings"
	"testing"
)

func TestShippingSuiteResolves(t *testing.T) {
	s, err := SuiteFor(1)
	if err != nil {
		t.Fatalf("v1 must be implemented: %v", err)
	}
	if s.KEMPublicKeySize != 1184 || s.SignaturePublicKeySize != 2592 || s.SignatureSize != 4627 {
		t.Fatalf("v1 sizes drifted: %+v", s)
	}
}

// A reserved version fails differently from an invented one. That distinction
// is the whole reason v2 is in the registry rather than absent from it: one
// error tells an operator to get a different build, the other tells them
// something is corrupt.
func TestReservedVersionIsDistinguishableFromUnknown(t *testing.T) {
	if _, err := SuiteFor(2); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("v2 must be ErrNotImplemented, got %v", err)
	}
	for _, v := range []uint32{0, 3, 99} {
		if _, err := SuiteFor(v); !errors.Is(err, ErrUnknownVersion) {
			t.Fatalf("version %d must be ErrUnknownVersion, got %v", v, err)
		}
	}
}

// **A server may not talk a node down.** The node's floor wins even when this
// build could happily speak what was offered.
func TestServerCannotOfferBelowTheNodesFloor(t *testing.T) {
	if _, err := Negotiate(1, 1); err != nil {
		t.Fatalf("v1 at floor 1 must succeed: %v", err)
	}
	if _, err := Negotiate(1, 2); !errors.Is(err, ErrBelowMinimum) {
		t.Fatalf("v1 under floor 2 must be ErrBelowMinimum, got %v", err)
	}
	// A floor above anything implemented refuses everything, which is correct:
	// a node configured for a suite this build cannot speak must not fall back
	// to one it can.
	if _, err := Negotiate(2, 2); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("v2 at floor 2 must be ErrNotImplemented, got %v", err)
	}
}

func TestPinsAreCheckedAgainstTheSuiteNotAConstant(t *testing.T) {
	s, err := SuiteFor(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckPins(make([]byte, 1184), make([]byte, 2592)); err != nil {
		t.Fatalf("correct pins rejected: %v", err)
	}
	err = s.CheckPins(make([]byte, 1568), make([]byte, 2592))
	if err == nil {
		t.Fatal("a v2-sized KEM pin was accepted for v1")
	}
	// Both numbers must appear, so an operator is told what they have and what
	// the configured version wants rather than merely that something is wrong.
	if msg := err.Error(); !strings.Contains(msg, "1568") || !strings.Contains(msg, "1184") {
		t.Fatalf("error names only one size: %s", msg)
	}
}

// **The registry's KEM sizes must be the standard's, not typed numbers.**
//
// ADR-0015 item 3 put ML-KEM-1024 in the tree, and v2's row claimed its sizes
// before any of it existed. Checking them against `crypto/mlkem`'s own
// constants is what turns that row from an assertion into a fact — and it is
// the only check that would catch a transposed digit in a suite nothing yet
// speaks.
func TestRegistryKEMSizesMatchTheStandard(t *testing.T) {
	for _, s := range Suites {
		var wantPK, wantCT int
		switch s.Version {
		case 1:
			wantPK, wantCT = mlkem.EncapsulationKeySize768, mlkem.CiphertextSize768
		case 2:
			wantPK, wantCT = mlkem.EncapsulationKeySize1024, mlkem.CiphertextSize1024
		default:
			t.Fatalf("version %d has no known parameter set; add one here", s.Version)
		}
		if s.KEMPublicKeySize != wantPK {
			t.Errorf("%s: KEM public key %d, standard says %d", s.Name, s.KEMPublicKeySize, wantPK)
		}
		if s.KEMCiphertextSize != wantCT {
			t.Errorf("%s: KEM ciphertext %d, standard says %d", s.Name, s.KEMCiphertextSize, wantCT)
		}
	}
}

// ML-KEM-1024 is reachable from this build, which is what makes v2 a matter of
// wiring rather than of a missing primitive. Go's standard library carries both
// parameter sets, so item 3 costs nothing on this side beyond saying so.
func TestMLKEM1024IsAvailableToThisBuild(t *testing.T) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		t.Fatalf("ML-KEM-1024 keygen: %v", err)
	}
	ek := dk.EncapsulationKey()
	if got := len(ek.Bytes()); got != mlkem.EncapsulationKeySize1024 {
		t.Fatalf("encapsulation key is %d bytes, want %d", got, mlkem.EncapsulationKeySize1024)
	}
	// Note the order: Go returns the shared key first, the ciphertext second.
	ss, ct := ek.Encapsulate()
	if len(ct) != mlkem.CiphertextSize1024 {
		t.Fatalf("ciphertext is %d bytes, want %d", len(ct), mlkem.CiphertextSize1024)
	}
	got, err := dk.Decapsulate(ct)
	if err != nil {
		t.Fatalf("decapsulate: %v", err)
	}
	if string(got) != string(ss) {
		t.Fatal("shared secrets disagree")
	}
	// A 768 ciphertext offered to a 1024 key must be refused on length. The two
	// encodings are distinguished by nothing else.
	dk768, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	_, ct768 := dk768.EncapsulationKey().Encapsulate()
	if _, err := dk.Decapsulate(ct768); err == nil {
		t.Fatal("a 1024 key decapsulated a 768 ciphertext")
	}
}
