// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package psk derives the per-pair pre-shared keys described in PLAN.md §2.6.
//
// These exist for assumption diversity. Everything else in Karst rests
// post-quantum confidentiality on lattices; a symmetric secret is PQ-safe by
// construction, so mixing one into the handshake means a total ML-KEM break is
// not automatically a total break:
//
//	Against a classical attacker: secure if X25519 OR ML-KEM holds.
//	Against a quantum attacker:   secure if ML-KEM holds, OR the attacker does
//	                              not hold the PSK.
//
// The honest caveat, from §2.6: because the server derives them, server
// compromise *plus* a total lattice break is a full break. Server compromise
// alone is not.
//
// # Deriving rather than storing
//
//	psk(A, B, epoch) = HKDF-SHA-512(master, min(A,B) ‖ max(A,B) ‖ epoch)
//
// Server state is O(1) — one master key — instead of O(N²) stored pair keys.
// The ordering is what makes both ends of a pair agree without coordinating.
//
// # These are secrets that travel
//
// PSKs are shipped to nodes in the netmap, which is why the control channel
// has a cryptographic layer of its own inside TLS (ADR-0011). Within this
// process they are handled as a distinct type whose String, Format, GoString,
// MarshalJSON and MarshalText all refuse to render the bytes. That is not
// decoration: Phase 3's exit criterion requires an automated scan of logs,
// traces and a generated bugreport to find zero PSK bytes, and the reliable
// way to pass that is for the value to be unprintable by construction rather
// than for every call site to remember.
package psk

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// Size is 32 bytes, matching the PSK width in phreatic-v1.md §7.
const Size = 32

// MasterSize is the master key width. 32 bytes of entropy is the security
// level; HKDF-SHA-512 expands from it.
const MasterSize = 32

const (
	label      = "karst-psk-v1"
	discoLabel = "karst-disco-v1"
)

var (
	ErrMasterSize = errors.New("psk: master key must be 32 bytes")
	ErrNoPeer     = errors.New("psk: empty peer handle")
	ErrSamePeer   = errors.New("psk: a peer has no PSK with itself")
)

// Key is a per-pair PSK. It deliberately does not print.
type Key [Size]byte

// Zero is the all-zero PSK a node falls back to when it holds none for a peer
// (§2.6). Such sessions are lattice-only and MUST be flagged in the crypto
// posture view — the fallback protects connectivity, not confidentiality.
var Zero Key

// IsZero reports whether this is the fallback rather than a derived key.
func (k Key) IsZero() bool {
	return subtle.ConstantTimeCompare(k[:], Zero[:]) == 1
}

// Bytes exposes the raw key. Every caller of this is a place a PSK can escape,
// so there is exactly one of them by design: the netmap encoder.
func (k Key) Bytes() []byte { return k[:] }

// The rendering methods below all redact. A PSK reaching a log line is a
// reportable defect, and the type is the only place that can be enforced
// rather than remembered.
func (Key) String() string               { return "psk(redacted)" }
func (Key) GoString() string             { return "psk(redacted)" }
func (Key) MarshalText() ([]byte, error) { return []byte("psk(redacted)"), nil }
func (Key) MarshalJSON() ([]byte, error) { return []byte(`"psk(redacted)"`), nil }

// Format implements fmt.Formatter so that even %x, %v and %+v redact.
// Without this, `log.Printf("%x", key)` would print the secret.
func (Key) Format(f fmt.State, verb rune) {
	_, _ = f.Write([]byte("psk(redacted)"))
}

// Custodian holds the master key. It is an interface so that a KMS or HSM can
// hold the material and only ever perform derivations, per §2.6 and §12; the
// software implementation below is the documented fallback for self-hosters
// without one.
type Custodian interface {
	// Derive expands the master key over info. Implementations MUST NOT log
	// info or the result.
	Derive(info []byte, n int) ([]byte, error)
}

// SoftwareMaster keeps the master key in process memory.
//
// This is the fallback, not the recommendation. Go gives no way to pin memory
// or reliably zero it — the garbage collector may copy the key and the runtime
// may page it out — so a KMS or HSM Custodian is preferred wherever one
// exists. Saying so here is the "documented software fallback" §2.6 asks for.
type SoftwareMaster struct {
	key []byte
}

// NewSoftwareMaster wraps an existing 32-byte master key.
func NewSoftwareMaster(master []byte) (*SoftwareMaster, error) {
	if len(master) != MasterSize {
		return nil, fmt.Errorf("%w: got %d", ErrMasterSize, len(master))
	}
	k := make([]byte, MasterSize)
	copy(k, master)
	return &SoftwareMaster{key: k}, nil
}

// GenerateSoftwareMaster creates a fresh master key.
func GenerateSoftwareMaster() (*SoftwareMaster, error) {
	k := make([]byte, MasterSize)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("psk: generate master: %w", err)
	}
	return &SoftwareMaster{key: k}, nil
}

func (m *SoftwareMaster) Derive(info []byte, n int) ([]byte, error) {
	// info is already a fully domain-separated, length-prefixed transcript
	// (see Deriver.Pair), so an empty salt adds nothing here.
	out, err := hkdf.Key(sha512.New, m.key, nil, string(info), n)
	if err != nil {
		return nil, fmt.Errorf("psk: derive: %w", err)
	}
	return out, nil
}

// Deriver produces per-pair keys from a custodian.
type Deriver struct{ master Custodian }

func NewDeriver(master Custodian) (*Deriver, error) {
	if master == nil {
		return nil, errors.New("psk: nil custodian")
	}
	return &Deriver{master: master}, nil
}

// Pair derives the PSK shared by two node handles at an epoch.
//
// Order-independent: the handles are sorted, so A and B derive the same key
// without having to agree who is "first". Getting this wrong would produce two
// different keys per pair and a handshake failure that looks like a key
// mismatch rather than a sorting bug.
func (d *Deriver) Pair(a, b string, epoch uint32) (Key, error) {
	return d.pair(label, a, b, epoch)
}

// Disco derives the AVEN discovery key shared by two node handles at an
// epoch. It deliberately uses a separate transcript label from Pair: a key
// which authenticates path-discovery messages must never also authenticate a
// PHREATIC handshake.
func (d *Deriver) Disco(a, b string, epoch uint32) (Key, error) {
	return d.pair(discoLabel, a, b, epoch)
}

func (d *Deriver) pair(domain string, a, b string, epoch uint32) (Key, error) {
	var k Key
	if a == "" || b == "" {
		return k, ErrNoPeer
	}
	if a == b {
		// Not merely useless: a self-pair would derive a key that both
		// "sides" of a loopback session share, which is a shape no caller
		// should be relying on.
		return k, ErrSamePeer
	}
	lo, hi := a, b
	if lo > hi {
		lo, hi = hi, lo
	}

	// Length-prefixed, so that ("ab","c") and ("a","bc") cannot collide into
	// the same PSK. Handles are fixed-width today; this does not depend on it.
	info := make([]byte, 0, len(domain)+len(lo)+len(hi)+12)
	info = append(info, domain...)
	info = appendField(info, []byte(lo))
	info = appendField(info, []byte(hi))
	var e [4]byte
	binary.BigEndian.PutUint32(e[:], epoch)
	info = appendField(info, e[:])

	out, err := d.master.Derive(info, Size)
	if err != nil {
		return k, err
	}
	copy(k[:], out)
	return k, nil
}

func appendField(dst, field []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(field)))
	dst = append(dst, l[:]...)
	return append(dst, field...)
}
