// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package psk_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/psk"
)

func newDeriver(t *testing.T) *psk.Deriver {
	t.Helper()
	m, err := psk.GenerateSoftwareMaster()
	if err != nil {
		t.Fatalf("master: %v", err)
	}
	d, err := psk.NewDeriver(m)
	if err != nil {
		t.Fatalf("deriver: %v", err)
	}
	return d
}

// The property the whole scheme rests on: both ends of a pair derive the same
// key without agreeing who goes first. If this breaks, every handshake fails
// with what looks like a key mismatch rather than a sorting bug.
func TestPairIsOrderIndependent(t *testing.T) {
	d := newDeriver(t)
	ab, err := d.Pair("alice", "bob", 1)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	ba, err := d.Pair("bob", "alice", 1)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if !bytes.Equal(ab.Bytes(), ba.Bytes()) {
		t.Fatal("psk(A,B) != psk(B,A)")
	}
}

func TestDistinctPairsAndEpochs(t *testing.T) {
	d := newDeriver(t)
	base, _ := d.Pair("alice", "bob", 1)

	cases := []struct {
		name  string
		a, b  string
		epoch uint32
	}{
		{"different peer", "alice", "carol", 1},
		{"both different", "dave", "erin", 1},
		{"next epoch", "alice", "bob", 2},
		{"far epoch", "alice", "bob", 4294967295},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k, err := d.Pair(tc.a, tc.b, tc.epoch)
			if err != nil {
				t.Fatalf("pair: %v", err)
			}
			if bytes.Equal(k.Bytes(), base.Bytes()) {
				t.Fatal("derived the same key as a different pair/epoch")
			}
		})
	}
}

// Length prefixing: ("ab","c") and ("a","bc") must not collide. Handles are
// fixed-width today, so this guards a future change rather than a live bug.
func TestConcatenationCannotCollide(t *testing.T) {
	d := newDeriver(t)
	x, err := d.Pair("ab", "c", 1)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	y, err := d.Pair("a", "bc", 1)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if bytes.Equal(x.Bytes(), y.Bytes()) {
		t.Fatal("ambiguous concatenation: two different pairs share a PSK")
	}
}

func TestDifferentMastersDifferentKeys(t *testing.T) {
	a, b := newDeriver(t), newDeriver(t)
	ka, _ := a.Pair("alice", "bob", 1)
	kb, _ := b.Pair("alice", "bob", 1)
	if bytes.Equal(ka.Bytes(), kb.Bytes()) {
		t.Fatal("two independent masters derived the same PSK")
	}
}

func TestDerivationIsDeterministic(t *testing.T) {
	m, err := psk.GenerateSoftwareMaster()
	if err != nil {
		t.Fatalf("master: %v", err)
	}
	d1, _ := psk.NewDeriver(m)
	d2, _ := psk.NewDeriver(m)
	k1, _ := d1.Pair("alice", "bob", 7)
	k2, _ := d2.Pair("alice", "bob", 7)
	if !bytes.Equal(k1.Bytes(), k2.Bytes()) {
		t.Fatal("the same master and pair produced different keys")
	}
}

func TestRejectsDegenerateInput(t *testing.T) {
	d := newDeriver(t)
	if _, err := d.Pair("", "bob", 1); err != psk.ErrNoPeer {
		t.Fatalf("empty handle: got %v", err)
	}
	if _, err := d.Pair("alice", "", 1); err != psk.ErrNoPeer {
		t.Fatalf("empty handle: got %v", err)
	}
	if _, err := d.Pair("alice", "alice", 1); err != psk.ErrSamePeer {
		t.Fatalf("self pair: got %v", err)
	}
}

func TestMasterKeySizeEnforced(t *testing.T) {
	for _, n := range []int{0, 1, 31, 33, 64} {
		if _, err := psk.NewSoftwareMaster(bytes.Repeat([]byte{1}, n)); err == nil {
			t.Fatalf("accepted a %d-byte master key", n)
		}
	}
}

func TestZeroFallback(t *testing.T) {
	if !psk.Zero.IsZero() {
		t.Fatal("Zero does not report itself as zero")
	}
	d := newDeriver(t)
	k, err := d.Pair("alice", "bob", 1)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if k.IsZero() {
		t.Fatal("a derived PSK collided with the all-zero fallback")
	}
}

// The exit criterion for Phase 3 is that a scan of logs, traces and a
// bugreport finds zero PSK bytes. The reliable way to get there is a type that
// cannot be printed, rather than a rule every call site must remember. These
// are the formatting routes a PSK could otherwise escape through.
func TestKeyNeverRenders(t *testing.T) {
	d := newDeriver(t)
	k, err := d.Pair("alice", "bob", 1)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	secret := k.Bytes()

	renders := map[string]string{
		"String":      k.String(),
		"%v":          fmt.Sprintf("%v", k),
		"%s":          fmt.Sprintf("%s", k),
		"%x":          fmt.Sprintf("%x", k),
		"%X":          fmt.Sprintf("%X", k),
		"%+v":         fmt.Sprintf("%+v", k),
		"%#v":         fmt.Sprintf("%#v", k),
		"%q":          fmt.Sprintf("%q", k),
		"%d":          fmt.Sprintf("%d", k),
		"in a struct": fmt.Sprintf("%v", struct{ K psk.Key }{k}),
		"in a slice":  fmt.Sprintf("%v", []psk.Key{k}),
		"pointer":     fmt.Sprintf("%v", &k),
	}
	for name, out := range renders {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(out, "redacted") {
				t.Fatalf("%s rendered %q, which is not redacted", name, out)
			}
			assertNoSecret(t, []byte(out), secret)
		})
	}

	j, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	assertNoSecret(t, j, secret)

	j, err = json.Marshal(struct {
		K psk.Key `json:"k"`
	}{k})
	if err != nil {
		t.Fatalf("json struct: %v", err)
	}
	assertNoSecret(t, j, secret)
}

// assertNoSecret looks for the raw bytes and for the two textual encodings a
// logger would most plausibly produce.
func assertNoSecret(t *testing.T, out, secret []byte) {
	t.Helper()
	if bytes.Contains(out, secret) {
		t.Fatal("output contains the raw PSK bytes")
	}
	hexed := fmt.Sprintf("%x", secret)
	if bytes.Contains(bytes.ToLower(out), []byte(hexed)) {
		t.Fatal("output contains the PSK in hex")
	}
	// A few bytes of the key appearing verbatim is enough to be a leak.
	if len(secret) >= 8 && bytes.Contains(out, secret[:8]) {
		t.Fatal("output contains a prefix of the PSK")
	}
}
