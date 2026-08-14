// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package node_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/management/internals/karst/node"
)

func newStore(t *testing.T) *node.Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Each test gets a clean table: the shared in-memory DSN is per-process.
	if err := db.Exec("DROP TABLE IF EXISTS karst_node_identities").Error; err != nil {
		t.Fatalf("reset: %v", err)
	}
	s, err := node.NewStore(db)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return s
}

// A node registers its PHREATIC keys alongside its identity; peers cannot
// handshake without them.
func testKeys() node.DataPlaneKeys {
	return node.DataPlaneKeys{
		KemPublicKey: bytes.Repeat([]byte{0xAB}, 1184),
		DhPublicKey:  bytes.Repeat([]byte{0xCD}, 32),
	}
}

func newIdentity(t *testing.T) *identity.Key {
	t.Helper()
	k, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return k
}

// The handle must occupy the same 44 characters a WireGuard key does, or it
// does not fit the forked schema's column and unique index.
func TestHandleIsWireGuardKeyShaped(t *testing.T) {
	k := newIdentity(t)
	h := node.Handle(k.Public())
	if len(h) != node.HandleLength {
		t.Fatalf("handle length: got %d want %d", len(h), node.HandleLength)
	}
}

func TestHandleIsStableAndDistinct(t *testing.T) {
	a, b := newIdentity(t), newIdentity(t)
	if node.Handle(a.Public()) != node.Handle(a.Public()) {
		t.Fatal("handle is not stable for one identity")
	}
	if node.Handle(a.Public()) == node.Handle(b.Public()) {
		t.Fatal("two identities produced the same handle")
	}
}

func TestRegisterThenLookup(t *testing.T) {
	s := newStore(t)
	k := newIdentity(t)

	handle, err := s.Register(k.Public(), testKeys())
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if handle != node.Handle(k.Public()) {
		t.Fatal("register returned a handle that does not match Handle()")
	}

	got, err := s.Lookup(handle)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !bytes.Equal(got, k.Public()) {
		t.Fatal("lookup returned a different key than was registered")
	}
}

// A node re-running enrolment after losing local state must not be an error.
func TestRegisterIsIdempotent(t *testing.T) {
	s := newStore(t)
	k := newIdentity(t)

	first, err := s.Register(k.Public(), testKeys())
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	second, err := s.Register(k.Public(), testKeys())
	if err != nil {
		t.Fatalf("second register: %v", err)
	}
	if first != second {
		t.Fatal("re-registration produced a different handle")
	}
}

func TestLookupUnknownHandle(t *testing.T) {
	s := newStore(t)
	if _, err := s.Lookup("not-a-real-handle"); err != node.ErrUnknownNode {
		t.Fatalf("got %v want %v", err, node.ErrUnknownNode)
	}
}

func TestRegisterRejectsMalformedKey(t *testing.T) {
	s := newStore(t)
	for _, n := range []int{0, 1, identity.PublicKeySize - 1, identity.PublicKeySize + 1} {
		if _, err := s.Register(bytes.Repeat([]byte{1}, n), testKeys()); err == nil {
			t.Fatalf("a %d-byte public key was accepted", n)
		}
	}
}

// A node with no usable data-plane keys would be silently skipped by every
// other node's netmap, presenting as "the peer never appears" rather than as a
// registration failure. Refuse it at the door instead.
func TestRegisterRejectsMalformedDataPlaneKeys(t *testing.T) {
	s := newStore(t)
	k := newIdentity(t)
	cases := []struct {
		name string
		keys node.DataPlaneKeys
	}{
		{"no keys at all", node.DataPlaneKeys{}},
		{"missing kem", node.DataPlaneKeys{DhPublicKey: bytes.Repeat([]byte{1}, 32)}},
		{"missing dh", node.DataPlaneKeys{KemPublicKey: bytes.Repeat([]byte{1}, 1184)}},
		{"short kem", node.DataPlaneKeys{KemPublicKey: bytes.Repeat([]byte{1}, 1183), DhPublicKey: bytes.Repeat([]byte{1}, 32)}},
		{"long dh", node.DataPlaneKeys{KemPublicKey: bytes.Repeat([]byte{1}, 1184), DhPublicKey: bytes.Repeat([]byte{1}, 33)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.Register(k.Public(), tc.keys); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// Data-plane keys rotate independently of the identity: a node that
// regenerates them re-registers under the same handle and the new keys must
// take effect, or peers keep handshaking against keys it no longer holds.
func TestDataPlaneKeysCanRotate(t *testing.T) {
	s := newStore(t)
	k := newIdentity(t)

	handle, err := s.Register(k.Public(), testKeys())
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	rotated := node.DataPlaneKeys{
		KemPublicKey: bytes.Repeat([]byte{0x11}, 1184),
		DhPublicKey:  bytes.Repeat([]byte{0x22}, 32),
	}
	again, err := s.Register(k.Public(), rotated)
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if again != handle {
		t.Fatal("rotating data-plane keys changed the handle")
	}

	rec, err := s.Get(handle)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(rec.KemPublicKey, rotated.KemPublicKey) ||
		!bytes.Equal(rec.DhPublicKey, rotated.DhPublicKey) {
		t.Fatal("rotated keys were not persisted")
	}
	if !bytes.Equal(rec.PublicKey, k.Public()) {
		t.Fatal("the identity key moved during a data-plane rotation")
	}
}

func TestGetManyReturnsOnlyKnownHandles(t *testing.T) {
	s := newStore(t)
	a, b := newIdentity(t), newIdentity(t)
	ha, err := s.Register(a.Public(), testKeys())
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	hb, err := s.Register(b.Public(), testKeys())
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	got, err := s.GetMany([]string{ha, hb, "not-a-handle"})
	if err != nil {
		t.Fatalf("get many: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	if got[ha] == nil || got[hb] == nil {
		t.Fatal("a registered handle was missing")
	}
	if _, ok := got["not-a-handle"]; ok {
		t.Fatal("an unknown handle produced a record")
	}

	empty, err := s.GetMany(nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty query: %v, %d records", err, len(empty))
	}
}

// LookupFunc must return nil rather than an error for anything unresolvable:
// the caller is mid-handshake with an unauthenticated peer.
func TestLookupFuncReturnsNilForUnknown(t *testing.T) {
	s := newStore(t)
	f := s.LookupFunc()
	if f(nil) != nil {
		t.Fatal("empty node id resolved to a key")
	}
	if f([]byte("unknown")) != nil {
		t.Fatal("unknown handle resolved to a key")
	}

	k := newIdentity(t)
	handle, err := s.Register(k.Public(), testKeys())
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if got := f([]byte(handle)); !bytes.Equal(got, k.Public()) {
		t.Fatal("registered handle did not resolve to its key")
	}
}

// Pin the construction independently, so the domain label cannot be dropped
// or changed without a test failing. An earlier version of this test compared
// Handle(x) against Handle(label||x), which passes whether or not the label is
// used and therefore proved nothing.
//
// The label matters because the data plane hashes public keys too — ADR-0005's
// peer_id_hint over the KEM key. Two unlabelled hashes of related material is
// how a correlation channel gets built by accident.
func TestHandleMatchesTheSpecifiedConstruction(t *testing.T) {
	k := newIdentity(t)
	pub := k.Public()

	h := sha256.New()
	h.Write([]byte("karst-node-handle-v1"))
	h.Write(pub)
	want := base64.StdEncoding.EncodeToString(h.Sum(nil))

	if got := node.Handle(pub); got != want {
		t.Fatalf("handle construction changed:\n got %s\nwant %s", got, want)
	}

	// And an unlabelled hash must not produce the same handle.
	bare := sha256.Sum256(pub)
	if node.Handle(pub) == base64.StdEncoding.EncodeToString(bare[:]) {
		t.Fatal("handle is a bare hash: the domain label is not being used")
	}
}
