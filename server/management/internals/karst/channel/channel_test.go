// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package channel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// Ed25519 stands in for ML-DSA-65 in these tests. It has the same shape — a
// detached signature over a message, verified against a public key — and Go
// has no stdlib ML-DSA as of 1.25. Nothing here depends on the signature
// scheme's parameters; when the ML-DSA library is chosen, only testSigner
// changes. See ADR-0011.
type testSigner struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	return &testSigner{pub: pub, priv: priv}
}

func (s *testSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }
func (s *testSigner) PublicKey() []byte               { return s.pub }

type testVerifier struct{}

func (testVerifier) Verify(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// One server identity shared across the tests. The server signs its ephemeral
// key with this; nodes pin the public half. Without that signature an attacker
// substitutes the ephemeral and forward secrecy is lost — see
// TestForwardSecrecyAttackFromTheModel and spec/models/karst-control.pv.
var testServerKey = mustServerKey()

func mustServerKey() *testSigner {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &testSigner{pub: pub, priv: priv}
}

func srvSigner(t *testing.T) Signer { t.Helper(); return testServerKey }

func serverPins(s *StaticKey) ServerPins {
	return ServerPins{StaticKEM: s.PublicKey(), VerifyKey: testServerKey.pub}
}

func noLookup([]byte) []byte { return nil }

func lookupFixed(key []byte) IdentityLookup {
	return func(id []byte) []byte {
		if len(id) == 0 {
			return nil
		}
		return key
	}
}

// handshake runs a full exchange and returns both ends.
func handshake(t *testing.T) (nodeCh, srvCh *Channel, signer *testSigner, static *StaticKey) {
	t.Helper()
	static, err := GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	signer = newTestSigner(t)

	hello, pending, err := static.Hello(srvSigner(t))
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	init, nodeCh, err := Initiate(hello, serverPins(static), testVerifier{}, nil, signer, true)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	srvCh, identity, err := static.Accept(pending, init, noLookup, testVerifier{})
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if !bytes.Equal(identity, signer.PublicKey()) {
		t.Fatal("accept returned an identity that is not the one presented")
	}
	return nodeCh, srvCh, signer, static
}

func TestRoundTripBothDirections(t *testing.T) {
	nodeCh, srvCh, _, _ := handshake(t)

	up := []byte("netmap request")
	env, err := nodeCh.Seal([]byte("node-1"), up)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := srvCh.Open(env)
	if err != nil {
		t.Fatalf("open node->server: %v", err)
	}
	if !bytes.Equal(got, up) {
		t.Fatalf("node->server: got %q want %q", got, up)
	}

	down := []byte("netmap delta with a PSK in it")
	env, err = srvCh.Seal([]byte("node-1"), down)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err = nodeCh.Open(env)
	if err != nil {
		t.Fatalf("open server->node: %v", err)
	}
	if !bytes.Equal(got, down) {
		t.Fatalf("server->node: got %q want %q", got, down)
	}
}

// The directions must not share a key, or a counter that is fine in one
// direction collides with the other and reuses a nonce.
func TestDirectionsUseDifferentKeys(t *testing.T) {
	nodeCh, srvCh, _, _ := handshake(t)
	if bytes.Equal(nodeCh.send, nodeCh.recv) {
		t.Fatal("node send and recv keys are identical")
	}
	if !bytes.Equal(nodeCh.send, srvCh.recv) || !bytes.Equal(nodeCh.recv, srvCh.send) {
		t.Fatal("the two ends did not agree on the directional keys")
	}
}

// An envelope sealed by the node must not be openable by the node: that would
// mean one key in both directions.
func TestNodeCannotOpenItsOwnEnvelope(t *testing.T) {
	nodeCh, _, _, _ := handshake(t)
	env, err := nodeCh.Seal([]byte("node-1"), []byte("x"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := nodeCh.Open(env); err == nil {
		t.Fatal("node opened its own envelope")
	}
}

func TestReplayRejected(t *testing.T) {
	nodeCh, srvCh, _, _ := handshake(t)
	env, err := nodeCh.Seal([]byte("node-1"), []byte("once"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := srvCh.Open(env); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if _, err := srvCh.Open(env); err != ErrReplay {
		t.Fatalf("replayed envelope: got %v want %v", err, ErrReplay)
	}
}

// A forged envelope must not consume a sequence number the real peer still
// intends to use — otherwise anyone who can inject one message can wedge the
// channel by burning the counter ahead of the sender.
func TestForgedEnvelopeDoesNotAdvanceSequence(t *testing.T) {
	nodeCh, srvCh, _, _ := handshake(t)

	forged := &proto.KarstEnvelope{
		NodeId:  []byte("node-1"),
		Body:    bytes.Repeat([]byte{0xAA}, 64),
		Seq:     99,
		Version: Version,
	}
	if _, err := srvCh.Open(forged); err != ErrDecrypt {
		t.Fatalf("forged envelope: got %v want %v", err, ErrDecrypt)
	}

	env, err := nodeCh.Seal([]byte("node-1"), []byte("legitimate"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := srvCh.Open(env); err != nil {
		t.Fatalf("real message after a forgery: %v", err)
	}
}

// node_id is cleartext, so it must be bound to the ciphertext. Otherwise a
// proxy could relabel one node's traffic as another's.
func TestNodeIDRewriteRejected(t *testing.T) {
	nodeCh, srvCh, _, _ := handshake(t)
	env, err := nodeCh.Seal([]byte("node-1"), []byte("payload"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	env.NodeId = []byte("node-2")
	if _, err := srvCh.Open(env); err != ErrDecrypt {
		t.Fatalf("rewritten node_id: got %v want %v", err, ErrDecrypt)
	}
}

// A node that pins the wrong *KEM* key still fails closed. The hello signature
// is verified against the pinned verification key, which is correct here, so
// this isolates the implicit-authentication property of ct_static on its own:
// the derived key diverges and the channel dies on first use.
func TestWrongServerStaticKeyFailsClosed(t *testing.T) {
	real, err := GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	impostor, err := GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	signer := newTestSigner(t)

	hello, pending, err := real.Hello(srvSigner(t))
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	// Node pins the impostor's key by mistake.
	init, nodeCh, err := Initiate(hello, ServerPins{StaticKEM: impostor.PublicKey(), VerifyKey: testServerKey.pub}, testVerifier{}, nil, signer, true)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	srvCh, _, err := real.Accept(pending, init, noLookup, testVerifier{})
	if err != nil {
		// Decapsulation of a ciphertext made for another key does not fail in
		// ML-KEM — it yields an implicit-rejection secret — so reaching here
		// would mean something else went wrong.
		t.Fatalf("accept: %v", err)
	}
	env, err := nodeCh.Seal([]byte("node-1"), []byte("secret"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := srvCh.Open(env); err != ErrDecrypt {
		t.Fatalf("mismatched static key: got %v want %v", err, ErrDecrypt)
	}
}

func TestTamperedCiphertextBreaksSignature(t *testing.T) {
	static, err := GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	signer := newTestSigner(t)
	hello, pending, err := static.Hello(srvSigner(t))
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	init, _, err := Initiate(hello, serverPins(static), testVerifier{}, nil, signer, true)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	init.CtEph[0] ^= 0xFF
	if _, _, err := static.Accept(pending, init, noLookup, testVerifier{}); err != ErrSignature {
		t.Fatalf("tampered ct_eph: got %v want %v", err, ErrSignature)
	}
}

// A node the server already knows must not be able to present a different
// identity key: that is identity substitution, not re-registration.
func TestKnownNodePresentingDifferentIdentityRejected(t *testing.T) {
	static, err := GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	enrolled := newTestSigner(t)
	attacker := newTestSigner(t)

	hello, pending, err := static.Hello(srvSigner(t))
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	// Attacker knows the node_id and signs with its own key, presenting it.
	init, _, err := Initiate(hello, serverPins(static), testVerifier{}, []byte("node-1"), attacker, true)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	_, _, err = static.Accept(pending, init, lookupFixed(enrolled.PublicKey()), testVerifier{})
	if err != ErrSignature {
		t.Fatalf("identity substitution: got %v want %v", err, ErrSignature)
	}
}

// The same attack without presenting a key: sign with the wrong private key
// and rely on the server looking up the enrolled one.
func TestKnownNodeWrongSignatureRejected(t *testing.T) {
	static, err := GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	enrolled := newTestSigner(t)
	attacker := newTestSigner(t)

	hello, pending, err := static.Hello(srvSigner(t))
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	init, _, err := Initiate(hello, serverPins(static), testVerifier{}, []byte("node-1"), attacker, false)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	if _, _, err := static.Accept(pending, init, lookupFixed(enrolled.PublicKey()), testVerifier{}); err != ErrSignature {
		t.Fatalf("wrong signature: got %v want %v", err, ErrSignature)
	}
}

func TestRegistrationWithoutIdentityRejected(t *testing.T) {
	static, err := GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	signer := newTestSigner(t)
	hello, pending, err := static.Hello(srvSigner(t))
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	// presentIdentity=false with no stored key: nothing to verify against.
	init, _, err := Initiate(hello, serverPins(static), testVerifier{}, nil, signer, false)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	if _, _, err := static.Accept(pending, init, noLookup, testVerifier{}); err != ErrNoIdentity {
		t.Fatalf("no identity: got %v want %v", err, ErrNoIdentity)
	}
}

// Forward secrecy rests on the ephemeral key differing per connection. If two
// connections to the same static key derived the same channel key, recording
// one and compromising the static key later would decrypt both.
func TestEphemeralKeyMakesEachConnectionDistinct(t *testing.T) {
	static, err := GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	signer := newTestSigner(t)

	var keys [][]byte
	for i := 0; i < 2; i++ {
		hello, _, err := static.Hello(srvSigner(t))
		if err != nil {
			t.Fatalf("hello: %v", err)
		}
		_, ch, err := Initiate(hello, serverPins(static), testVerifier{}, nil, signer, true)
		if err != nil {
			t.Fatalf("initiate: %v", err)
		}
		keys = append(keys, ch.send)
	}
	if bytes.Equal(keys[0], keys[1]) {
		t.Fatal("two connections derived the same channel key: no forward secrecy")
	}
}

// The server's freshness contribution is what stops a captured ChannelInit
// being replayed onto a new connection.
func TestInitCannotBeReplayedOntoANewConnection(t *testing.T) {
	static, err := GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	signer := newTestSigner(t)

	hello1, _, err := static.Hello(srvSigner(t))
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	init, _, err := Initiate(hello1, serverPins(static), testVerifier{}, nil, signer, true)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}

	// A second connection: new server_random, new ephemeral key.
	_, pending2, err := static.Hello(srvSigner(t))
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	if _, _, err := static.Accept(pending2, init, noLookup, testVerifier{}); err != ErrSignature {
		t.Fatalf("replayed init: got %v want %v", err, ErrSignature)
	}
}

func TestVersionMismatchRejected(t *testing.T) {
	nodeCh, srvCh, _, _ := handshake(t)
	env, err := nodeCh.Seal([]byte("node-1"), []byte("x"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	env.Version = Version + 1
	if _, err := srvCh.Open(env); err != ErrVersion {
		t.Fatalf("bad version: got %v want %v", err, ErrVersion)
	}
}

func TestSequenceIncreasesMonotonically(t *testing.T) {
	nodeCh, srvCh, _, _ := handshake(t)
	for i := uint64(1); i <= 100; i++ {
		env, err := nodeCh.Seal([]byte("node-1"), []byte("m"))
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		if env.Seq != i {
			t.Fatalf("seq: got %d want %d", env.Seq, i)
		}
		if _, err := srvCh.Open(env); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}
}

// TestEphemeralSubstitutionRejected is the regression test for the attack
// ProVerif found in spec/models/karst-control.pv.
//
// The attacker rewrites ChannelHello so that eph_kem_pk is the server's own
// *static* public key. A node that does not authenticate the hello then
// encapsulates BOTH ciphertexts to one long-term key, and every byte it sends
// decrypts later, when that key leaks. "The channel fails closed" is no
// defence: the node transmits before it can possibly notice.
//
// The hello signature is what stops it, so the substituted hello must be
// refused outright rather than merely producing a divergent key.
func TestEphemeralSubstitutionRejected(t *testing.T) {
	static, err := GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	hello, _, err := static.Hello(srvSigner(t))
	if err != nil {
		t.Fatalf("hello: %v", err)
	}

	// The exact substitution from the model's trace.
	hello.EphKemPk = static.PublicKey()

	if _, _, err := Initiate(hello, serverPins(static), testVerifier{}, nil,
		newTestSigner(t), true); err != ErrServerAuth {
		t.Fatalf("substituted ephemeral: got %v want %v", err, ErrServerAuth)
	}
}

// Any tampering with the hello must be caught, not just that one substitution.
func TestTamperedHelloRejected(t *testing.T) {
	static, err := GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	signer := newTestSigner(t)

	cases := []struct {
		name   string
		mangle func(h *proto.ChannelHello)
	}{
		{"ephemeral key replaced", func(h *proto.ChannelHello) {
			other, _ := GenerateStatic()
			h.EphKemPk = other.PublicKey()
		}},
		{"server random replaced", func(h *proto.ChannelHello) {
			h.ServerRandom = bytes.Repeat([]byte{9}, randomLen)
		}},
		{"signature stripped", func(h *proto.ChannelHello) { h.Signature = nil }},
		{"signature corrupted", func(h *proto.ChannelHello) { h.Signature[0] ^= 0xFF }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hello, _, err := static.Hello(srvSigner(t))
			if err != nil {
				t.Fatalf("hello: %v", err)
			}
			tc.mangle(hello)
			if _, _, err := Initiate(hello, serverPins(static), testVerifier{}, nil,
				signer, true); err != ErrServerAuth {
				t.Fatalf("got %v want %v", err, ErrServerAuth)
			}
		})
	}
}

// Pinning only the KEM half must not be silently accepted: it would leave the
// hello unauthenticated, which is the whole vulnerability.
func TestMissingServerVerifyKeyRefused(t *testing.T) {
	static, err := GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	hello, _, err := static.Hello(srvSigner(t))
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	pins := ServerPins{StaticKEM: static.PublicKey()} // no VerifyKey
	if _, _, err := Initiate(hello, pins, testVerifier{}, nil, newTestSigner(t), true); err != ErrNoIdentity {
		t.Fatalf("got %v want %v", err, ErrNoIdentity)
	}
}
