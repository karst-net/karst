// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package channel_test

import (
	"bytes"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/channel"
	"github.com/netbirdio/netbird/management/internals/karst/identity"
)

// The rest of the channel tests stand Ed25519 in for ML-DSA-87 to stay
// independent of the signature library. This one is the integration: the real
// construction, end to end, with the real algorithm.

func TestChannelWithRealMLDSA(t *testing.T) {
	static, err := channel.GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	node, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	signer := identity.ControlSigner{Key: node}
	srvKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	srv := identity.ControlSigner{Key: srvKey}

	hello, pending, err := static.Hello(srv)
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	pins := channel.ServerPins{StaticKEM: static.PublicKey(), VerifyKey: srvKey.Public()}
	init, nodeCh, err := channel.Initiate(hello, pins, identity.ControlVerifier{}, nil, signer, true)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	srvCh, gotIdentity, err := static.Accept(pending, init,
		func([]byte) []byte { return nil }, identity.ControlVerifier{})
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if !bytes.Equal(gotIdentity, node.Public()) {
		t.Fatal("server bound an identity other than the one presented")
	}

	secret := []byte("a netmap delta carrying a per-pair PSK")
	env, err := srvCh.Seal([]byte("node-1"), secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := nodeCh.Open(env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("got %q want %q", got, secret)
	}
}

func TestRealMLDSARejectsForgedSignature(t *testing.T) {
	static, err := channel.GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	enrolled, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	attacker, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	srvKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	hello, pending, err := static.Hello(identity.ControlSigner{Key: srvKey})
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	pins := channel.ServerPins{StaticKEM: static.PublicKey(), VerifyKey: srvKey.Public()}
	init, _, err := channel.Initiate(hello, pins, identity.ControlVerifier{}, []byte("node-1"),
		identity.ControlSigner{Key: attacker}, false)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	_, _, err = static.Accept(pending, init,
		func([]byte) []byte { return enrolled.Public() }, identity.ControlVerifier{})
	if err != channel.ErrSignature {
		t.Fatalf("got %v want %v", err, channel.ErrSignature)
	}
}

// Handshake size is a design constraint, not a curiosity: PLAN.md sizes the
// datapath handshake carefully (ADR-0004), and the control channel should not
// be quietly enormous either. This records what the construction actually
// costs so a change shows up as a diff.
func TestHandshakeSizes(t *testing.T) {
	static, err := channel.GenerateStatic()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	node, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	srvKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	hello, _, err := static.Hello(identity.ControlSigner{Key: srvKey})
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	pins := channel.ServerPins{StaticKEM: static.PublicKey(), VerifyKey: srvKey.Public()}
	init, _, err := channel.Initiate(hello, pins, identity.ControlVerifier{}, nil,
		identity.ControlSigner{Key: node}, true)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}

	// ML-KEM-768: 1184-byte encapsulation key, 1088-byte ciphertext.
	// ML-DSA-87: 2592-byte public key, 4627-byte signature.
	checks := []struct {
		name string
		got  int
		want int
	}{
		{"hello.eph_kem_pk", len(hello.GetEphKemPk()), 1184},
		{"hello.server_random", len(hello.GetServerRandom()), 32},
		{"init.ct_static", len(init.GetCtStatic()), 1088},
		{"init.ct_eph", len(init.GetCtEph()), 1088},
		{"init.identity_pk", len(init.GetIdentityPk()), 2592},
		{"init.signature", len(init.GetSignature()), 4627},
		{"hello.signature", len(hello.GetSignature()), 4627},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %d want %d", c.name, c.got, c.want)
		}
	}

	t.Logf("ChannelHello  ~%d B", len(hello.GetEphKemPk())+len(hello.GetServerRandom())+
		len(hello.GetServerKemPkId())+len(hello.GetSignature()))
	t.Logf("ChannelInit   ~%d B (registration, identity presented)",
		len(init.GetCtStatic())+len(init.GetCtEph())+len(init.GetIdentityPk())+len(init.GetSignature()))
	t.Logf("ChannelInit   ~%d B (steady state, identity looked up)",
		len(init.GetCtStatic())+len(init.GetCtEph())+len(init.GetSignature()))
}
