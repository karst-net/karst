// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/channel"
	"github.com/netbirdio/netbird/management/internals/karst/control"
	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/netbirdio/netbird/management/internals/karst/psk"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// Cross-implementation test vectors for KARST-CONTROL v1.
//
// The Go server and the Rust node implement one specification. Everywhere they
// must agree byte-for-byte, they can silently disagree instead — a mismatched
// label, a missing length prefix, the wrong nonce half — and the symptom is a
// handshake that fails with no useful error. Vectors turn that class of bug
// into a test failure in whichever implementation drifted.
//
// Scope is deliberate. These cover the *derivation and framing* functions:
// signing inputs, the key schedule, the record layer, handle derivation and
// PSK derivation. They do not cover ML-KEM or ML-DSA themselves, which are
// library primitives with their own NIST KATs — and which cannot be pinned
// deterministically here anyway, since Go's crypto/mlkem exposes no seam for
// encapsulation randomness.
//
// Regenerate with:  go test ./management/internals/karst/control/ -run Vectors -update

type vectorFile struct {
	Spec  string      `json:"spec"`
	Note  string      `json:"note"`
	Cases vectorCases `json:"cases"`
}

type vectorCases struct {
	HelloSigningInput []helloSigCase `json:"hello_signing_input"`
	InitSigningInput  []initSigCase  `json:"init_signing_input"`
	DeriveKeys        []deriveCase   `json:"derive_keys"`
	Seal              []sealCase     `json:"seal"`
	Handle            []handleCase   `json:"handle"`
	PSK               []pskCase      `json:"psk"`
	PeerDigest        []digestCase   `json:"peer_digest"`
	NetmapVersion     []versionCase  `json:"netmap_version"`
}

// netmap_version is the other function both ends compute, and the one whose
// disagreement is hardest to notice by inspection. The node recomputes it over
// the netmap it assembled and refuses one that does not match; without a
// vector, a drift here would be discovered only as "no netmap ever applies".
type versionCase struct {
	PskEpoch     uint32        `json:"psk_epoch"`
	NodeID       string        `json:"node_id"`
	DNSName      string        `json:"dns_name"`
	Addresses    []string      `json:"addresses"`
	Peers        []versionPeer `json:"peers"`
	PacketFilter []versionRule `json:"packet_filter"`
	EgressFilter []versionRule `json:"egress_filter"`
	Version      uint64        `json:"version"`
}

type versionPeer struct {
	NodeID       string   `json:"node_id"`
	KemPublicKey string   `json:"kem_public_key"`
	DhPublicKey  string   `json:"dh_public_key"`
	DNSName      string   `json:"dns_name"`
	Endpoint     string   `json:"endpoint"`
	AllowedIPs   []string `json:"allowed_ips"`
	// Present so the vector proves the PSK bytes are NOT hashed: two cases
	// differ only here and must produce the same version.
	PSK string `json:"psk"`
}

// versionRule serves both directions. `srcs` carries the node handles either
// way; which direction it is comes from the field it appears in, which is
// exactly why the hash puts a separator between the two lists.
type versionRule struct {
	Srcs  []string           `json:"srcs"`
	Ports []versionPortRange `json:"ports"`
}

type versionPortRange struct {
	First uint32 `json:"first"`
	Last  uint32 `json:"last"`
}

// peer_digest is computed by BOTH ends: the node derives it from what it
// stored, the server from what it would send. A disagreement means either
// endless resending of unchanged entries or — worse — a change that is never
// delivered because both sides believe it already arrived.
type digestCase struct {
	Epoch        uint32   `json:"epoch"`
	NodeID       string   `json:"node_id"`
	KemPublicKey string   `json:"kem_public_key"`
	DhPublicKey  string   `json:"dh_public_key"`
	DNSName      string   `json:"dns_name"`
	Endpoint     string   `json:"endpoint"`
	AllowedIPs   []string `json:"allowed_ips"`
	Digest       uint64   `json:"digest"`
}

type helloSigCase struct {
	ServerRandom string `json:"server_random"`
	EphKemPk     string `json:"eph_kem_pk"`
	Expected     string `json:"expected"`
}

type initSigCase struct {
	ServerRandom string `json:"server_random"`
	CtStatic     string `json:"ct_static"`
	CtEph        string `json:"ct_eph"`
	NodeID       string `json:"node_id"`
	Expected     string `json:"expected"`
}

type deriveCase struct {
	SsStatic     string `json:"ss_static"`
	SsEph        string `json:"ss_eph"`
	ServerRandom string `json:"server_random"`
	CtStatic     string `json:"ct_static"`
	CtEph        string `json:"ct_eph"`
	KeyC2S       string `json:"key_c2s"`
	KeyS2C       string `json:"key_s2c"`
}

type sealCase struct {
	Key        string `json:"key"`
	NodeID     string `json:"node_id"`
	Seq        uint64 `json:"seq"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

type handleCase struct {
	IdentityPk string `json:"identity_pk"`
	Handle     string `json:"handle"`
}

type pskCase struct {
	Master string `json:"master"`
	A      string `json:"a"`
	B      string `json:"b"`
	Epoch  uint32 `json:"epoch"`
	PSK    string `json:"psk"`
}

// pattern makes a deterministic byte string, so vectors are reproducible
// without depending on a CSPRNG.
func pattern(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed + byte(i)
	}
	return out
}

func vectorsPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this source file")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "..",
		"spec", "vectors", "karst-control-v1.json")
}

func TestVectors(t *testing.T) {
	got := vectorFile{
		Spec: "KARST-CONTROL v1",
		Note: "Cross-implementation vectors. Covers derivation and framing, " +
			"not ML-KEM/ML-DSA themselves (those have NIST KATs). " +
			"Generated by server/management/internals/karst/control/vectors_test.go.",
	}

	for i, sr := range [][]byte{pattern(32, 0x00), pattern(32, 0x40)} {
		eph := pattern(1184, byte(0x10*(i+1)))
		got.Cases.HelloSigningInput = append(got.Cases.HelloSigningInput, helloSigCase{
			ServerRandom: hex.EncodeToString(sr),
			EphKemPk:     hex.EncodeToString(eph),
			Expected:     hex.EncodeToString(channel.HelloSigningInput(sr, eph)),
		})
	}

	// Including an empty node_id: that is the registration case, and an
	// implementation that omits the length prefix rather than writing a
	// zero-length field will agree on every other vector and fail on this one.
	for _, nodeID := range [][]byte{nil, []byte("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGk=")} {
		sr := pattern(32, 0x01)
		cs := pattern(1088, 0x20)
		ce := pattern(1088, 0x30)
		got.Cases.InitSigningInput = append(got.Cases.InitSigningInput, initSigCase{
			ServerRandom: hex.EncodeToString(sr),
			CtStatic:     hex.EncodeToString(cs),
			CtEph:        hex.EncodeToString(ce),
			NodeID:       hex.EncodeToString(nodeID),
			Expected:     hex.EncodeToString(channel.SigningInput(sr, cs, ce, nodeID)),
		})
	}

	for i := 0; i < 2; i++ {
		ssS := pattern(32, byte(0x50+i))
		ssE := pattern(32, byte(0x60+i))
		sr := pattern(32, byte(0x70+i))
		cs := pattern(1088, byte(0x80+i))
		ce := pattern(1088, byte(0x90+i))
		c2s, s2c, err := channel.DeriveKeysForTest(ssS, ssE, sr, cs, ce)
		if err != nil {
			t.Fatalf("derive: %v", err)
		}
		got.Cases.DeriveKeys = append(got.Cases.DeriveKeys, deriveCase{
			SsStatic:     hex.EncodeToString(ssS),
			SsEph:        hex.EncodeToString(ssE),
			ServerRandom: hex.EncodeToString(sr),
			CtStatic:     hex.EncodeToString(cs),
			CtEph:        hex.EncodeToString(ce),
			KeyC2S:       hex.EncodeToString(c2s),
			KeyS2C:       hex.EncodeToString(s2c),
		})
	}

	for _, tc := range []struct {
		seq       uint64
		nodeID    []byte
		plaintext []byte
	}{
		{1, []byte("node-one"), []byte("first message")},
		{2, []byte("node-one"), []byte("")},
		{4294967296, nil, []byte("high sequence, empty node id")},
	} {
		key := pattern(32, 0xA0)
		ct, err := channel.SealForTest(key, tc.nodeID, tc.seq, tc.plaintext)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		got.Cases.Seal = append(got.Cases.Seal, sealCase{
			Key:        hex.EncodeToString(key),
			NodeID:     hex.EncodeToString(tc.nodeID),
			Seq:        tc.seq,
			Plaintext:  hex.EncodeToString(tc.plaintext),
			Ciphertext: hex.EncodeToString(ct),
		})
	}

	for i := 0; i < 2; i++ {
		pk := pattern(1952, byte(0xB0+i))
		got.Cases.Handle = append(got.Cases.Handle, handleCase{
			IdentityPk: hex.EncodeToString(pk),
			Handle:     node.Handle(pk),
		})
	}

	master := pattern(32, 0xC0)
	sm, err := psk.NewSoftwareMaster(master)
	if err != nil {
		t.Fatalf("master: %v", err)
	}
	d, err := psk.NewDeriver(sm)
	if err != nil {
		t.Fatalf("deriver: %v", err)
	}
	for _, tc := range []struct {
		a, b  string
		epoch uint32
	}{
		{"alice", "bob", 1},
		{"bob", "alice", 1}, // must equal the previous: Pair sorts
		{"alice", "bob", 2},
		{"ab", "c", 1}, // length prefixing: must differ from ("a","bc")
		{"a", "bc", 1},
	} {
		k, err := d.Pair(tc.a, tc.b, tc.epoch)
		if err != nil {
			t.Fatalf("psk: %v", err)
		}
		got.Cases.PSK = append(got.Cases.PSK, pskCase{
			Master: hex.EncodeToString(master),
			A:      tc.a,
			B:      tc.b,
			Epoch:  tc.epoch,
			PSK:    hex.EncodeToString(k.Bytes()),
		})
	}

	for _, tc := range []struct {
		epoch    uint32
		nodeID   string
		dnsName  string
		endpoint string
		ips      []string
	}{
		{3, "node-one", "alpha", "", []string{"100.64.0.1/32"}},
		{3, "node-one", "alpha", "", []string{"100.64.0.1/32", "fd00::1/128"}},
		{4, "node-one", "alpha", "", []string{"100.64.0.1/32"}}, // epoch alone must change it
		{3, "node-two", "", "1.2.3.4:51820", nil},
	} {
		p := &proto.KarstNetmapPeer{
			NodeId:       []byte(tc.nodeID),
			KemPublicKey: pattern(1184, 0xD0),
			DhPublicKey:  pattern(32, 0xE0),
			DnsName:      tc.dnsName,
			Endpoint:     tc.endpoint,
			AllowedIps:   tc.ips,
		}
		got.Cases.PeerDigest = append(got.Cases.PeerDigest, digestCase{
			Epoch:        tc.epoch,
			NodeID:       hex.EncodeToString(p.GetNodeId()),
			KemPublicKey: hex.EncodeToString(p.GetKemPublicKey()),
			DhPublicKey:  hex.EncodeToString(p.GetDhPublicKey()),
			DNSName:      tc.dnsName,
			Endpoint:     tc.endpoint,
			AllowedIPs:   tc.ips,
			Digest:       control.PeerDigest(p, tc.epoch),
		})
	}

	for _, tc := range []struct {
		name string
		resp *proto.KarstNetmapResponse
		psks []string // PSK bytes to attach, one per peer; hex
	}{
		{
			name: "a node alone in its network",
			resp: &proto.KarstNetmapResponse{
				PskEpoch:  9,
				NodeId:    []byte("node-one"),
				DnsName:   "alpha",
				Addresses: []string{"100.64.0.1", "fd00::1"},
			},
		},
		{
			name: "one peer",
			resp: &proto.KarstNetmapResponse{
				PskEpoch:  9,
				NodeId:    []byte("node-one"),
				DnsName:   "alpha",
				Addresses: []string{"100.64.0.1"},
				Peers: []*proto.KarstNetmapPeer{{
					NodeId:       []byte("node-two"),
					KemPublicKey: pattern(1184, 0xD0),
					DhPublicKey:  pattern(32, 0xE0),
					DnsName:      "beta",
					AllowedIps:   []string{"100.64.0.2/32"},
				}},
			},
			psks: []string{hex.EncodeToString(pattern(32, 0x70))},
		},
		{
			// Byte-identical to the previous case except for the PSK, which is
			// deliberately not hashed. The two versions MUST match: a value
			// sent in clear must not be a function of secret material.
			name: "the same netmap with a different PSK",
			resp: &proto.KarstNetmapResponse{
				PskEpoch:  9,
				NodeId:    []byte("node-one"),
				DnsName:   "alpha",
				Addresses: []string{"100.64.0.1"},
				Peers: []*proto.KarstNetmapPeer{{
					NodeId:       []byte("node-two"),
					KemPublicKey: pattern(1184, 0xD0),
					DhPublicKey:  pattern(32, 0xE0),
					DnsName:      "beta",
					AllowedIps:   []string{"100.64.0.2/32"},
				}},
			},
			psks: []string{hex.EncodeToString(pattern(32, 0x71))},
		},
		{
			// A policy edit changes nothing else, so if the filter were not
			// hashed every node would be told "unchanged" and the new rules
			// would never arrive.
			name: "the same netmap with a packet filter",
			resp: &proto.KarstNetmapResponse{
				PskEpoch:  9,
				NodeId:    []byte("node-one"),
				DnsName:   "alpha",
				Addresses: []string{"100.64.0.1"},
				Peers: []*proto.KarstNetmapPeer{{
					NodeId:       []byte("node-two"),
					KemPublicKey: pattern(1184, 0xD0),
					DhPublicKey:  pattern(32, 0xE0),
					DnsName:      "beta",
					AllowedIps:   []string{"100.64.0.2/32"},
				}},
				PacketFilter: []*proto.KarstFilterRule{{
					Srcs:  []string{"node-two"},
					Ports: []*proto.KarstPortRange{{First: 22, Last: 22}},
				}},
			},
			psks: []string{hex.EncodeToString(pattern(32, 0x70))},
		},
		{
			// The same rule, in the other direction. Its version MUST differ
			// from the previous case: without a separator between the two rule
			// lists the byte streams are identical, so inverting a policy would
			// leave the version unmoved and the change undelivered.
			name: "the same rule moved to the egress filter",
			resp: &proto.KarstNetmapResponse{
				PskEpoch:  9,
				NodeId:    []byte("node-one"),
				DnsName:   "alpha",
				Addresses: []string{"100.64.0.1"},
				Peers: []*proto.KarstNetmapPeer{{
					NodeId:       []byte("node-two"),
					KemPublicKey: pattern(1184, 0xD0),
					DhPublicKey:  pattern(32, 0xE0),
					DnsName:      "beta",
					AllowedIps:   []string{"100.64.0.2/32"},
				}},
				EgressFilter: []*proto.KarstEgressRule{{
					Dsts:  []string{"node-two"},
					Ports: []*proto.KarstPortRange{{First: 22, Last: 22}},
				}},
			},
			psks: []string{hex.EncodeToString(pattern(32, 0x70))},
		},
	} {
		vc := versionCase{
			PskEpoch:  tc.resp.GetPskEpoch(),
			NodeID:    hex.EncodeToString(tc.resp.GetNodeId()),
			DNSName:   tc.resp.GetDnsName(),
			Addresses: tc.resp.GetAddresses(),
			Version:   control.NetmapVersion(tc.resp),
		}
		for i, p := range tc.resp.GetPeers() {
			vp := versionPeer{
				NodeID:       hex.EncodeToString(p.GetNodeId()),
				KemPublicKey: hex.EncodeToString(p.GetKemPublicKey()),
				DhPublicKey:  hex.EncodeToString(p.GetDhPublicKey()),
				DNSName:      p.GetDnsName(),
				Endpoint:     p.GetEndpoint(),
				AllowedIPs:   p.GetAllowedIps(),
			}
			if i < len(tc.psks) {
				vp.PSK = tc.psks[i]
			}
			vc.Peers = append(vc.Peers, vp)
		}
		for _, r := range tc.resp.GetPacketFilter() {
			vc.PacketFilter = append(vc.PacketFilter, versionRule{
				Srcs:  r.GetSrcs(),
				Ports: portsOf(r.GetPorts()),
			})
		}
		for _, r := range tc.resp.GetEgressFilter() {
			vc.EgressFilter = append(vc.EgressFilter, versionRule{
				Srcs:  r.GetDsts(),
				Ports: portsOf(r.GetPorts()),
			})
		}
		got.Cases.NetmapVersion = append(got.Cases.NetmapVersion, vc)
	}

	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	encoded = append(encoded, '\n')

	path := vectorsPath(t)
	if os.Getenv("UPDATE_VECTORS") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Logf("wrote %s", path)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors (regenerate with UPDATE_VECTORS=1): %v", err)
	}
	if string(want) != string(encoded) {
		t.Fatal("generated vectors differ from the committed file. " +
			"If this is an intended protocol change, regenerate with " +
			"UPDATE_VECTORS=1 and expect the Rust side to fail until it is updated too.")
	}
}

func portsOf(in []*proto.KarstPortRange) []versionPortRange {
	var out []versionPortRange
	for _, p := range in {
		out = append(out, versionPortRange{First: p.GetFirst(), Last: p.GetLast()})
	}
	return out
}
