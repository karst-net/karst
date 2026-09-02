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
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
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
	PskEpoch     uint32         `json:"psk_epoch"`
	NodeID       string         `json:"node_id"`
	DNSName      string         `json:"dns_name"`
	Addresses    []string       `json:"addresses"`
	Peers        []versionPeer  `json:"peers"`
	PacketFilter []versionRule  `json:"packet_filter"`
	EgressFilter []versionRule  `json:"egress_filter"`
	Relays       []versionRelay `json:"relays"`
	DNS          versionDNS     `json:"dns"`
	Bedrock      versionBedrock `json:"bedrock"`
	Version      uint64         `json:"version"`
}

// versionBedrock is the Bedrock log tip as the version hash sees it. Without
// it in the construction a server could advance its log, answer "unchanged",
// and leave every node enforcing a policy that has moved — which for a
// fail-closed mechanism means stale coverage decisions nobody can see.
type versionBedrock struct {
	Hash string `json:"hash,omitempty"`
	Seq  uint64 `json:"seq,omitempty"`
	// Mode is hashed so that enabling enforcement from a console reaches nodes
	// on their next poll. Without it, turning on the network lock would be the
	// one change the server could not deliver.
	Mode uint32 `json:"mode,omitempty"`
}

type versionDNS struct {
	Nameservers   []string          `json:"nameservers,omitempty"`
	SearchDomains []string          `json:"search_domains,omitempty"`
	Routes        []versionDNSRoute `json:"routes,omitempty"`
	Zone          string            `json:"zone,omitempty"`
	MagicDNS      bool              `json:"magic_dns,omitempty"`
}

type versionDNSRoute struct {
	MatchDomain string   `json:"match_domain"`
	Resolvers   []string `json:"resolvers"`
}

// versionRelay is the relay registry as the version hash sees it.
//
// The `karst-relays` term has existed on both sides since 2026-08-18 and until
// now no vector carried a single relay, so the one field of the netmap that a
// production server had never populated (GitHub issue [#48](https://github.com/karst-net/karst/issues/48)) was also the one the
// two implementations had never been checked to agree on. A disagreement here
// is not a degraded relay: the node recomputes the version over the netmap it
// assembled and refuses one that does not match, so no netmap would ever apply.
type versionRelay struct {
	Address       string `json:"address"`
	TLSServerName string `json:"tls_server_name"`
	RelayID       string `json:"relay_id"`
	IdentityKey   string `json:"identity_key"`
	Region        string `json:"region"`
}

type versionPeer struct {
	NodeID       string   `json:"node_id"`
	KemPublicKey string   `json:"kem_public_key"`
	DhPublicKey  string   `json:"dh_public_key"`
	DNSName      string   `json:"dns_name"`
	Endpoint     string   `json:"endpoint"`
	HomeRelay    string   `json:"home_relay"`
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
	HomeRelay    string   `json:"home_relay"`
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

// relayFor builds a registry entry with its id derived the way production does.
//
// Through relayreg rather than a literal, so the fixture cannot drift from the
// package that renders real registries — and karstd recomputes the same digest
// while decoding, rejecting the whole netmap when it disagrees.
func relayFor(address, serverName string, seed byte, region string) *proto.KarstRelay {
	key := pattern(relayreg.IdentityKeySize, seed)
	return &proto.KarstRelay{
		Address:       address,
		TlsServerName: serverName,
		RelayId:       relayreg.RelayID(key),
		IdentityKey:   key,
		Region:        region,
	}
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
			"2026-08-18: netmap_version gained the domain-separated karst-relays " +
			"term; pre-change version values are intentionally incompatible. " +
			"2026-08-21: netmap_version cases carry relay registries. The term " +
			"had been hashed by both ends since 2026-08-18 with no vector " +
			"exercising it, because no production server ever populated the " +
			"field (GitHub issue [#48](https://github.com/karst-net/karst/issues/48)). " +
			"2026-08-25: netmap_version gained the domain-separated karst-bedrock " +
			"term (bedrock-v1.md §5), and then the enforcement mode within it. " +
			"Pre-change version values are intentionally " +
			"incompatible. " +
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
		pk := pattern(2592, byte(0xB0+i))
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
		home     []byte
		ips      []string
	}{
		{3, "node-one", "alpha", "", nil, []string{"100.64.0.1/32"}},
		{3, "node-one", "alpha", "", nil, []string{"100.64.0.1/32", "fd00::1/128"}},
		{4, "node-one", "alpha", "", nil, []string{"100.64.0.1/32"}}, // epoch alone must change it
		{3, "node-two", "", "1.2.3.4:51820", nil, nil},
		// A non-empty home relay, so the vector proves the two languages agree
		// on the *value* and not merely on the field's position. An empty one
		// still shifts the hash through its length prefix, so without this case
		// a side that hashed the field and a side that skipped it entirely
		// would disagree — but a side that hashed it in the wrong place might
		// not.
		{3, "node-three", "gamma", "", pattern(32, 0x7A), []string{"100.64.0.3/32"}},
	} {
		p := &proto.KarstNetmapPeer{
			NodeId:       []byte(tc.nodeID),
			KemPublicKey: pattern(1184, 0xD0),
			DhPublicKey:  pattern(32, 0xE0),
			DnsName:      tc.dnsName,
			Endpoint:     tc.endpoint,
			HomeRelay:    tc.home,
			AllowedIps:   tc.ips,
		}
		got.Cases.PeerDigest = append(got.Cases.PeerDigest, digestCase{
			Epoch:        tc.epoch,
			NodeID:       hex.EncodeToString(p.GetNodeId()),
			KemPublicKey: hex.EncodeToString(p.GetKemPublicKey()),
			DhPublicKey:  hex.EncodeToString(p.GetDhPublicKey()),
			DNSName:      tc.dnsName,
			Endpoint:     tc.endpoint,
			HomeRelay:    hex.EncodeToString(tc.home),
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
		{
			name: "a netmap with resolver policy",
			resp: &proto.KarstNetmapResponse{
				PskEpoch:  9,
				NodeId:    []byte("node-one"),
				DnsName:   "alpha",
				Addresses: []string{"100.64.0.1"},
				DnsConfig: &proto.KarstDNSConfig{
					Zone:          "aquifer.karst.",
					MagicDns:      true,
					Nameservers:   []string{"1.1.1.1:53"},
					SearchDomains: []string{"corp.example"},
					Routes: []*proto.KarstDNSRoute{{
						MatchDomain: "internal.example",
						Resolvers:   []string{"100.64.0.53:53"},
					}},
				},
			},
		},
		{
			// A relay registry, which no vector carried until now. Its version
			// MUST differ from "one peer": if the registry were not hashed,
			// publishing a relay would leave every node told "unchanged" and
			// the relay would never be dialled by anyone.
			name: "the same netmap with a relay registry",
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
				Relays: []*proto.KarstRelay{relayFor("203.0.113.7:443", "relay.example.com", 0xA0, "default")},
			},
			psks: []string{hex.EncodeToString(pattern(32, 0x70))},
		},
		{
			// The same relay moved to another region. §8 refuses to mesh across
			// regions and §9 selects by them, so a version that ignored the
			// region would let a re-homed relay go undelivered — the registry
			// would read correctly on the server and be stale on every node.
			name: "the same relay in a different region",
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
				Relays: []*proto.KarstRelay{relayFor("203.0.113.7:443", "relay.example.com", 0xA0, "eu-west")},
			},
			psks: []string{hex.EncodeToString(pattern(32, 0x70))},
		},
		{
			// Two relays, so the vector pins the *order* they are folded in.
			// Implementations that iterate a map rather than the repeated field
			// agree on every single-relay case and disagree here.
			// A Bedrock head. Its version MUST differ from "a node alone in
			// its network", which is byte-identical but for this field: if the
			// head were not hashed, a log that advanced would leave every node
			// told "unchanged" and enforcing on coverage that had since
			// changed. That is the one failure mode a fail-closed mechanism
			// cannot afford to have be silent.
			name: "a netmap carrying a Bedrock head",
			resp: &proto.KarstNetmapResponse{
				PskEpoch:  9,
				NodeId:    []byte("node-one"),
				DnsName:   "alpha",
				Addresses: []string{"100.64.0.1", "fd00::1"},
				BedrockHead: &proto.KarstBedrockHead{
					Hash: pattern(64, 0xC0),
					Seq:  7,
				},
			},
		},
		{
			// The same head at a different sequence. Hashing only the hash and
			// not the sequence would make these collide, and a node could then
			// be handed a rewound log at the same tip without the version
			// moving.
			name: "the same Bedrock head with enforcement enabled",
			resp: &proto.KarstNetmapResponse{
				PskEpoch:  9,
				NodeId:    []byte("node-one"),
				DnsName:   "alpha",
				Addresses: []string{"100.64.0.1", "fd00::1"},
				BedrockHead: &proto.KarstBedrockHead{
					Hash: pattern(64, 0xC0),
					Seq:  7,
					Mode: proto.KarstBedrockMode_KARST_BEDROCK_MODE_ENFORCING,
				},
			},
		},
		{
			name: "the same Bedrock hash at a different sequence",
			resp: &proto.KarstNetmapResponse{
				PskEpoch:  9,
				NodeId:    []byte("node-one"),
				DnsName:   "alpha",
				Addresses: []string{"100.64.0.1", "fd00::1"},
				BedrockHead: &proto.KarstBedrockHead{
					Hash: pattern(64, 0xC0),
					Seq:  8,
				},
			},
		},
		{
			name: "two relays",
			resp: &proto.KarstNetmapResponse{
				PskEpoch:  9,
				NodeId:    []byte("node-one"),
				DnsName:   "alpha",
				Addresses: []string{"100.64.0.1"},
				Relays: []*proto.KarstRelay{
					relayFor("203.0.113.7:443", "relay.example.com", 0xA0, "default"),
					relayFor("198.51.100.9:443", "two.example.com", 0xB0, "eu-west"),
				},
			},
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
				HomeRelay:    hex.EncodeToString(p.GetHomeRelay()),
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
		for _, r := range tc.resp.GetRelays() {
			vc.Relays = append(vc.Relays, versionRelay{
				Address:       r.GetAddress(),
				TLSServerName: r.GetTlsServerName(),
				RelayID:       hex.EncodeToString(r.GetRelayId()),
				IdentityKey:   hex.EncodeToString(r.GetIdentityKey()),
				Region:        r.GetRegion(),
			})
		}
		for _, route := range tc.resp.GetDnsConfig().GetRoutes() {
			vc.DNS.Routes = append(vc.DNS.Routes, versionDNSRoute{
				MatchDomain: route.GetMatchDomain(), Resolvers: route.GetResolvers(),
			})
		}
		vc.DNS.Nameservers = tc.resp.GetDnsConfig().GetNameservers()
		vc.DNS.SearchDomains = tc.resp.GetDnsConfig().GetSearchDomains()
		vc.DNS.Zone = tc.resp.GetDnsConfig().GetZone()
		vc.DNS.MagicDNS = tc.resp.GetDnsConfig().GetMagicDns()
		vc.Bedrock.Hash = hex.EncodeToString(tc.resp.GetBedrockHead().GetHash())
		vc.Bedrock.Seq = tc.resp.GetBedrockHead().GetSeq()
		vc.Bedrock.Mode = uint32(tc.resp.GetBedrockHead().GetMode())
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
