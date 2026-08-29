// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package bedrock

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Cross-implementation test vectors for BEDROCK v1.
//
// The Go server and the Rust node verify one chain. Everywhere they must agree
// byte-for-byte they can silently disagree instead — a missing length prefix, a
// context string with different spacing, a body field in the wrong order — and
// the symptom is a node that refuses every peer, or worse, one that accepts a
// peer it should not. Vectors turn that into a test failure in whichever
// implementation drifted.
//
// **These pin exact signature bytes**, which the KARST-CONTROL vectors
// deliberately do not. That is possible because ADR-0014 makes Bedrock signing
// deterministic, and it was measured before it was relied on: circl and
// RustCrypto produce identical bytes for the same key, message and context. It
// is worth doing because a vector that merely asserts "both implementations
// verify this signature" still passes when one side signs the wrong message
// under the right key.
//
// The rejected[] cases matter as much as the valid ones. A verifier that
// accepts everything passes every positive vector.
//
// Regenerate with:
//
//	UPDATE_VECTORS=1 go test ./management/internals/karst/bedrock/ -run Vectors

type bedrockVectorFile struct {
	Spec  string             `json:"spec"`
	Note  string             `json:"note"`
	Cases bedrockVectorCases `json:"cases"`
}

type bedrockVectorCases struct {
	RootSign      []rootSignCase  `json:"root_sign"`
	AuthoritySign []authSignCase  `json:"authority_sign"`
	ChainHash     []chainHashCase `json:"chain_hash"`
	Bodies        []bodyCase      `json:"bodies"`
	Logs          []logCase       `json:"logs"`
	Rejected      []rejectedCase  `json:"rejected"`
}

// rootSignCase carries a 32-byte seed. Before ADR-0015 Option A it had to carry
// the whole 96-byte FIPS 205 private key, because circl derived a key from a
// seed by running MGF1 over it and RustCrypto had no matching function — so the
// private key was the only representation both libraries shared. With both
// tiers on ML-DSA-87 the seed expands identically everywhere.
type rootSignCase struct {
	Seed      string `json:"seed"`
	PublicKey string `json:"public_key"`
	Context   string `json:"context"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

type authSignCase struct {
	Seed      string `json:"seed"`
	PublicKey string `json:"public_key"`
	Context   string `json:"context"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

type chainHashCase struct {
	Prev string `json:"prev"`
	Seq  uint64 `json:"seq"`
	Time int64  `json:"time"`
	Op   string `json:"op"`
	Body string `json:"body"`
	Hash string `json:"hash"`
}

// bodyCase pins each body layout from spec §3.4. A disagreement here is a
// signature failure on every entry of that type, with no other symptom.
type bodyCase struct {
	Op       string `json:"op"`
	Note     string `json:"note"`
	Encoding string `json:"encoding"`
}

type logCase struct {
	Name     string         `json:"name"`
	Encoded  string         `json:"encoded"`
	Head     string         `json:"head"`
	HeadSeq  uint64         `json:"head_seq"`
	Zone     string         `json:"zone"`
	Quorum   uint32         `json:"quorum"`
	Disabled bool           `json:"disabled"`
	Coverage []coverageCase `json:"coverage"`
}

// coverageCase pins the enforcement decision. All three keys travel, because
// all three are compared — spec §6.1.
// coverageCase pins the enforcement decision. Only the datapath keys travel,
// because only those are what a netmap supplies and therefore what is compared
// — spec §6.1.
type coverageCase struct {
	Handle       string `json:"handle"`
	KemPublicKey string `json:"kem_public_key"`
	DhPublicKey  string `json:"dh_public_key"`
	At           int64  `json:"at"`
	Covered      bool   `json:"covered"`
}

// rejectedCase is a log that MUST fail verification, with the reason it must
// fail stated so a reader of the vector file knows what is being asserted.
type rejectedCase struct {
	Name    string `json:"name"`
	Why     string `json:"why"`
	Encoded string `json:"encoded"`
}

func bedrockVectorsPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this source file")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "..",
		"spec", "vectors", "bedrock-v1.json")
}

// vectorFixture is deliberately smaller than log_test.go's: two roots at k=1
// and three authorities at q=2. Every root signature is 16 224 bytes and the
// vectors carry them in hex, so a third root would add 32 KB to the file for
// no property that k=1-of-2 does not already pin.
type vectorFixture struct {
	roots   []*RootKey
	auths   []*AuthorityKey
	rootPKs [][]byte
	authPKs [][]byte
	alice   testNode
	bob     testNode
}

func newVectorFixture(t *testing.T) *vectorFixture {
	t.Helper()
	f := &vectorFixture{}
	for i := 0; i < 2; i++ {
		r := testRoot(t, byte(0x10*(i+1)))
		f.roots = append(f.roots, r)
		f.rootPKs = append(f.rootPKs, r.Public())
	}
	for i := 0; i < 3; i++ {
		a := testAuthority(t, byte(0x40+i))
		f.auths = append(f.auths, a)
		f.authPKs = append(f.authPKs, a.Public())
	}
	f.alice = nodeKeys(t, 0x77)
	f.bob = nodeKeys(t, 0x88)
	return f
}

func (f *vectorFixture) rootQuorum(t *testing.T, b *Builder, at int64, op Op, body []byte) {
	t.Helper()
	e, input := b.Prepare(at, op, body)
	sigs, err := SignRoots(input, RootSigner{Index: 0, Key: f.roots[0]})
	if err != nil {
		t.Fatalf("sign roots: %v", err)
	}
	if err := b.Commit(e, sigs); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func (f *vectorFixture) authQuorum(t *testing.T, b *Builder, at int64, op Op, body []byte) {
	t.Helper()
	e, input := b.Prepare(at, op, body)
	sigs, err := SignAuthorities(input,
		AuthoritySigner{Index: 0, Key: f.auths[0]},
		AuthoritySigner{Index: 1, Key: f.auths[1]},
	)
	if err != nil {
		t.Fatalf("sign authorities: %v", err)
	}
	if err := b.Commit(e, sigs); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func (f *vectorFixture) genesisBody() []byte {
	return GenesisBody("aquifer.karst.", f.rootPKs, 1, f.authPKs, 2)
}

func TestVectors(t *testing.T) {
	f := newVectorFixture(t)

	got := bedrockVectorFile{
		Spec: "BEDROCK v1",
		Note: "Cross-implementation vectors for spec/bedrock-v1.md. Pins exact " +
			"signature bytes, which is possible because ADR-0014 makes Bedrock " +
			"signing deterministic and because circl and RustCrypto were measured " +
			"to agree byte-for-byte. Root cases carry the 96-byte private key " +
			"rather than a seed: circl derives a key from a seed via MGF1 and " +
			"RustCrypto has no matching derivation, so the private key is the only " +
			"representation both libraries share. The rejected[] cases must FAIL " +
			"verification in both implementations; a verifier that accepts " +
			"everything passes every valid case. " +
			"2026-08-25: both tiers moved to ML-DSA-87 (ADR-0015 Option A); CNSA 2.0 " +
			"excludes SLH-DSA, so the hash-based root is gone and root cases now " +
			"carry a 32-byte seed. node-sign covers the ML-KEM and X25519 static keys as " +
			"well as the ML-DSA identity key (spec §6.1) — the identity key is not " +
			"used by PHREATIC, so covering it alone authorized a node to exist " +
			"without constraining which session keys were its. Pre-change bodies " +
			"are intentionally incompatible. " +
			"Generated by server/management/internals/karst/bedrock/vectors_test.go.",
	}

	// ── signature primitives ────────────────────────────────────────────────

	for _, msg := range [][]byte{{}, []byte("the authority list")} {
		seed := f.roots[0].Seed()
		pub := f.roots[0].Public()
		sig, err := f.roots[0].Sign(msg)
		if err != nil {
			t.Fatalf("root sign: %v", err)
		}
		got.Cases.RootSign = append(got.Cases.RootSign, rootSignCase{
			Seed:      hex.EncodeToString(seed),
			PublicKey: hex.EncodeToString(pub),
			Context:   RootContext,
			Message:   hex.EncodeToString(msg),
			Signature: hex.EncodeToString(sig),
		})
	}

	for _, msg := range [][]byte{{}, []byte("countersign alice")} {
		seed := make([]byte, AuthoritySeedSize)
		for i := range seed {
			seed[i] = 0x40 + byte(i)
		}
		sig, err := f.auths[0].Sign(msg)
		if err != nil {
			t.Fatalf("authority sign: %v", err)
		}
		got.Cases.AuthoritySign = append(got.Cases.AuthoritySign, authSignCase{
			Seed:      hex.EncodeToString(seed),
			PublicKey: hex.EncodeToString(f.auths[0].Public()),
			Context:   AuthorityContext,
			Message:   hex.EncodeToString(msg),
			Signature: hex.EncodeToString(sig),
		})
	}

	// ── the chain hash ──────────────────────────────────────────────────────
	//
	// Including a genesis-shaped case with an empty prev, and two that differ
	// only in op — an implementation that forgot to hash the op agrees on every
	// other case and fails that pair.
	for _, tc := range []struct {
		prev []byte
		seq  uint64
		time int64
		op   Op
		body []byte
	}{
		{nil, 1, 1000, OpGenesis, []byte("body")},
		{[]byte("0123456789abcdef"), 2, 1100, OpNodeSign, []byte("body")},
		{[]byte("0123456789abcdef"), 2, 1100, OpNodeRevoke, []byte("body")},
		{[]byte("0123456789abcdef"), 2, 1100, OpNodeSign, []byte{}},
	} {
		got.Cases.ChainHash = append(got.Cases.ChainHash, chainHashCase{
			Prev: hex.EncodeToString(tc.prev),
			Seq:  tc.seq,
			Time: tc.time,
			Op:   string(tc.op),
			Body: hex.EncodeToString(tc.body),
			Hash: hex.EncodeToString(ChainHash(tc.prev, tc.seq, tc.time, tc.op, tc.body)),
		})
	}

	// ── body layouts ────────────────────────────────────────────────────────

	for _, tc := range []struct {
		op   Op
		note string
		body []byte
	}{
		{OpGenesis, "two roots at k=1, three authorities at q=2", f.genesisBody()},
		{OpAuthorityList, "three authorities at q=2", AuthorityListBody(f.authPKs, 2)},
		{OpNodeSign, "no not-before, no expiry", signBody(f.alice, 0, 0)},
		{OpNodeSign, "a bounded window", signBody(f.bob, 1500, 2500)},
		{OpNodeRevoke, "with a reason", NodeRevokeBody(f.alice.Handle, "laptop stolen", 1300)},
		{OpQuorumChange, "raise the quorum to three", QuorumChangeBody(3)},
		{OpAnchor, "an audit head at sequence 42", AnchorBody([]byte("audit-head"), 42)},
		{OpDisable, "with a reason", DisableBody("decommissioning")},
		// Adjacent variable-length fields, to pin that they are length-prefixed:
		// without prefixes these two produce identical bytes.
		{OpNodeRevoke, "length prefixing: ab|c", NodeRevokeBody("ab", "c", 1)},
		{OpNodeRevoke, "length prefixing: a|bc", NodeRevokeBody("a", "bc", 1)},
	} {
		got.Cases.Bodies = append(got.Cases.Bodies, bodyCase{
			Op:       string(tc.op),
			Note:     tc.note,
			Encoding: hex.EncodeToString(tc.body),
		})
	}

	// ── a complete log ──────────────────────────────────────────────────────

	full := NewBuilder()
	f.rootQuorum(t, full, 1000, OpGenesis, f.genesisBody())
	f.authQuorum(t, full, 1100, OpNodeSign, signBody(f.alice, 0, 0))
	f.authQuorum(t, full, 1200, OpNodeSign, signBody(f.bob, 1500, 2500))
	f.authQuorum(t, full, 1300, OpNodeRevoke, NodeRevokeBody(f.alice.Handle, "laptop stolen", 1400))

	st, err := VerifyLog(full.Entries())
	if err != nil {
		t.Fatalf("verify full log: %v", err)
	}
	got.Cases.Logs = append(got.Cases.Logs, logCase{
		Name:    "genesis, two node-signs, one revocation",
		Encoded: hex.EncodeToString(EncodeLog(full.Entries())),
		Head:    hex.EncodeToString(st.Head),
		HeadSeq: st.HeadSeq,
		Zone:    st.Zone,
		Quorum:  st.Q,
		Coverage: coverageCases(st, []coverageCase{
			keyCase(f.alice.Handle, f.alice.Keys, 1350),
			keyCase(f.alice.Handle, f.alice.Keys, 1400), // revoked from 1400
			keyCase(f.alice.Handle, f.bob.Keys, 1350),   // right handle, wrong keys
			keyCase(f.bob.Handle, f.bob.Keys, 1499),     // before not_before
			keyCase(f.bob.Handle, f.bob.Keys, 1500),
			keyCase(f.bob.Handle, f.bob.Keys, 2500), // at expiry
			keyCase("an-unknown-handle", f.alice.Keys, 1350),
			// Each datapath key swapped in isolation, so a verifier that
			// compares only one of the two fails exactly one of these rather
			// than none.
			keyCase(f.alice.Handle, PeerKeys{f.bob.Keys.KemPublicKey, f.alice.Keys.DhPublicKey}, 1350),
			keyCase(f.alice.Handle, PeerKeys{f.alice.Keys.KemPublicKey, f.bob.Keys.DhPublicKey}, 1350),
		}),
	})

	// ── logs that must be rejected ──────────────────────────────────────────

	base := NewBuilder()
	f.rootQuorum(t, base, 1000, OpGenesis, f.genesisBody())
	f.authQuorum(t, base, 1100, OpNodeSign, signBody(f.alice, 0, 0))
	f.authQuorum(t, base, 1200, OpNodeSign, signBody(f.bob, 0, 0))

	clone := func() []Entry {
		out := make([]Entry, len(base.Entries()))
		copy(out, base.Entries())
		return out
	}

	// A tampered body: the signatures are genuine, the content is not.
	tampered := clone()
	tamperedBody := append([]byte(nil), tampered[1].Body...)
	tamperedBody[len(tamperedBody)-1] ^= 0x01
	tampered[1].Body = tamperedBody

	// Genuine signatures over the wrong entry.
	swapped := clone()
	swapped[1].Sigs = base.Entries()[2].Sigs

	// One authority signing twice to reach q=2 alone.
	dupInput := base.Entries()[2].SigningInput(base.Entries()[1].Hash)
	dupSig, err := f.auths[0].Sign(dupInput)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	duplicated := clone()
	duplicated[2].Sigs = []Signature{{SignerIndex: 0, Sig: dupSig}, {SignerIndex: 0, Sig: dupSig}}

	// A dropped middle entry.
	dropped := []Entry{base.Entries()[0], base.Entries()[2]}

	// Reordered entries.
	reordered := clone()
	reordered[1], reordered[2] = reordered[2], reordered[1]

	// An unknown op.
	unknown := clone()
	unknown[1].Op = "node-bless"

	// A quorum of authorities appointing their own successors.
	authorityCoup := NewBuilder()
	f.rootQuorum(t, authorityCoup, 1000, OpGenesis, f.genesisBody())
	f.authQuorum(t, authorityCoup, 1100, OpAuthorityList, AuthorityListBody(f.authPKs, 1))

	for _, tc := range []struct {
		name, why string
		entries   []Entry
	}{
		{"tampered body", "the body was modified after signing", tampered},
		{"signatures over another entry", "genuine signatures, wrong entry hash", swapped},
		{"one authority signing twice", "a duplicate signer index must not reach quorum", duplicated},
		{"dropped middle entry", "the chain no longer links", dropped},
		{"reordered entries", "sequence and predecessor no longer agree", reordered},
		{"unknown op", "an unrecognized op is a hard failure, not a skip", unknown},
		{"authority-signed authority-list", "authorities must not appoint their own successors", authorityCoup.Entries()},
	} {
		if _, err := VerifyLog(tc.entries); err == nil {
			t.Fatalf("rejected case %q verified in Go; the vector would be wrong", tc.name)
		}
		got.Cases.Rejected = append(got.Cases.Rejected, rejectedCase{
			Name:    tc.name,
			Why:     tc.why,
			Encoded: hex.EncodeToString(EncodeLog(tc.entries)),
		})
	}

	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	encoded = append(encoded, '\n')

	path := bedrockVectorsPath(t)
	if os.Getenv("UPDATE_VECTORS") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Logf("wrote %s (%d bytes)", path, len(encoded))
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

func coverageCases(st *State, in []coverageCase) []coverageCase {
	out := make([]coverageCase, 0, len(in))
	for _, c := range in {
		kem, err1 := hex.DecodeString(c.KemPublicKey)
		dh, err2 := hex.DecodeString(c.DhPublicKey)
		if err1 != nil || err2 != nil {
			continue
		}
		c.Covered = st.IsCovered(c.Handle, PeerKeys{KemPublicKey: kem, DhPublicKey: dh}, c.At)
		out = append(out, c)
	}
	return out
}

// keyCase renders a key set into a coverage vector.
func keyCase(handle string, k PeerKeys, at int64) coverageCase {
	return coverageCase{
		Handle:       handle,
		KemPublicKey: hex.EncodeToString(k.KemPublicKey),
		DhPublicKey:  hex.EncodeToString(k.DhPublicKey),
		At:           at,
	}
}
