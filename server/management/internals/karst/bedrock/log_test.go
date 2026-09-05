// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package bedrock

import (
	"bytes"
	"errors"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/node"
)

// ── deterministic fixtures ──────────────────────────────────────────────────
//
// Both tiers expand a 32-byte seed since ADR-0015 Option A, so a fixture is a
// seed and a cross-implementation vector can carry one directly. The previous
// root fixture had to travel as a 96-byte FIPS 205 private key, because circl
// derived a key from a seed by running MGF1 over it and RustCrypto had no
// matching function.
func testRoot(t *testing.T, seed byte) *RootKey {
	t.Helper()
	s := make([]byte, RootSeedSize)
	for i := range s {
		s[i] = seed + byte(i)
	}
	k, err := RootFromSeed(s)
	if err != nil {
		t.Fatalf("fixture root: %v", err)
	}
	return k
}

func testAuthority(t *testing.T, seed byte) *AuthorityKey {
	t.Helper()
	s := make([]byte, AuthoritySeedSize)
	for i := range s {
		s[i] = seed + byte(i)
	}
	k, err := AuthorityFromSeed(s)
	if err != nil {
		t.Fatalf("fixture authority: %v", err)
	}
	return k
}

// nodeKeys builds the three keys a node-sign covers. The identity key is a
// real ML-DSA key; the datapath keys are patterns, because nothing here
// verifies a signature under them — spec §6.1 requires only that they be
// compared, and comparing a pattern proves that as well as a real key would.
// testNode is a node's full key set plus the handle its identity derives to.
// Handles are derived, never invented: verifyNodeSign enforces the binding.
type testNode struct {
	Handle   string
	Identity []byte
	Keys     PeerKeys
}

// The identity key is a pattern rather than a real ML-DSA-65 key, and that is
// sound: nothing verifies a signature under a node's identity key. The chain
// checks its length and that the handle is the one it derives to, and a pattern
// satisfies both exactly as a real key would. It also keeps the fixture from
// depending on the identity package, which would be a cycle waiting to happen.
func nodeKeys(t *testing.T, seed byte) testNode {
	t.Helper()
	identity := patternBytes(NodeIdentityKeySize, seed)
	return testNode{
		Handle:   node.Handle(identity),
		Identity: identity,
		Keys: PeerKeys{
			KemPublicKey: patternBytes(KemPublicKeySize, seed),
		},
	}
}

func patternBytes(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed + byte(i)
	}
	return out
}

// signBody is NodeSignBody over a node. It takes no handle argument on purpose:
// the handle must be the one the identity key derives to, so letting a caller
// pass one would only let a fixture build an entry the verifier must reject.
func signBody(n testNode, notBefore, expiry int64) []byte {
	return NodeSignBody(n.Handle, n.Identity, n.Keys.KemPublicKey, notBefore, expiry)
}

// fixture is a small but complete network: three roots at k=2, three
// authorities at q=2, and one covered node.
type fixture struct {
	roots       []*RootKey
	authorities []*AuthorityKey
	rootPKs     [][]byte
	authPKs     [][]byte
	alice       testNode
	b           *Builder
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{b: NewBuilder()}
	for i := 0; i < 3; i++ {
		r := testRoot(t, byte(0x10*(i+1)))
		f.roots = append(f.roots, r)
		f.rootPKs = append(f.rootPKs, r.Public())

		a := testAuthority(t, byte(0x40+i))
		f.authorities = append(f.authorities, a)
		f.authPKs = append(f.authPKs, a.Public())
	}
	f.alice = nodeKeys(t, 0x77)

	f.appendRoot(t, 1000, OpGenesis, GenesisBody("aquifer.karst.", f.rootPKs, 2, f.authPKs, 2, nil))
	f.appendAuth(t, 1100, OpNodeSign, signBody(f.alice, 0, 0))
	return f
}

// appendRoot signs with roots 0 and 1 — a k=2 quorum.
func (f *fixture) appendRoot(t *testing.T, at int64, op Op, body []byte) {
	t.Helper()
	e, input := f.b.Prepare(at, op, body)
	sigs, err := SignRoots(input,
		RootSigner{Index: 0, Key: f.roots[0]},
		RootSigner{Index: 1, Key: f.roots[1]},
	)
	if err != nil {
		t.Fatalf("sign roots: %v", err)
	}
	if err := f.b.Commit(e, sigs); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// appendAuth signs with authorities 0 and 1 — a q=2 quorum.
func (f *fixture) appendAuth(t *testing.T, at int64, op Op, body []byte) {
	t.Helper()
	e, input := f.b.Prepare(at, op, body)
	sigs, err := SignAuthorities(input,
		AuthoritySigner{Index: 0, Key: f.authorities[0]},
		AuthoritySigner{Index: 1, Key: f.authorities[1]},
	)
	if err != nil {
		t.Fatalf("sign authorities: %v", err)
	}
	if err := f.b.Commit(e, sigs); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func (f *fixture) entries() []Entry {
	// A copy, so a negative test that mutates entries cannot affect the next.
	out := make([]Entry, len(f.b.Entries()))
	copy(out, f.b.Entries())
	return out
}

// mustBreak asserts that a tampered log is rejected. Every negative test funnels
// through here so that none of them can accidentally assert "no error".
func mustBreak(t *testing.T, entries []Entry, why string) {
	t.Helper()
	if _, err := VerifyLog(entries); err == nil {
		t.Fatalf("%s: chain verified but must not have", why)
	} else if !errors.Is(err, ErrBroken) && !errors.Is(err, ErrMalformed) {
		t.Fatalf("%s: wrong error: %v", why, err)
	}
}

// ── the happy path ──────────────────────────────────────────────────────────

func TestValidChainVerifies(t *testing.T) {
	f := newFixture(t)
	st, err := f.b.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if st.Zone != "aquifer.karst." {
		t.Errorf("zone = %q", st.Zone)
	}
	if st.HeadSeq != 2 {
		t.Errorf("head seq = %d, want 2", st.HeadSeq)
	}
	if len(st.Head) != 64 {
		t.Errorf("head is %d bytes, want 64 (SHA-512)", len(st.Head))
	}
	if !st.IsCovered(f.alice.Handle, f.alice.Keys, 2000) {
		t.Error("alice should be covered")
	}
}

func TestCoverageBindsHandleAndKeyTogether(t *testing.T) {
	f := newFixture(t)
	st, err := f.b.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	// The whole point of the mechanism: a compromised server that keeps the
	// name and swaps the key gets nothing.
	if st.IsCovered(f.alice.Handle, nodeKeys(t, 0x99).Keys, 2000) {
		t.Error("a different key under a covered handle must not be covered")
	}
	if st.IsCovered("mallory", f.alice.Keys, 2000) {
		t.Error("an unknown handle must not be covered")
	}
}

func TestNotBeforeAndExpiryAreEnforced(t *testing.T) {
	f := newFixture(t)
	bob := nodeKeys(t, 0x88)
	f.appendAuth(t, 1200, OpNodeSign, signBody(bob, 1500, 2500))

	st, err := f.b.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, tc := range []struct {
		at   int64
		want bool
	}{
		{1499, false}, // before not_before
		{1500, true},  // inclusive lower bound
		{2499, true},
		{2500, false}, // exclusive upper bound
		{9999, false},
	} {
		if got := st.IsCovered(bob.Handle, bob.Keys, tc.at); got != tc.want {
			t.Errorf("covered at %d = %v, want %v", tc.at, got, tc.want)
		}
	}
}

func TestRevocationTakesEffectAtItsTime(t *testing.T) {
	f := newFixture(t)
	f.appendAuth(t, 1200, OpNodeRevoke, NodeRevokeBody(f.alice.Handle, "laptop stolen", 1300))

	st, err := f.b.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !st.IsCovered(f.alice.Handle, f.alice.Keys, 1299) {
		t.Error("must still be covered before the revocation takes effect")
	}
	if st.IsCovered(f.alice.Handle, f.alice.Keys, 1300) {
		t.Error("must be uncovered from the effective time")
	}
}

func TestReSigningReadmitsARevokedNode(t *testing.T) {
	f := newFixture(t)
	f.appendAuth(t, 1200, OpNodeRevoke, NodeRevokeBody(f.alice.Handle, "suspected", 1200))
	f.appendAuth(t, 1300, OpNodeSign, signBody(f.alice, 0, 0))

	st, err := f.b.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !st.IsCovered(f.alice.Handle, f.alice.Keys, 1400) {
		t.Error("a later node-sign must supersede an earlier revocation")
	}
}

func TestQuorumChangeIsVerifiedUnderTheOldThreshold(t *testing.T) {
	f := newFixture(t)
	// q is 2 here; moving to 3 must be authorized by 2 signatures, not 3.
	f.appendAuth(t, 1200, OpQuorumChange, QuorumChangeBody(3))

	st, err := f.b.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if st.Q != 3 {
		t.Fatalf("q = %d, want 3", st.Q)
	}

	// And from here on, two signatures are no longer enough.
	e, input := f.b.Prepare(1300, OpNodeSign, signBody(nodeKeys(t, 0x88), 0, 0))
	sigs, err := SignAuthorities(input,
		AuthoritySigner{Index: 0, Key: f.authorities[0]},
		AuthoritySigner{Index: 1, Key: f.authorities[1]},
	)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := f.b.Commit(e, sigs); err != nil {
		t.Fatalf("commit: %v", err)
	}
	mustBreak(t, f.entries(), "two signatures under q=3")
}

func TestAnchorNeedsOnlyOneAuthority(t *testing.T) {
	f := newFixture(t)
	e, input := f.b.Prepare(1200, OpAnchor, AnchorBody([]byte("audit-head"), 42))
	sigs, err := SignAuthorities(input, AuthoritySigner{Index: 2, Key: f.authorities[2]})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := f.b.Commit(e, sigs); err != nil {
		t.Fatalf("commit: %v", err)
	}

	st, err := f.b.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if st.Anchor == nil || st.Anchor.AuditSeq != 42 {
		t.Fatalf("anchor = %+v", st.Anchor)
	}
	if !bytes.Equal(st.Anchor.AuditHead, []byte("audit-head")) {
		t.Errorf("anchor head = %q", st.Anchor.AuditHead)
	}
}

// ADR-0016's new §4 rule: without it a server that truncates its own audit
// log could simply anchor the truncated head and every node would accept the
// rewind.
func TestAnchorAuditSeqMustAdvance(t *testing.T) {
	f := newFixture(t)
	f.appendAuth(t, 1200, OpAnchor, AnchorBody([]byte("first"), 42))
	base := f.entries() // genesis, node-sign, anchor@42

	// signNext resumes on top of base — rather than f.b, which a candidate
	// entry must not permanently join — and signs one more anchor.
	signNext := func(t *testing.T, at int64, body []byte) Entry {
		t.Helper()
		b, err := FromEntries(base)
		if err != nil {
			t.Fatalf("resume: %v", err)
		}
		e, input := b.Prepare(at, OpAnchor, body)
		sigs, err := SignAuthorities(input, AuthoritySigner{Index: 2, Key: f.authorities[2]})
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		e.Sigs = sigs
		return *e
	}
	withNext := func(next Entry) []Entry {
		return append(append([]Entry(nil), base...), next)
	}

	stalled := signNext(t, 1300, AnchorBody([]byte("second"), 42))
	mustBreak(t, withNext(stalled), "an anchor that does not advance audit_seq")

	rewound := signNext(t, 1300, AnchorBody([]byte("rewound"), 10))
	mustBreak(t, withNext(rewound), "an anchor that moves audit_seq backwards")

	advanced := signNext(t, 1300, AnchorBody([]byte("second"), 43))
	st, err := VerifyLog(withNext(advanced))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if st.Anchor.AuditSeq != 43 {
		t.Errorf("anchor audit_seq = %d, want 43", st.Anchor.AuditSeq)
	}
}

// A dedicated anchor key signs under ADR-0016's concatenated signer-index
// space: index 3 is past the three-authority list (indices 0-2) and selects
// anchor-list index 0.
func TestAnchorKeySignsUnderTheConcatenatedIndexSpace(t *testing.T) {
	root := testRoot(t, 0x10)
	authority := testAuthority(t, 0x40)
	anchorKey, err := GenerateAnchor()
	if err != nil {
		t.Fatalf("generate anchor: %v", err)
	}

	b := NewBuilder()
	e, input := b.Prepare(1000, OpGenesis, GenesisBody("z.karst.", [][]byte{root.Public()}, 1,
		[][]byte{authority.Public()}, 1, [][]byte{anchorKey.Public()}))
	sigs, err := SignRoots(input, RootSigner{Index: 0, Key: root})
	if err != nil {
		t.Fatalf("sign genesis: %v", err)
	}
	if err := b.Commit(e, sigs); err != nil {
		t.Fatalf("commit genesis: %v", err)
	}

	e, input = b.Prepare(1100, OpAnchor, AnchorBody([]byte("audit-head"), 7))
	sigs, err = SignAnchors(input, AnchorSigner{Index: 1, Key: anchorKey}) // 1 authority + index 0 in the anchor list
	if err != nil {
		t.Fatalf("sign anchor: %v", err)
	}
	if err := b.Commit(e, sigs); err != nil {
		t.Fatalf("commit anchor: %v", err)
	}

	st, err := b.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if st.Anchor == nil || st.Anchor.AuditSeq != 7 {
		t.Fatalf("anchor = %+v", st.Anchor)
	}

	// The same index is out of range for an authority-only op: rule 6 stays
	// unchanged for everything but anchor.
	e2, input2 := b.Prepare(1200, OpNodeRevoke, NodeRevokeBody("some-handle", "test", 1))
	sig, err := anchorKey.Sign(input2)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	e2.Sigs = []Signature{{SignerIndex: 1, Sig: sig}}
	entries := append(append([]Entry(nil), b.Entries()...), *e2)
	mustBreak(t, entries, "an anchor key's signature accepted for a non-anchor op")
}

func TestDisableRequiresRootsNotAuthorities(t *testing.T) {
	f := newFixture(t)

	// Authorities must not be able to switch the mechanism off, even at full
	// strength — spec §3.1. This is the property that keeps a compromise of q
	// admin devices visible.
	e, input := f.b.Prepare(1200, OpDisable, DisableBody("attacker says so"))
	sigs, err := SignAuthorities(input,
		AuthoritySigner{Index: 0, Key: f.authorities[0]},
		AuthoritySigner{Index: 1, Key: f.authorities[1]},
		AuthoritySigner{Index: 2, Key: f.authorities[2]},
	)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := f.b.Commit(e, sigs); err != nil {
		t.Fatalf("commit: %v", err)
	}
	mustBreak(t, f.entries(), "disable signed by authorities")

	// Roots can.
	f2 := newFixture(t)
	f2.appendRoot(t, 1200, OpDisable, DisableBody("decommissioning"))
	st, err := f2.b.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !st.Disabled || st.DisabledReason != "decommissioning" {
		t.Errorf("disabled = %v, reason = %q", st.Disabled, st.DisabledReason)
	}
}

// ── negative chain tests: one per way to lie (plan §11) ─────────────────────

func TestReorderedEntriesAreRejected(t *testing.T) {
	f := newFixture(t)
	f.appendAuth(t, 1200, OpNodeSign, signBody(nodeKeys(t, 0x88), 0, 0))
	e := f.entries()
	e[1], e[2] = e[2], e[1]
	mustBreak(t, e, "reordered entries")
}

func TestDroppedEntryIsRejected(t *testing.T) {
	f := newFixture(t)
	f.appendAuth(t, 1200, OpNodeSign, signBody(nodeKeys(t, 0x88), 0, 0))
	e := f.entries()
	mustBreak(t, []Entry{e[0], e[2]}, "a dropped middle entry")
}

func TestTruncationIsRejectedOnlyAgainstAKnownHead(t *testing.T) {
	f := newFixture(t)
	f.appendAuth(t, 1200, OpNodeSign, signBody(nodeKeys(t, 0x88), 0, 0))
	full := f.entries()

	// A truncated chain still verifies on its own — that is inherent to a hash
	// chain and is why §5 puts the head in the netmap and compares it between
	// peers. The test records the property rather than pretending otherwise.
	st, err := VerifyLog(full[:2])
	if err != nil {
		t.Fatalf("a truncated prefix is still internally valid: %v", err)
	}
	if st.HeadSeq != 2 {
		t.Fatalf("head seq = %d", st.HeadSeq)
	}
	bob := nodeKeys(t, 0x88)
	if st.IsCovered(bob.Handle, bob.Keys, 2000) {
		t.Error("the dropped entry's effect must be absent")
	}
}

func TestQuorumMinusOneIsRejected(t *testing.T) {
	f := newFixture(t)
	e, input := f.b.Prepare(1200, OpNodeSign, signBody(nodeKeys(t, 0x88), 0, 0))
	sigs, err := SignAuthorities(input, AuthoritySigner{Index: 0, Key: f.authorities[0]})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := f.b.Commit(e, sigs); err != nil {
		t.Fatalf("commit: %v", err)
	}
	mustBreak(t, f.entries(), "q-1 signatures")
}

func TestDuplicateSignerCannotReachQuorumAlone(t *testing.T) {
	f := newFixture(t)
	e, input := f.b.Prepare(1200, OpNodeSign, signBody(nodeKeys(t, 0x88), 0, 0))
	sig, err := f.authorities[0].Sign(input)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// One compromised authority, signing twice. Both signatures are valid; the
	// set is not. Without the duplicate rule this reduces q to 1 everywhere.
	if err := f.b.Commit(e, []Signature{
		{SignerIndex: 0, Sig: sig},
		{SignerIndex: 0, Sig: sig},
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	mustBreak(t, f.entries(), "one authority signing twice")
}

func TestAuthoritySignatureOnARootOnlyOpIsRejected(t *testing.T) {
	f := newFixture(t)
	// authority-list is a root op. Authorities must not be able to appoint
	// their own successors.
	e, input := f.b.Prepare(1200, OpAuthorityList, AuthorityListBody(f.authPKs, 1, nil))
	sigs, err := SignAuthorities(input,
		AuthoritySigner{Index: 0, Key: f.authorities[0]},
		AuthoritySigner{Index: 1, Key: f.authorities[1]},
	)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := f.b.Commit(e, sigs); err != nil {
		t.Fatalf("commit: %v", err)
	}
	mustBreak(t, f.entries(), "authority signature on a root op")
}

func TestSignatureOverADifferentEntryHashIsRejected(t *testing.T) {
	f := newFixture(t)
	f.appendAuth(t, 1200, OpNodeSign, signBody(nodeKeys(t, 0x88), 0, 0))
	f.appendAuth(t, 1300, OpNodeSign, signBody(nodeKeys(t, 0xAA), 0, 0))

	e := f.entries()
	// Genuine signatures, genuine signers, wrong entry. This is the bug a
	// vector that only checked "the signature verifies" would miss.
	e[2].Sigs = e[3].Sigs
	mustBreak(t, e, "valid signatures over another entry's hash")
}

func TestForkedChainIsRejected(t *testing.T) {
	f := newFixture(t)
	f.appendAuth(t, 1200, OpNodeSign, signBody(nodeKeys(t, 0x88), 0, 0))
	original := f.entries()

	// Build a different entry 2 on the same genesis, then splice entry 3 from
	// the original chain on top of it. Every signature is genuine; the chain is
	// not, because entry 3 commits to a predecessor that is no longer there.
	fork := NewBuilder()
	if err := fork.Commit(&Entry{
		Seq: original[0].Seq, Time: original[0].Time,
		Op: original[0].Op, Body: original[0].Body,
	}, original[0].Sigs); err != nil {
		t.Fatalf("commit genesis: %v", err)
	}
	e, input := fork.Prepare(1100, OpNodeSign, signBody(nodeKeys(t, 0xBB), 0, 0))
	sigs, err := SignAuthorities(input,
		AuthoritySigner{Index: 0, Key: f.authorities[0]},
		AuthoritySigner{Index: 1, Key: f.authorities[1]},
	)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := fork.Commit(e, sigs); err != nil {
		t.Fatalf("commit: %v", err)
	}

	spliced := append(fork.Entries(), original[2]) //nolint:gocritic // deliberate splice
	mustBreak(t, spliced, "a fork at sequence 2 with a spliced tail")
}

func TestReplayedRevocationIsRejected(t *testing.T) {
	f := newFixture(t)
	f.appendAuth(t, 1200, OpNodeRevoke, NodeRevokeBody(f.alice.Handle, "stolen", 1200))
	f.appendAuth(t, 1300, OpNodeSign, signBody(f.alice, 0, 0))
	e := f.entries()

	// Replaying the revocation entry verbatim after the re-signature would
	// re-revoke a readmitted node. Its signatures are genuine but they commit
	// to position 2, not position 4.
	replayed := append(e, e[2]) //nolint:gocritic // deliberate replay
	mustBreak(t, replayed, "a revocation replayed at a later sequence")
}

func TestExpiredNodeSignDoesNotCover(t *testing.T) {
	f := newFixture(t)
	bob := nodeKeys(t, 0x88)
	f.appendAuth(t, 1200, OpNodeSign, signBody(bob, 1200, 1400))

	st, err := f.b.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// The chain is perfectly valid; the coverage has simply lapsed. An
	// implementation that treated expiry as a chain error would refuse to
	// verify a log containing any expired node, which is every real log.
	if st.IsCovered(bob.Handle, bob.Keys, 1500) {
		t.Error("an expired node-sign must not cover")
	}
	if !st.IsCovered(f.alice.Handle, f.alice.Keys, 1500) {
		t.Error("an unrelated node must be unaffected")
	}
}

func TestTimeMustNotMoveBackwards(t *testing.T) {
	f := newFixture(t)
	e := f.entries()
	e[1].Time = 500 // genesis is at 1000
	mustBreak(t, e, "an entry earlier than its predecessor")
}

func TestGenesisMustBeFirstAndUnique(t *testing.T) {
	f := newFixture(t)
	e := f.entries()
	mustBreak(t, e[1:], "a log that does not start at genesis")

	f2 := newFixture(t)
	f2.appendRoot(t, 1200, OpGenesis, GenesisBody("other.karst.", f2.rootPKs, 2, f2.authPKs, 2, nil))
	mustBreak(t, f2.entries(), "a second genesis")
}

func TestUnknownOpIsAHardFailure(t *testing.T) {
	f := newFixture(t)
	e := f.entries()
	e[1].Op = "node-bless"
	mustBreak(t, e, "an unknown op")
}

func TestTamperedBodyIsRejected(t *testing.T) {
	f := newFixture(t)
	e := f.entries()
	body := append([]byte(nil), e[1].Body...)
	body[len(body)-1] ^= 0x01
	e[1].Body = body
	mustBreak(t, e, "a modified body")
}

func TestSignerIndexOutOfRangeIsRejected(t *testing.T) {
	f := newFixture(t)
	e := f.entries()
	e[1].Sigs[0].SignerIndex = 99
	mustBreak(t, e, "a signer index past the end of the authority list")
}

func TestUnreachableQuorumIsRejected(t *testing.T) {
	f := newFixture(t)
	// q greater than the number of authorities would make the log permanently
	// unextendable — the network-lock equivalent of losing the roots.
	e, input := f.b.Prepare(1200, OpQuorumChange, QuorumChangeBody(9))
	sigs, err := SignAuthorities(input,
		AuthoritySigner{Index: 0, Key: f.authorities[0]},
		AuthoritySigner{Index: 1, Key: f.authorities[1]},
	)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := f.b.Commit(e, sigs); err != nil {
		t.Fatalf("commit: %v", err)
	}
	mustBreak(t, f.entries(), "a quorum larger than the authority list")
}

// ── encoding ────────────────────────────────────────────────────────────────

func TestLogRoundTripsThroughEncoding(t *testing.T) {
	f := newFixture(t)
	f.appendAuth(t, 1200, OpNodeRevoke, NodeRevokeBody(f.alice.Handle, "rotated", 1250))

	decoded, err := DecodeLog(EncodeLog(f.entries()))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	st, err := VerifyLog(decoded)
	if err != nil {
		t.Fatalf("verify decoded: %v", err)
	}
	original, err := f.b.Verify()
	if err != nil {
		t.Fatalf("verify original: %v", err)
	}
	if !bytes.Equal(st.Head, original.Head) {
		t.Error("a round trip through the encoding changed the head")
	}
}

func TestMalformedEncodingsAreRejectedNotPanickedOn(t *testing.T) {
	f := newFixture(t)
	good := EncodeLog(f.entries())

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"count only", good[:4]},
		{"truncated mid-entry", good[:len(good)/2]},
		{"trailing bytes", append(append([]byte(nil), good...), 0x00)},
		{"absurd entry count", []byte{0xFF, 0xFF, 0xFF, 0xFF}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeLog(tc.in); err == nil {
				t.Fatal("decoded successfully but must not have")
			}
		})
	}
}

func TestTrailingBytesInABodyAreRejected(t *testing.T) {
	// A body with slack is a body two implementations could read differently.
	if _, err := ParseNodeSign(append(signBody(nodeKeys(t, 1), 0, 0), 0x00)); err == nil {
		t.Error("trailing bytes in a node-sign body must not parse")
	}
	if _, err := ParseGenesis(append(GenesisBody("z", [][]byte{make([]byte, RootPublicKeySize)}, 1,
		[][]byte{make([]byte, AuthorityPublicKeySize)}, 1, nil), 0x00)); err == nil {
		t.Error("trailing bytes in a genesis body must not parse")
	}
}

func TestWrongSizedKeysInABodyAreRejected(t *testing.T) {
	body := GenesisBody("z", [][]byte{make([]byte, 47)}, 1, [][]byte{make([]byte, AuthorityPublicKeySize)}, 1, nil)
	if _, err := ParseGenesis(body); err == nil {
		t.Error("a 47-byte root key must not parse")
	}
}

// A body that ends right after q means s = 0. Writing BE32(0) explicitly is
// the second byte string for that same meaning and must be rejected —
// ADR-0016, spec §3.4.
func TestAnchorBlockZeroCountMustBeEncodedAsAbsence(t *testing.T) {
	body := append(GenesisBody("z", [][]byte{make([]byte, RootPublicKeySize)}, 1,
		[][]byte{make([]byte, AuthorityPublicKeySize)}, 1, nil), 0x00, 0x00, 0x00, 0x00)
	if _, err := ParseGenesis(body); err == nil {
		t.Error("an explicit BE32(0) anchor-key count must not parse")
	}
}

// An anchor key duplicated in the authority list would answer under two
// context strings and is the exact mistake ADR-0016's separate tier exists to
// make impossible — rejected at verification rather than relied on
// procedurally.
func TestAnchorKeyDuplicatedInAuthorityListIsRejected(t *testing.T) {
	root := testRoot(t, 0x10)
	authority := testAuthority(t, 0x40)
	anchor := testAuthority(t, 0x40) // same seed: same public key as authority

	b := NewBuilder()
	e, input := b.Prepare(1000, OpGenesis, GenesisBody("z.karst.", [][]byte{root.Public()}, 1,
		[][]byte{authority.Public()}, 1, [][]byte{anchor.Public()}))
	sigs, err := SignRoots(input, RootSigner{Index: 0, Key: root})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := b.Commit(e, sigs); err != nil {
		t.Fatalf("commit: %v", err)
	}
	mustBreak(t, b.Entries(), "an anchor key that duplicates an authority key")
}

// Length prefixing is what stops two different bodies hashing identically.
// Without it ("ab","c") and ("a","bc") would produce the same bytes.
func TestFieldsAreLengthPrefixed(t *testing.T) {
	if bytes.Equal(NodeRevokeBody("ab", "c", 1), NodeRevokeBody("a", "bc", 1)) {
		t.Error("adjacent fields are not length-prefixed")
	}
}

// The op is part of the hash, and it is length-prefixed too — spec §3.2 records
// the deviation from PLAN.md's sketch, which left it bare.
func TestOpIsCoveredByTheChainHash(t *testing.T) {
	a := ChainHash(nil, 1, 1000, OpNodeSign, []byte("x"))
	b := ChainHash(nil, 1, 1000, OpNodeRevoke, []byte("x"))
	if bytes.Equal(a, b) {
		t.Error("the op does not affect the chain hash")
	}
}

func TestChainHashCoversItsPredecessor(t *testing.T) {
	a := ChainHash([]byte("one"), 2, 1000, OpAnchor, []byte("x"))
	b := ChainHash([]byte("two"), 2, 1000, OpAnchor, []byte("x"))
	if bytes.Equal(a, b) {
		t.Error("the previous hash does not affect the chain hash")
	}
}

func TestUncoveredListsExactlyThosePeersThatWouldBeCut(t *testing.T) {
	f := newFixture(t)
	st, err := f.b.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	bob := nodeKeys(t, 0x88)
	got := st.Uncovered(map[string]PeerKeys{
		f.alice.Handle: f.alice.Keys,
		bob.Handle:     bob.Keys,
	}, 2000)
	if len(got) != 1 || got[0] != bob.Handle {
		t.Errorf("uncovered = %v, want [%s]", got, bob.Handle)
	}
}

// ── generated keys ──────────────────────────────────────────────────────────

// The fixtures above build keys through RootFromBytes, so these constructors
// went untested until an integration test called one and it failed on a type
// assertion. A generated key must round-trip and sign like any other.
func TestGeneratedKeysWork(t *testing.T) {
	root, err := GenerateRoot()
	if err != nil {
		t.Fatalf("generate root: %v", err)
	}
	pub := root.Public()
	if len(pub) != RootPublicKeySize {
		t.Fatalf("root public key is %d bytes, want %d", len(pub), RootPublicKeySize)
	}
	sig, err := root.Sign([]byte("m"))
	if err != nil {
		t.Fatalf("root sign: %v", err)
	}
	if !VerifyRoot(pub, []byte("m"), sig) {
		t.Error("a generated root key produced a signature it cannot verify")
	}

	restored, err := RootFromSeed(root.Seed())
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	restoredPub := restored.Public()
	if !bytes.Equal(pub, restoredPub) {
		t.Error("a generated root key did not survive serialization")
	}

	authority, err := GenerateAuthority()
	if err != nil {
		t.Fatalf("generate authority: %v", err)
	}
	asig, err := authority.Sign([]byte("m"))
	if err != nil {
		t.Fatalf("authority sign: %v", err)
	}
	if !VerifyAuthority(authority.Public(), []byte("m"), asig) {
		t.Error("a generated authority key produced a signature it cannot verify")
	}
}

// Two generated roots must differ. A constructor that returned a zero value
// would pass every test above and give every deployment the same root key.
func TestGeneratedRootsAreDistinct(t *testing.T) {
	a, err := GenerateRoot()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, err := GenerateRoot()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if bytes.Equal(a.Public(), b.Public()) {
		t.Fatal("two generated root keys are identical")
	}
}

// A node-sign must name the handle its identity key derives to.
//
// Without this, a quorum could sign "handle alice, identity key bob's" — naming
// one node while authorizing another's. The check makes the handle
// self-certifying, so nothing downstream has to treat it as a label the log
// merely asserts.
func TestNodeSignHandleMustMatchItsIdentityKey(t *testing.T) {
	f := newFixture(t)
	alice := nodeKeys(t, 0x77)
	mallory := nodeKeys(t, 0xBB)

	// Alice's handle, Mallory's identity key.
	f.appendAuth(t, 1200, OpNodeSign, NodeSignBody(
		alice.Handle, mallory.Identity,
		alice.Keys.KemPublicKey, 0, 0))
	mustBreak(t, f.entries(), "a handle that does not derive from its identity key")
}

// The datapath keys are what a coverage query compares, because they are what
// PHREATIC authenticates and what a netmap actually carries — spec §6.1.
func TestCoverageComparesTheDatapathKeys(t *testing.T) {
	f := newFixture(t)
	st, err := f.b.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	other := nodeKeys(t, 0x99)

	if !st.IsCovered(f.alice.Handle, f.alice.Keys, 2000) {
		t.Fatal("alice should be covered")
	}
	for _, tc := range []struct {
		name string
		keys PeerKeys
	}{
		{"a substituted KEM key", PeerKeys{other.Keys.KemPublicKey}},
		{"both substituted", other.Keys},
	} {
		if st.IsCovered(f.alice.Handle, tc.keys, 2000) {
			t.Errorf("%s was accepted as covered", tc.name)
		}
	}
}
