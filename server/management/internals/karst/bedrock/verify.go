// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Chain verification and the coverage query — spec/bedrock-v1.md §4 and §6.
//
// This is the fail-closed path. Every failure here must return an error rather
// than a degraded result, and every rule in spec §4 is checked in the order the
// spec lists, because the order is load-bearing: a body is parsed only after
// the signatures over it have verified.
package bedrock

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/netbirdio/netbird/management/internals/karst/node"
)

// NodeCoverage is what a node-sign established: a handle bound to a specific
// set of keys, for a window.
//
// The binding is to the handle *and the keys together*. A node-sign for a
// handle does not cover different keys later presented under the same handle,
// which is precisely what stops a compromised server substituting keys it
// controls while keeping the name (spec §6).
type NodeCoverage struct {
	Handle string
	// IdentityKey is the ML-DSA-65 control-channel key.
	IdentityKey []byte
	// KemPublicKey and DhPublicKey are the static keys PHREATIC actually
	// authenticates against — spec §6.1. Covering these is what makes the
	// mechanism more than a formality.
	KemPublicKey []byte
	DhPublicKey  []byte
	NotBefore    int64
	Expiry       int64 // zero means no expiry
}

// PeerKeys is what a netmap presents for a peer, as the coverage query sees it.
//
// The identity key is deliberately absent. A netmap carries a peer's handle,
// KEM key and DH key — never its ML-DSA identity key — so a predicate that took
// one could only be handed the value already in the log, and comparing the log
// to itself proves nothing. The identity binding is checked once, during chain
// verification, as the invariant handle == Handle(identity_key); see
// verifyNodeSign.
type PeerKeys struct {
	KemPublicKey []byte
	DhPublicKey  []byte
}

// State is the result of verifying a log: everything a node needs in order to
// make an enforcement decision, and nothing else.
type State struct {
	Zone        string
	Roots       [][]byte
	K           uint32
	Authorities [][]byte
	Q           uint32

	// Covered is the latest node-sign per handle.
	Covered map[string]NodeCoverage
	// Revoked is the effective time of the latest node-revoke per handle.
	Revoked map[string]int64

	// Disabled records a root-signed disable entry. Enforcement stops; the
	// fact that it stopped is permanently in the log.
	Disabled       bool
	DisabledReason string

	// Anchor is the most recent audit-log head committed to the chain.
	Anchor *Anchor

	// Head and HeadSeq identify the verified tip, for the netmap and for
	// peer-to-peer head comparison (spec §5).
	Head    []byte
	HeadSeq uint64

	lastTime int64
}

// VerifyLog walks a log from genesis and returns the state it establishes.
//
// It verifies the whole chain every time rather than trusting a stored result.
// A node does this on every fetch and on every boot from cache: the cost is
// linear in a log that is small by construction, and the alternative is a
// stored State that an attacker with filesystem access can edit.
func VerifyLog(entries []Entry) (*State, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: empty log", ErrBroken)
	}

	st := &State{
		Covered: make(map[string]NodeCoverage),
		Revoked: make(map[string]int64),
	}
	var prev []byte

	for i := range entries {
		e := &entries[i]
		expectSeq := uint64(i + 1)

		// §4.1 — contiguous sequence from 1.
		if e.Seq != expectSeq {
			return nil, fmt.Errorf("%w: expected seq %d, found %d", ErrBroken, expectSeq, e.Seq)
		}

		// §4.3 — time does not go backwards. A chain whose times move
		// backwards cannot be reasoned about with not-before and expiry.
		if e.Time < st.lastTime {
			return nil, fmt.Errorf("%w: entry %d moves time backwards", ErrBroken, e.Seq)
		}

		// §4.5 — the op set is closed.
		tier, known := TierOf(e.Op)
		if !known {
			return nil, fmt.Errorf("%w: entry %d has unknown op %q", ErrBroken, e.Seq, e.Op)
		}

		// §4 — genesis is first and appears once.
		if (e.Seq == 1) != (e.Op == OpGenesis) {
			return nil, fmt.Errorf("%w: entry %d: genesis must be the first entry and only the first", ErrBroken, e.Seq)
		}

		// §4.2 and §4.4 — the chain hash, computed rather than trusted.
		h := ChainHash(prev, e.Seq, e.Time, e.Op, e.Body)

		// genesis defines the very key list its own signatures index into, so
		// its body must be read before they can be checked. This is the single
		// exception to "parse only after verifying", and it is unavoidable: the
		// alternative is a root list delivered out of band, which is the thing
		// Bedrock exists to remove.
		var genesis *Genesis
		if e.Op == OpGenesis {
			g, err := ParseGenesis(e.Body)
			if err != nil {
				return nil, fmt.Errorf("%w: entry 1: %w", ErrBroken, err)
			}
			if err := validateGenesis(g); err != nil {
				return nil, fmt.Errorf("%w: entry 1: %w", ErrBroken, err)
			}
			genesis = g
			st.Roots, st.K = g.Roots, g.K
		}

		// §4.6, §4.7, §4.8 — signatures.
		keys, threshold := st.Roots, st.K
		if tier == TierAuthority {
			keys, threshold = st.Authorities, st.Q
		}
		if e.Op == OpAnchor {
			// An anchor is a claim about the audit log, not a policy change.
			// One authority is enough to make truncation detectable, and
			// requiring q would mean anchors stop being written exactly when
			// the authorities are hardest to assemble.
			threshold = 1
		}
		if err := verifySignatures(e, h, tier, keys, threshold); err != nil {
			return nil, fmt.Errorf("%w: entry %d: %w", ErrBroken, e.Seq, err)
		}

		// §4.9 — only now is the body trusted enough to act on.
		if err := st.apply(e, genesis); err != nil {
			return nil, fmt.Errorf("%w: entry %d: %w", ErrBroken, e.Seq, err)
		}

		e.Hash = h
		prev = h
		st.lastTime = e.Time
		st.Head, st.HeadSeq = h, e.Seq
	}

	return st, nil
}

// verifySignatures checks rules §4.6 through §4.8 for one entry.
func verifySignatures(e *Entry, entryHash []byte, tier Tier, keys [][]byte, threshold uint32) error {
	if threshold == 0 {
		return errors.New("no threshold established for this tier")
	}
	if uint32(len(e.Sigs)) < threshold {
		return fmt.Errorf("%d signatures, need %d", len(e.Sigs), threshold)
	}

	// §3.5 — duplicate signer indices are rejected. Without this a single
	// compromised authority reaches any quorum by repeating itself, which
	// silently reduces q to 1 for every operation in the log.
	seen := make(map[uint32]struct{}, len(e.Sigs))
	for _, s := range e.Sigs {
		if _, dup := seen[s.SignerIndex]; dup {
			return fmt.Errorf("signer %d appears twice", s.SignerIndex)
		}
		seen[s.SignerIndex] = struct{}{}

		if int(s.SignerIndex) >= len(keys) {
			return fmt.Errorf("signer index %d is out of range for %d keys", s.SignerIndex, len(keys))
		}
		key := keys[s.SignerIndex]

		ok := false
		switch tier {
		case TierRoot:
			ok = VerifyRoot(key, entryHash, s.Sig)
		case TierAuthority:
			ok = VerifyAuthority(key, entryHash, s.Sig)
		}
		if !ok {
			return fmt.Errorf("signature from signer %d does not verify", s.SignerIndex)
		}
	}
	return nil
}

// apply folds a verified entry into the state.
func (st *State) apply(e *Entry, genesis *Genesis) error {
	switch e.Op {
	case OpGenesis:
		st.Zone = genesis.Zone
		st.Authorities, st.Q = genesis.Authorities, genesis.Q

	case OpAuthorityList:
		a, err := ParseAuthorityList(e.Body)
		if err != nil {
			return err
		}
		if len(a.Authorities) == 0 {
			return errors.New("authority-list with no authorities")
		}
		if a.Q == 0 || int(a.Q) > len(a.Authorities) {
			return fmt.Errorf("quorum %d is unreachable with %d authorities", a.Q, len(a.Authorities))
		}
		st.Authorities, st.Q = a.Authorities, a.Q

	case OpNodeSign:
		n, err := ParseNodeSign(e.Body)
		if err != nil {
			return err
		}
		if n.Expiry != 0 && n.Expiry <= n.NotBefore {
			return fmt.Errorf("node-sign for %q expires before it begins", n.Handle)
		}
		// The handle must be the one this identity key derives to. Checked here,
		// once, rather than at every coverage query: it makes the handle
		// self-certifying, so nothing downstream has to treat it as a label the
		// log merely asserts. A quorum that signed a mismatched pair would be
		// naming one node while authorizing another's key.
		if want := node.Handle(n.IdentityKey); want != n.Handle {
			return fmt.Errorf("node-sign handle %q does not match its identity key (want %q)", n.Handle, want)
		}
		st.Covered[n.Handle] = NodeCoverage{
			Handle:       n.Handle,
			IdentityKey:  n.IdentityKey,
			KemPublicKey: n.KemPublicKey,
			DhPublicKey:  n.DhPublicKey,
			NotBefore:    n.NotBefore,
			Expiry:       n.Expiry,
		}
		// A re-signature supersedes an earlier revocation: an operator who
		// countersigns a handle again after revoking it means to readmit it.
		delete(st.Revoked, n.Handle)

	case OpNodeRevoke:
		r, err := ParseNodeRevoke(e.Body)
		if err != nil {
			return err
		}
		st.Revoked[r.Handle] = r.Effective

	case OpQuorumChange:
		q, err := ParseQuorumChange(e.Body)
		if err != nil {
			return err
		}
		if q == 0 || int(q) > len(st.Authorities) {
			return fmt.Errorf("quorum %d is unreachable with %d authorities", q, len(st.Authorities))
		}
		// The entry was verified against the OLD q in VerifyLog — spec §4.8.
		st.Q = q

	case OpAnchor:
		a, err := ParseAnchor(e.Body)
		if err != nil {
			return err
		}
		st.Anchor = a

	case OpDisable:
		reason, err := ParseDisable(e.Body)
		if err != nil {
			return err
		}
		st.Disabled = true
		st.DisabledReason = reason
	}
	return nil
}

func validateGenesis(g *Genesis) error {
	if len(g.Roots) == 0 {
		return errors.New("genesis with no roots")
	}
	if g.K == 0 || int(g.K) > len(g.Roots) {
		return fmt.Errorf("root threshold %d is unreachable with %d roots", g.K, len(g.Roots))
	}
	if len(g.Authorities) == 0 {
		return errors.New("genesis with no authorities")
	}
	if g.Q == 0 || int(g.Q) > len(g.Authorities) {
		return fmt.Errorf("quorum %d is unreachable with %d authorities", g.Q, len(g.Authorities))
	}
	return nil
}

// ── the coverage query ──────────────────────────────────────────────────────

// IsCovered reports whether a handle presenting these keys may be peered with
// at time t — spec §6.
//
// **The datapath keys are what is compared.** Checking the identity key here
// would not do: it is not used by PHREATIC (phreatic-v1.md §4) and does not
// appear in a netmap, so a check that ignored the static KEM and DH keys would
// authorize a node to exist without constraining which session keys are its —
// and a compromised server would still substitute the keys a handshake actually
// runs against. Spec §6.1. The identity key is bound to the handle during chain
// verification instead.
//
// This is the whole enforcement decision, in one total function with no I/O, so
// that the node's datapath filter and the console's "who would be cut off" list
// cannot drift apart by being computed two different ways.
func (st *State) IsCovered(handle string, keys PeerKeys, t int64) bool {
	c, ok := st.Covered[handle]
	if !ok {
		return false
	}
	// Constant time is not required — every value here is public — but
	// comparing the datapath keys at all is the point of the mechanism.
	if !bytes.Equal(c.KemPublicKey, keys.KemPublicKey) ||
		!bytes.Equal(c.DhPublicKey, keys.DhPublicKey) {
		return false
	}
	if t < c.NotBefore {
		return false
	}
	if c.Expiry != 0 && t >= c.Expiry {
		return false
	}
	if eff, revoked := st.Revoked[handle]; revoked && eff <= t {
		return false
	}
	return true
}

// Uncovered returns those of the given peers that would be dropped under
// enforcement at time t, sorted.
//
// The console uses this to render the confirmation list before an operator
// moves an aquifer to enforcing; the node uses IsCovered directly. Both go
// through the same predicate on purpose.
func (st *State) Uncovered(peers map[string]PeerKeys, t int64) []string {
	out := make([]string, 0)
	for handle, keys := range peers {
		if !st.IsCovered(handle, keys, t) {
			out = append(out, handle)
		}
	}
	sort.Strings(out)
	return out
}
