// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Building a log, in the three steps the offline workflow actually has.
//
// The split into Prepare / sign / Commit is not ceremony for its own sake: it
// is the shape of the real deployment. The console *prepares* an entry and
// exports the signing input; an admin carries it to a machine with no network
// interface and signs it there; the console *commits* the result. A one-call
// Append that took private keys would only ever be usable by a server that
// holds authority keys, which is the arrangement Bedrock exists to avoid.
package bedrock

import (
	"errors"
	"fmt"
)

// Builder accumulates a log, tracking the chain so a caller never computes a
// previous hash by hand.
type Builder struct {
	entries []Entry
	prev    []byte
}

// NewBuilder starts an empty log.
func NewBuilder() *Builder { return &Builder{} }

// FromEntries resumes building on top of an already verified log.
//
// It re-verifies rather than trusting the caller's entries: this is the path a
// rebuilt server takes when it is re-seeded from a node's replicated copy
// (spec §7), and that copy arrived over the network.
func FromEntries(entries []Entry) (*Builder, error) {
	st, err := VerifyLog(entries)
	if err != nil {
		return nil, err
	}
	return &Builder{entries: entries, prev: st.Head}, nil
}

// Prepare returns the next entry and the hash its signers must sign.
//
// The entry is not yet part of the log; nothing is appended until Commit.
func (b *Builder) Prepare(t int64, op Op, body []byte) (*Entry, []byte) {
	e := &Entry{Seq: uint64(len(b.entries)) + 1, Time: t, Op: op, Body: body}
	return e, e.SigningInput(b.prev)
}

// Commit appends a prepared entry with the signatures collected for it.
//
// It re-derives the hash from the builder's own chain state rather than
// trusting anything on the entry, so a caller who mutated the entry between
// Prepare and Commit gets a signature failure rather than a divergent chain.
func (b *Builder) Commit(e *Entry, sigs []Signature) error {
	if e.Seq != uint64(len(b.entries))+1 {
		return fmt.Errorf("bedrock: entry has seq %d, expected %d", e.Seq, len(b.entries)+1)
	}
	e.Sigs = sigs
	e.Hash = e.SigningInput(b.prev)
	b.prev = e.Hash
	b.entries = append(b.entries, *e)
	return nil
}

// Entries returns the log built so far.
func (b *Builder) Entries() []Entry { return b.entries }

// Verify checks the log built so far and returns its state.
func (b *Builder) Verify() (*State, error) { return VerifyLog(b.entries) }

// ── signing helpers ─────────────────────────────────────────────────────────

// RootSigner is a root key together with its index in the root list.
type RootSigner struct {
	Index uint32
	Key   *RootKey
}

// AuthoritySigner is an authority key together with its index in the authority
// list.
type AuthoritySigner struct {
	Index uint32
	Key   *AuthorityKey
}

// SignRoots produces signatures over a signing input from a set of root keys.
func SignRoots(input []byte, signers ...RootSigner) ([]Signature, error) {
	out := make([]Signature, 0, len(signers))
	for _, s := range signers {
		if s.Key == nil {
			return nil, errors.New("bedrock: nil root key")
		}
		sig, err := s.Key.Sign(input)
		if err != nil {
			return nil, err
		}
		out = append(out, Signature{SignerIndex: s.Index, Sig: sig})
	}
	return out, nil
}

// SignAuthorities produces signatures over a signing input from a set of
// authority keys.
func SignAuthorities(input []byte, signers ...AuthoritySigner) ([]Signature, error) {
	out := make([]Signature, 0, len(signers))
	for _, s := range signers {
		if s.Key == nil {
			return nil, errors.New("bedrock: nil authority key")
		}
		sig, err := s.Key.Sign(input)
		if err != nil {
			return nil, err
		}
		out = append(out, Signature{SignerIndex: s.Index, Sig: sig})
	}
	return out, nil
}

// AnchorSigner is an anchor key together with its index in the concatenated
// authority+anchor signer space an `anchor` entry indexes into — spec §3.5.
type AnchorSigner struct {
	Index uint32
	Key   *AnchorKey
}

// SignAnchors produces signatures over a signing input from a set of anchor
// keys.
func SignAnchors(input []byte, signers ...AnchorSigner) ([]Signature, error) {
	out := make([]Signature, 0, len(signers))
	for _, s := range signers {
		if s.Key == nil {
			return nil, errors.New("bedrock: nil anchor key")
		}
		sig, err := s.Key.Sign(input)
		if err != nil {
			return nil, err
		}
		out = append(out, Signature{SignerIndex: s.Index, Sig: sig})
	}
	return out, nil
}
