// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// The Bedrock log: entry types, the hash chain, and the encoding both
// implementations must agree on byte-for-byte. See spec/bedrock-v1.md §3.
//
// # Bodies are opaque here, on purpose
//
// An entry's body is a []byte. This package builds bodies (for a signer) and
// parses them (for display and policy), but it never *re-serializes* one it was
// given: the bytes that were signed are the bytes that are hashed and stored.
//
// A parse-then-reserialize round trip is where canonicalization bugs live, and
// the whole point of §3.3 is that this code has no such round trip in it. If
// you find yourself adding a `func (b *NodeSignBody) Encode()` that gets called
// on the verification path, that is the bug this comment exists to prevent.
package bedrock

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// ChainLabel domain-separates the Bedrock chain from every other hash chain in
// the system. It is written bare; every field after it is length-prefixed.
const ChainLabel = "karst-bedrock-v1"

// Op is an entry's operation. The set is closed: §4 rule 5 makes an unknown op
// a hard verification failure rather than a skipped entry, because a verifier
// that ignores what it does not understand can be handed a log whose meaning it
// does not share with its peers.
type Op string

const (
	OpGenesis       Op = "genesis"
	OpAuthorityList Op = "authority-list"
	OpNodeSign      Op = "node-sign"
	OpNodeRevoke    Op = "node-revoke"
	OpQuorumChange  Op = "quorum-change"
	OpAnchor        Op = "anchor"
	OpDisable       Op = "disable"
)

// Tier says which key list an op's signatures index into.
type Tier int

const (
	// TierRoot — signatures come from the offline root list, threshold k.
	TierRoot Tier = iota
	// TierAuthority — signatures come from the authority list, threshold q.
	TierAuthority
)

// TierOf reports which tier signs an op, and whether the op is known at all.
func TierOf(op Op) (Tier, bool) {
	switch op {
	case OpGenesis, OpAuthorityList, OpDisable:
		return TierRoot, true
	case OpNodeSign, OpNodeRevoke, OpQuorumChange, OpAnchor:
		return TierAuthority, true
	default:
		return TierRoot, false
	}
}

// Signature is one signer's signature over an entry hash, carried with the
// index of the key that produced it — into the root list for root ops, the
// authority list for authority ops.
//
// An index rather than a public key: the log already defines the list, and four
// bytes cost 1948 fewer than repeating an ML-DSA-65 key on every entry.
type Signature struct {
	SignerIndex uint32
	Sig         []byte
}

// Entry is one record in the log.
//
// Hash is *not* carried on the wire and is not part of the encoding; it is
// computed during verification and cached here afterwards. Carrying it would
// create a second source of truth and the question of which one to believe.
type Entry struct {
	Seq  uint64
	Time int64 // Unix seconds — §3.2
	Op   Op
	Body []byte
	Sigs []Signature

	// Hash is filled in by Verify. Empty on a freshly decoded entry.
	Hash []byte
}

var (
	// ErrMalformed is returned when bytes do not decode.
	ErrMalformed = errors.New("bedrock: malformed encoding")
	// ErrBroken is returned when a chain does not verify.
	ErrBroken = errors.New("bedrock: chain does not verify")
)

// ── length-prefixed field encoding ──────────────────────────────────────────
//
// LP(x) is a four-byte big-endian length followed by x, the same construction
// as karst-control-v1.md §5.5 and audit.go's writeField.

func writeLP(h hash.Hash, field []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(field)))
	h.Write(l[:])
	h.Write(field)
}

func appendLP(dst, field []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(field)))
	dst = append(dst, l[:]...)
	return append(dst, field...)
}

func appendBE32(dst []byte, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return append(dst, b[:]...)
}

func appendBE64(dst []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(dst, b[:]...)
}

func be64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

// cursor reads a length-prefixed field sequence. Every read is bounds-checked;
// this parses attacker-supplied bytes on the node's verification path.
type cursor struct {
	b   []byte
	pos int
	err error
}

func (c *cursor) fail() { c.err = ErrMalformed }

func (c *cursor) u32() uint32 {
	if c.err != nil {
		return 0
	}
	if c.pos+4 > len(c.b) {
		c.fail()
		return 0
	}
	v := binary.BigEndian.Uint32(c.b[c.pos : c.pos+4])
	c.pos += 4
	return v
}

func (c *cursor) u64() uint64 {
	if c.err != nil {
		return 0
	}
	if c.pos+8 > len(c.b) {
		c.fail()
		return 0
	}
	v := binary.BigEndian.Uint64(c.b[c.pos : c.pos+8])
	c.pos += 8
	return v
}

func (c *cursor) lp() []byte {
	n := c.u32()
	if c.err != nil {
		return nil
	}
	// The length is attacker-controlled; check it against what remains rather
	// than trusting it to allocate.
	if int(n) < 0 || c.pos+int(n) > len(c.b) {
		c.fail()
		return nil
	}
	v := c.b[c.pos : c.pos+int(n)]
	c.pos += int(n)
	return v
}

// done reports that the cursor consumed exactly the input, with no error.
// Trailing bytes are a decode failure: a body with slack in it is a body two
// implementations could disagree about.
func (c *cursor) done() bool { return c.err == nil && c.pos == len(c.b) }

// ── the chain ───────────────────────────────────────────────────────────────

// ChainHash computes an entry's hash from its content and its predecessor.
//
//	SHA-512(ChainLabel ‖ LP(prev) ‖ LP(BE64(seq)) ‖ LP(BE64(time))
//	                   ‖ LP(op) ‖ LP(body))
//
// Every field is length-prefixed, including op. PLAN.md's sketch left op bare;
// a bare variable-length field followed by a length prefix is exactly the
// ambiguity §3.3 exists to remove, so the prefix was added and spec §3.2
// records the deviation.
func ChainHash(prev []byte, seq uint64, t int64, op Op, body []byte) []byte {
	h := sha512.New()
	h.Write([]byte(ChainLabel))
	writeLP(h, prev)
	writeLP(h, be64(seq))
	writeLP(h, be64(uint64(t)))
	writeLP(h, []byte(op))
	writeLP(h, body)
	return h.Sum(nil)
}

// ── entry and log encoding ──────────────────────────────────────────────────
//
// One encoder serves storage, the offline signer's bundles, the node's cache,
// and the control-plane wire (carried as opaque `bytes` in the proto message).
// Protobuf is not canonical, so putting the entry *inside* a bytes field rather
// than modeling it as a message is what keeps the two implementations from
// having to agree on a protobuf serializer's field ordering.

// Encode serializes an entry:
//
//	LP(BE64(seq)) ‖ LP(BE64(time)) ‖ LP(op) ‖ LP(body)
//	   ‖ BE32(sig_count) ‖ sig_count × ( BE32(index) ‖ LP(sig) )
func (e *Entry) Encode() []byte {
	out := make([]byte, 0, 64+len(e.Body)+len(e.Sigs)*RootSignatureSize)
	out = appendLP(out, be64(e.Seq))
	out = appendLP(out, be64(uint64(e.Time)))
	out = appendLP(out, []byte(e.Op))
	out = appendLP(out, e.Body)
	out = appendBE32(out, uint32(len(e.Sigs)))
	for _, s := range e.Sigs {
		out = appendBE32(out, s.SignerIndex)
		out = appendLP(out, s.Sig)
	}
	return out
}

// SigningInput is what a signer signs: the entry's chain hash.
//
// It takes prev explicitly because an entry does not know its own predecessor —
// which is the point. A signature is over a position in a specific history, so
// the same node-sign at a different point in a different chain is a different
// signature.
func (e *Entry) SigningInput(prev []byte) []byte {
	return ChainHash(prev, e.Seq, e.Time, e.Op, e.Body)
}

func decodeEntry(b []byte) (Entry, error) {
	c := &cursor{b: b}
	var e Entry

	seqRaw := c.lp()
	timeRaw := c.lp()
	op := c.lp()
	body := c.lp()
	if c.err != nil {
		return e, ErrMalformed
	}
	if len(seqRaw) != 8 || len(timeRaw) != 8 {
		return e, fmt.Errorf("%w: seq and time are eight bytes", ErrMalformed)
	}
	e.Seq = binary.BigEndian.Uint64(seqRaw)
	e.Time = int64(binary.BigEndian.Uint64(timeRaw))
	e.Op = Op(op)
	// Copy: the caller's buffer may be reused, and this body is about to be
	// stored and hashed.
	e.Body = append([]byte(nil), body...)

	n := c.u32()
	if c.err != nil {
		return e, ErrMalformed
	}
	// A signature count is bounded by the largest key list anyone would
	// plausibly configure; without a bound a four-byte count is an allocation
	// primitive for anyone who can hand us bytes.
	if n > maxSigners {
		return e, fmt.Errorf("%w: %d signatures exceeds the limit", ErrMalformed, n)
	}
	for i := uint32(0); i < n; i++ {
		idx := c.u32()
		sig := c.lp()
		if c.err != nil {
			return e, ErrMalformed
		}
		e.Sigs = append(e.Sigs, Signature{SignerIndex: idx, Sig: append([]byte(nil), sig...)})
	}
	if !c.done() {
		return e, fmt.Errorf("%w: trailing bytes after entry", ErrMalformed)
	}
	return e, nil
}

// maxSigners bounds both the signature count on an entry and the size of a key
// list. It is a sanity limit, not a policy: a deployment needing more than this
// many roots or authorities has a different problem.
const maxSigners = 64

// EncodeLog serializes a whole log: BE32(count) ‖ count × LP(entry).
func EncodeLog(entries []Entry) []byte {
	out := appendBE32(nil, uint32(len(entries)))
	for i := range entries {
		out = appendLP(out, entries[i].Encode())
	}
	return out
}

// DecodeLog parses a whole log.
func DecodeLog(b []byte) ([]Entry, error) {
	c := &cursor{b: b}
	n := c.u32()
	if c.err != nil {
		return nil, ErrMalformed
	}
	if n > maxLogEntries {
		return nil, fmt.Errorf("%w: %d entries exceeds the limit", ErrMalformed, n)
	}
	entries := make([]Entry, 0, n)
	for i := uint32(0); i < n; i++ {
		raw := c.lp()
		if c.err != nil {
			return nil, ErrMalformed
		}
		e, err := decodeEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		entries = append(entries, e)
	}
	if !c.done() {
		return nil, fmt.Errorf("%w: trailing bytes after log", ErrMalformed)
	}
	return entries, nil
}

// maxLogEntries bounds a decoded log. One entry per node per enrollment plus
// revocations and anchors; a million is far past any real deployment and still
// far short of an allocation attack.
const maxLogEntries = 1 << 20

// ── bodies ──────────────────────────────────────────────────────────────────
//
// Builders produce the bytes a signer signs. Parsers read them back for display
// and policy. Nothing calls a builder on the verification path — see the
// package comment.

// GenesisBody builds a genesis body — spec §3.4.
//
// anchorPKs is the optional ADR-0016 trailing block: pass nil or an empty
// slice for a deployment that does not enable anchor keys, which produces a
// body byte-identical to before the ADR. len(anchorPKs) == 0 MUST NOT be
// encoded as an explicit BE32(0) — see appendOptionalAnchorKeys.
func GenesisBody(zone string, rootPKs [][]byte, k uint32, authorityPKs [][]byte, q uint32, anchorPKs [][]byte) []byte {
	out := appendLP(nil, []byte(zone))
	out = appendBE32(out, uint32(len(rootPKs)))
	for _, pk := range rootPKs {
		out = appendLP(out, pk)
	}
	out = appendBE32(out, k)
	out = appendBE32(out, uint32(len(authorityPKs)))
	for _, pk := range authorityPKs {
		out = appendLP(out, pk)
	}
	out = appendBE32(out, q)
	return appendOptionalAnchorKeys(out, anchorPKs)
}

// Genesis is a parsed genesis body.
type Genesis struct {
	Zone        string
	Roots       [][]byte
	K           uint32
	Authorities [][]byte
	Q           uint32
	// AnchorKeys is ADR-0016's optional anchor-key block, nil when the
	// deployment has not enabled it (spec §3.4's "s = 0 MUST be encoded as
	// absence").
	AnchorKeys [][]byte
}

// ParseGenesis reads a genesis body.
func ParseGenesis(b []byte) (*Genesis, error) {
	c := &cursor{b: b}
	g := &Genesis{Zone: string(c.lp())}
	g.Roots = readKeys(c, RootPublicKeySize)
	g.K = c.u32()
	g.Authorities = readKeys(c, AuthorityPublicKeySize)
	g.Q = c.u32()
	g.AnchorKeys = readOptionalAnchorKeys(c)
	if !c.done() {
		return nil, fmt.Errorf("%w: genesis body", ErrMalformed)
	}
	return g, nil
}

// AuthorityListBody builds an authority-list body — spec §3.4.
//
// anchorPKs is ADR-0016's optional trailing block — see GenesisBody.
func AuthorityListBody(authorityPKs [][]byte, q uint32, anchorPKs [][]byte) []byte {
	out := appendBE32(nil, uint32(len(authorityPKs)))
	for _, pk := range authorityPKs {
		out = appendLP(out, pk)
	}
	out = appendBE32(out, q)
	return appendOptionalAnchorKeys(out, anchorPKs)
}

// AuthorityList is a parsed authority-list body.
type AuthorityList struct {
	Authorities [][]byte
	Q           uint32
	// AnchorKeys is ADR-0016's optional anchor-key block — see Genesis.
	AnchorKeys [][]byte
}

// ParseAuthorityList reads an authority-list body.
func ParseAuthorityList(b []byte) (*AuthorityList, error) {
	c := &cursor{b: b}
	a := &AuthorityList{}
	a.Authorities = readKeys(c, AuthorityPublicKeySize)
	a.Q = c.u32()
	a.AnchorKeys = readOptionalAnchorKeys(c)
	if !c.done() {
		return nil, fmt.Errorf("%w: authority-list body", ErrMalformed)
	}
	return a, nil
}

// Datapath key sizes. These are what a PHREATIC session authenticates against,
// and therefore what a countersignature must cover — spec §6.1.
const (
	// KemPublicKeySize is 1568 bytes (ML-KEM-1024 S_pk).
	KemPublicKeySize = 1568
)

// NodeSignBody builds a node-sign body — spec §3.4.
//
// Both identity and static KEM keys. See spec §6.1: the identity key is
// not used by PHREATIC, so covering only it would authorize a node to exist
// without constraining which session keys are its.
func NodeSignBody(handle string, identityKey, kemKey []byte, notBefore, expiry int64) []byte {
	out := appendLP(nil, []byte(handle))
	out = appendLP(out, identityKey)
	out = appendLP(out, kemKey)

	out = appendBE64(out, uint64(notBefore))
	return appendBE64(out, uint64(expiry))
}

// NodeSign is a parsed node-sign body.
type NodeSign struct {
	Handle string
	// IdentityKey is the ML-DSA-65 control-channel key the handle derives from.
	IdentityKey []byte
	// KemPublicKey is the static key PHREATIC authenticates
	// against — spec §6.1.
	KemPublicKey []byte

	NotBefore int64
	// Expiry of zero means no expiry.
	Expiry int64
}

// ParseNodeSign reads a node-sign body.
func ParseNodeSign(b []byte) (*NodeSign, error) {
	c := &cursor{b: b}
	n := &NodeSign{Handle: string(c.lp())}
	identity := c.lp()
	kem := c.lp()

	n.NotBefore = int64(c.u64())
	n.Expiry = int64(c.u64())
	if !c.done() {
		return nil, fmt.Errorf("%w: node-sign body", ErrMalformed)
	}
	if len(identity) != NodeIdentityKeySize {
		return nil, fmt.Errorf("%w: identity key is %d bytes, want %d", ErrMalformed, len(identity), NodeIdentityKeySize)
	}
	if len(kem) != KemPublicKeySize {
		return nil, fmt.Errorf("%w: KEM key is %d bytes, want %d", ErrMalformed, len(kem), KemPublicKeySize)
	}
	if n.Handle == "" {
		return nil, fmt.Errorf("%w: node-sign with an empty handle", ErrMalformed)
	}
	n.IdentityKey = append([]byte(nil), identity...)
	n.KemPublicKey = append([]byte(nil), kem...)

	return n, nil
}

// NodeRevokeBody builds a node-revoke body — spec §3.4.
func NodeRevokeBody(handle, reason string, effective int64) []byte {
	out := appendLP(nil, []byte(handle))
	out = appendLP(out, []byte(reason))
	return appendBE64(out, uint64(effective))
}

// NodeRevoke is a parsed node-revoke body.
type NodeRevoke struct {
	Handle    string
	Reason    string
	Effective int64
}

// ParseNodeRevoke reads a node-revoke body.
func ParseNodeRevoke(b []byte) (*NodeRevoke, error) {
	c := &cursor{b: b}
	r := &NodeRevoke{Handle: string(c.lp()), Reason: string(c.lp())}
	r.Effective = int64(c.u64())
	if !c.done() {
		return nil, fmt.Errorf("%w: node-revoke body", ErrMalformed)
	}
	if r.Handle == "" {
		return nil, fmt.Errorf("%w: node-revoke with an empty handle", ErrMalformed)
	}
	return r, nil
}

// QuorumChangeBody builds a quorum-change body — spec §3.4.
func QuorumChangeBody(q uint32) []byte { return appendBE32(nil, q) }

// ParseQuorumChange reads a quorum-change body.
func ParseQuorumChange(b []byte) (uint32, error) {
	c := &cursor{b: b}
	q := c.u32()
	if !c.done() {
		return 0, fmt.Errorf("%w: quorum-change body", ErrMalformed)
	}
	return q, nil
}

// AnchorBody builds an anchor body — spec §3.4.
func AnchorBody(auditHead []byte, auditSeq uint64) []byte {
	return appendBE64(appendLP(nil, auditHead), auditSeq)
}

// Anchor is a parsed anchor body: an audit-log head, published into a log the
// server cannot rewrite. This is what closes audit.go's tail-truncation gap.
type Anchor struct {
	AuditHead []byte
	AuditSeq  uint64
}

// ParseAnchor reads an anchor body.
func ParseAnchor(b []byte) (*Anchor, error) {
	c := &cursor{b: b}
	a := &Anchor{}
	head := c.lp()
	a.AuditSeq = c.u64()
	if !c.done() {
		return nil, fmt.Errorf("%w: anchor body", ErrMalformed)
	}
	a.AuditHead = append([]byte(nil), head...)
	return a, nil
}

// DisableBody builds a disable body — spec §3.4.
func DisableBody(reason string) []byte { return appendLP(nil, []byte(reason)) }

// ParseDisable reads a disable body.
func ParseDisable(b []byte) (string, error) {
	c := &cursor{b: b}
	reason := string(c.lp())
	if !c.done() {
		return "", fmt.Errorf("%w: disable body", ErrMalformed)
	}
	return reason, nil
}

// readKeys reads BE32(count) followed by that many length-prefixed keys, each
// of which must be exactly size bytes. A wrong-sized key is a decode failure
// rather than a verification failure later: a key list whose entries are not
// keys has no valid interpretation.
func readKeys(c *cursor, size int) [][]byte {
	n := c.u32()
	if c.err != nil {
		return nil
	}
	return readKeysCounted(c, n, size)
}

// readKeysCounted reads n length-prefixed keys of exactly size bytes each,
// given a count already read from the cursor.
func readKeysCounted(c *cursor, n uint32, size int) [][]byte {
	if n > maxSigners {
		c.fail()
		return nil
	}
	out := make([][]byte, 0, n)
	for i := uint32(0); i < n; i++ {
		k := c.lp()
		if c.err != nil {
			return nil
		}
		if len(k) != size {
			c.fail()
			return nil
		}
		out = append(out, append([]byte(nil), k...))
	}
	return out
}

// appendOptionalAnchorKeys appends ADR-0016's trailing anchor-key block, or
// nothing at all when anchorPKs is empty.
//
// Spec §3.4: "A body that ends after q means s = 0, and s = 0 MUST be encoded
// as absence. Emitting BE32(0) is a decode failure." Without that rule there
// are two byte strings for one meaning — exactly the canonicalization hazard
// §3.3 exists to remove — and it is what lets a deployment that never enables
// anchor keys keep producing bodies byte-identical to before this ADR.
func appendOptionalAnchorKeys(dst []byte, anchorPKs [][]byte) []byte {
	if len(anchorPKs) == 0 {
		return dst
	}
	dst = appendBE32(dst, uint32(len(anchorPKs)))
	for _, pk := range anchorPKs {
		dst = appendLP(dst, pk)
	}
	return dst
}

// readOptionalAnchorKeys reads ADR-0016's trailing anchor-key block.
//
// c.done() is a non-consuming peek: if the body ends right after q, s = 0 and
// there is no block to read. If bytes remain, they must be a well-formed
// block — and per appendOptionalAnchorKeys's doc, a present block whose count
// is zero is itself malformed, because that is the second byte string for a
// meaning absence already encodes.
func readOptionalAnchorKeys(c *cursor) [][]byte {
	if c.done() {
		return nil
	}
	n := c.u32()
	if c.err != nil {
		return nil
	}
	if n == 0 {
		c.fail()
		return nil
	}
	return readKeysCounted(c, n, AnchorPublicKeySize)
}
