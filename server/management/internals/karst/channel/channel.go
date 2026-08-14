// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package channel implements the Karst control-channel handshake and record
// layer described in ADR-0011.
//
// It replaces NetBird's NaCl-box envelope, which keys message encryption on
// the peer's static X25519 WireGuard key and so fuses the authentication
// handle, the database index and the transport key into one object. Karst's
// identity is ML-DSA-65 plus a static ML-KEM-768 key; nothing here may be used
// as all three at once, and node identifiers never appear as key material.
//
// The layer sits *inside* TLS and is not redundant with it. The netmap carries
// per-pair PSKs (PLAN.md §2.6), so anything that terminates TLS in front of
// the control server — a load balancer, an ingress controller, a service mesh
// sidecar — would otherwise read every PSK in the network.
package channel

import (
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// Version is the envelope format version: the construction in ADR-0011.
const Version = 1

const (
	labelTranscript = "karst-control-v1"
	labelInitSig    = "karst-control-init-v1"
	labelHelloSig   = "karst-control-hello-v1"
	labelClientKey  = "karst-control-v1 node-to-server"
	labelServerKey  = "karst-control-v1 server-to-node"

	randomLen = 32
)

var (
	ErrVersion      = errors.New("channel: unsupported version")
	ErrMalformed    = errors.New("channel: malformed message")
	ErrDecrypt      = errors.New("channel: decryption failed")
	ErrReplay       = errors.New("channel: sequence number replayed or out of order")
	ErrSignature    = errors.New("channel: identity signature did not verify")
	ErrNoIdentity   = errors.New("channel: no identity key available to verify against")
	ErrSeqExhausted = errors.New("channel: sequence space exhausted")
	ErrServerAuth   = errors.New("channel: server hello signature did not verify")
)

// Verifier checks an ML-DSA-65 signature. It is an interface because Go has no
// stdlib ML-DSA as of 1.25 and the library choice is still open; the
// construction does not depend on which one wins.
type Verifier interface {
	Verify(publicKey, message, signature []byte) bool
}

// Signer produces one. Held by the node, not the server.
type Signer interface {
	Sign(message []byte) ([]byte, error)
	PublicKey() []byte
}

// IdentityLookup resolves a node_id to its stored ML-DSA-65 public key.
// Returns nil when the node is unknown, which is the registration case.
type IdentityLookup func(nodeID []byte) []byte

// StaticKey is the server's long-lived ML-KEM-768 key. Nodes pin its public
// half at enrolment; encapsulating to it is what authenticates the server.
type StaticKey struct {
	dk *mlkem.DecapsulationKey768
}

// GenerateStatic creates a server static key.
func GenerateStatic() (*StaticKey, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("generate static key: %w", err)
	}
	return &StaticKey{dk: dk}, nil
}

// NewStaticFromSeed restores a static key from its 64-byte seed.
func NewStaticFromSeed(seed []byte) (*StaticKey, error) {
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, fmt.Errorf("restore static key: %w", err)
	}
	return &StaticKey{dk: dk}, nil
}

// Seed returns the 64-byte seed. Secret; belongs in KMS/HSM custody per §2.6.
func (s *StaticKey) Seed() []byte { return s.dk.Bytes() }

// PublicKey returns the 1184-byte encapsulation key nodes pin.
func (s *StaticKey) PublicKey() []byte { return s.dk.EncapsulationKey().Bytes() }

// ID is a short stable handle for the static key so the server can rotate
// without breaking nodes mid-rotation: ChannelHello names which key to use.
func (s *StaticKey) ID() []byte {
	sum := sha512.Sum512_256(s.PublicKey())
	return sum[:16]
}

// Pending is server-side state between Hello and Accept. It holds the
// ephemeral decapsulation key, which is what forward secrecy depends on:
// it must be dropped when the connection ends and never persisted.
type Pending struct {
	eph          *mlkem.DecapsulationKey768
	serverRandom []byte
}

// HelloSigningInput is the byte string the server signs over its ephemeral
// key. Exported so the two ends cannot drift.
func HelloSigningInput(serverRandom, ephKemPk []byte) []byte {
	h := sha512.New()
	h.Write([]byte(labelHelloSig))
	for _, part := range [][]byte{serverRandom, ephKemPk} {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(part)))
		h.Write(l[:])
		h.Write(part)
	}
	return h.Sum(nil)
}

// Hello opens a channel. The server speaks first so that it contributes
// freshness before the node signs anything; otherwise a node's signature could
// be replayed onto another connection.
//
// PHREATIC uses a timestamp instead (spec §5) because it must be
// single-datagram and stateless under flood. A control stream is neither, so
// it can have the stronger property without paying a round trip for it.
//
// The ephemeral key is signed. It was not in the first revision, on the
// reasoning that an attacker who substitutes it makes the channel fail closed.
// ProVerif disproved that as a forward-secrecy argument: the attacker sends
// the server's own static public key as the ephemeral, the node encapsulates
// both ciphertexts to one long-term key, and the recorded session decrypts
// when that key later leaks. The node transmits before the channel dies.
func (s *StaticKey) Hello(signer Signer) (*proto.ChannelHello, *Pending, error) {
	if signer == nil {
		return nil, nil, errors.New("channel: server identity signer is required")
	}
	eph, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral: %w", err)
	}
	nonce := make([]byte, randomLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("server random: %w", err)
	}
	ephPub := eph.EncapsulationKey().Bytes()
	sig, err := signer.Sign(HelloSigningInput(nonce, ephPub))
	if err != nil {
		return nil, nil, fmt.Errorf("sign hello: %w", err)
	}
	hello := &proto.ChannelHello{
		ServerKemPkId: s.ID(),
		EphKemPk:      ephPub,
		ServerRandom:  nonce,
		Signature:     sig,
		Version:       Version,
	}
	return hello, &Pending{eph: eph, serverRandom: nonce}, nil
}

// transcript binds the whole exchange into one hash. Both the channel key and
// the signature are computed over it, so a man-in-the-middle cannot mix halves
// from two different exchanges.
func transcript(label string, serverRandom, ctStatic, ctEph, nodeID []byte) []byte {
	h := sha512.New()
	h.Write([]byte(label))
	for _, part := range [][]byte{serverRandom, ctStatic, ctEph, nodeID} {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(part)))
		h.Write(l[:])
		h.Write(part)
	}
	return h.Sum(nil)
}

// deriveKeys turns the two shared secrets into one key per direction.
//
// Separate directions so a nonce can be a plain counter without any risk of
// the two sides colliding on one.
func deriveKeys(ssStatic, ssEph, serverRandom, ctStatic, ctEph []byte) (c2s, s2c []byte, err error) {
	secret := make([]byte, 0, len(ssStatic)+len(ssEph))
	secret = append(secret, ssStatic...)
	secret = append(secret, ssEph...)

	salt := transcript(labelTranscript, serverRandom, ctStatic, ctEph, nil)

	c2s, err = hkdf.Key(sha512.New, secret, salt, labelClientKey, chacha20poly1305.KeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("derive c2s: %w", err)
	}
	s2c, err = hkdf.Key(sha512.New, secret, salt, labelServerKey, chacha20poly1305.KeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("derive s2c: %w", err)
	}
	return c2s, s2c, nil
}

// SigningInput is the exact byte string an initiating node signs. Exported so
// the node implementation cannot drift from the server's expectation.
func SigningInput(serverRandom, ctStatic, ctEph, nodeID []byte) []byte {
	return transcript(labelInitSig, serverRandom, ctStatic, ctEph, nodeID)
}

// Initiate is the node side. It encapsulates twice — once to the server's
// pinned static key, once to the per-connection ephemeral key — and signs the
// transcript.
//
// Both encapsulations are load-bearing. ct_static authenticates the server
// implicitly, because only the holder of the pinned static key can decapsulate
// it. ct_eph provides forward secrecy: compromising the server's static key
// later does not decrypt a recorded session, and recorded sessions carry PSKs.
// ServerPins is what a node is given out of band at enrolment. Both halves
// must be pinned: the KEM key authenticates the server implicitly, and the
// verification key is what makes the ephemeral key trustworthy — and so what
// makes forward secrecy real.
type ServerPins struct {
	StaticKEM []byte // ML-KEM-768 encapsulation key, 1184 B
	VerifyKey []byte // ML-DSA-65 verification key, 1952 B
}

func Initiate(hello *proto.ChannelHello, pins ServerPins, verifier Verifier, nodeID []byte, signer Signer, presentIdentity bool) (*proto.ChannelInit, *Channel, error) {
	if hello.GetVersion() != Version {
		return nil, nil, ErrVersion
	}
	if len(hello.GetServerRandom()) != randomLen {
		return nil, nil, ErrMalformed
	}
	// Before anything else, and specifically before this function returns a
	// Channel the caller will immediately transmit on.
	if verifier == nil || len(pins.VerifyKey) == 0 {
		return nil, nil, ErrNoIdentity
	}
	if !verifier.Verify(pins.VerifyKey,
		HelloSigningInput(hello.GetServerRandom(), hello.GetEphKemPk()),
		hello.GetSignature()) {
		return nil, nil, ErrServerAuth
	}
	staticEK, err := mlkem.NewEncapsulationKey768(pins.StaticKEM)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: server static key: %v", ErrMalformed, err)
	}
	ephEK, err := mlkem.NewEncapsulationKey768(hello.GetEphKemPk())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: ephemeral key: %v", ErrMalformed, err)
	}

	ssStatic, ctStatic := staticEK.Encapsulate()
	ssEph, ctEph := ephEK.Encapsulate()

	sig, err := signer.Sign(SigningInput(hello.GetServerRandom(), ctStatic, ctEph, nodeID))
	if err != nil {
		return nil, nil, fmt.Errorf("sign init: %w", err)
	}

	init := &proto.ChannelInit{
		CtStatic:  ctStatic,
		CtEph:     ctEph,
		NodeId:    nodeID,
		Signature: sig,
		Version:   Version,
	}
	// A registering node has no stored key for the server to look up, so it
	// presents one. An existing node must not: that would let anyone holding a
	// node_id substitute their own identity.
	if presentIdentity {
		init.IdentityPk = signer.PublicKey()
	}

	c2s, s2c, err := deriveKeys(ssStatic, ssEph, hello.GetServerRandom(), ctStatic, ctEph)
	if err != nil {
		return nil, nil, err
	}
	ch, err := newChannel(c2s, s2c, true)
	if err != nil {
		return nil, nil, err
	}
	return init, ch, nil
}

// Accept is the server side of the handshake.
//
// Order matters: decapsulate and derive first, verify the signature second,
// and only then hand back a channel. The signature check needs the identity
// key, and for a registering node that key arrives in this very message, so it
// is attacker-supplied until the lookup or the registration policy says
// otherwise.
func (s *StaticKey) Accept(p *Pending, init *proto.ChannelInit, lookup IdentityLookup, verifier Verifier) (*Channel, []byte, error) {
	if init.GetVersion() != Version {
		return nil, nil, ErrVersion
	}
	ssStatic, err := s.dk.Decapsulate(init.GetCtStatic())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: static: %v", ErrMalformed, err)
	}
	ssEph, err := p.eph.Decapsulate(init.GetCtEph())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: ephemeral: %v", ErrMalformed, err)
	}

	identity := lookup(init.GetNodeId())
	if identity == nil {
		// Registration: the node presents its identity and the caller decides
		// whether to accept it (auth key, OIDC, Bedrock countersignature).
		identity = init.GetIdentityPk()
		if len(identity) == 0 {
			return nil, nil, ErrNoIdentity
		}
	} else if len(init.GetIdentityPk()) != 0 &&
		subtle.ConstantTimeCompare(identity, init.GetIdentityPk()) != 1 {
		// A known node presenting a *different* key is an identity
		// substitution attempt, not a re-registration.
		return nil, nil, ErrSignature
	}

	msg := SigningInput(p.serverRandom, init.GetCtStatic(), init.GetCtEph(), init.GetNodeId())
	if !verifier.Verify(identity, msg, init.GetSignature()) {
		return nil, nil, ErrSignature
	}

	c2s, s2c, err := deriveKeys(ssStatic, ssEph, p.serverRandom, init.GetCtStatic(), init.GetCtEph())
	if err != nil {
		return nil, nil, err
	}
	ch, err := newChannel(c2s, s2c, false)
	if err != nil {
		return nil, nil, err
	}
	return ch, identity, nil
}

// Channel is the record layer: one AEAD per direction, a counter per
// direction, and no other state.
type Channel struct {
	send     []byte
	recv     []byte
	sendAEAD interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
	recvAEAD interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
	sendSeq uint64
	recvSeq uint64
}

func newChannel(c2s, s2c []byte, isNode bool) (*Channel, error) {
	send, recv := c2s, s2c
	if !isNode {
		send, recv = s2c, c2s
	}
	sa, err := chacha20poly1305.New(send)
	if err != nil {
		return nil, fmt.Errorf("send aead: %w", err)
	}
	ra, err := chacha20poly1305.New(recv)
	if err != nil {
		return nil, fmt.Errorf("recv aead: %w", err)
	}
	return &Channel{send: send, recv: recv, sendAEAD: sa, recvAEAD: ra}, nil
}

func nonceFor(seq uint64) []byte {
	var n [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(n[4:], seq)
	return n[:]
}

// Seal wraps a marshalled inner message in an envelope.
func (c *Channel) Seal(nodeID, plaintext []byte) (*proto.KarstEnvelope, error) {
	if c.sendSeq == ^uint64(0) {
		return nil, ErrSeqExhausted
	}
	c.sendSeq++
	seq := c.sendSeq
	return &proto.KarstEnvelope{
		NodeId:  nodeID,
		Body:    c.sendAEAD.Seal(nil, nonceFor(seq), plaintext, associatedData(nodeID, seq)),
		Seq:     seq,
		Version: Version,
	}, nil
}

// Open unwraps one.
//
// The sequence number is checked *before* the AEAD, so a replayed envelope
// costs a comparison rather than a decryption. The transport is an ordered
// stream, so anything not strictly increasing is a duplicate or a reorder and
// both are errors here — no replay window is needed, unlike the datapath
// (spec §8), which runs over UDP.
func (c *Channel) Open(env *proto.KarstEnvelope) ([]byte, error) {
	if env.GetVersion() != Version {
		return nil, ErrVersion
	}
	if env.GetSeq() <= c.recvSeq {
		return nil, ErrReplay
	}
	pt, err := c.recvAEAD.Open(nil, nonceFor(env.GetSeq()), env.GetBody(),
		associatedData(env.GetNodeId(), env.GetSeq()))
	if err != nil {
		return nil, ErrDecrypt
	}
	// Advanced only on success, so a forged envelope cannot burn sequence
	// numbers the real peer still intends to use.
	c.recvSeq = env.GetSeq()
	return pt, nil
}

// associatedData binds the cleartext envelope fields to the ciphertext, so a
// node_id cannot be rewritten in flight to make one node's traffic look like
// another's.
func associatedData(nodeID []byte, seq uint64) []byte {
	ad := make([]byte, 0, len(nodeID)+8)
	ad = append(ad, nodeID...)
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	return append(ad, s[:]...)
}
