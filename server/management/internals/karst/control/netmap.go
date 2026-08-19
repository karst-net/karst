// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"sort"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/internals/karst/psk"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// PeerLister is the slice of the forked account manager the netmap needs:
// which peers a given peer may talk to. Narrow for the same reason
// PeerLoginer is.
type PeerLister interface {
	GetPeersFromAccount(ctx context.Context, accountID, peerID, userID string) ([]*nbpeer.Peer, error)
	GetAccountIDForPeerKey(ctx context.Context, peerKey string) (string, error)
	GetPeerByPeerPubKey(ctx context.Context, peerKey string) (*nbpeer.Peer, error)

	// AccountPrefixes returns the prefix lengths of the account's overlay
	// networks: the IPv4 subnet (a /16 out of 100.64.0.0/10) and the IPv6 ULA
	// (a /64).
	//
	// The node needs these to bring its interface up. A peer's address is
	// stored bare, and an address assigned without a prefix is a /32: the
	// interface comes up, the node has an address, and no peer is on-link, so
	// nothing routes and every packet is dropped before it reaches the tunnel.
	// The symptom looks like a handshake failure and is not one.
	AccountPrefixes(ctx context.Context, accountID string) (v4 uint8, v6 uint8, err error)
}

// NetmapHandler answers KarstNetmapRequest.
//
// This is the point at which ADR-0011 stops being an argument and starts being
// load-bearing: the response carries a per-pair PSK for every peer, so a
// netmap in plaintext would hand every PSK in the network to anything
// terminating TLS in front of the server.
type NetmapHandler struct {
	Nodes   *node.Store
	Peers   PeerLister
	PSK     *psk.Deriver
	Epoch   uint32
	DNSZone string
	// Relays is the authenticated Ponor registry. Entries are static at this
	// boundary until relay administration is moved into the control database.
	Relays []*proto.KarstRelay

	// Policy is the ACL document to compile a per-node filter from (§4.3).
	//
	// A nil Policy means no rules, which compiles to an empty filter and so to
	// DEFAULT DENY. That is the safe direction: a server that has not yet
	// loaded a policy denies traffic rather than permitting all of it, and the
	// symptom is a network that does not work rather than one that works too
	// well.
	Policy *policy.Document
}

// Handle implements Handler.
func (h *NetmapHandler) Handle(ctx context.Context, _, identity, payload []byte) ([]byte, error) {
	req := &proto.KarstNetmapRequest{}
	if err := pb.Unmarshal(payload, req); err != nil {
		return nil, status.Error(codes.InvalidArgument, "malformed netmap request")
	}

	// Derived from the authenticated identity, never from the request. A node
	// cannot ask for another node's netmap, and so cannot ask for PSKs it has
	// no business holding.
	self := node.Handle(identity)

	accountID, err := h.Peers.GetAccountIDForPeerKey(ctx, self)
	if err != nil {
		return nil, status.Error(codes.NotFound, "node is not registered")
	}
	selfPeer, err := h.Peers.GetPeerByPeerPubKey(ctx, self)
	if err != nil {
		return nil, status.Error(codes.NotFound, "node is not registered")
	}
	peers, err := h.Peers.GetPeersFromAccount(ctx, accountID, selfPeer.ID, selfPeer.UserID)
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}

	handles := make([]string, 0, len(peers))
	for _, p := range peers {
		if p.Key == self {
			continue
		}
		handles = append(handles, p.Key)
	}
	keys, err := h.Nodes.GetMany(handles)
	if err != nil {
		return nil, fmt.Errorf("peer keys: %w", err)
	}

	// The prefix lengths the node's interface needs. Fetched rather than
	// assumed: hard-coding /16 and /64 would be right today and silently wrong
	// the day an account is allocated differently.
	v4Bits, v6Bits, err := h.Peers.AccountPrefixes(ctx, accountID)
	if err != nil {
		// Deliberately fatal. Falling back to a bare address would hand the node
		// a /32, which brings the interface up with no peer on-link — a network
		// where nothing routes and the symptom looks like a handshake failure.
		return nil, fmt.Errorf("account prefixes: %w", err)
	}

	resp := &proto.KarstNetmapResponse{
		PskEpoch:  h.Epoch,
		NodeId:    []byte(self),
		Addresses: addressesOf(selfPeer, v4Bits, v6Bits),
		DnsName:   selfPeer.DNSLabel,
		Relays:    h.Relays,
	}

	for _, p := range peers {
		if p.Key == self {
			continue
		}
		id, ok := keys[p.Key]
		if !ok {
			// Registered as a peer but with no Karst data-plane keys on file:
			// a WireGuard-era row, or a registration that did not complete.
			// Shipping it would produce a peer no one can handshake with, and
			// a PSK for a pair that cannot use it.
			continue
		}

		entry := &proto.KarstNetmapPeer{
			NodeId:       []byte(p.Key),
			AllowedIps:   allowedIPsOf(p),
			DnsName:      p.DNSLabel,
			KemPublicKey: id.KemPublicKey,
			DhPublicKey:  id.DhPublicKey,
		}

		// The PSK is derived per (self, peer) pair and is the same value both
		// ends compute, because Pair sorts its arguments.
		k, err := h.PSK.Pair(self, p.Key, h.Epoch)
		if err != nil {
			// A derivation failure must not silently downgrade the pair to the
			// all-zero fallback: that is a real security state (§2.6) reserved
			// for a node that genuinely has no PSK, and it is flagged as such
			// in the console. Manufacturing it here would hide a server bug as
			// a lattice-only session.
			return nil, fmt.Errorf("derive psk: %w", err)
		}
		entry.Psk = k.Bytes()

		// AVEN path discovery has its own pair key. Reusing the PHREATIC PSK
		// here would couple two independent authenticators and make a protocol
		// change in either one a cross-protocol key-reuse bug.
		disco, err := h.PSK.Disco(self, p.Key, h.Epoch)
		if err != nil {
			return nil, fmt.Errorf("derive disco key: %w", err)
		}
		entry.DiscoKey = disco.Bytes()

		// And the previous epoch, because phreatic-v1.md §7.3 requires a
		// responder to accept n and n-1. Without it, a rotation leaves every
		// node unable to answer a peer that has not refetched yet — which §7.3
		// resolves by falling back to an all-zero PSK, so the visible symptom
		// is not an outage but a fleet-wide silent downgrade to lattice-only.
		if h.Epoch > 0 {
			prev, err := h.PSK.Pair(self, p.Key, h.Epoch-1)
			if err != nil {
				return nil, fmt.Errorf("derive previous psk: %w", err)
			}
			entry.PskPrevious = prev.Bytes()
		}

		resp.Peers = append(resp.Peers, entry)
	}

	// Stable order, so a node can compare two netmaps and so the version below
	// is a function of content rather than of map iteration order.
	sort.Slice(resp.Peers, func(i, j int) bool {
		return string(resp.Peers[i].NodeId) < string(resp.Peers[j].NodeId)
	})
	// The ACL-derived filters, compiled for this node alone — inbound and
	// outbound. Both are needed for §4.3's "enforced on both ends", and neither
	// is derivable from the other: Karst's ACLs are unidirectional grants, so a
	// node's inbound rules say nothing about what it may send.
	filter, egress, err := h.compileFilter(self, peers)
	if err != nil {
		return nil, err
	}
	resp.PacketFilter = filter
	resp.EgressFilter = egress

	resp.Version = NetmapVersion(resp)

	// A delta, when the node told us what it holds.
	//
	// The node's digests are the server's memory: it keeps none of its own, so
	// two servers behind a load balancer answer identically and a restart
	// loses nothing. That is the property that would have been given up by
	// storing per-node history instead.
	if len(req.GetHolds()) > 0 {
		held := make(map[string]uint64, len(req.GetHolds()))
		for _, h := range req.GetHolds() {
			held[string(h.GetNodeId())] = h.GetDigest()
		}

		var changed []*proto.KarstNetmapPeer
		present := make(map[string]struct{}, len(resp.Peers))
		for _, p := range resp.Peers {
			id := string(p.GetNodeId())
			present[id] = struct{}{}
			if d, ok := held[id]; ok && d == PeerDigest(p, resp.GetPskEpoch()) {
				continue // the node already has this entry, unchanged
			}
			changed = append(changed, p)
		}

		var removed [][]byte
		for id := range held {
			if _, still := present[id]; !still {
				removed = append(removed, []byte(id))
			}
		}
		sort.Slice(removed, func(i, j int) bool { return string(removed[i]) < string(removed[j]) })

		resp.Peers = changed
		resp.RemovedPeers = removed
		resp.Delta = true
	}

	// Nothing has changed since the node last asked, so send no peers.
	//
	// This is not a delta — it is the case that makes deltas mostly
	// unnecessary. A node polls repeatedly and the answer is usually identical;
	// re-shipping 1184-byte KEM keys and a PSK per peer each time is the
	// expensive part, and it is pure waste. A true delta needs per-node
	// history, which costs the O(1) server state §2.6 chose deliberately.
	if req.GetKnownVersion() != 0 && req.GetKnownVersion() == resp.Version {
		resp.Peers = nil
		resp.RemovedPeers = nil
		resp.Delta = false
		resp.Unchanged = true
	}

	out, err := pb.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal netmap: %w", err)
	}
	return out, nil
}

// compileFilter turns the policy into this node's packet filters, inbound and
// outbound.
func (h *NetmapHandler) compileFilter(self string, peers []*nbpeer.Peer) (
	[]*proto.KarstFilterRule, []*proto.KarstEgressRule, error,
) {
	doc := h.Policy
	if doc == nil {
		// No policy loaded: empty filters, which are default deny in both
		// directions.
		return nil, nil, nil
	}

	all := make([]policy.Node, 0, len(peers))
	var target policy.Node
	for _, p := range peers {
		n := policy.Node{Handle: p.Key, User: p.UserID, Addresses: allowedIPsOf(p)}
		all = append(all, n)
		if p.Key == self {
			target = n
		}
	}
	if target.Handle == "" {
		target = policy.Node{Handle: self}
	}

	compiled, err := doc.Compile(target, all)
	if err != nil {
		return nil, nil, fmt.Errorf("compile policy: %w", err)
	}
	outbound, err := doc.CompileEgress(target, all)
	if err != nil {
		return nil, nil, fmt.Errorf("compile egress policy: %w", err)
	}

	out := make([]*proto.KarstFilterRule, 0, len(compiled.Rules))
	for _, r := range compiled.Rules {
		out = append(out, &proto.KarstFilterRule{Srcs: r.Srcs, Ports: portRanges(r.Ports)})
	}
	eg := make([]*proto.KarstEgressRule, 0, len(outbound.Rules))
	for _, r := range outbound.Rules {
		eg = append(eg, &proto.KarstEgressRule{Dsts: r.Dsts, Ports: portRanges(r.Ports)})
	}
	return out, eg, nil
}

func portRanges(in []policy.PortRange) []*proto.KarstPortRange {
	out := make([]*proto.KarstPortRange, 0, len(in))
	for _, p := range in {
		out = append(out, &proto.KarstPortRange{First: uint32(p.First), Last: uint32(p.Last)})
	}
	return out
}

// PeerDigest summarises one peer entry, so a node can tell the server what it
// already holds without sending the entry back.
//
// Exported because both ends must compute it identically: the node derives it
// from what it stored, the server from what it would send, and a disagreement
// means either endless re-sending of unchanged entries or — worse — a change
// that is never delivered because both sides think it already arrived. It is
// pinned by spec/vectors/karst-control-v1.json for exactly that reason.
//
// The PSK bytes are deliberately excluded. A PSK is determined by (pair,
// epoch, master), so covering the epoch detects a rotation without making a
// value the node computes and transmits a function of secret material.
func PeerDigest(p *proto.KarstNetmapPeer, epoch uint32) uint64 {
	h := sha256.New()
	h.Write([]byte("karst-peer-digest-v1"))

	var e [4]byte
	binary.BigEndian.PutUint32(e[:], epoch)
	writeField(h, e[:])

	writeField(h, p.GetNodeId())
	writeField(h, p.GetKemPublicKey())
	writeField(h, p.GetDhPublicKey())
	writeField(h, []byte(p.GetDnsName()))
	writeField(h, []byte(p.GetEndpoint()))
	for _, ip := range p.GetAllowedIps() {
		writeField(h, []byte(ip))
	}
	return binary.BigEndian.Uint64(h.Sum(nil)[:8])
}

// addressesOf is what the node assigns to its interface: its own host address
// with the *on-link* prefix length of the account's overlay.
//
// Note the asymmetry with allowedIPsOf below, which is deliberate and easy to
// get backwards. This one keeps the host bits and carries the network's prefix
// length, because that is what makes peers on-link. That one is a single-host
// prefix, because it states which addresses a peer owns.
func addressesOf(p *nbpeer.Peer, v4Bits, v6Bits uint8) []string {
	var out []string
	if p.IP.IsValid() {
		out = append(out, fmt.Sprintf("%s/%d", p.IP, v4Bits))
	}
	if p.IPv6.IsValid() && v6Bits > 0 {
		out = append(out, fmt.Sprintf("%s/%d", p.IPv6, v6Bits))
	}
	return out
}

// allowedIPsOf is the cryptokey-routing entry for a peer: the addresses it is
// permitted to source traffic from, as single-host prefixes.
//
// This is *not* the ACL. Karst's packet filter is compiled from policy and
// shipped separately (PLAN.md §4.3); this is the narrower statement that a
// peer owns these addresses and nothing else.
func allowedIPsOf(p *nbpeer.Peer) []string {
	var out []string
	if p.IP.IsValid() {
		out = append(out, p.IP.String()+"/32")
	}
	if p.IPv6.IsValid() {
		out = append(out, p.IPv6.String()+"/128")
	}
	return out
}

// NetmapVersion is a content hash: identical netmaps always yield the same
// version, and any change yields a different one. That is what lets a node ask
// "has anything changed?" without the server keeping per-node history.
//
// A counter would not do. The version this replaced was `known_version + 1`,
// which increments on every request whether or not anything changed — so it
// could never answer the only question it exists to answer.
//
// # Both ends compute it
//
// Exported for the same reason PeerDigest is. The node recomputes this over
// the netmap it assembled and refuses one that does not reproduce the version
// the server reported — because if the two ever silently disagreed, the node
// would send back a version describing a netmap it does not hold, the server
// would answer "unchanged" forever, and a peer added afterwards would never be
// delivered. Pinned by spec/vectors/karst-control-v1.json.
//
// # The PSK bytes are deliberately not hashed
//
// A PSK is a deterministic function of (pair, epoch, master), so hashing the
// peer set and the epoch detects exactly the same changes as hashing the keys
// themselves. Feeding secret material into a value that is sent in clear buys
// nothing and means a public identifier is a function of a secret. Preimage
// resistance would almost certainly make that safe; "almost certainly safe"
// is not a reason to do it.
func NetmapVersion(resp *proto.KarstNetmapResponse) uint64 {
	h := sha256.New()
	h.Write([]byte("karst-netmap-version-v1"))

	var buf [8]byte
	binary.BigEndian.PutUint32(buf[:4], resp.GetPskEpoch())
	h.Write(buf[:4])
	writeField(h, resp.GetNodeId())
	writeField(h, []byte(resp.GetDnsName()))
	for _, a := range resp.GetAddresses() {
		writeField(h, []byte(a))
	}

	for _, p := range resp.GetPeers() {
		writeField(h, p.GetNodeId())
		writeField(h, p.GetKemPublicKey())
		writeField(h, p.GetDhPublicKey())
		writeField(h, []byte(p.GetDnsName()))
		writeField(h, []byte(p.GetEndpoint()))
		for _, ip := range p.GetAllowedIps() {
			writeField(h, []byte(ip))
		}
	}

	// Both filters are part of the content. Without this, changing a policy
	// would leave the version identical, every node would be told "unchanged",
	// and the new rules would never be delivered — a policy edit that appears
	// to apply and does not.
	for _, r := range resp.GetPacketFilter() {
		for _, src := range r.GetSrcs() {
			writeField(h, []byte(src))
		}
		writePorts(h, r.GetPorts())
	}
	// A separator, not decoration. Concatenating the two rule lists without one
	// makes them indistinguishable: a rule moving from "who may reach me" to
	// "whom may I reach" produces the identical byte stream, the version does
	// not move, and the inverted policy is never delivered.
	writeField(h, []byte("karst-egress-filter"))
	for _, r := range resp.GetEgressFilter() {
		for _, dst := range r.GetDsts() {
			writeField(h, []byte(dst))
		}
		writePorts(h, r.GetPorts())
	}
	writeField(h, []byte("karst-relays"))
	for _, relay := range resp.GetRelays() {
		writeField(h, []byte(relay.GetAddress()))
		writeField(h, []byte(relay.GetTlsServerName()))
		writeField(h, relay.GetRelayId())
		writeField(h, relay.GetIdentityKey())
		writeField(h, []byte(relay.GetRegion()))
	}

	sum := h.Sum(nil)
	v := binary.BigEndian.Uint64(sum[:8])
	// Zero means "I hold no netmap" on the request side, so it must never be a
	// legitimate version or a node holding it would be told nothing changed.
	if v == 0 {
		v = 1
	}
	return v
}

func writePorts(h hash.Hash, ports []*proto.KarstPortRange) {
	for _, p := range ports {
		var pr [8]byte
		binary.BigEndian.PutUint32(pr[:4], p.GetFirst())
		binary.BigEndian.PutUint32(pr[4:], p.GetLast())
		writeField(h, pr[:])
	}
}

func writeField(h hash.Hash, field []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(field)))
	h.Write(l[:])
	h.Write(field)
}
