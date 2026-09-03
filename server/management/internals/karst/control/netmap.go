// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sort"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/management/internals/karst/bedrock"
	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/internals/karst/psk"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/turncred"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
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
	// DNS projects the account DNS settings into the smaller resolver contract
	// Karst nodes consume. Keeping this narrow prevents the control handler from
	// acquiring ownership of the management server's DNS storage.
	DNS interface {
		GetAccount(context.Context, string) (*types.Account, error)
	}
	// Bedrock is the account's network-lock log, or nil where Bedrock is not
	// configured.
	//
	// The head is what travels in the netmap; the entries go on their own
	// request, so a netmap does not grow by the size of a chain. State is read
	// to decide whether the *requesting* node is covered — see §"the netmap is
	// not free" in Handle.
	Bedrock interface {
		Head(ctx context.Context, accountID string) ([]byte, uint64, error)
		State(ctx context.Context, accountID string) (*bedrock.State, error)
	}
	// BedrockMode reports the operator-selected enforcement level. Nil means
	// off. It is advertised, never imposed: a node takes the stronger of this
	// and its own configured floor, so a compromised server can raise
	// enforcement but not lower it (ADR-0006's rule, applied to the network
	// lock).
	BedrockMode interface {
		Mode(ctx context.Context, accountID string) proto.KarstBedrockMode
	}

	// Relays is the authenticated Ponor registry. Entries are static at this
	// boundary until relay administration is moved into the control database.
	Relays     []*proto.KarstRelay
	RelayStore interface {
		NetmapRelays(context.Context) ([]*proto.KarstRelay, error)
	}

	// TurnServers and TurnMinter are ADR-0008 §4's TURN fallback: an
	// operator-configured server list and a shared-secret minter, both nil
	// for a deployment that has not configured TURN — turncred.NetmapEntries
	// then produces no turn_servers field at all, so this feature is opt-in
	// the same way Relays above is.
	TurnServers []turncred.Entry
	TurnMinter  *turncred.Minter
	// TurnStore is the account-scoped, DB-backed TURN registry, mirroring
	// RelayStore above. Entries are static at this boundary until an account
	// has written its own registry, exactly as Relays/RelayStore fall back.
	// TurnMinter is unaffected: the shared secret stays file/env-configured
	// regardless of where the server list comes from.
	TurnStore interface {
		Entries(context.Context) ([]turncred.Entry, error)
	}

	// Policy is the ACL document to compile a per-node filter from (§4.3).
	//
	// A nil Policy means no rules, which compiles to an empty filter and so to
	// DEFAULT DENY. That is the safe direction: a server that has not yet
	// loaded a policy denies traffic rather than permitting all of it, and the
	// symptom is a network that does not work rather than one that works too
	// well.
	Policy      *policy.Document
	PolicyStore interface {
		Current(context.Context) (*policy.Version, error)
	}
	policyCacheMu sync.RWMutex
	policyCache   map[policyCacheKey]*policy.Document
}

// refuseIfUncovered declines to serve a netmap to a node the Bedrock log does
// not cover, when the aquifer is enforcing.
//
// Only under `enforcing`. Under `advisory` the whole point is that an operator
// can see what enforcement *would* do without anything being cut off, and a
// server that refused netmaps in advisory mode would cut them off — which is
// the one thing that mode exists to avoid.
//
// A node that is refused here is not stuck: it keeps polling, and the moment an
// authority countersigns it the next poll succeeds. That is the ordinary
// enroll-then-countersign order, and it costs the node a poll interval rather
// than a re-enrollment.
func (h *NetmapHandler) refuseIfUncovered(ctx context.Context, accountID, self string) error {
	if h.Bedrock == nil || h.BedrockMode == nil {
		return nil
	}
	if h.BedrockMode.Mode(ctx, accountID) != proto.KarstBedrockMode_KARST_BEDROCK_MODE_ENFORCING {
		return nil
	}

	state, err := h.Bedrock.State(ctx, accountID)
	if err != nil {
		if errors.Is(err, bedrock.ErrNoLog) {
			// Enforcing with no log covers nobody. Refusing every node in the
			// account is the correct reading and a severe one, so it is worth
			// being explicit: an operator cannot reach `enforcing` without a
			// log except by editing the database.
			return status.Error(codes.PermissionDenied,
				"bedrock enforcement is on but this account has no log, so no node is covered")
		}
		return fmt.Errorf("bedrock state: %w", err)
	}
	if state.Disabled {
		return nil
	}

	identity, err := h.Nodes.Get(self)
	if err != nil {
		return status.Error(codes.NotFound, "node is not registered")
	}
	keys := bedrock.PeerKeys{
		KemPublicKey: identity.KemPublicKey,
		DhPublicKey:  identity.DhPublicKey,
	}
	if !state.IsCovered(self, keys, time.Now().UTC().Unix()) {
		return status.Error(codes.PermissionDenied,
			"this node is not countersigned by the Bedrock log, and the aquifer is enforcing; "+
				"an authority must countersign its handle and static keys")
	}
	return nil
}

// policyCacheKey identifies an immutable stored revision. Policy versions are
// append-only per account, so a parsed document can be shared safely across
// netmap refreshes without delaying a newly written revision.
type policyCacheKey struct {
	accountID string
	version   uint64
}

const maxCachedPolicyDocuments = 128

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

	// §9.1's report, from the node that measured it. Recorded before the
	// response is assembled so that a node whose relay just moved sees its own
	// change reflected in the version it is handed, rather than one poll later.
	//
	// A malformed value is refused rather than ignored. Ignoring it would leave
	// the node believing it had published a relay while every peer kept dialling
	// the old one — an unreachable node with nothing anywhere saying why.
	if err := h.Nodes.SetHomeRelay(self, req.GetHomeRelay()); err != nil {
		if errors.Is(err, node.ErrBadHomeRelay) {
			return nil, status.Error(codes.InvalidArgument, "malformed home relay id")
		}
		return nil, fmt.Errorf("record home relay: %w", err)
	}
	accountID, err := h.Peers.GetAccountIDForPeerKey(ctx, self)
	if err != nil {
		return nil, status.Error(codes.NotFound, "node is not registered")
	}

	// **A netmap is not free to hand out.** It carries every peer's handle,
	// data-plane keys, addresses and endpoints, and a per-pair PSK for each one
	// — so serving it to a node the log does not cover leaks the shape of the
	// whole network, and its PSKs, to whoever presented a setup key.
	//
	// The node-side filter (bedrock-v1.md §6) is what carries the security
	// property, and it is unchanged: this server may be compromised, so nothing
	// here is trusted by anyone. This is the *disclosure* half — a
	// non-compromised server declining to hand out what an uncovered node has
	// no use for, since every peer would refuse it anyway.
	if err := h.refuseIfUncovered(ctx, accountID, self); err != nil {
		return nil, err
	}

	selfPeer, err := h.Peers.GetPeerByPeerPubKey(ctx, self)
	if err != nil {
		return nil, status.Error(codes.NotFound, "node is not registered")
	}
	peers, err := h.Peers.GetPeersFromAccount(ctx, accountID, selfPeer.ID, selfPeer.UserID)
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	// A report is only meaningful for another peer in the reporting node's
	// account. Without this check a malicious or stale client could create
	// arbitrary handles in the global observation table and leak them through
	// posture aggregation. Telemetry remains advisory: bad input is logged and
	// ignored, never allowed to deny the node its netmap.
	knownPeers := make(map[string]struct{}, len(peers))
	for _, p := range peers {
		if p.Key != self {
			knownPeers[p.Key] = struct{}{}
		}
	}
	observations := make([]node.SessionObservation, 0, len(req.GetSessions()))
	for _, report := range req.GetSessions() {
		peerHandle := string(report.GetPeerId())
		if _, ok := knownPeers[peerHandle]; !ok {
			log.WithFields(log.Fields{"node": self, "peer": peerHandle}).Warn("ignore Karst session observation for unauthorized peer")
			continue
		}
		observations = append(observations, node.SessionObservation{
			PeerHandle: peerHandle, Path: report.GetPath(),
			Endpoint: report.GetEndpoint(), LatticeOnly: report.GetLatticeOnly(), PSKEpoch: report.GetPskEpoch(),
			Suite: report.GetSuite(),
		})
	}
	// An absent repeated field is indistinguishable from an empty one in proto3.
	// Preserve the last report for pre-upgrade nodes rather than treating their
	// first old-client poll as a deletion of useful, explicitly timestamped data.
	if len(observations) > 0 {
		if err := h.Nodes.ReplaceSessionObservations(self, observations); err != nil {
			// Session telemetry is advisory. Losing a netmap over a failed
			// observation write turns monitoring pressure into a connectivity
			// outage, and a database failure is not a client protocol error.
			log.WithError(err).WithField("node", self).Warn("record Karst session observations")
		}
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

	relays := h.Relays
	if h.RelayStore != nil {
		var err error
		relays, err = h.RelayStore.NetmapRelays(relayreg.WithAccount(ctx, accountID))
		if err != nil {
			return nil, fmt.Errorf("load relays: %w", err)
		}
	}
	turnEntries := h.TurnServers
	if h.TurnStore != nil {
		turnEntries, err = h.TurnStore.Entries(turncred.WithAccount(ctx, accountID))
		if err != nil {
			return nil, fmt.Errorf("load turn servers: %w", err)
		}
	}
	turnServers, err := turncred.NetmapEntries(turnEntries, h.TurnMinter)
	if err != nil {
		return nil, fmt.Errorf("mint turn credentials: %w", err)
	}
	resp := &proto.KarstNetmapResponse{
		PskEpoch:    h.Epoch,
		NodeId:      []byte(self),
		Addresses:   addressesOf(selfPeer, v4Bits, v6Bits),
		DnsName:     selfPeer.DNSLabel,
		Relays:      relays,
		TurnServers: turnServers,
	}
	resp.DnsConfig, err = h.dnsConfig(ctx, accountID, selfPeer.ID)
	if err != nil {
		return nil, fmt.Errorf("project dns config: %w", err)
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
			// Where to reach this peer when no direct path exists. Empty for a
			// peer holding no relay, which is a peer reachable only directly.
			HomeRelay: id.HomeRelay,
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
	filter, egress, err := h.compileFilter(policy.WithAccount(ctx, accountID), self, peers)
	if err != nil {
		return nil, err
	}
	resp.PacketFilter = filter
	resp.EgressFilter = egress

	// The Bedrock log tip, so a node can tell whether the log it has verified
	// is the log the server is serving — bedrock-v1.md §5, layer 1. Absent when
	// the account has no log, which is the common case and not an error.
	if h.Bedrock != nil {
		hash, seq, err := h.Bedrock.Head(ctx, accountID)
		switch {
		case err == nil:
			mode := proto.KarstBedrockMode_KARST_BEDROCK_MODE_OFF
			if h.BedrockMode != nil {
				mode = h.BedrockMode.Mode(ctx, accountID)
			}
			resp.BedrockHead = &proto.KarstBedrockHead{Hash: hash, Seq: seq, Mode: mode}
		case errors.Is(err, bedrock.ErrNoLog):
		default:
			return nil, fmt.Errorf("bedrock head: %w", err)
		}
	}

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
func (h *NetmapHandler) compileFilter(ctx context.Context, self string, peers []*nbpeer.Peer) (
	[]*proto.KarstFilterRule, []*proto.KarstEgressRule, error,
) {
	doc := h.Policy
	if h.PolicyStore != nil {
		version, err := h.PolicyStore.Current(ctx)
		if errors.Is(err, policy.ErrNoVersion) {
			doc = nil
		} else if err != nil {
			return nil, nil, fmt.Errorf("load current policy: %w", err)
		} else if doc, err = h.parsedPolicy(version); err != nil {
			return nil, nil, err
		}
	}
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

func (h *NetmapHandler) parsedPolicy(version *policy.Version) (*policy.Document, error) {
	key := policyCacheKey{accountID: version.AccountID, version: version.Version}
	h.policyCacheMu.RLock()
	doc := h.policyCache[key]
	h.policyCacheMu.RUnlock()
	if doc != nil {
		return doc, nil
	}
	parsed, err := policy.Parse([]byte(version.Document))
	if err != nil {
		return nil, fmt.Errorf("stored policy: %w", err)
	}
	h.policyCacheMu.Lock()
	defer h.policyCacheMu.Unlock()
	if h.policyCache == nil {
		h.policyCache = make(map[policyCacheKey]*policy.Document)
	}
	if existing := h.policyCache[key]; existing != nil {
		return existing, nil
	}
	if len(h.policyCache) >= maxCachedPolicyDocuments {
		// Versions are immutable and the cache is only a parse optimization, so
		// arbitrary eviction preserves correctness while bounding memory under a
		// stream of policy edits.
		for stale := range h.policyCache {
			delete(h.policyCache, stale)
			break
		}
	}
	h.policyCache[key] = parsed
	return parsed, nil
}

func portRanges(in []policy.PortRange) []*proto.KarstPortRange {
	out := make([]*proto.KarstPortRange, 0, len(in))
	for _, p := range in {
		out = append(out, &proto.KarstPortRange{First: uint32(p.First), Last: uint32(p.Last)})
	}
	return out
}

// PeerDigest summarizes one peer entry, so a node can tell the server what it
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
	// The home relay is routable content: it is the second way a node reaches
	// this peer (ponor-v1.md §9.1). Omitting it would leave the digest
	// unchanged when a peer moved relay, the delta would never be sent, and
	// every other node would keep dialling a relay the peer had left.
	writeField(h, p.GetHomeRelay())
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
		writeField(h, p.GetHomeRelay())
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
	writeField(h, []byte("karst-dns"))
	dns := resp.GetDnsConfig()
	writeField(h, []byte(dns.GetZone()))
	if dns.GetMagicDns() {
		binary.BigEndian.PutUint32(buf[:4], 1)
	} else {
		binary.BigEndian.PutUint32(buf[:4], 0)
	}
	h.Write(buf[:4])
	for _, nameserver := range dns.GetNameservers() {
		writeField(h, []byte(nameserver))
	}
	for _, domain := range dns.GetSearchDomains() {
		writeField(h, []byte(domain))
	}
	for _, route := range dns.GetRoutes() {
		writeField(h, []byte(route.GetMatchDomain()))
		for _, resolver := range route.GetResolvers() {
			writeField(h, []byte(resolver))
		}
	}
	// The Bedrock head, so a server that advances its log cannot answer
	// "unchanged" and leave a node enforcing on a policy that has moved. An
	// absent head hashes as its all-zero default, exactly as an absent DNS
	// config does, so there is one construction rather than two.
	writeField(h, []byte("karst-bedrock"))
	head := resp.GetBedrockHead()
	writeField(h, head.GetHash())
	binary.BigEndian.PutUint64(buf[:], head.GetSeq())
	writeField(h, buf[:])
	// The mode too, so that enabling enforcement from a console reaches nodes
	// on their next poll. Without it, turning on the network lock would be the
	// one change the server could not deliver.
	binary.BigEndian.PutUint32(buf[:4], uint32(head.GetMode()))
	h.Write(buf[:4])

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
