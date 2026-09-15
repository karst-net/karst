// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The compiled packet filter — ACL enforcement in the datapath.
//!
//! PLAN.md §4.3: *"The control server is a distributor of policy, not an
//! enforcement point — a compromised server can misroute but cannot read
//! traffic."* The server compiles a policy document into per-node rules; this
//! is what evaluates them, on every packet, in both directions.
//!
//! # Both directions, and why neither is redundant
//!
//! The netmap carries two rule sets. **Ingress** says who may reach this node,
//! and is the one that carries the security property: a compromised peer will
//! ignore its own filter, and this check is what stops it. **Egress** says whom
//! this node may reach; it buys a denied flow that fails locally and
//! immediately rather than being dropped after a round trip, and it keeps
//! forbidden traffic away from a peer's cryptography entirely.
//!
//! Neither is derivable from the other. Karst's ACLs are unidirectional grants,
//! so a node's inbound rules say nothing about what it may send.
//!
//! # Empty is deny
//!
//! A rule set with no rules denies everything. That is the single most
//! important thing in this module, and the reason [`PacketFilter::unrestricted`]
//! has the name it does: the *absence of a policy source* and *a policy that
//! grants nothing* are different states, and a type that let them look alike
//! would eventually let one be read as the other.

use std::collections::BTreeSet;
use std::net::IpAddr;

use karst_control_client::transport::pb;
use karst_tun::ip;

use crate::routing::{PeerIndex, Prefix};

/// Which way a packet is going, for the ACL check and for connection tracking.
///
/// Lives here rather than in the engine because [`crate::flow`] needs it too:
/// the direction is what decides which half of a packet is *this* node's, and
/// so what makes one flow produce one key from either end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// From a peer, to this host.
    In,
    /// From this host, to a peer.
    Out,
}

/// An inclusive port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PortRange {
    first: u16,
    last: u16,
}

impl PortRange {
    /// Build from the wire's `u32` pair, refusing anything that is not a real
    /// range.
    ///
    /// A port above 65535 or an inverted range is nonsense. Clamping would turn
    /// it into a grant the policy author never wrote — most likely a very broad
    /// one — so it is dropped instead.
    fn from_wire(r: pb::KarstPortRange) -> Option<Self> {
        let first = u16::try_from(r.first).ok()?;
        let last = u16::try_from(r.last).ok()?;
        (first <= last).then_some(Self { first, last })
    }

    fn contains(self, port: u16) -> bool {
        port >= self.first && port <= self.last
    }
}

/// Which peers a rule names.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NodeSet {
    /// The policy said `*`.
    Any,
    /// Concrete peers, by index.
    These(BTreeSet<PeerIndex>),
}

impl NodeSet {
    fn contains(&self, peer: PeerIndex) -> bool {
        match self {
            Self::Any => true,
            Self::These(set) => set.contains(&peer),
        }
    }
}

/// One compiled rule.
///
/// `dst_prefixes` is only ever populated on an egress rule (a destination
/// network a policy grants directly — see `karst_control.proto`'s
/// `KarstEgressRule.dst_cidrs`); an ingress or SSH-gate rule always compiles
/// with it empty, so `permits` below is a no-op change for those directions.
#[derive(Debug, Clone)]
struct Rule {
    nodes: NodeSet,
    dst_prefixes: Vec<Prefix>,
    ports: Vec<PortRange>,
}

impl Rule {
    /// `destination` is the packet's real destination address, checked
    /// against `dst_prefixes` **independent of `peer`** — a CIDR grant is
    /// about the destination network, not about which specific gateway peer
    /// happens to be carrying it right now (a route's effective gateway can
    /// change under HA failover without the policy needing to change too).
    ///
    /// `peer_owns_destination` gates the node-handle side: a rule naming
    /// `peer` only matches when the packet is actually addressed to that
    /// peer's own identity, never merely because `peer` happens to be the
    /// next hop. Without this, a plain "may reach node gw-primary" grant —
    /// entirely ordinary mesh connectivity, unrelated to subnet access —
    /// would double as unlimited permission to route arbitrary traffic
    /// through gw-primary to anything it gateways, since the datapath's
    /// per-packet check is keyed on the next-hop peer alone. `evaluate`
    /// computes this from the caller's own address list on egress, and
    /// passes `true` unconditionally on ingress and for the SSH gate, where
    /// no such ambiguity exists (see their own call sites).
    fn permits(
        &self,
        peer: PeerIndex,
        port: u16,
        destination: Option<IpAddr>,
        peer_owns_destination: bool,
    ) -> bool {
        let via_node = self.nodes.contains(peer) && peer_owns_destination;
        let via_cidr = destination.is_some_and(|d| self.dst_prefixes.iter().any(|p| p.contains(d)));
        (via_node || via_cidr) && self.ports.iter().any(|r| r.contains(port))
    }
}

/// Why a packet was dropped, for the counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The packet is permitted.
    Permit,
    /// A rule set exists and none of its rules matched.
    Denied,
    /// The packet's ports could not be established, so no rule could be
    /// evaluated. Denied, but worth counting separately: a sustained rate here
    /// means something is fragmenting or tunnelling, not that a policy is
    /// wrong.
    Unclassifiable,
}

impl Verdict {
    /// Whether the packet may pass.
    #[must_use]
    pub fn permitted(self) -> bool {
        matches!(self, Self::Permit)
    }
}

/// The node's compiled ACLs.
pub struct PacketFilter {
    /// `None` means there is no policy source at all — see
    /// [`PacketFilter::unrestricted`]. `Some(rules)` with an empty `rules` is
    /// default deny, which is a completely different thing.
    ingress: Option<Vec<Rule>>,
    egress: Option<Vec<Rule>>,
}

impl std::fmt::Debug for PacketFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Rendered so the two states cannot be confused at a glance in a log.
        let describe = |r: &Option<Vec<Rule>>| match r {
            None => "unrestricted".to_owned(),
            Some(rules) if rules.is_empty() => "deny-all".to_owned(),
            Some(rules) => format!("{} rule(s)", rules.len()),
        };
        f.debug_struct("PacketFilter")
            .field("ingress", &describe(&self.ingress))
            .field("egress", &describe(&self.egress))
            .finish()
    }
}

impl PacketFilter {
    /// A filter that permits everything, for a node with **no policy source**.
    ///
    /// This is the static TOML roster of Phase 2, which has no notion of an
    /// ACL: there is nothing to enforce, and denying every packet because no
    /// policy was supplied would be wrong rather than safe.
    ///
    /// It is emphatically **not** what an empty netmap filter compiles to. A
    /// netmap that ships no rules is a policy that grants nothing, and
    /// [`PacketFilter::compile`] turns it into deny-all. The two states are
    /// separate constructors precisely so that "I was given no rules" can never
    /// be reached by way of "I was given an empty list".
    #[must_use]
    pub fn unrestricted() -> Self {
        Self {
            ingress: None,
            egress: None,
        }
    }

    /// Compile a netmap's rules against the peer order the datapath uses.
    ///
    /// `handles` are the peers' node IDs in index order; a rule naming a peer
    /// not in the list has that source dropped. **If that leaves a rule with no
    /// peers, the rule is discarded rather than widened** — an empty source
    /// list read as "any" is how a policy inverts itself.
    #[must_use]
    pub fn compile(
        ingress: &[pb::KarstFilterRule],
        egress: &[pb::KarstEgressRule],
        handles: &[Vec<u8>],
    ) -> Self {
        let inbound = ingress
            .iter()
            .filter_map(|r| compile_rule(&r.srcs, &r.ports, handles))
            .collect();
        let outbound = egress
            .iter()
            .filter_map(|r| compile_egress_rule(&r.dsts, &r.dst_cidrs, &r.ports, handles))
            .collect();
        Self {
            ingress: Some(inbound),
            egress: Some(outbound),
        }
    }

    /// May `from` send this packet to us?
    ///
    /// The security-carrying direction. Called after the AEAD has authenticated
    /// the packet and after cryptokey routing has confirmed the source address,
    /// because a rule about a peer means nothing until the packet is known to
    /// have come from that peer.
    #[must_use]
    pub fn ingress(&self, from: PeerIndex, packet: &[u8]) -> Verdict {
        // `true`: no gateway-forwarding ambiguity exists on this side. A
        // packet's destination here is always this node's own address, never
        // `from`'s, so "does `from` own the destination" would ask the wrong
        // question entirely — it must not gate an ingress node-handle grant
        // the way it gates an egress one. `dst_prefixes` is empty on every
        // ingress rule regardless (see `Rule`'s own doc comment), so this
        // flag is moot for the CIDR side either way.
        Self::evaluate(self.ingress.as_deref(), from, packet, None)
    }

    /// May we send this packet to `to`?
    ///
    /// `to_addresses` is `to`'s own advertised ranges (its overlay `/32`
    /// and/or `/128`) — see [`Rule::permits`]'s doc comment for why a
    /// node-handle grant must be checked against it. This node's own
    /// caller (`engine.rs`) is expected to pass the peer's real, netmap-
    /// authenticated addresses; an empty slice here degrades safely to "no
    /// node-handle grant can match at all" rather than to "any packet is
    /// this peer's own", so a caller that cannot supply them yet only loses
    /// egress the CIDR path can restore, never gains anything.
    #[must_use]
    pub fn egress(&self, to: PeerIndex, packet: &[u8], to_addresses: &[Prefix]) -> Verdict {
        Self::evaluate(self.egress.as_deref(), to, packet, Some(to_addresses))
    }

    /// `own_addresses`: `None` means a node-handle grant matches
    /// unconditionally (ingress and the SSH gate, where the packet's
    /// destination is always this node itself, never the sending peer's own
    /// address — asking "does `peer` own the destination" would ask the
    /// wrong question). `Some(addresses)` restricts a node-handle grant to
    /// packets actually addressed to one of them (egress only).
    fn evaluate(
        rules: Option<&[Rule]>,
        peer: PeerIndex,
        packet: &[u8],
        own_addresses: Option<&[Prefix]>,
    ) -> Verdict {
        let Some(rules) = rules else {
            return Verdict::Permit; // no policy source at all
        };
        // `None` here is not "no ports" — that is `Some` with port 0. It means
        // the ports could not be established: a non-first fragment, or an
        // encrypted payload. Reading two arbitrary bytes as a port would let an
        // attacker bypass every port rule by fragmenting.
        let Some(ports) = ip::ports(packet) else {
            return Verdict::Unclassifiable;
        };
        // Only ever consulted by a rule with a populated `dst_prefixes`
        // (egress only); cheap to compute unconditionally rather than thread
        // a direction flag through just to skip it on ingress.
        let destination = ip::destination(packet);
        let peer_owns_destination = match own_addresses {
            None => true,
            Some(addresses) => destination.is_some_and(|d| addresses.iter().any(|p| p.contains(d))),
        };
        if rules
            .iter()
            .any(|r| r.permits(peer, ports.destination, destination, peer_owns_destination))
        {
            Verdict::Permit
        } else {
            Verdict::Denied
        }
    }

    /// Whether any policy is being enforced, for `karst status`.
    ///
    /// An operator debugging "why can I not reach this host" needs to
    /// distinguish a node enforcing deny-all from one enforcing nothing, and
    /// those look identical from the outside in opposite ways.
    #[must_use]
    pub fn is_enforcing(&self) -> bool {
        self.ingress.is_some()
    }

    /// How many rules each direction carries, for `karst status`.
    #[must_use]
    pub fn rule_counts(&self) -> Option<(usize, usize)> {
        Some((self.ingress.as_ref()?.len(), self.egress.as_ref()?.len()))
    }
}

/// The independent SSH admission gate for TCP/22
/// (`plans/phase-6/07-acl-gated-ssh.md` §3.1) — a second, separately
/// evaluated check `AND`ed with, and never merged into, the general ingress
/// `PacketFilter`. Reuses [`Rule`]; every rule this compiles from carries
/// ports `{22, 22}`, since gating an SSH connection has no port of its own.
///
/// Shares `PacketFilter::ingress`'s "empty is deny" discipline, with one more
/// state on top of it: `None` here means "no `ssh` block in policy at all" —
/// SSH reachability governed by the general filter alone, today's behavior
/// unaffected by this gate (§3.2) — which is a *third* state alongside
/// `PacketFilter::unrestricted`'s `None` and a present, empty rule list.
pub struct SshFilter(Option<Vec<Rule>>);

impl std::fmt::Debug for SshFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match &self.0 {
            None => "absent".to_owned(),
            Some(rules) if rules.is_empty() => "deny-all".to_owned(),
            Some(rules) => format!("{} rule(s)", rules.len()),
        };
        f.debug_tuple("SshFilter").field(&state).finish()
    }
}

impl SshFilter {
    /// No `ssh` block in policy: this gate does not apply, and SSH
    /// reachability is governed by the general ingress filter alone (§3.2).
    #[must_use]
    pub fn absent() -> Self {
        Self(None)
    }

    /// Compile a netmap's `ssh_filter` rules.
    ///
    /// `present` carries the wire's `ssh_filter_present` flag (§3.2):
    /// `false` means no `ssh` block at all — [`Self::absent`], regardless of
    /// `rules` — and `true` with an empty `rules` means the block is present
    /// but grants nothing, i.e. deny all SSH beyond the general filter.
    #[must_use]
    pub fn compile(rules: &[pb::KarstFilterRule], present: bool, handles: &[Vec<u8>]) -> Self {
        if !present {
            return Self::absent();
        }
        let compiled = rules
            .iter()
            .filter_map(|r| compile_rule(&r.srcs, &r.ports, handles))
            .collect();
        Self(Some(compiled))
    }

    /// May `from` open an SSH connection to this node?
    ///
    /// Called once per new flow to local port 22 (§3.4), never per packet —
    /// see `crate::flow::SshAdmissions`, the cache that makes that true by
    /// remembering a flow's admission decision across the rest of its life.
    #[must_use]
    pub fn admit(&self, from: PeerIndex) -> Verdict {
        let Some(rules) = self.0.as_deref() else {
            return Verdict::Permit; // no "ssh" block: this gate does not apply
        };
        // `true`: the SSH gate is ingress-shaped (who may reach *this* node's
        // port 22), the same "destination is always us" reasoning as
        // `PacketFilter::ingress` — see its own doc comment.
        if rules.iter().any(|r| r.permits(from, 22, None, true)) {
            Verdict::Permit
        } else {
            Verdict::Denied
        }
    }

    /// Whether the ssh gate is enforcing at all, for `karst status`.
    #[must_use]
    pub fn is_enforcing(&self) -> bool {
        self.0.is_some()
    }

    /// How many rules the gate carries, for `karst status`.
    #[must_use]
    pub fn rule_count(&self) -> Option<usize> {
        Some(self.0.as_ref()?.len())
    }
}

/// Resolve a wire node-name list to a `NodeSet` — `Any` for a literal `"*"`,
/// otherwise only the names this node actually holds a peer for. A named peer
/// this node does not hold is silently dropped, not an error: the rule still
/// compiles, just without that peer.
fn node_set(nodes: &[String], handles: &[Vec<u8>]) -> NodeSet {
    if nodes.iter().any(|n| n == "*") {
        return NodeSet::Any;
    }
    let mut set = BTreeSet::new();
    for name in nodes {
        // Handles are base64 on the wire and bytes in the netmap.
        if let Some(index) = handles.iter().position(|h| h == name.as_bytes()) {
            set.insert(index);
        }
    }
    NodeSet::These(set)
}

/// Compile one ingress or SSH-gate rule, or `None` if it grants nothing.
///
/// These directions have no CIDR concept (see `Rule`'s own doc comment): who
/// may reach *this node* is always a question about peers, never about an
/// external network.
fn compile_rule(
    nodes: &[String],
    ports: &[pb::KarstPortRange],
    handles: &[Vec<u8>],
) -> Option<Rule> {
    let ports: Vec<PortRange> = ports
        .iter()
        .copied()
        .filter_map(PortRange::from_wire)
        .collect();
    if ports.is_empty() {
        // A rule with no usable port range grants nothing. Treating it as "any
        // port" is the permissive reading of an empty list, which is exactly
        // the mistake this module exists to avoid — and the server always emits
        // at least one range, so an empty list means something already went
        // wrong upstream.
        return None;
    }

    let nodes = node_set(nodes, handles);
    if matches!(&nodes, NodeSet::These(set) if set.is_empty()) {
        // Every named peer is unknown to this node — a rule about peers we do
        // not hold. It grants nothing, and must not be widened into one that
        // grants everything.
        return None;
    }
    Some(Rule {
        nodes,
        dst_prefixes: Vec::new(),
        ports,
    })
}

/// Compile one egress rule, or `None` if it grants nothing.
///
/// The mirror of [`compile_rule`], with one addition: `dst_cidrs` names
/// destination networks directly, never resolved against a peer at all (a
/// routed subnet has no node of its own to be a `dsts` entry). A malformed
/// CIDR is dropped rather than rejected outright — the server validates on
/// write, so this is defense in depth against a wire value this node cannot
/// itself trust blindly, not an expected case.
fn compile_egress_rule(
    dsts: &[String],
    dst_cidrs: &[String],
    ports: &[pb::KarstPortRange],
    handles: &[Vec<u8>],
) -> Option<Rule> {
    let ports: Vec<PortRange> = ports
        .iter()
        .copied()
        .filter_map(PortRange::from_wire)
        .collect();
    if ports.is_empty() {
        return None;
    }

    let nodes = node_set(dsts, handles);
    let dst_prefixes: Vec<Prefix> = dst_cidrs.iter().filter_map(|c| c.parse().ok()).collect();
    let grants_no_peer = matches!(&nodes, NodeSet::These(set) if set.is_empty());
    if grants_no_peer && dst_prefixes.is_empty() {
        // Neither a peer nor a network resolved to anything real. Grants
        // nothing, and must not be widened into one that grants everything.
        return None;
    }
    Some(Rule {
        nodes,
        dst_prefixes,
        ports,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]

    use super::*;

    fn handles() -> Vec<Vec<u8>> {
        vec![b"alice".to_vec(), b"bob".to_vec()]
    }

    fn port(first: u32, last: u32) -> pb::KarstPortRange {
        pb::KarstPortRange { first, last }
    }

    fn rule(srcs: &[&str], ports: Vec<pb::KarstPortRange>) -> pb::KarstFilterRule {
        pb::KarstFilterRule {
            srcs: srcs.iter().map(|s| (*s).to_owned()).collect(),
            ports,
        }
    }

    fn egress_rule(dsts: &[&str], ports: Vec<pb::KarstPortRange>) -> pb::KarstEgressRule {
        pb::KarstEgressRule {
            dsts: dsts.iter().map(|s| (*s).to_owned()).collect(),
            ports,
            ..Default::default()
        }
    }

    fn egress_cidr_rule(cidrs: &[&str], ports: Vec<pb::KarstPortRange>) -> pb::KarstEgressRule {
        pb::KarstEgressRule {
            dst_cidrs: cidrs.iter().map(|s| (*s).to_owned()).collect(),
            ports,
            ..Default::default()
        }
    }

    /// A TCP packet to `dst_port`.
    fn tcp(dst_port: u16) -> Vec<u8> {
        tcp_to([10, 0, 0, 2], dst_port)
    }

    /// A TCP packet to a chosen destination address, for the destination-CIDR
    /// egress rules — [`tcp`] hardcodes `10.0.0.2`, which every peer-based
    /// test relies on, so this is a separate function rather than an added
    /// parameter on it.
    fn tcp_to(dst: [u8; 4], dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 24];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&24u16.to_be_bytes());
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&40000u16.to_be_bytes());
        p[22..24].copy_from_slice(&dst_port.to_be_bytes());
        p
    }

    /// The IPv6 counterpart of [`tcp_to`], for the family-crossing test —
    /// same minimal-TCP-payload shape, over a 40-byte fixed header instead of
    /// 20.
    fn tcp6_to(dst: [u8; 16], dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 44];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&4u16.to_be_bytes());
        p[6] = 6; // next header: TCP
        p[7] = 64; // hop limit
        p[8..24].copy_from_slice(&[0xfd; 16]); // source, unused by the filter
        p[24..40].copy_from_slice(&dst);
        p[40..42].copy_from_slice(&40000u16.to_be_bytes());
        p[42..44].copy_from_slice(&dst_port.to_be_bytes());
        p
    }

    /// `tcp()`'s own fixed destination, as the address a peer "owns" for a
    /// test asserting a node-handle egress grant — `egress` now requires the
    /// carrying peer's own addresses to make that grant matter (GitHub issue
    /// #109's second half: a node-handle grant used to double as unlimited
    /// gateway-forwarding permission).
    fn owns_tcp_destination() -> Vec<Prefix> {
        vec!["10.0.0.2/32".parse().expect("valid prefix")]
    }

    /// An ICMP echo request — a protocol with no ports at all.
    fn icmp() -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[9] = 1;
        p[20] = 8;
        p
    }

    // ── default deny ────────────────────────────────────────────────────────

    /// **The property everything else rests on.** A netmap that ships no rules
    /// is a policy that grants nothing, so a policy typo removes access rather
    /// than granting it.
    #[test]
    fn an_empty_rule_set_denies_everything() {
        let f = PacketFilter::compile(&[], &[], &handles());
        assert_eq!(f.ingress(0, &tcp(22)), Verdict::Denied);
        assert_eq!(f.egress(0, &tcp(22), &[]), Verdict::Denied);
        assert_eq!(f.ingress(0, &icmp()), Verdict::Denied);
        assert!(f.is_enforcing());
    }

    /// And the state it must never be confused with: no policy *source*, which
    /// is the static roster with no notion of an ACL.
    #[test]
    fn no_policy_source_is_not_the_same_as_an_empty_policy() {
        let none = PacketFilter::unrestricted();
        assert_eq!(none.ingress(0, &tcp(22)), Verdict::Permit);
        assert!(!none.is_enforcing());
        assert_eq!(none.rule_counts(), None);

        let empty = PacketFilter::compile(&[], &[], &handles());
        assert_eq!(empty.ingress(0, &tcp(22)), Verdict::Denied);
        assert!(empty.is_enforcing());
        assert_eq!(empty.rule_counts(), Some((0, 0)));
    }

    /// The two states must be distinguishable in a log line, because an
    /// operator debugging "why can I not reach this host" needs to tell them
    /// apart and they look identical from the outside.
    #[test]
    fn the_two_states_are_distinguishable_in_debug_output() {
        let none = format!("{:?}", PacketFilter::unrestricted());
        let empty = format!("{:?}", PacketFilter::compile(&[], &[], &handles()));
        assert!(none.contains("unrestricted"), "{none}");
        assert!(empty.contains("deny-all"), "{empty}");
        assert_ne!(none, empty);
    }

    // ── matching ────────────────────────────────────────────────────────────

    #[test]
    fn a_rule_permits_only_its_own_peers_and_ports() {
        let f = PacketFilter::compile(&[rule(&["alice"], vec![port(22, 22)])], &[], &handles());
        assert_eq!(f.ingress(0, &tcp(22)), Verdict::Permit);
        assert_eq!(f.ingress(0, &tcp(23)), Verdict::Denied, "wrong port");
        assert_eq!(f.ingress(1, &tcp(22)), Verdict::Denied, "wrong peer");
    }

    #[test]
    fn a_wildcard_source_matches_any_peer() {
        let f = PacketFilter::compile(&[rule(&["*"], vec![port(443, 443)])], &[], &handles());
        assert_eq!(f.ingress(0, &tcp(443)), Verdict::Permit);
        assert_eq!(f.ingress(1, &tcp(443)), Verdict::Permit);
        assert_eq!(f.ingress(1, &tcp(80)), Verdict::Denied);
    }

    #[test]
    fn port_ranges_are_inclusive_at_both_ends() {
        let f = PacketFilter::compile(&[rule(&["*"], vec![port(8000, 8002)])], &[], &handles());
        for p in [8000u16, 8001, 8002] {
            assert_eq!(f.ingress(0, &tcp(p)), Verdict::Permit, "port {p}");
        }
        assert_eq!(f.ingress(0, &tcp(7999)), Verdict::Denied);
        assert_eq!(f.ingress(0, &tcp(8003)), Verdict::Denied);
    }

    /// `*` for ports compiles to 0–65535 on the server, which includes port 0
    /// — and port 0 is what a protocol without ports reports. So a policy that
    /// says "any port" permits ping, and one that says "port 22" does not.
    #[test]
    fn a_protocol_without_ports_is_covered_by_a_wildcard_port_range_only() {
        let any = PacketFilter::compile(&[rule(&["*"], vec![port(0, 65535)])], &[], &handles());
        assert_eq!(any.ingress(0, &icmp()), Verdict::Permit);

        let ssh = PacketFilter::compile(&[rule(&["*"], vec![port(22, 22)])], &[], &handles());
        assert_eq!(
            ssh.ingress(0, &icmp()),
            Verdict::Denied,
            "a rule about port 22 must not permit a protocol with no port"
        );
    }

    /// Rules are a union: any one of them permitting is enough.
    #[test]
    fn rules_accumulate() {
        let f = PacketFilter::compile(
            &[
                rule(&["alice"], vec![port(22, 22)]),
                rule(&["bob"], vec![port(443, 443)]),
            ],
            &[],
            &handles(),
        );
        assert_eq!(f.ingress(0, &tcp(22)), Verdict::Permit);
        assert_eq!(f.ingress(1, &tcp(443)), Verdict::Permit);
        assert_eq!(f.ingress(0, &tcp(443)), Verdict::Denied);
        assert_eq!(f.ingress(1, &tcp(22)), Verdict::Denied);
    }

    // ── the widening traps ──────────────────────────────────────────────────

    /// **A rule naming only peers we do not hold grants nothing.** Turning its
    /// empty source set into "any" is how a policy inverts itself; the rule is
    /// discarded instead.
    #[test]
    fn a_rule_naming_only_unknown_peers_is_discarded_not_widened() {
        let f = PacketFilter::compile(
            &[rule(&["nobody", "stranger"], vec![port(0, 65535)])],
            &[],
            &handles(),
        );
        assert_eq!(f.rule_counts(), Some((0, 0)), "the rule must be dropped");
        assert_eq!(f.ingress(0, &tcp(22)), Verdict::Denied);
        assert_eq!(f.ingress(1, &tcp(22)), Verdict::Denied);
    }

    /// A rule naming a mix keeps the peers it knows and only those.
    #[test]
    fn unknown_peers_are_dropped_from_a_rule_that_still_names_a_known_one() {
        let f = PacketFilter::compile(
            &[rule(&["nobody", "bob"], vec![port(22, 22)])],
            &[],
            &handles(),
        );
        assert_eq!(f.ingress(1, &tcp(22)), Verdict::Permit);
        assert_eq!(f.ingress(0, &tcp(22)), Verdict::Denied);
    }

    /// A rule with no port ranges grants nothing. The permissive reading of an
    /// empty list is the same mistake in a different field.
    #[test]
    fn a_rule_with_no_ports_is_discarded_not_widened() {
        let f = PacketFilter::compile(&[rule(&["*"], vec![])], &[], &handles());
        assert_eq!(f.rule_counts(), Some((0, 0)));
        assert_eq!(f.ingress(0, &tcp(22)), Verdict::Denied);
    }

    /// A range that cannot be a range is dropped rather than clamped. Clamping
    /// would turn nonsense into a grant nobody wrote — most likely a wide one.
    #[test]
    fn impossible_port_ranges_are_dropped_rather_than_clamped() {
        let f = PacketFilter::compile(
            &[rule(&["*"], vec![port(100, 50), port(70000, 80000)])],
            &[],
            &handles(),
        );
        assert_eq!(f.rule_counts(), Some((0, 0)));
        assert_eq!(f.ingress(0, &tcp(75)), Verdict::Denied);
        assert_eq!(f.ingress(0, &tcp(65535)), Verdict::Denied);
    }

    // ── the fragment bypass ─────────────────────────────────────────────────

    /// **A filter bypass if it were not handled.** A non-first fragment has no
    /// transport header, so its "ports" are two arbitrary payload bytes.
    /// Everything unclassifiable is denied.
    #[test]
    fn an_unclassifiable_packet_is_denied() {
        let f = PacketFilter::compile(&[rule(&["*"], vec![port(0, 65535)])], &[], &handles());

        let mut fragment = tcp(22);
        fragment[6] = 0x00;
        fragment[7] = 0x01; // fragment offset 1
        assert_eq!(f.ingress(0, &fragment), Verdict::Unclassifiable);
        assert!(!f.ingress(0, &fragment).permitted());

        // Even a wildcard-everything policy does not pass garbage.
        assert!(!f.ingress(0, &[0xFF; 40]).permitted());
        assert!(!f.ingress(0, &[]).permitted());
    }

    /// Denied and unclassifiable are both refusals but different diagnoses: one
    /// says the policy forbids this, the other says the packet could not be
    /// judged at all.
    #[test]
    fn a_refusal_says_which_kind_it_is() {
        let f = PacketFilter::compile(&[rule(&["*"], vec![port(22, 22)])], &[], &handles());
        assert_eq!(f.ingress(0, &tcp(80)), Verdict::Denied);
        assert_eq!(f.ingress(0, &[0x45, 0x00]), Verdict::Unclassifiable);
    }

    // ── the two directions ──────────────────────────────────────────────────

    /// The directions are independent. A node permitted to receive on 22 is not
    /// thereby permitted to send to 22, because Karst's ACLs are unidirectional
    /// grants.
    #[test]
    fn the_two_directions_do_not_imply_each_other() {
        let f = PacketFilter::compile(
            &[rule(&["bob"], vec![port(22, 22)])],
            &[egress_rule(&["alice"], vec![port(443, 443)])],
            &handles(),
        );

        assert_eq!(f.ingress(1, &tcp(22)), Verdict::Permit);
        assert_eq!(
            f.egress(1, &tcp(22), &owns_tcp_destination()),
            Verdict::Denied,
            "being allowed to receive from bob on 22 says nothing about sending"
        );

        assert_eq!(
            f.egress(0, &tcp(443), &owns_tcp_destination()),
            Verdict::Permit
        );
        assert_eq!(f.ingress(0, &tcp(443)), Verdict::Denied);
    }

    /// An egress rule set that is empty denies outbound traffic even when the
    /// ingress set is permissive — the mirror of the default-deny check, and
    /// the one a "the filter is really just the inbound rules" refactor would
    /// break.
    #[test]
    fn an_empty_egress_set_denies_even_when_ingress_permits() {
        let f = PacketFilter::compile(&[rule(&["*"], vec![port(0, 65535)])], &[], &handles());
        assert_eq!(f.ingress(0, &tcp(22)), Verdict::Permit);
        assert_eq!(
            f.egress(0, &tcp(22), &owns_tcp_destination()),
            Verdict::Denied
        );
    }

    // ── destination-CIDR egress rules ───────────────────────────────────────
    //
    // A routed subnet behind a gateway has no node handle of its own — this is
    // the only way a policy can grant reachability to it (GitHub issue #109:
    // a policy naming a subnet by CIDR previously compiled to zero rules for
    // everyone, so a "denied" recipient reached it exactly like an "allowed"
    // one).

    /// The basic grant: a destination inside the CIDR is permitted, regardless
    /// of which peer carries the packet **and without that peer owning the
    /// destination at all** — a CIDR grant is about the network, not about
    /// which gateway happens to be forwarding to it right now. `&[]` here is
    /// deliberate: it proves the CIDR path grants this on its own, not
    /// through the node-handle path `owns_tcp_destination()` exercises
    /// elsewhere in this file.
    #[test]
    fn a_dst_cidr_grant_permits_any_peer_carrying_a_matching_destination() {
        let f = PacketFilter::compile(
            &[],
            &[egress_cidr_rule(&["10.50.0.0/24"], vec![port(0, 65535)])],
            &handles(),
        );
        assert_eq!(
            f.egress(0, &tcp_to([10, 50, 0, 10], 80), &[]),
            Verdict::Permit
        );
        assert_eq!(
            f.egress(1, &tcp_to([10, 50, 0, 10], 80), &[]),
            Verdict::Permit,
            "a different peer carrying the same granted destination is equally permitted"
        );
    }

    /// The regression case: a destination outside every granted CIDR (and
    /// matching no node-handle rule either) is denied — this is what makes a
    /// "denied" client's traffic actually stop, not just look configured.
    #[test]
    fn a_destination_outside_every_granted_cidr_is_denied() {
        let f = PacketFilter::compile(
            &[],
            &[egress_cidr_rule(&["10.50.0.0/24"], vec![port(0, 65535)])],
            &handles(),
        );
        assert_eq!(
            f.egress(0, &tcp_to([10, 50, 1, 10], 80), &[]),
            Verdict::Denied,
            "10.50.1.0/24 is a sibling network, not the granted /24"
        );
        assert_eq!(
            f.egress(0, &tcp_to([203, 0, 113, 1], 80), &[]),
            Verdict::Denied
        );
    }

    /// IPv4 and IPv6 must never cross here either — the same standard
    /// `routing.rs`'s `AllowedIps` holds itself to. A v4-only grant must not
    /// let a v6 destination through, encoded or not.
    #[test]
    fn dst_cidr_matching_never_crosses_address_families() {
        let f = PacketFilter::compile(
            &[],
            &[egress_cidr_rule(&["10.50.0.0/24"], vec![port(0, 65535)])],
            &handles(),
        );
        let mapped = tcp6_to(
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 50, 0, 10],
            80,
        );
        assert_eq!(
            f.egress(0, &mapped, &[]),
            Verdict::Denied,
            "a v4-mapped v6 destination must not match a v4 prefix"
        );
    }

    /// A node-handle grant and a destination-CIDR grant on the same node are
    /// independent, additive rules — one does not widen or narrow the other.
    #[test]
    fn a_node_grant_and_a_dst_cidr_grant_apply_independently() {
        let f = PacketFilter::compile(
            &[],
            &[
                egress_rule(&["alice"], vec![port(443, 443)]),
                egress_cidr_rule(&["10.50.0.0/24"], vec![port(80, 80)]),
            ],
            &handles(),
        );
        assert_eq!(
            f.egress(0, &tcp(443), &owns_tcp_destination()),
            Verdict::Permit,
            "alice, port 443"
        );
        assert_eq!(
            f.egress(0, &tcp(80), &owns_tcp_destination()),
            Verdict::Denied,
            "alice on 80 matches neither rule (10.0.0.2 is outside the /24)"
        );
        assert_eq!(
            f.egress(1, &tcp_to([10, 50, 0, 5], 80), &[]),
            Verdict::Permit,
            "bob reaching the granted subnet on 80, via the CIDR grant alone — bob owns nothing here"
        );
        assert_eq!(
            f.egress(1, &tcp_to([10, 50, 0, 5], 443), &[]),
            Verdict::Denied,
            "the subnet grant is scoped to port 80, not 443"
        );
    }

    /// A malformed CIDR on the wire is dropped, not trusted blindly or turned
    /// into a panic — the server validates on write, but this node cannot
    /// assume the wire value is well-formed.
    #[test]
    fn an_unparseable_dst_cidr_grants_nothing() {
        let f = PacketFilter::compile(
            &[],
            &[egress_cidr_rule(&["not-a-cidr"], vec![port(0, 65535)])],
            &handles(),
        );
        assert_eq!(
            f.egress(0, &tcp_to([10, 50, 0, 10], 80), &[]),
            Verdict::Denied
        );
    }

    /// **The second half of GitHub issue #109's fix, and the one that makes
    /// the first half actually mean something.** A plain node-handle grant to
    /// a gateway peer — ordinary mesh connectivity, unrelated to subnet
    /// access — must not double as unlimited permission to route arbitrary
    /// traffic through that gateway to whatever it forwards. Before this,
    /// `nodes.contains(peer)` matched on the next-hop peer alone, so any
    /// grant naming the gateway (however innocuous) silently bypassed every
    /// CIDR restriction: a "denied" client reached a routed subnet exactly
    /// like an "allowed" one, live, in a real deployment, the moment its
    /// policy happened to include any rule at all granting it the gateway's
    /// own handle.
    #[test]
    fn a_node_handle_grant_to_a_gateway_does_not_leak_its_forwarded_traffic() {
        let f = PacketFilter::compile(
            &[],
            &[egress_rule(&["alice"], vec![port(0, 65535)])],
            &handles(),
        );
        // alice (peer 0) is granted egress to alice's own handle — ordinary,
        // and it must still work when the destination really is alice's own
        // address.
        assert_eq!(
            f.egress(0, &tcp(80), &owns_tcp_destination()),
            Verdict::Permit,
            "a node-handle grant must still work for the peer's own address"
        );
        // The same rule, the same peer index, but the packet is headed to a
        // subnet alice merely gateways — alice does not own it. No CIDR rule
        // grants it either. This must be denied.
        assert_eq!(
            f.egress(0, &tcp_to([10, 50, 0, 10], 80), &owns_tcp_destination()),
            Verdict::Denied,
            "a node-handle grant to the gateway must not forward to a subnet it merely carries"
        );
    }

    /// A peer index beyond the roster must not match anything, whatever the
    /// rules say. `NodeSet::Any` is the one case where it can, and that is
    /// correct — a wildcard rule is about the packet, not the peer.
    #[test]
    fn an_out_of_range_peer_matches_only_a_wildcard() {
        let named = PacketFilter::compile(&[rule(&["alice"], vec![port(22, 22)])], &[], &handles());
        assert_eq!(named.ingress(99, &tcp(22)), Verdict::Denied);

        let any = PacketFilter::compile(&[rule(&["*"], vec![port(22, 22)])], &[], &handles());
        assert_eq!(any.ingress(99, &tcp(22)), Verdict::Permit);
    }

    // ── the ssh gate ────────────────────────────────────────────────────────

    /// The state nothing else has: no `ssh` block at all, distinct from both
    /// `PacketFilter::unrestricted` and an empty, enforcing `ssh` block.
    #[test]
    fn an_absent_ssh_block_permits_everything() {
        let f = SshFilter::absent();
        assert_eq!(f.admit(0), Verdict::Permit);
        assert!(!f.is_enforcing());
        assert_eq!(f.rule_count(), None);
    }

    /// `"ssh": []` denies every connection, the same "empty is deny"
    /// discipline `PacketFilter` uses — and observably different from absent.
    #[test]
    fn an_empty_ssh_rule_set_denies_everything() {
        let f = SshFilter::compile(&[], true, &handles());
        assert_eq!(f.admit(0), Verdict::Denied);
        assert!(f.is_enforcing());
        assert_eq!(f.rule_count(), Some(0));
    }

    /// `present: false` means absent regardless of what `rules` says — the
    /// wire's `ssh_filter_present` flag is authoritative, not emptiness.
    #[test]
    fn present_false_is_absent_even_with_rules() {
        let f = SshFilter::compile(&[rule(&["alice"], vec![port(22, 22)])], false, &handles());
        assert_eq!(f.admit(0), Verdict::Permit);
        assert!(!f.is_enforcing());
    }

    /// The three states must be distinguishable in a log line, for the same
    /// reason `PacketFilter`'s two states must be.
    #[test]
    fn the_three_states_are_distinguishable_in_debug_output() {
        let absent = format!("{:?}", SshFilter::absent());
        let deny_all = format!("{:?}", SshFilter::compile(&[], true, &handles()));
        let granting = format!(
            "{:?}",
            SshFilter::compile(&[rule(&["alice"], vec![port(22, 22)])], true, &handles())
        );
        assert!(absent.contains("absent"), "{absent}");
        assert!(deny_all.contains("deny-all"), "{deny_all}");
        assert!(granting.contains("1 rule"), "{granting}");
        assert_ne!(absent, deny_all);
        assert_ne!(deny_all, granting);
    }

    #[test]
    fn an_ssh_rule_permits_only_its_own_peer() {
        let f = SshFilter::compile(&[rule(&["alice"], vec![port(22, 22)])], true, &handles());
        assert_eq!(f.admit(0), Verdict::Permit);
        assert_eq!(f.admit(1), Verdict::Denied);
    }

    /// The general filter and the ssh gate are separate checks: this module
    /// makes no attempt to AND them together — that is `Engine::permit`'s job
    /// — so an ssh-only test must not assume anything about `PacketFilter`.
    #[test]
    fn an_ssh_wildcard_matches_any_peer() {
        let f = SshFilter::compile(&[rule(&["*"], vec![port(22, 22)])], true, &handles());
        assert_eq!(f.admit(0), Verdict::Permit);
        assert_eq!(f.admit(1), Verdict::Permit);
    }

    /// A peer named in an ssh rule but unknown to this node grants nothing,
    /// the same widening trap `PacketFilter::compile` guards against.
    #[test]
    fn an_ssh_rule_naming_only_unknown_peers_is_discarded_not_widened() {
        let f = SshFilter::compile(
            &[rule(&["nobody", "stranger"], vec![port(22, 22)])],
            true,
            &handles(),
        );
        assert_eq!(f.rule_count(), Some(0));
        assert_eq!(f.admit(0), Verdict::Denied);
    }
}
