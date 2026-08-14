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

use karst_control_client::transport::pb;
use karst_tun::ip;

use crate::routing::PeerIndex;

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
#[derive(Debug, Clone)]
struct Rule {
    nodes: NodeSet,
    ports: Vec<PortRange>,
}

impl Rule {
    fn permits(&self, peer: PeerIndex, port: u16) -> bool {
        self.nodes.contains(peer) && self.ports.iter().any(|r| r.contains(port))
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
            .filter_map(|r| compile_rule(&r.dsts, &r.ports, handles))
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
        Self::evaluate(self.ingress.as_deref(), from, packet)
    }

    /// May we send this packet to `to`?
    #[must_use]
    pub fn egress(&self, to: PeerIndex, packet: &[u8]) -> Verdict {
        Self::evaluate(self.egress.as_deref(), to, packet)
    }

    fn evaluate(rules: Option<&[Rule]>, peer: PeerIndex, packet: &[u8]) -> Verdict {
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
        if rules.iter().any(|r| r.permits(peer, ports.destination)) {
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

/// Compile one rule, or `None` if it grants nothing.
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

    if nodes.iter().any(|n| n == "*") {
        return Some(Rule {
            nodes: NodeSet::Any,
            ports,
        });
    }

    let mut set = BTreeSet::new();
    for name in nodes {
        // Handles are base64 on the wire and bytes in the netmap.
        if let Some(index) = handles.iter().position(|h| h == name.as_bytes()) {
            set.insert(index);
        }
    }
    if set.is_empty() {
        // Every named peer is unknown to this node — a rule about peers we do
        // not hold. It grants nothing, and must not be widened into one that
        // grants everything.
        return None;
    }
    Some(Rule {
        nodes: NodeSet::These(set),
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
        }
    }

    /// A TCP packet to `dst_port`.
    fn tcp(dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 24];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&24u16.to_be_bytes());
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[20..22].copy_from_slice(&40000u16.to_be_bytes());
        p[22..24].copy_from_slice(&dst_port.to_be_bytes());
        p
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
        assert_eq!(f.egress(0, &tcp(22)), Verdict::Denied);
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
            f.egress(1, &tcp(22)),
            Verdict::Denied,
            "being allowed to receive from bob on 22 says nothing about sending"
        );

        assert_eq!(f.egress(0, &tcp(443)), Verdict::Permit);
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
        assert_eq!(f.egress(0, &tcp(22)), Verdict::Denied);
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
}
