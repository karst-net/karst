// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Connection tracking, so a permitted request's reply is permitted too.
//!
//! # Why this exists
//!
//! PLAN.md §4.3 makes Karst's ACLs **unidirectional grants**: a rule says who
//! may *initiate* to whom, on which ports. A stateless filter reading that rule
//! permits `A → B:22` and denies `B:22 → A:54321`, because the reply's
//! destination port matches nothing — so **no TCP connection can complete**,
//! which is the primary use of the feature and the example the plan itself
//! gives. That was GitHub issue [#22](https://github.com/karst-net/karst/issues/22), and it was found by two daemons
//! carrying real traffic rather than by any of the tests below this line.
//!
//! # The rule
//!
//! A flow is recorded **only when a rule permits a packet**. Nothing an
//! attacker sends can create one, because a packet no rule permits is dropped
//! before it gets here. The flow then permits exactly the reverse five-tuple
//! and nothing else.
//!
//! That is the difference between this and the stateless approximation it would
//! have been easy to ship instead — "permit a packet whose *source* port
//! matches a rule" needs no state at all, and grants a permitted peer the right
//! to reach **every** port on this node by choosing its source port. The old
//! hole in "allow anything from port 53". A grant of `A → B:22` must not become
//! a grant of `B → A:*`.
//!
//! # Keyed from this node's point of view
//!
//! One flow produces one key whichever direction a packet is traveling, by
//! naming the local and remote halves rather than the source and destination
//! halves. The direction decides which is which, and that is the whole of the
//! bookkeeping.

use std::collections::HashMap;
use std::net::IpAddr;

use karst_tun::ip;

use crate::filter::Direction;

/// Most flows tracked per peer.
///
/// State a peer's traffic causes this node to allocate, so it is counted and
/// capped like every other such thing (`aven-v1.md` §7.1 makes the same
/// argument for probes). Four thousand is far more than a node legitimately
/// holds open to one peer and far less than an attacker would need to matter.
const MAX_FLOWS: usize = 4096;

/// How long a flow survives without a packet.
///
/// Two minutes, which is longer than a TCP handshake and shorter than a
/// half-open connection is interesting. There is deliberately no per-protocol
/// tuning: this is a permission lifetime, not a connection-state machine, and a
/// table that modeled TCP state would be a second, subtly different TCP
/// implementation living in the datapath.
const IDLE_MS: u64 = 120_000;

/// One flow, named from this node's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    protocol: u8,
    local: IpAddr,
    remote: IpAddr,
    local_port: u16,
    remote_port: u16,
}

impl Key {
    /// Build the key a packet belongs to.
    ///
    /// `None` when the ports cannot be established — a non-first fragment or a
    /// protocol with no ports the parser refuses to guess at. Such a packet
    /// neither creates a flow nor matches one, which leaves it exactly where
    /// the filter's `Unclassifiable` verdict already puts it.
    fn of(direction: Direction, packet: &[u8]) -> Option<Self> {
        let ports = ip::ports(packet)?;
        let addrs = ip::addresses(packet)?;
        // Outbound, *we* are the source; inbound, we are the destination. This
        // is the only place the two directions differ, and it is what makes one
        // flow produce one key from either end of it.
        let (local, remote, local_port, remote_port) = match direction {
            Direction::Out => (
                addrs.source,
                addrs.destination,
                ports.source,
                ports.destination,
            ),
            Direction::In => (
                addrs.destination,
                addrs.source,
                ports.destination,
                ports.source,
            ),
        };
        Some(Self {
            protocol: ports.protocol,
            local,
            remote,
            local_port,
            remote_port,
        })
    }
}

/// The flows this node holds open with one peer.
#[derive(Debug, Default)]
pub struct Flows {
    seen: HashMap<Key, u64>,
}

impl Flows {
    /// An empty table, which permits nothing on its own.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a rule permitted this packet.
    ///
    /// Only ever called for a packet a *rule* allowed. That is the property the
    /// whole design rests on: an attacker cannot open a flow, because a packet
    /// that reaches here was already permitted without one.
    pub fn record(&mut self, direction: Direction, packet: &[u8], now_ms: u64) {
        let Some(key) = Key::of(direction, packet) else {
            return;
        };
        if self.seen.len() >= MAX_FLOWS && !self.seen.contains_key(&key) {
            self.make_room(now_ms);
        }
        self.seen.insert(key, now_ms);
    }

    /// Whether an existing flow permits this packet, refreshing it if so.
    ///
    /// The lookup is by the *same* key the opposite direction recorded, so this
    /// answers "is this the other half of something we already allowed".
    pub fn permits(&mut self, direction: Direction, packet: &[u8], now_ms: u64) -> bool {
        let Some(key) = Key::of(direction, packet) else {
            return false;
        };
        let Some(last) = self.seen.get_mut(&key) else {
            return false;
        };
        // Expiry is checked on read rather than swept on a timer: a flow nobody
        // asks about costs a map entry and nothing else, and the entry is
        // reclaimed by `make_room` when the cap is reached.
        if now_ms.saturating_sub(*last) > IDLE_MS {
            self.seen.remove(&key);
            return false;
        }
        *last = now_ms;
        true
    }

    /// Forget everything.
    ///
    /// **Called when the policy changes.** A flow is a cached permission, and a
    /// policy edit that revoked access while existing flows kept working would
    /// be a policy edit that did not take effect — which is the failure mode
    /// §4.3's whole "distributor of policy, not an enforcement point" argument
    /// depends on not having.
    pub fn clear(&mut self) {
        self.seen.clear();
    }

    /// Flows currently held, for diagnostics and for the tests that assert the
    /// cap is real.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether nothing is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Drop expired flows, then the least recently used, until there is room.
    fn make_room(&mut self, now_ms: u64) {
        evict_to_capacity(&mut self.seen, now_ms);
    }
}

/// Drop expired entries, then the least recently used, until `map` is under
/// [`MAX_FLOWS`]. Shared by [`Flows`] and [`SshAdmissions`], which have
/// identical bounding logic over otherwise-independent state.
///
/// Expired first because those are free — nothing is lost by forgetting a
/// permission that had already lapsed. Only when none has expired does this
/// evict a live entry, and then the one that has gone longest without a
/// packet, which is the one least likely to still be carrying anything.
fn evict_to_capacity(map: &mut HashMap<Key, u64>, now_ms: u64) {
    map.retain(|_, last| now_ms.saturating_sub(*last) <= IDLE_MS);
    while map.len() >= MAX_FLOWS {
        let Some(oldest) = map.iter().min_by_key(|(_, last)| **last).map(|(k, _)| *k) else {
            return;
        };
        map.remove(&oldest);
    }
}

/// A cache of flows the SSH gate ([`crate::filter::SshFilter`]) has already
/// admitted, so its rule match runs once per flow rather than once per packet
/// (`plans/phase-6/07-acl-gated-ssh.md` §3.4).
///
/// Distinct from [`Flows`] and not an alias for it: `Flows` remembers *that a
/// rule permitted a packet*, so its reverse direction may reply; this
/// remembers *that the SSH gate specifically admitted this flow*, so a policy
/// change is not re-evaluated against a connection already carrying traffic.
/// The two would answer different questions even if their shapes are
/// identical, so they get separate types rather than one reused for both.
///
/// Shares `Flows`'s core invariant: an entry exists **only because
/// [`crate::filter::SshFilter::admit`] permitted the flow it names**. Nothing
/// an attacker sends can create one on its own, and a flow the gate denied is
/// never recorded — the next packet of that same denied attempt is checked
/// again, not remembered as a standing refusal.
#[derive(Debug, Default)]
pub struct SshAdmissions {
    seen: HashMap<Key, u64>,
}

impl SshAdmissions {
    /// An empty cache: every flow still needs its first admission check.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this flow was already admitted by the SSH gate, refreshing it
    /// if so.
    ///
    /// `false` means [`crate::filter::SshFilter::admit`] must be consulted:
    /// either this is genuinely the first packet of a new flow, or the
    /// previous admission went idle long enough to expire (`IDLE_MS`, the
    /// same window `Flows` uses) — in either case, a policy revocation since
    /// the last check is only observed here, never mid-flow (§3.4).
    pub fn is_admitted(&mut self, direction: Direction, packet: &[u8], now_ms: u64) -> bool {
        let Some(key) = Key::of(direction, packet) else {
            return false;
        };
        let Some(last) = self.seen.get_mut(&key) else {
            return false;
        };
        if now_ms.saturating_sub(*last) > IDLE_MS {
            self.seen.remove(&key);
            return false;
        }
        *last = now_ms;
        true
    }

    /// Record that the SSH gate admitted this flow.
    ///
    /// Only ever called right after [`crate::filter::SshFilter::admit`]
    /// returned a permit — the same "recorded only on permit" discipline
    /// [`Flows::record`] documents, and for the identical reason.
    pub fn admit(&mut self, direction: Direction, packet: &[u8], now_ms: u64) {
        let Some(key) = Key::of(direction, packet) else {
            return;
        };
        if self.seen.len() >= MAX_FLOWS && !self.seen.contains_key(&key) {
            evict_to_capacity(&mut self.seen, now_ms);
        }
        self.seen.insert(key, now_ms);
    }

    /// Forget every admission. Called alongside [`Flows::clear`] whenever
    /// policy is reconfigured, so a stale admission cannot outlive the "ssh"
    /// block that granted it.
    pub fn clear(&mut self) {
        self.seen.clear();
    }

    /// Admissions currently held, for diagnostics and tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether nothing is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
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

    /// A TCP packet, so the tests read like the traffic they describe.
    fn tcp(src: [u8; 4], src_port: u16, dst: [u8; 4], dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        let total = u16::try_from(p.len()).expect("small");
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&src_port.to_be_bytes());
        p[22..24].copy_from_slice(&dst_port.to_be_bytes());
        p
    }

    const US: [u8; 4] = [100, 64, 0, 2];
    const THEM: [u8; 4] = [100, 64, 0, 3];

    /// **The finding, in one test.** A request this node was allowed to send
    /// makes its reply allowed to arrive.
    #[test]
    fn a_reply_to_a_permitted_request_is_permitted() {
        let mut flows = Flows::new();
        let request = tcp(US, 54321, THEM, 22);
        let reply = tcp(THEM, 22, US, 54321);

        assert!(
            !flows.permits(Direction::In, &reply, 0),
            "a reply was permitted before anything was sent"
        );
        flows.record(Direction::Out, &request, 0);
        assert!(flows.permits(Direction::In, &reply, 1));
    }

    /// And the other side of the same conversation: a request this node was
    /// allowed to *receive* makes its reply allowed to leave.
    #[test]
    fn a_reply_to_a_permitted_inbound_request_may_be_sent() {
        let mut flows = Flows::new();
        let request = tcp(THEM, 54321, US, 22);
        let reply = tcp(US, 22, THEM, 54321);

        flows.record(Direction::In, &request, 0);
        assert!(flows.permits(Direction::Out, &reply, 1));
    }

    /// **What a flow must not become.** It permits the reverse five-tuple and
    /// nothing else — not another port, not another address, not another
    /// protocol. This is the difference between connection tracking and the
    /// stateless "allow anything from port 22" that would also have made the
    /// test above pass.
    #[test]
    fn a_flow_permits_nothing_but_its_own_reverse() {
        let mut flows = Flows::new();
        flows.record(Direction::Out, &tcp(US, 54321, THEM, 22), 0);

        for (what, packet) in [
            ("a different local port", tcp(THEM, 22, US, 54322)),
            ("a different remote port", tcp(THEM, 23, US, 54321)),
            (
                "a different remote address",
                tcp([100, 64, 0, 9], 22, US, 54321),
            ),
            (
                "a different local address",
                tcp(THEM, 22, [100, 64, 0, 9], 54321),
            ),
        ] {
            assert!(
                !flows.permits(Direction::In, &packet, 1),
                "the flow permitted {what}"
            );
        }

        // Same five-tuple, different protocol.
        let mut udp = tcp(THEM, 22, US, 54321);
        udp[9] = 17;
        assert!(!flows.permits(Direction::In, &udp, 1), "protocol ignored");
    }

    #[test]
    fn a_flow_expires_when_it_goes_quiet() {
        let mut flows = Flows::new();
        flows.record(Direction::Out, &tcp(US, 54321, THEM, 22), 0);
        let reply = tcp(THEM, 22, US, 54321);

        assert!(flows.permits(Direction::In, &reply, IDLE_MS));
        assert!(!flows.permits(Direction::In, &reply, IDLE_MS * 2 + 1));
    }

    /// Traffic keeps a flow open, or a long-lived connection would be cut off
    /// mid-conversation two minutes in.
    #[test]
    fn traffic_refreshes_a_flow() {
        let mut flows = Flows::new();
        flows.record(Direction::Out, &tcp(US, 54321, THEM, 22), 0);
        let reply = tcp(THEM, 22, US, 54321);

        let mut now = 0;
        for _ in 0..10 {
            now += IDLE_MS - 1;
            assert!(
                flows.permits(Direction::In, &reply, now),
                "cut off at {now}"
            );
        }
    }

    /// Flows are state a peer's traffic makes this node allocate, so they are
    /// bounded — and the bound holds even though every packet here is one a
    /// rule permitted.
    #[test]
    fn the_table_is_bounded() {
        let mut flows = Flows::new();
        for n in 0..MAX_FLOWS * 2 {
            let port = u16::try_from(n % 60000).unwrap_or(0).saturating_add(1024);
            let addr = [100, 64, 1, u8::try_from(n / 60000).unwrap_or(0)];
            flows.record(Direction::Out, &tcp(US, port, addr, 22), 0);
        }
        assert!(flows.len() <= MAX_FLOWS, "{} flows held", flows.len());
    }

    /// An expired flow is reclaimed in preference to a live one, so a burst of
    /// new connections does not evict the conversation currently carrying data.
    #[test]
    fn expiry_is_reclaimed_before_anything_live() {
        let mut flows = Flows::new();
        for n in 0..MAX_FLOWS {
            let port = u16::try_from(n).unwrap_or(0).saturating_add(1024);
            flows.record(Direction::Out, &tcp(US, port, THEM, 22), 0);
        }
        let live = tcp(US, 60001, THEM, 22);
        flows.record(Direction::Out, &live, IDLE_MS * 2);

        // Everything from t=0 has lapsed, so the newcomer costs nothing live.
        assert!(flows.permits(Direction::In, &tcp(THEM, 22, US, 60001), IDLE_MS * 2 + 1));
        assert!(flows.len() <= MAX_FLOWS);
    }

    /// A policy change must actually take effect, including on traffic already
    /// flowing.
    #[test]
    fn clearing_revokes_every_cached_permission() {
        let mut flows = Flows::new();
        flows.record(Direction::Out, &tcp(US, 54321, THEM, 22), 0);
        flows.clear();
        assert!(flows.is_empty());
        assert!(!flows.permits(Direction::In, &tcp(THEM, 22, US, 54321), 1));
    }

    /// A packet whose ports cannot be read neither opens a flow nor matches
    /// one. Guessing at two bytes would let a fragment claim any flow it liked.
    #[test]
    fn an_unclassifiable_packet_is_inert() {
        let mut flows = Flows::new();
        let mut fragment = tcp(US, 54321, THEM, 22);
        fragment[6] = 0x00;
        fragment[7] = 0x10; // non-zero fragment offset

        flows.record(Direction::Out, &fragment, 0);
        assert!(flows.is_empty(), "a fragment opened a flow");
        assert!(!flows.permits(Direction::Out, &fragment, 0));
    }

    // ── the ssh admission cache ─────────────────────────────────────────────

    /// A flow with no admission entry must be reported as needing one — the
    /// signal `Engine::permit` uses to decide whether `SshFilter::admit` has
    /// to run at all.
    #[test]
    fn an_unadmitted_flow_is_reported_as_such() {
        let mut admissions = SshAdmissions::new();
        let flow = tcp(THEM, 54321, US, 22);
        assert!(!admissions.is_admitted(Direction::In, &flow, 0));
    }

    /// Once admitted, the same flow is reported as such — the property that
    /// makes the gate run once per flow rather than once per packet.
    #[test]
    fn admitting_a_flow_makes_it_report_as_admitted() {
        let mut admissions = SshAdmissions::new();
        let flow = tcp(THEM, 54321, US, 22);
        admissions.admit(Direction::In, &flow, 0);
        assert!(admissions.is_admitted(Direction::In, &flow, 1));
    }

    /// An admission is scoped to its own five-tuple, the same as `Flows` — a
    /// grant for one client's connection must not cover a different one.
    #[test]
    fn an_admission_covers_only_its_own_flow() {
        let mut admissions = SshAdmissions::new();
        admissions.admit(Direction::In, &tcp(THEM, 54321, US, 22), 0);
        assert!(!admissions.is_admitted(Direction::In, &tcp(THEM, 54322, US, 22), 1));
    }

    /// An admission that goes idle expires, so a policy revocation reaches a
    /// connection that has gone quiet long enough — the same window `Flows`
    /// uses, applied to the same underlying question: is this still the
    /// connection that was checked, or has enough time passed that it should
    /// be treated as new.
    #[test]
    fn an_admission_expires_when_it_goes_quiet() {
        let mut admissions = SshAdmissions::new();
        let flow = tcp(THEM, 54321, US, 22);
        admissions.admit(Direction::In, &flow, 0);
        assert!(admissions.is_admitted(Direction::In, &flow, IDLE_MS));
        assert!(!admissions.is_admitted(Direction::In, &flow, IDLE_MS * 2 + 1));
    }

    /// Ongoing traffic keeps an admission alive, or an interactive SSH session
    /// would be forced back through the gate every two minutes regardless of
    /// whether it was still carrying data.
    #[test]
    fn traffic_refreshes_an_admission() {
        let mut admissions = SshAdmissions::new();
        let flow = tcp(THEM, 54321, US, 22);
        admissions.admit(Direction::In, &flow, 0);

        let mut now = 0;
        for _ in 0..10 {
            now += IDLE_MS - 1;
            assert!(admissions.is_admitted(Direction::In, &flow, now), "cut off at {now}");
        }
    }

    /// Reconfiguration must clear admissions the same way it clears `Flows`,
    /// or a revoked "ssh" rule would leave every already-open connection
    /// permanently grandfathered in.
    #[test]
    fn clearing_revokes_every_admission() {
        let mut admissions = SshAdmissions::new();
        let flow = tcp(THEM, 54321, US, 22);
        admissions.admit(Direction::In, &flow, 0);
        admissions.clear();
        assert!(admissions.is_empty());
        assert!(!admissions.is_admitted(Direction::In, &flow, 1));
    }

    /// A packet whose ports cannot be read neither creates an admission nor
    /// matches one, the same discipline `Flows` applies to a fragment.
    #[test]
    fn an_unclassifiable_packet_does_not_create_an_admission() {
        let mut admissions = SshAdmissions::new();
        let mut fragment = tcp(THEM, 54321, US, 22);
        fragment[6] = 0x00;
        fragment[7] = 0x10; // non-zero fragment offset

        admissions.admit(Direction::In, &fragment, 0);
        assert!(admissions.is_empty(), "a fragment created an admission");
    }
}
