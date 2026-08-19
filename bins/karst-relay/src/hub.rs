// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The forwarding core — `spec/ponor-v1.md` §7.2, §7.3, §7.5, §7.6 and §8.
//!
//! Sans-io, like the protocol crates below it. The hub owns the connection
//! registry, the presence table and the per-destination write queues; it does
//! not own a socket, a clock or a task. Frames go in with a timestamp, bytes
//! come out of [`Hub::take_outbound`].
//!
//! The queues live here rather than in the I/O layer on purpose. §7.3 makes
//! the queue discipline a **correctness** requirement — bounded, drop-oldest,
//! never applying backpressure to the source — and a rule that is a property
//! of the code that touches sockets is a rule nobody can unit-test.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use karst_relay_proto::consts::ID_LEN;
use karst_relay_proto::{Admitted, AquiferId, Frame, Reason, Roster};

use crate::limits::{Budget, Meter};

/// A 32-byte node or relay identifier.
pub type Id = [u8; ID_LEN];

/// The I/O layer's handle for a connection. Opaque to the hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnId(pub u64);

/// Why a frame did not reach a destination.
///
/// Every one of these is a **drop**, never a close: §7.4 forbids ending a
/// connection over a burst, and the rest are ordinary consequences of a
/// distributed presence table that is eventually consistent by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dropped {
    /// Over the peer's rate budget — §7.4.
    RateLimited,
    /// The destination is not in the roster, or not in this aquifer — §5.4.
    NotAdmitted,
    /// Nobody here or on the mesh holds the destination.
    NotHere,
    /// A peer addressed itself.
    SelfAddressed,
    /// The destination's write queue was full — §7.3.
    QueueFull,
}

/// A frame that is legal on the wire but not on this connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubError {
    /// §8: a relay MUST NOT accept `SendPacket` on a mesh connection, nor
    /// `Forward` on a client one. Also covers relay→peer frames arriving from
    /// a peer, which is either a bug or a probe.
    IllegalForRole,
    /// The connection is not registered. A caller bug, not a peer's.
    UnknownConn,
}

/// Per-connection accounting for the operator — §7.4.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnStats {
    /// Frames accepted from the peer.
    pub frames_in: u64,
    /// Bytes accepted from the peer, frame headers included.
    pub bytes_in: u64,
    /// Frames queued towards the peer.
    pub frames_out: u64,
    /// Bytes queued towards the peer.
    pub bytes_out: u64,
    /// Frames refused by the rate limiter.
    pub dropped_rate: u64,
    /// Frames discarded because this peer's write queue was full.
    pub dropped_queue: u64,
    /// Frames from this peer that could not be delivered.
    pub undeliverable: u64,
}

/// How the hub is configured.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Rate allowance for a node.
    pub client_budget: Budget,
    /// Rate allowance for a meshed relay, which carries many nodes' traffic
    /// and so cannot share a node's budget.
    pub mesh_budget: Budget,
    /// Per-destination write queue depth — §7.3.
    pub queue_depth: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            client_budget: Budget::default(),
            mesh_budget: Budget::unlimited(),
            queue_depth: karst_relay_proto::consts::WRITE_QUEUE_DEPTH,
        }
    }
}

#[derive(Debug)]
struct Conn {
    peer: Admitted,
    queue: VecDeque<Vec<u8>>,
    meter: Meter,
    close_after_flush: Option<Reason>,
    stats: ConnStats,
}

impl Conn {
    fn node_id(&self) -> Option<Id> {
        match self.peer {
            Admitted::Client { node_id, .. } => Some(node_id),
            Admitted::Mesh { .. } => None,
        }
    }
    fn relay_id(&self) -> Option<Id> {
        match self.peer {
            Admitted::Mesh { relay_id } => Some(relay_id),
            Admitted::Client { .. } => None,
        }
    }
    fn aquifer(&self) -> Option<&AquiferId> {
        match &self.peer {
            Admitted::Client { aquifer, .. } => Some(aquifer),
            Admitted::Mesh { .. } => None,
        }
    }
}

/// The relay's connection registry and forwarding engine.
///
/// `BTreeMap` rather than `HashMap` for the connection table: fan-out to mesh
/// peers then happens in a deterministic order, which makes a test that
/// asserts on gossip reproducible instead of flaky.
#[derive(Debug)]
pub struct Hub {
    cfg: Config,
    conns: BTreeMap<ConnId, Conn>,
    by_node: HashMap<Id, ConnId>,
    by_mesh: HashMap<Id, ConnId>,
    /// Which meshed relay holds a node that is not connected here — §8.
    ///
    /// Advisory. A relay MUST tolerate a `Forward` for a node that has just
    /// left, and MUST NOT treat presence disagreement as an error: the state
    /// is eventually consistent by construction and anything stricter would
    /// fail on every client roam.
    presence: HashMap<Id, Id>,
    /// Connections whose queue has grown since the caller last asked.
    ///
    /// The hub is pull-based, so an I/O layer needs to know *which* sockets to
    /// wake. Waking every connection after every frame would make a relay's
    /// cost quadratic in its client count; this keeps it proportional to the
    /// work actually done.
    dirty: BTreeSet<ConnId>,
}

impl Hub {
    /// An empty hub.
    #[must_use]
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            conns: BTreeMap::new(),
            by_node: HashMap::new(),
            by_mesh: HashMap::new(),
            presence: HashMap::new(),
            dirty: BTreeSet::new(),
        }
    }

    /// Connections with something new to write, cleared by the call.
    pub fn take_dirty(&mut self) -> Vec<ConnId> {
        core::mem::take(&mut self.dirty).into_iter().collect()
    }

    /// Register a connection whose handshake has completed.
    ///
    /// Returns the connection this one **replaced**, if any. §7.6: newest
    /// wins, and the caller must close the returned connection with
    /// [`Reason::Replaced`]. Refusing the new connection instead would
    /// black-hole a node whose old TCP connection is a half-open zombie the
    /// relay has not timed out — the common case after a suspend or a mobile
    /// handover. It is safe because it requires the peer's identity key.
    pub fn admit(&mut self, id: ConnId, peer: Admitted, now_ms: u64) -> Option<ConnId> {
        let (budget, replaced, announce) = match &peer {
            Admitted::Client { node_id, .. } => {
                let prev = self.by_node.insert(*node_id, id);
                // Only announce presence the mesh does not already have. A
                // replacement is not an arrival: the node never left.
                (self.cfg.client_budget, prev, prev.is_none())
            }
            Admitted::Mesh { relay_id } => {
                let prev = self.by_mesh.insert(*relay_id, id);
                (self.cfg.mesh_budget, prev, false)
            }
        };

        let is_mesh = matches!(peer, Admitted::Mesh { .. });
        self.conns.insert(
            id,
            Conn {
                peer,
                queue: VecDeque::new(),
                meter: Meter::new(budget, now_ms),
                close_after_flush: None,
                stats: ConnStats::default(),
            },
        );

        if announce {
            if let Some(node_id) = self.conns.get(&id).and_then(Conn::node_id) {
                self.gossip(&Frame::PeerPresent { node_id }, None);
            }
        }
        if is_mesh {
            // §8: on establishment each side sends PeerPresent for every
            // client it currently holds. Bounded by the connected count.
            let locals: Vec<Id> = self.by_node.keys().copied().collect();
            for node_id in locals {
                self.enqueue(id, &Frame::PeerPresent { node_id });
            }
        }

        // A replacement of *this same* id is not a replacement of a live
        // connection when the previous entry is the one we just wrote.
        replaced.filter(|prev| *prev != id)
    }

    /// Handle one inbound frame.
    ///
    /// # Errors
    /// [`HubError::IllegalForRole`] for a frame this connection may not send —
    /// the caller must close, per §10. [`HubError::UnknownConn`] is a caller
    /// bug.
    pub fn on_frame(
        &mut self,
        id: ConnId,
        frame: &Frame<'_>,
        roster: &impl Roster,
        now_ms: u64,
    ) -> Result<Option<Dropped>, HubError> {
        let len = frame.encoded_len() as u64;
        let conn = self.conns.get_mut(&id).ok_or(HubError::UnknownConn)?;

        // Charged before anything is done with the frame, and charged on every
        // frame rather than only on SendPacket: a Ping flood is cheap in bytes
        // and is still work.
        if !conn.meter.admit(len, now_ms) {
            conn.stats.dropped_rate += 1;
            return Ok(Some(Dropped::RateLimited));
        }
        conn.stats.frames_in += 1;
        conn.stats.bytes_in += len;

        let is_mesh = conn.relay_id().is_some();
        match (*frame, is_mesh) {
            // ── Either role ───────────────────────────────────────────────
            (Frame::Ping(token), _) => {
                // §7.5: ahead of queued RecvPacket frames. A keepalive stuck
                // behind a full queue is a keepalive that misses its deadline
                // and takes the connection down with it.
                self.enqueue_priority(id, &Frame::Pong(token));
                Ok(None)
            }
            // The peer's own RTT accounting. Nothing for the relay to do.
            (Frame::Pong(_), _) => Ok(None),
            (Frame::Close(_), _) => {
                self.begin_close(id, None);
                Ok(None)
            }

            // ── Client only ───────────────────────────────────────────────
            (Frame::SendPacket { dst_id, payload }, false) => {
                Ok(self.forward_from_client(id, dst_id, payload, roster))
            }

            // ── Mesh only ─────────────────────────────────────────────────
            (
                Frame::Forward {
                    src_id,
                    dst_id,
                    payload,
                },
                true,
            ) => Ok(self.deliver_from_mesh(id, src_id, dst_id, payload, roster)),
            (Frame::PeerPresent { node_id }, true) => {
                if let Some(relay_id) = self.conns.get(&id).and_then(Conn::relay_id) {
                    self.presence.insert(node_id, relay_id);
                }
                Ok(None)
            }
            (Frame::PeerGone { peer_id, .. }, true) => {
                // Only the relay that claimed a node may retract it.
                let owner = self.conns.get(&id).and_then(Conn::relay_id);
                if self.presence.get(&peer_id).copied() == owner {
                    self.presence.remove(&peer_id);
                }
                Ok(None)
            }

            // Everything else is either a relay→peer frame arriving from a
            // peer, or a frame for the other role. §8's role separation is
            // enforced here and nowhere else.
            _ => Err(HubError::IllegalForRole),
        }
    }

    /// §7.2. The relay stamps the connection's authenticated id as the source;
    /// `SendPacket` has no source field, so there is nothing to spoof.
    fn forward_from_client(
        &mut self,
        from: ConnId,
        dst_id: Id,
        payload: &[u8],
        roster: &impl Roster,
    ) -> Option<Dropped> {
        let conn = self.conns.get(&from)?;
        let (Some(src_id), Some(src_aquifer)) = (conn.node_id(), conn.aquifer().cloned()) else {
            return None;
        };

        if dst_id == src_id {
            self.count_undeliverable(from);
            return Some(Dropped::SelfAddressed);
        }

        // §5.4. "Unknown" and "in another aquifer" deliberately produce the
        // same outcome and the same NOT_ADMITTED code: distinguishing them
        // would tell one tenant whether an id exists in another, which is a
        // cross-customer membership oracle on a shared relay.
        let admitted = roster
            .client(&dst_id)
            .is_some_and(|e| e.aquifer == src_aquifer);
        if !admitted {
            self.reply(
                from,
                &Frame::PeerGone {
                    peer_id: dst_id,
                    reason: Reason::NotAdmitted,
                },
            );
            self.count_undeliverable(from);
            return Some(Dropped::NotAdmitted);
        }

        if let Some(&to) = self.by_node.get(&dst_id) {
            return self.deliver(from, to, &Frame::RecvPacket { src_id, payload });
        }

        if let Some(to) = self
            .presence
            .get(&dst_id)
            .and_then(|relay| self.by_mesh.get(relay))
            .copied()
        {
            return self.deliver(
                from,
                to,
                &Frame::Forward {
                    src_id,
                    dst_id,
                    payload,
                },
            );
        }

        self.reply(
            from,
            &Frame::PeerGone {
                peer_id: dst_id,
                reason: Reason::NotHere,
            },
        );
        self.count_undeliverable(from);
        Some(Dropped::NotHere)
    }

    /// §8. **One hop.** A `Forward` is delivered locally or not at all; it is
    /// never forwarded onward, so a mesh loop is not expressible rather than
    /// merely bounded.
    fn deliver_from_mesh(
        &mut self,
        from: ConnId,
        src_id: Id,
        dst_id: Id,
        payload: &[u8],
        roster: &impl Roster,
    ) -> Option<Dropped> {
        let Some(&to) = self.by_node.get(&dst_id) else {
            // Our presence claim reached them and the node has since left.
            // Correcting the sender's table is the whole reason this is not a
            // silent drop.
            self.reply(
                from,
                &Frame::PeerGone {
                    peer_id: dst_id,
                    reason: Reason::Disconnected,
                },
            );
            self.count_undeliverable(from);
            return Some(Dropped::NotHere);
        };

        // The originating relay already checked §5.4, and we check it again
        // against our own roster. A meshed relay is other infrastructure, not
        // an oracle we have to believe: re-checking here is what stops a
        // compromised mesh peer from injecting cross-aquifer traffic, and it
        // costs one lookup we were going to do anyway.
        let same_aquifer = match (roster.client(&src_id), roster.client(&dst_id)) {
            (Some(s), Some(d)) => s.aquifer == d.aquifer,
            _ => false,
        };
        if !same_aquifer {
            self.count_undeliverable(from);
            return Some(Dropped::NotAdmitted);
        }

        self.deliver(from, to, &Frame::RecvPacket { src_id, payload })
    }

    fn deliver(&mut self, from: ConnId, to: ConnId, frame: &Frame<'_>) -> Option<Dropped> {
        if self.enqueue(to, frame) {
            None
        } else {
            self.count_undeliverable(from);
            Some(Dropped::QueueFull)
        }
    }

    /// Queue a frame towards `to`, dropping the **oldest** on overflow.
    ///
    /// Returns whether it went in without displacing anything.
    ///
    /// §7.3, and the two halves are separate requirements. *Bounded* is what
    /// stops a slow destination from being a memory-exhaustion vector.
    /// *Never blocking* is what stops it from being everyone else's problem:
    /// a relay that lets one slow peer apply backpressure to a source's read
    /// loop has made every other peer of that source hostage to the slowest.
    ///
    /// Dropping the head rather than the tail keeps the queue's contents
    /// fresh — everything in it is either a handshake retransmission or a
    /// datagram whose usefulness decays.
    fn enqueue(&mut self, to: ConnId, frame: &Frame<'_>) -> bool {
        let depth = self.cfg.queue_depth;
        let Some(conn) = self.conns.get_mut(&to) else {
            return false;
        };
        let bytes = frame.encoded_len() as u64;
        let mut clean = true;
        while conn.queue.len() >= depth {
            conn.queue.pop_front();
            conn.stats.dropped_queue += 1;
            clean = false;
        }
        conn.queue.push_back(frame.to_vec());
        conn.stats.frames_out += 1;
        conn.stats.bytes_out += bytes;
        self.dirty.insert(to);
        clean
    }

    /// Queue at the head, past whatever is waiting.
    ///
    /// Only for `Pong` (§7.5). Anything else jumping the queue would reorder
    /// a peer's datagrams for no reason.
    fn enqueue_priority(&mut self, to: ConnId, frame: &Frame<'_>) {
        let depth = self.cfg.queue_depth;
        let Some(conn) = self.conns.get_mut(&to) else {
            return;
        };
        let bytes = frame.encoded_len() as u64;
        while conn.queue.len() >= depth {
            conn.queue.pop_front();
            conn.stats.dropped_queue += 1;
        }
        conn.queue.push_front(frame.to_vec());
        conn.stats.frames_out += 1;
        conn.stats.bytes_out += bytes;
        self.dirty.insert(to);
    }

    fn reply(&mut self, to: ConnId, frame: &Frame<'_>) {
        self.enqueue(to, frame);
    }

    fn count_undeliverable(&mut self, id: ConnId) {
        if let Some(conn) = self.conns.get_mut(&id) {
            conn.stats.undeliverable += 1;
        }
    }

    fn gossip(&mut self, frame: &Frame<'_>, except: Option<ConnId>) {
        let peers: Vec<ConnId> = self
            .by_mesh
            .values()
            .copied()
            .filter(|c| Some(*c) != except)
            .collect();
        for peer in peers {
            self.enqueue(peer, frame);
        }
    }

    /// Ask the relay to shut this connection down once its queue has drained.
    pub fn begin_close(&mut self, id: ConnId, reason: Option<Reason>) {
        if let Some(conn) = self.conns.get_mut(&id) {
            if let Some(r) = reason {
                conn.queue.push_back(Frame::Close(r).to_vec());
            }
            conn.close_after_flush = Some(reason.unwrap_or(Reason::Disconnected));
            self.dirty.insert(id);
        }
    }

    /// Forget a connection and correct the tables that referred to it.
    ///
    /// Returns the client whose mapping this actually released, which is
    /// `None` for a mesh peer and for a connection that had already been
    /// replaced. The caller needs that distinction to retire the same node's
    /// reflect key (`ponor-v1.md` §7.7) without retiring its *successor's* —
    /// and deriving it from `Admitted` at the call site would be a second copy
    /// of the ownership rule below, free to drift from it.
    pub fn disconnect(&mut self, id: ConnId) -> Option<[u8; ID_LEN]> {
        let conn = self.conns.remove(&id)?;
        let mut released = None;

        if let Some(node_id) = conn.node_id() {
            // Only if this connection is still the one that owns the id: a
            // replaced connection closing later must not retract the mapping
            // its successor now holds, nor announce a departure that did not
            // happen.
            if self.by_node.get(&node_id) == Some(&id) {
                self.by_node.remove(&node_id);
                released = Some(node_id);
                self.gossip(
                    &Frame::PeerGone {
                        peer_id: node_id,
                        reason: Reason::Disconnected,
                    },
                    None,
                );
            }
        }

        if let Some(relay_id) = conn.relay_id() {
            if self.by_mesh.get(&relay_id) == Some(&id) {
                self.by_mesh.remove(&relay_id);
                // Every presence claim this peer made goes with it. Leaving
                // them would send Forwards into a connection that no longer
                // exists, for as long as the process runs.
                self.presence.retain(|_, owner| *owner != relay_id);
            }
        }
        released
    }

    /// The next frame to write to `id`, if any.
    pub fn take_outbound(&mut self, id: ConnId) -> Option<Vec<u8>> {
        self.conns.get_mut(&id)?.queue.pop_front()
    }

    /// Whether the caller should close `id` once its queue has drained.
    #[must_use]
    pub fn close_reason(&self, id: ConnId) -> Option<Reason> {
        self.conns.get(&id)?.close_after_flush
    }

    /// Frames waiting to be written to `id`.
    #[must_use]
    pub fn pending(&self, id: ConnId) -> usize {
        self.conns.get(&id).map_or(0, |c| c.queue.len())
    }

    /// Accounting for the operator — §7.4.
    #[must_use]
    pub fn stats(&self, id: ConnId) -> Option<ConnStats> {
        self.conns.get(&id).map(|c| c.stats)
    }

    /// Nodes connected directly to this relay.
    #[must_use]
    pub fn local_clients(&self) -> usize {
        self.by_node.len()
    }

    /// Meshed relays currently connected.
    #[must_use]
    pub fn mesh_peers(&self) -> usize {
        self.by_mesh.len()
    }

    /// Nodes reachable through a meshed relay rather than directly.
    #[must_use]
    pub fn remote_clients(&self) -> usize {
        self.presence.len()
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
    use karst_relay_proto::{RelayEntry, RosterEntry};

    struct TestRoster {
        aquifers: HashMap<Id, &'static str>,
    }

    impl TestRoster {
        fn new() -> Self {
            Self {
                aquifers: HashMap::new(),
            }
        }
        fn with(mut self, id: Id, aquifer: &'static str) -> Self {
            self.aquifers.insert(id, aquifer);
            self
        }
    }

    impl Roster for TestRoster {
        fn client(&self, node_id: &Id) -> Option<RosterEntry> {
            self.aquifers.get(node_id).map(|t| RosterEntry {
                identity_pk: vec![0; 1952],
                aquifer: AquiferId((*t).to_owned()),
            })
        }
        fn mesh_peer(&self, _: &Id) -> Option<RelayEntry> {
            None
        }
        fn decoy_key(&self) -> &[u8] {
            &[]
        }
    }

    fn id(b: u8) -> Id {
        [b; ID_LEN]
    }

    fn client(node: u8, aquifer: &str) -> Admitted {
        Admitted::Client {
            node_id: id(node),
            aquifer: AquiferId(aquifer.to_owned()),
        }
    }

    fn mesh(relay: u8) -> Admitted {
        Admitted::Mesh {
            relay_id: id(relay),
        }
    }

    /// Decode everything queued for a connection.
    fn drain(hub: &mut Hub, conn: ConnId) -> Vec<Frame<'static>> {
        let mut out = Vec::new();
        while let Some(bytes) = hub.take_outbound(conn) {
            let (f, _) = karst_relay_proto::frame::decode(&bytes)
                .expect("relay emitted an undecodable frame")
                .expect("relay emitted a truncated frame");
            // Re-encode into an owned frame so the borrow of `bytes` ends.
            out.push(match f {
                Frame::RecvPacket { src_id, payload } => Frame::RecvPacket {
                    src_id,
                    payload: Box::leak(payload.to_vec().into_boxed_slice()),
                },
                Frame::Forward {
                    src_id,
                    dst_id,
                    payload,
                } => Frame::Forward {
                    src_id,
                    dst_id,
                    payload: Box::leak(payload.to_vec().into_boxed_slice()),
                },
                Frame::Ping(t) | Frame::Pong(t) => Frame::Pong(Box::leak(Box::new(*t))),
                Frame::PeerGone { peer_id, reason } => Frame::PeerGone { peer_id, reason },
                Frame::PeerPresent { node_id } => Frame::PeerPresent { node_id },
                Frame::Close(r) => Frame::Close(r),
                other => panic!("unexpected frame {other:?}"),
            });
        }
        out
    }

    const A: ConnId = ConnId(1);
    const B: ConnId = ConnId(2);
    const M: ConnId = ConnId(3);

    fn two_clients() -> (Hub, TestRoster) {
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        hub.admit(B, client(0xb2, "t1"), 0);
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xb2), "t1");
        (hub, roster)
    }

    #[test]
    fn a_packet_reaches_a_local_peer_with_the_source_stamped() {
        let (mut hub, roster) = two_clients();
        let payload = [7u8; 100];
        let dropped = hub
            .on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal frame");
        assert_eq!(dropped, None);

        let got = drain(&mut hub, B);
        assert_eq!(got.len(), 1);
        match got[0] {
            Frame::RecvPacket { src_id, payload: p } => {
                // The source is the connection's authenticated id, not
                // anything the sender supplied — SendPacket has no source
                // field precisely so there is nothing to spoof.
                assert_eq!(src_id, id(0xa1));
                assert_eq!(p, &[7u8; 100]);
            }
            ref other => panic!("expected RecvPacket, got {other:?}"),
        }
    }

    #[test]
    fn an_unrostered_destination_is_not_admitted() {
        let (mut hub, _) = two_clients();
        let roster = TestRoster::new().with(id(0xa1), "t1"); // B absent
        let payload = [1u8; 10];
        let dropped = hub
            .on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal frame");
        assert_eq!(dropped, Some(Dropped::NotAdmitted));
        assert!(drain(&mut hub, B).is_empty());
        assert_eq!(
            drain(&mut hub, A),
            vec![Frame::PeerGone {
                peer_id: id(0xb2),
                reason: Reason::NotAdmitted
            }]
        );
    }

    #[test]
    fn a_relay_does_not_forward_between_aquifers() {
        // §5.4. Without this a multi-tenant relay is a general-purpose message
        // bus between any two keys it has ever been told about.
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        hub.admit(B, client(0xb2, "t2"), 0);
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xb2), "t2");

        let payload = [1u8; 10];
        let dropped = hub
            .on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal frame");
        assert_eq!(dropped, Some(Dropped::NotAdmitted));
        assert!(drain(&mut hub, B).is_empty());
    }

    #[test]
    fn a_cross_aquifer_destination_is_indistinguishable_from_an_unknown_one() {
        // Both must yield NOT_ADMITTED. Telling them apart would let one
        // tenant probe whether an id exists in another, on a shared relay.
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        let payload = [1u8; 10];

        let other_aquifer = TestRoster::new().with(id(0xa1), "t1").with(id(0xff), "t2");
        hub.on_frame(
            A,
            &Frame::SendPacket {
                dst_id: id(0xff),
                payload: &payload,
            },
            &other_aquifer,
            0,
        )
        .expect("legal");
        let cross = drain(&mut hub, A);

        let unknown = TestRoster::new().with(id(0xa1), "t1");
        hub.on_frame(
            A,
            &Frame::SendPacket {
                dst_id: id(0xff),
                payload: &payload,
            },
            &unknown,
            0,
        )
        .expect("legal");
        let absent = drain(&mut hub, A);

        assert_eq!(cross, absent);
    }

    #[test]
    fn an_offline_peer_produces_not_here() {
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xb2), "t1");
        let payload = [1u8; 10];

        let dropped = hub
            .on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal frame");
        assert_eq!(dropped, Some(Dropped::NotHere));
        assert_eq!(
            drain(&mut hub, A),
            vec![Frame::PeerGone {
                peer_id: id(0xb2),
                reason: Reason::NotHere
            }]
        );
    }

    #[test]
    fn a_node_cannot_relay_to_itself() {
        let (mut hub, roster) = two_clients();
        let payload = [1u8; 10];
        let dropped = hub
            .on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xa1),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal frame");
        assert_eq!(dropped, Some(Dropped::SelfAddressed));
        assert!(drain(&mut hub, A).is_empty(), "no echo, no reflection");
    }

    // ── Roles ──────────────────────────────────────────────────────────────

    #[test]
    fn a_mesh_peer_may_not_send_a_packet() {
        // §8: SendPacket on a mesh connection is illegal. This is what the
        // role binding in the handshake (spec §5.5) protects.
        let mut hub = Hub::new(Config::default());
        hub.admit(M, mesh(0x0e), 0);
        let roster = TestRoster::new();
        let payload = [1u8; 10];
        assert_eq!(
            hub.on_frame(
                M,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload
                },
                &roster,
                0
            ),
            Err(HubError::IllegalForRole)
        );
    }

    #[test]
    fn a_client_may_not_forward() {
        let (mut hub, roster) = two_clients();
        let payload = [1u8; 10];
        assert_eq!(
            hub.on_frame(
                A,
                &Frame::Forward {
                    src_id: id(0xff),
                    dst_id: id(0xb2),
                    payload: &payload
                },
                &roster,
                0
            ),
            Err(HubError::IllegalForRole)
        );
    }

    #[test]
    fn a_client_may_not_announce_presence() {
        let (mut hub, roster) = two_clients();
        assert_eq!(
            hub.on_frame(A, &Frame::PeerPresent { node_id: id(0xff) }, &roster, 0),
            Err(HubError::IllegalForRole)
        );
    }

    #[test]
    fn a_peer_may_not_send_a_relay_to_peer_frame() {
        let (mut hub, roster) = two_clients();
        let payload = [1u8; 10];
        for f in [
            Frame::RecvPacket {
                src_id: id(1),
                payload: &payload,
            },
            Frame::RelayHello {
                relay_id: id(1),
                relay_random: id(2),
            },
            Frame::Restarting {
                reconnect_in_ms: 1,
                try_for_ms: 2,
            },
        ] {
            assert_eq!(
                hub.on_frame(A, &f, &roster, 0),
                Err(HubError::IllegalForRole),
                "{f:?} should be illegal from a client"
            );
        }
    }

    // ── Mesh ───────────────────────────────────────────────────────────────

    #[test]
    fn a_new_client_is_announced_to_the_mesh() {
        let mut hub = Hub::new(Config::default());
        hub.admit(M, mesh(0x0e), 0);
        let _ = drain(&mut hub, M);
        hub.admit(A, client(0xa1, "t1"), 0);
        assert_eq!(
            drain(&mut hub, M),
            vec![Frame::PeerPresent { node_id: id(0xa1) }]
        );
    }

    #[test]
    fn a_new_mesh_peer_learns_every_local_client() {
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        hub.admit(B, client(0xb2, "t1"), 0);
        hub.admit(M, mesh(0x0e), 0);
        let got = drain(&mut hub, M);
        assert_eq!(got.len(), 2);
        assert!(got.contains(&Frame::PeerPresent { node_id: id(0xa1) }));
        assert!(got.contains(&Frame::PeerPresent { node_id: id(0xb2) }));
    }

    #[test]
    fn a_packet_for_a_remote_peer_goes_to_the_mesh_peer_holding_it() {
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        hub.admit(M, mesh(0x0e), 0);
        let _ = drain(&mut hub, M);
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xb2), "t1");

        hub.on_frame(M, &Frame::PeerPresent { node_id: id(0xb2) }, &roster, 0)
            .expect("legal");
        assert_eq!(hub.remote_clients(), 1);

        let payload = [3u8; 20];
        let dropped = hub
            .on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal");
        assert_eq!(dropped, None);
        assert_eq!(
            drain(&mut hub, M),
            vec![Frame::Forward {
                src_id: id(0xa1),
                dst_id: id(0xb2),
                payload: &[3u8; 20]
            }]
        );
    }

    #[test]
    fn a_forward_is_never_forwarded_onward() {
        // §8's one-hop rule, enforced by frame type: a Forward arriving from a
        // mesh peer is delivered locally or dropped. Two meshed relays and a
        // destination neither of them holds must not produce a loop.
        let mut hub = Hub::new(Config::default());
        hub.admit(M, mesh(0x0e), 0);
        hub.admit(ConnId(4), mesh(0x0f), 0);
        let _ = drain(&mut hub, M);
        let _ = drain(&mut hub, ConnId(4));
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xb2), "t1");

        // The other mesh peer claims the destination.
        hub.on_frame(
            ConnId(4),
            &Frame::PeerPresent { node_id: id(0xb2) },
            &roster,
            0,
        )
        .expect("legal");
        let _ = drain(&mut hub, ConnId(4));

        let payload = [1u8; 10];
        let dropped = hub
            .on_frame(
                M,
                &Frame::Forward {
                    src_id: id(0xa1),
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal");

        assert_eq!(dropped, Some(Dropped::NotHere));
        assert!(
            drain(&mut hub, ConnId(4)).is_empty(),
            "a Forward was relayed onward — mesh loop"
        );
        // And the sender's stale presence entry is corrected.
        assert_eq!(
            drain(&mut hub, M),
            vec![Frame::PeerGone {
                peer_id: id(0xb2),
                reason: Reason::Disconnected
            }]
        );
    }

    #[test]
    fn a_mesh_peer_cannot_inject_cross_aquifer_traffic() {
        // The originating relay checks §5.4, and so do we. A meshed relay is
        // other infrastructure, not an oracle we have to believe.
        let mut hub = Hub::new(Config::default());
        hub.admit(B, client(0xb2, "t1"), 0);
        hub.admit(M, mesh(0x0e), 0);
        let _ = drain(&mut hub, M);
        let roster = TestRoster::new().with(id(0xb2), "t1").with(id(0xc3), "t2");

        let payload = [1u8; 10];
        let dropped = hub
            .on_frame(
                M,
                &Frame::Forward {
                    src_id: id(0xc3),
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal");
        assert_eq!(dropped, Some(Dropped::NotAdmitted));
        assert!(drain(&mut hub, B).is_empty());
    }

    #[test]
    fn only_the_claiming_relay_may_retract_a_presence_entry() {
        let mut hub = Hub::new(Config::default());
        hub.admit(M, mesh(0x0e), 0);
        hub.admit(ConnId(4), mesh(0x0f), 0);
        let roster = TestRoster::new();

        hub.on_frame(M, &Frame::PeerPresent { node_id: id(0xb2) }, &roster, 0)
            .expect("legal");
        assert_eq!(hub.remote_clients(), 1);

        // The other relay says the node is gone. It never claimed it.
        hub.on_frame(
            ConnId(4),
            &Frame::PeerGone {
                peer_id: id(0xb2),
                reason: Reason::Disconnected,
            },
            &roster,
            0,
        )
        .expect("legal");
        assert_eq!(hub.remote_clients(), 1, "a third party retracted a claim");

        hub.on_frame(
            M,
            &Frame::PeerGone {
                peer_id: id(0xb2),
                reason: Reason::Disconnected,
            },
            &roster,
            0,
        )
        .expect("legal");
        assert_eq!(hub.remote_clients(), 0);
    }

    #[test]
    fn losing_a_mesh_peer_drops_the_presence_it_claimed() {
        // Otherwise Forwards go into a connection that no longer exists, for
        // as long as the process runs.
        let mut hub = Hub::new(Config::default());
        hub.admit(M, mesh(0x0e), 0);
        let roster = TestRoster::new();
        hub.on_frame(M, &Frame::PeerPresent { node_id: id(0xb2) }, &roster, 0)
            .expect("legal");
        assert_eq!(hub.remote_clients(), 1);

        hub.disconnect(M);
        assert_eq!(hub.remote_clients(), 0);
        assert_eq!(hub.mesh_peers(), 0);
    }

    #[test]
    fn a_departing_client_is_announced_to_the_mesh() {
        let mut hub = Hub::new(Config::default());
        hub.admit(M, mesh(0x0e), 0);
        hub.admit(A, client(0xa1, "t1"), 0);
        let _ = drain(&mut hub, M);

        hub.disconnect(A);
        assert_eq!(
            drain(&mut hub, M),
            vec![Frame::PeerGone {
                peer_id: id(0xa1),
                reason: Reason::Disconnected
            }]
        );
    }

    // ── Replacement — §7.6 ────────────────────────────────────────────────

    #[test]
    fn a_reconnecting_node_replaces_its_old_connection() {
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        let replaced = hub.admit(B, client(0xa1, "t1"), 0);
        assert_eq!(replaced, Some(A));
        assert_eq!(hub.local_clients(), 1);

        // Traffic goes to the new connection.
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xc3), "t1");
        hub.admit(ConnId(9), client(0xc3, "t1"), 0);
        let payload = [1u8; 10];
        hub.on_frame(
            ConnId(9),
            &Frame::SendPacket {
                dst_id: id(0xa1),
                payload: &payload,
            },
            &roster,
            0,
        )
        .expect("legal");
        assert_eq!(hub.pending(B), 1);
        assert_eq!(hub.pending(A), 0);
    }

    #[test]
    fn closing_a_replaced_connection_does_not_evict_its_successor() {
        // The subtle one. The old connection is closed *after* the new one is
        // admitted, and its teardown must not remove the mapping the new one
        // now owns, nor announce a departure that did not happen.
        let mut hub = Hub::new(Config::default());
        hub.admit(M, mesh(0x0e), 0);
        hub.admit(A, client(0xa1, "t1"), 0);
        let _ = drain(&mut hub, M);
        hub.admit(B, client(0xa1, "t1"), 0);

        hub.disconnect(A);

        assert_eq!(hub.local_clients(), 1, "successor was evicted");
        assert!(
            drain(&mut hub, M).is_empty(),
            "announced a departure that did not happen"
        );
    }

    #[test]
    fn a_replacement_is_not_announced_as_an_arrival() {
        let mut hub = Hub::new(Config::default());
        hub.admit(M, mesh(0x0e), 0);
        hub.admit(A, client(0xa1, "t1"), 0);
        let _ = drain(&mut hub, M);

        hub.admit(B, client(0xa1, "t1"), 0);
        assert!(
            drain(&mut hub, M).is_empty(),
            "the node never left, so it never arrived"
        );
    }

    // ── Queueing — §7.3 ───────────────────────────────────────────────────

    #[test]
    fn a_full_queue_drops_the_oldest_and_never_blocks() {
        let cfg = Config {
            queue_depth: 4,
            client_budget: Budget::unlimited(),
            ..Config::default()
        };
        let mut hub = Hub::new(cfg);
        hub.admit(A, client(0xa1, "t1"), 0);
        hub.admit(B, client(0xb2, "t1"), 0);
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xb2), "t1");

        // B never reads. A keeps sending, and must never be told to stop.
        for n in 0u8..10 {
            let payload = [n; 8];
            let dropped = hub
                .on_frame(
                    A,
                    &Frame::SendPacket {
                        dst_id: id(0xb2),
                        payload: &payload,
                    },
                    &roster,
                    0,
                )
                .expect("legal");
            // The sender learns the queue was full, and is not stopped by it.
            assert!(dropped.is_none() || dropped == Some(Dropped::QueueFull));
        }

        assert_eq!(hub.pending(B), 4, "queue exceeded its bound");
        let got = drain(&mut hub, B);
        // Drop-oldest: what survives is the newest four.
        let last: Vec<u8> = got
            .iter()
            .map(|f| match f {
                Frame::RecvPacket { payload, .. } => payload[0],
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(last, vec![6, 7, 8, 9]);

        let stats = hub.stats(B).expect("B exists");
        assert_eq!(stats.dropped_queue, 6);
    }

    #[test]
    fn a_pong_jumps_the_queue() {
        // §7.5: ahead of queued RecvPacket frames. A keepalive stuck behind a
        // backlog is a keepalive that misses its deadline.
        let cfg = Config {
            queue_depth: 8,
            client_budget: Budget::unlimited(),
            ..Config::default()
        };
        let mut hub = Hub::new(cfg);
        hub.admit(A, client(0xa1, "t1"), 0);
        hub.admit(B, client(0xb2, "t1"), 0);
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xb2), "t1");

        for n in 0u8..4 {
            let payload = [n; 8];
            hub.on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal");
        }
        let token = [9u8; 8];
        hub.on_frame(B, &Frame::Ping(&token), &roster, 0)
            .expect("legal");

        let got = drain(&mut hub, B);
        assert_eq!(got.first(), Some(&Frame::Pong(&[9u8; 8])));
        assert_eq!(got.len(), 5);
    }

    // ── Rate limiting — §7.4 ──────────────────────────────────────────────

    #[test]
    fn an_over_budget_peer_is_dropped_not_disconnected() {
        // §7.4 forbids closing for a burst: a burst is what a relayed
        // handshake looks like.
        let cfg = Config {
            client_budget: Budget {
                bytes_per_sec: 1,
                byte_burst: 1,
                frames_per_sec: 1,
                frame_burst: 1,
            },
            ..Config::default()
        };
        let mut hub = Hub::new(cfg);
        hub.admit(A, client(0xa1, "t1"), 0);
        hub.admit(B, client(0xb2, "t1"), 0);
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xb2), "t1");

        let payload = [1u8; 100];
        let r = hub
            .on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("a rate-limited frame is still a legal frame");
        assert_eq!(r, Some(Dropped::RateLimited));
        assert!(drain(&mut hub, B).is_empty());
        assert_eq!(hub.stats(A).expect("A").dropped_rate, 1);
        assert!(hub.close_reason(A).is_none(), "closed over a burst");
    }

    #[test]
    fn accounting_survives_a_round_trip() {
        let (mut hub, roster) = two_clients();
        let payload = [1u8; 100];
        hub.on_frame(
            A,
            &Frame::SendPacket {
                dst_id: id(0xb2),
                payload: &payload,
            },
            &roster,
            0,
        )
        .expect("legal");

        let a = hub.stats(A).expect("A");
        let b = hub.stats(B).expect("B");
        assert_eq!(a.frames_in, 1);
        assert_eq!(a.bytes_in, 4 + 32 + 100);
        assert_eq!(a.frames_out, 0);
        assert_eq!(b.frames_out, 1);
        assert_eq!(b.bytes_out, 4 + 32 + 100);
        assert_eq!(b.frames_in, 0);
    }

    #[test]
    fn an_unknown_connection_is_a_caller_bug() {
        let (mut hub, roster) = two_clients();
        let token = [0u8; 8];
        assert_eq!(
            hub.on_frame(ConnId(999), &Frame::Ping(&token), &roster, 0),
            Err(HubError::UnknownConn)
        );
    }

    #[test]
    fn a_close_from_the_peer_ends_the_connection() {
        let (mut hub, roster) = two_clients();
        hub.on_frame(A, &Frame::Close(Reason::ShuttingDown), &roster, 0)
            .expect("legal");
        assert!(hub.close_reason(A).is_some());
        // And nothing is echoed: there is no reason to tell a peer that is
        // leaving why it is leaving.
        assert!(drain(&mut hub, A).is_empty());
    }
}
