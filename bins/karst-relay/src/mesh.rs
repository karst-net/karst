// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Deciding when to dial a mesh peer — `ponor-v1.md` §8.
//!
//! **Sans-io.** This says which peers are due and how long to wait after a
//! failure; it opens no socket and reads no clock.
//!
//! # Only one side dials, and the id decides which
//!
//! §8 describes a mesh connection and does not say who opens it. If both ends
//! dial, both succeed, and the hub — which keys a mesh peer by its relay id —
//! replaces one with the other. Two relays doing that on a timer displace each
//! other's connection indefinitely, and every displacement drops the presence
//! state §8 says is advisory but which still has to be resent.
//!
//! So: **the relay whose id sorts lower dials; the other only listens.** It is
//! deterministic, needs no negotiation and no extra frame, and it halves the
//! connections a region carries. The cost is that a mesh peer must be
//! *reachable* by the side that sorts lower, which is why every relay in a
//! region should be configured with the whole mesh list rather than half of it
//! — the rule then decides, and the configuration is the same file everywhere.
//!
//! A relay id is a hash of an ML-DSA-65 key (§5.2), so the ordering is
//! arbitrary and stable, which is all this needs. It is not a priority.

use std::collections::HashMap;

use karst_relay_proto::consts::ID_LEN;

/// A relay's id.
pub type Id = [u8; ID_LEN];

/// First wait after a failed dial.
pub const BACKOFF_MIN_MS: u64 = 1_000;

/// Longest wait between attempts.
///
/// A mesh peer that has been down for an hour is one an operator is already
/// dealing with; retrying every thirty seconds until it returns costs nothing
/// and means the region reconverges without anybody restarting a relay.
pub const BACKOFF_MAX_MS: u64 = 30_000;

/// A peer this relay should be meshed with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// The peer's relay id, from the roster.
    pub id: Id,
    /// Where to reach it. `host:port`, resolved by the caller.
    pub addr: String,
    /// The name its certificate is issued for, when that differs from `addr`.
    ///
    /// **A relay behind a load balancer is dialled by address and presents a
    /// name**, and the two are routinely different — which is one of §4.2's
    /// own arguments for not resting relay identity on certificates. `None`
    /// means the host part of `addr`, which is the ordinary case.
    pub name: Option<String>,
    /// Which region it serves — §8.
    pub region: String,
}

impl Peer {
    /// The name to validate the certificate against.
    #[must_use]
    pub fn server_name(&self) -> &str {
        match &self.name {
            Some(n) => n,
            None => self.addr.rsplit_once(':').map_or(&self.addr, |(h, _)| h),
        }
    }
}

/// A dial the caller should attempt now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Due {
    /// Which peer.
    pub id: Id,
    /// Where.
    pub addr: String,
    /// The name to validate its certificate against.
    pub name: String,
}

#[derive(Debug, Clone, Copy)]
struct Attempt {
    /// When the next attempt may be made.
    next_ms: u64,
    /// How long to wait after the next failure.
    wait_ms: u64,
}

/// Which mesh peers to dial, and when.
#[derive(Debug)]
pub struct Dialler {
    us: Id,
    region: String,
    peers: Vec<Peer>,
    attempts: HashMap<Id, Attempt>,
}

impl Dialler {
    /// A dialler for a relay with this id.
    #[must_use]
    pub fn new(us: Id, region: String) -> Self {
        Self {
            us,
            region,
            peers: Vec::new(),
            attempts: HashMap::new(),
        }
    }

    /// Whether `us` is the side that dials `them`.
    ///
    /// See the module documentation: lower id dials, and it is arbitrary but
    /// stable, which is all the rule needs to be.
    #[must_use]
    pub fn dials(us: &Id, them: &Id) -> bool {
        us < them
    }

    /// Replace the mesh list, keeping the backoff of peers that remain.
    ///
    /// **Backoff survives a roster reload**, or a relay whose roster refreshes
    /// on a timer would retry a dead peer at full rate for ever, with the
    /// reload resetting the very state that was meant to slow it down.
    pub fn set_peers(&mut self, peers: Vec<Peer>) {
        self.attempts
            .retain(|id, _| peers.iter().any(|p| &p.id == id));
        self.peers = peers;
    }

    /// Peers this relay is responsible for dialling at all.
    #[must_use]
    pub fn responsible(&self) -> Vec<&Peer> {
        self.peers
            .iter()
            .filter(|p| p.region == self.region && Self::dials(&self.us, &p.id))
            .collect()
    }

    /// What to dial now.
    ///
    /// `connected` answers whether a mesh connection to that id already
    /// exists; it is asked rather than tracked here because the hub owns that
    /// fact and a second copy of it would be free to drift.
    pub fn due(&mut self, now_ms: u64, connected: &impl Fn(&Id) -> bool) -> Vec<Due> {
        let mut out = Vec::new();
        for peer in &self.peers {
            if peer.region != self.region {
                continue;
            }
            if !Self::dials(&self.us, &peer.id) || connected(&peer.id) {
                continue;
            }
            let attempt = self.attempts.entry(peer.id).or_insert(Attempt {
                next_ms: now_ms,
                wait_ms: BACKOFF_MIN_MS,
            });
            if now_ms < attempt.next_ms {
                continue;
            }
            // Marked as attempted here rather than in `failed`, so a dial that
            // is still in flight is not dialled again on the next tick. A
            // success clears it; a failure extends it.
            attempt.next_ms = now_ms.saturating_add(attempt.wait_ms);
            out.push(Due {
                id: peer.id,
                addr: peer.addr.clone(),
                name: peer.server_name().to_owned(),
            });
        }
        out
    }

    /// A dial succeeded; forget its backoff.
    pub fn succeeded(&mut self, id: &Id) {
        self.attempts.remove(id);
    }

    /// A dial failed; wait longer next time.
    pub fn failed(&mut self, id: &Id, now_ms: u64) {
        let attempt = self.attempts.entry(*id).or_insert(Attempt {
            next_ms: now_ms,
            wait_ms: BACKOFF_MIN_MS,
        });
        attempt.wait_ms = attempt.wait_ms.saturating_mul(2).min(BACKOFF_MAX_MS);
        attempt.next_ms = now_ms.saturating_add(attempt.wait_ms);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn id(n: u8) -> Id {
        [n; ID_LEN]
    }

    fn peer(n: u8) -> Peer {
        Peer {
            id: id(n),
            addr: format!("relay{n}.test:8443"),
            name: None,
            region: "default".to_owned(),
        }
    }

    fn never(_: &Id) -> bool {
        false
    }

    #[test]
    fn a_certificate_name_may_differ_from_the_address_dialled() {
        // A relay behind a load balancer is reached at an address and presents
        // a name. Defaulting to the host part covers the ordinary case without
        // making every deployment state it twice.
        let plain = Peer {
            id: id(1),
            addr: "10.0.0.5:8443".to_owned(),
            name: None,
            region: "default".to_owned(),
        };
        assert_eq!(plain.server_name(), "10.0.0.5");
        let behind_lb = Peer {
            id: id(1),
            addr: "10.0.0.5:8443".to_owned(),
            name: Some("relay-a.example".to_owned()),
            region: "default".to_owned(),
        };
        assert_eq!(behind_lb.server_name(), "relay-a.example");
    }

    #[test]
    fn exactly_one_side_of_a_pair_dials() {
        // The property the rule exists for. If both dial, both succeed, and the
        // hub replaces one with the other — two relays doing that on a timer
        // displace each other's connection indefinitely.
        let (a, b) = (id(1), id(2));
        assert!(Dialler::dials(&a, &b));
        assert!(!Dialler::dials(&b, &a));
        assert!(!Dialler::dials(&a, &a), "a relay must not dial itself");
    }

    #[test]
    fn a_peer_in_another_region_is_never_dialled() {
        // §8: mesh is within a region, because cross-region relay-to-relay
        // forwarding would make every relay's bandwidth spendable by every
        // other region's operator. Enforced rather than trusted to the
        // configuration, so a peer from the wrong region in the mesh list is a
        // mistake that shows up at once instead of as a slow bandwidth
        // transfer nobody attributes to it.
        //
        // It is a guard against misconfiguration, not against a hostile
        // operator — whoever writes one file writes the other.
        let mut d = Dialler::new(id(1), "eu-west".to_owned());
        let mut far = peer(2);
        far.region = "us-east".to_owned();
        let mut near = peer(3);
        near.region = "eu-west".to_owned();
        d.set_peers(vec![far, near]);

        assert_eq!(d.responsible().len(), 1, "only the same-region peer");
        let due: Vec<Id> = d.due(0, &never).into_iter().map(|x| x.id).collect();
        assert_eq!(due, vec![id(3)]);
    }

    #[test]
    fn a_relay_dials_only_the_peers_it_is_responsible_for() {
        let mut d = Dialler::new(id(5), "default".to_owned());
        d.set_peers(vec![peer(1), peer(3), peer(7), peer(9)]);
        let ids: Vec<Id> = d.responsible().into_iter().map(|p| p.id).collect();
        assert_eq!(ids, vec![id(7), id(9)], "only the higher ids");
    }

    #[test]
    fn a_peer_already_connected_is_not_dialled() {
        // The hub owns this fact. Tracking it here as well would be a second
        // copy free to drift from the first.
        let mut d = Dialler::new(id(1), "default".to_owned());
        d.set_peers(vec![peer(2), peer(3)]);
        let connected = |i: &Id| *i == id(2);
        let due: Vec<Id> = d.due(0, &connected).into_iter().map(|x| x.id).collect();
        assert_eq!(due, vec![id(3)]);
    }

    #[test]
    fn a_dial_in_flight_is_not_dialled_again_on_the_next_tick() {
        // `due` runs on a timer. Without marking the attempt as it is handed
        // out, every tick between the dial and its outcome starts another one.
        let mut d = Dialler::new(id(1), "default".to_owned());
        d.set_peers(vec![peer(2)]);
        assert_eq!(d.due(0, &never).len(), 1);
        assert!(d.due(1, &never).is_empty(), "dialled twice in one second");
        assert!(d.due(500, &never).is_empty());
    }

    #[test]
    fn a_failure_doubles_the_wait_and_a_success_clears_it() {
        let mut d = Dialler::new(id(1), "default".to_owned());
        d.set_peers(vec![peer(2)]);

        assert_eq!(d.due(0, &never).len(), 1, "the first dial is immediate");
        d.failed(&id(2), 0);
        // `failed` doubles the minimum, so the next attempt is two minima out.
        assert!(
            d.due(2 * BACKOFF_MIN_MS - 1, &never).is_empty(),
            "retried before the backoff elapsed"
        );
        assert_eq!(d.due(2 * BACKOFF_MIN_MS, &never).len(), 1);

        d.failed(&id(2), 2 * BACKOFF_MIN_MS);
        assert!(
            d.due(3 * BACKOFF_MIN_MS, &never).is_empty(),
            "the wait did not grow after a second failure"
        );

        // A success puts the peer back to immediate, which is what makes a
        // flapping peer reconnect promptly rather than inheriting the wait
        // that its last outage earned.
        d.succeeded(&id(2));
        assert_eq!(d.due(3 * BACKOFF_MIN_MS, &never).len(), 1);
    }

    #[test]
    fn backoff_never_exceeds_the_cap() {
        // Without a cap, a peer down for an hour is one this relay stops
        // trying to reach — the region then needs a restart to reconverge,
        // which is the opposite of what a mesh is for.
        let mut d = Dialler::new(id(1), "default".to_owned());
        d.set_peers(vec![peer(2)]);
        let mut now = 0;
        for _ in 0..20 {
            d.failed(&id(2), now);
            now += BACKOFF_MAX_MS;
        }
        assert_eq!(
            d.due(now + BACKOFF_MAX_MS, &never).len(),
            1,
            "backoff grew past its cap and the peer became unreachable for ever"
        );
    }

    #[test]
    fn a_roster_reload_does_not_reset_backoff() {
        // A relay refreshes its roster on a timer. If a reload cleared the
        // backoff, a dead peer would be retried at full rate for ever and the
        // reload would be undoing the state meant to slow it down.
        let mut d = Dialler::new(id(1), "default".to_owned());
        d.set_peers(vec![peer(2)]);
        let _ = d.due(0, &never);
        d.failed(&id(2), 0);
        d.set_peers(vec![peer(2), peer(3)]);
        assert!(
            d.due(100, &never).iter().all(|x| x.id != id(2)),
            "the reload reset a failing peer's backoff"
        );
    }

    #[test]
    fn a_peer_removed_from_the_roster_is_forgotten() {
        let mut d = Dialler::new(id(1), "default".to_owned());
        d.set_peers(vec![peer(2), peer(3)]);
        let _ = d.due(0, &never);
        d.failed(&id(2), 0);
        d.set_peers(vec![peer(3)]);
        assert!(d.responsible().iter().all(|p| p.id != id(2)));
        // And re-adding it starts clean rather than inheriting a stale wait.
        d.set_peers(vec![peer(2), peer(3)]);
        assert!(d.due(1, &never).iter().any(|x| x.id == id(2)));
    }
}
