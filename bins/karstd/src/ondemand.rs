// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The connections `ponor-v1.md` §9.1's second rule opens, and when they end.
//!
//! > To reach a peer, a client uses, in order: […] 2. An on-demand connection
//! > to the peer's published home relay. On-demand connections SHOULD be closed
//! > after a period with no traffic; the home connection is never closed while
//! > the node runs.
//!
//! Sans-io, like `home.rs` beside it: this decides *whether* a relay needs
//! dialling and *when* a connection has outlived its traffic, and `run.rs` does
//! the dialling. Keeping the decision here is what makes it testable at all —
//! the alternative is a test that has to open TLS connections to observe a
//! timer.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A Ponor relay id.
pub type RelayId = [u8; karst_relay_proto::consts::ID_LEN];

/// A handle on a connection the pool is holding open.
pub trait Channel {
    /// Whether whatever serves this connection is still running.
    ///
    /// A worker that has given up — the relay went away and its backoff ran
    /// out — leaves a handle nothing reads. Without this the pool would keep
    /// handing datagrams to it, and a relay that had come back would never be
    /// dialled again.
    fn live(&self) -> bool;
}

impl<T> Channel for tokio::sync::mpsc::Sender<T> {
    fn live(&self) -> bool {
        !self.is_closed()
    }
}

/// One relay's connection and the clock that decides its lifetime.
#[derive(Debug)]
struct Open<T> {
    channel: T,
    /// Engine milliseconds at the last traffic **in either direction**.
    ///
    /// Shared with whatever is reading the connection, because only it sees the
    /// inbound half. Counting sends alone would close a connection carrying an
    /// inbound stream — the far peer is on this relay and reaches us here for
    /// as long as we hold it.
    last: Arc<AtomicU64>,
}

/// The set of relays this node is holding open for §9.1's second rule.
#[derive(Debug)]
pub struct Pool<T> {
    open: HashMap<RelayId, Open<T>>,
    idle_after_ms: u64,
}

impl<T: Channel> Pool<T> {
    /// A pool that closes a connection after `idle_after_ms` without traffic.
    #[must_use]
    pub fn new(idle_after_ms: u64) -> Self {
        Self {
            open: HashMap::new(),
            idle_after_ms,
        }
    }

    /// The connection for `relay`, or `None` when one must be dialled.
    ///
    /// Counts the traffic as it goes: a caller asking for a connection is a
    /// caller about to use it, and the two must not be separate steps — a
    /// missed update is a connection closed under live traffic.
    pub fn route(&mut self, relay: RelayId, now_ms: u64) -> Option<&T> {
        let entry = self.open.get(&relay).filter(|open| open.channel.live())?;
        entry.last.store(now_ms, Ordering::Relaxed);
        Some(&entry.channel)
    }

    /// Hold a newly dialled connection, replacing any dead one for that relay.
    ///
    /// `last` is shared with the reader so that inbound traffic counts too.
    pub fn insert(&mut self, relay: RelayId, channel: T, last: Arc<AtomicU64>) {
        self.open.insert(relay, Open { channel, last });
    }

    /// Let go of one relay's connection, if it is held.
    ///
    /// **A node must never hold two Ponor connections to one relay.** A relay
    /// keys its clients by node id (§5.3) and a second connection for the same
    /// id replaces the first, so two connections from one node do not coexist —
    /// they take turns, and every message in flight on the loser is lost. The
    /// case that produces it is ordinary: a relay measured as an alternative
    /// and then adopted as the home relay, which is `home.rs`'s whole purpose.
    pub fn close(&mut self, relay: RelayId) -> bool {
        self.open.remove(&relay).is_some()
    }

    /// Drop every connection nothing has crossed for the idle period, and every
    /// one whose worker has stopped.
    ///
    /// Dropping the handle is what closes the connection: the far end of the
    /// queue ends, and the worker stops rather than reconnecting.
    pub fn expire(&mut self, now_ms: u64) -> usize {
        let before = self.open.len();
        let idle_after = self.idle_after_ms;
        self.open.retain(|_, open| {
            open.channel.live()
                && now_ms.saturating_sub(open.last.load(Ordering::Relaxed)) < idle_after
        });
        before - self.open.len()
    }

    /// How many connections are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.open.len()
    }

    /// Whether the pool is holding nothing — the steady state of a node whose
    /// peers are all on its own relay.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// A stand-in for a connection's queue, whose liveness a test can change.
    struct Fake(std::cell::Cell<bool>);

    impl Channel for Fake {
        fn live(&self) -> bool {
            self.0.get()
        }
    }

    fn live() -> Fake {
        Fake(std::cell::Cell::new(true))
    }

    fn relay(tag: u8) -> RelayId {
        [tag; karst_relay_proto::consts::ID_LEN]
    }

    fn pool() -> Pool<Fake> {
        Pool::new(1_000)
    }

    /// The dial happens once. A pool that answered "dial" every time would open
    /// a TLS and ML-DSA-65 handshake per datagram, which is worse than not
    /// having the second rule at all.
    #[test]
    fn a_relay_is_dialled_once_and_then_reused() {
        let mut pool = pool();
        assert!(pool.route(relay(1), 0).is_none(), "nothing is open yet");
        pool.insert(relay(1), live(), Arc::new(AtomicU64::new(0)));
        assert!(pool.route(relay(1), 10).is_some());
        assert!(pool.route(relay(1), 20).is_some());
        assert_eq!(pool.len(), 1);
    }

    /// Two peers on two relays are two connections, not one that keeps being
    /// re-pointed.
    #[test]
    fn each_relay_is_its_own_connection() {
        let mut pool = pool();
        pool.insert(relay(1), live(), Arc::new(AtomicU64::new(0)));
        pool.insert(relay(2), live(), Arc::new(AtomicU64::new(0)));
        assert!(pool.route(relay(1), 5).is_some());
        assert!(pool.route(relay(2), 5).is_some());
        assert_eq!(pool.len(), 2);
    }

    /// §9.1's "closed after a period with no traffic".
    #[test]
    fn a_connection_nothing_crosses_is_closed() {
        let mut pool = pool();
        pool.insert(relay(1), live(), Arc::new(AtomicU64::new(0)));
        assert_eq!(pool.expire(999), 0, "the idle period has not elapsed");
        assert_eq!(pool.expire(1_000), 1);
        assert!(
            pool.route(relay(1), 1_000).is_none(),
            "a closed connection must be dialled again, not reused"
        );
    }

    /// **Sending keeps it open**, which is the part the caller controls.
    #[test]
    fn traffic_this_node_sends_keeps_a_connection_open() {
        let mut pool = pool();
        pool.insert(relay(1), live(), Arc::new(AtomicU64::new(0)));
        for now in [500, 1_000, 1_500, 2_000] {
            assert!(pool.route(relay(1), now).is_some());
            assert_eq!(pool.expire(now), 0, "traffic crossed it at {now}");
        }
    }

    /// **Traffic arriving keeps it open too**, and that is the half a pool
    /// counting only its own sends would get wrong: the peer this connection
    /// was opened for reaches this node on it, so an inbound stream with no
    /// reply would have its path closed underneath it every idle period.
    #[test]
    fn traffic_arriving_keeps_a_connection_open() {
        let mut pool = pool();
        let last = Arc::new(AtomicU64::new(0));
        pool.insert(relay(1), live(), Arc::clone(&last));
        // The reader saw a datagram. Nothing was sent.
        last.store(900, Ordering::Relaxed);
        assert_eq!(pool.expire(1_500), 0, "an inbound-only flow was cut");
        last.store(1_600, Ordering::Relaxed);
        assert_eq!(pool.expire(2_000), 0);
        assert_eq!(
            pool.expire(2_700),
            1,
            "and it still ends when it goes quiet"
        );
    }

    /// A worker that has stopped leaves a handle nothing reads. Routing to it
    /// would drop every datagram to that peer for as long as the entry lived.
    #[test]
    fn a_connection_whose_worker_stopped_is_not_used() {
        let mut pool = pool();
        let dead = Fake(std::cell::Cell::new(false));
        pool.insert(relay(1), dead, Arc::new(AtomicU64::new(0)));
        assert!(
            pool.route(relay(1), 10).is_none(),
            "a dead connection was handed out"
        );
        assert_eq!(pool.expire(10), 1, "and it is not kept");
        assert!(pool.is_empty());
    }
}
