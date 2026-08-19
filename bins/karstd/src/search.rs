// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The sockets §7.7's port search needs, and the one that wins.
//!
//! `karst_disco::search` decides *how many* sockets should exist and which
//! ports to probe. This owns the sockets themselves, because they are the part
//! §7.7 cannot express in a sans-io crate — and the part that costs a real
//! resource.
//!
//! # Why a socket per mapping
//!
//! A port-restricted symmetric NAT admits a datagram only from the exact
//! destination its mapping was created toward, so the peer's probe has to land
//! on a mapping some socket owns. One socket sending to many destination ports
//! earns many mappings toward the wrong places; **many sockets sending to the
//! one address the peer is reachable at** is what earns many mappings toward
//! the right one. That asymmetry is the whole mechanism and it is why this
//! module exists rather than a loop around `send_to`.
//!
//! # The cap is a file-descriptor budget
//!
//! `karst_disco::search::SCRATCH_MAX` bounds one peer. A node with two hundred
//! peers would still exhaust its descriptors, so [`SearchSockets`] applies a
//! **global** cap across peers as well — the per-peer cap cannot see the
//! others, which its own documentation says. Running out of descriptors would
//! take the tunnel down for every peer to chase a direct path for one, which is
//! a bad trade in any ordering.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use karst_transport::{UdpTransport, MAX_DATAGRAM};

/// The sockets the datapath must send from, published for the send path.
///
/// **Read on every direct datagram, so the empty case has to be free.** A
/// search wins rarely and for few peers, and the overwhelming majority of nodes
/// never run one at all — so the common path is a single relaxed load of
/// [`Winners::count`] and no lock. The map is only touched once that says there
/// is something in it.
#[derive(Debug, Default)]
pub struct Winners {
    count: AtomicUsize,
    map: RwLock<HashMap<SocketAddr, Arc<UdpTransport>>>,
}

impl Winners {
    /// Nothing has won.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The socket a datagram to `to` must leave from, if a search won it.
    #[must_use]
    pub fn get(&self, to: SocketAddr) -> Option<Arc<UdpTransport>> {
        if self.count.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let map = self.map.read().ok()?;
        map.get(&to).map(Arc::clone)
    }

    fn publish(&self, to: SocketAddr, sock: Arc<UdpTransport>) {
        if let Ok(mut map) = self.map.write() {
            map.insert(to, sock);
            self.count.store(map.len(), Ordering::Relaxed);
        }
    }

    fn withdraw(&self, to: SocketAddr) {
        if let Ok(mut map) = self.map.write() {
            map.remove(&to);
            self.count.store(map.len(), Ordering::Relaxed);
        }
    }
}

/// Most scratch sockets held across **all** peers at once.
///
/// Chosen against the default soft limit of 1024 descriptors: the TUN device,
/// the datapath socket, the control connection, the relay connection and the
/// log all need one, and a node should be able to lose this whole budget
/// without noticing. Four hundred is under half.
pub const GLOBAL_MAX: usize = 400;

/// A datagram that arrived on a scratch socket.
#[derive(Debug)]
pub struct Arrival {
    /// Which peer's pool it came in on.
    pub route_index: usize,
    /// Which socket within that pool — the index that
    /// [`SearchSockets::keep_only`] takes.
    pub socket: usize,
    /// The datagram.
    pub datagram: Vec<u8>,
    /// Where it came from.
    pub from: SocketAddr,
}

/// One socket that has earned a mapping, and whether it has won.
struct Pool {
    sockets: Vec<Arc<UdpTransport>>,
    /// Set once a datagram has arrived on one of them: this pool's peer talks
    /// on that socket and no other.
    winner: Option<usize>,
    /// The address the winning socket was published under, so it can be
    /// withdrawn again.
    published: Option<SocketAddr>,
}

/// Every peer's scratch sockets.
#[derive(Default)]
pub struct SearchSockets {
    pools: HashMap<usize, Pool>,
    winners: Arc<Winners>,
}

impl std::fmt::Debug for SearchSockets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchSockets")
            .field("peers", &self.pools.len())
            .field("sockets", &self.total())
            .finish_non_exhaustive()
    }
}

impl SearchSockets {
    /// Nothing open.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The published table the send path reads.
    #[must_use]
    pub fn winners(&self) -> Arc<Winners> {
        Arc::clone(&self.winners)
    }

    /// Sockets open across every peer.
    #[must_use]
    pub fn total(&self) -> usize {
        self.pools.values().map(|p| p.sockets.len()).sum()
    }

    /// Sockets open for one peer.
    #[must_use]
    pub fn len_for(&self, route_index: usize) -> usize {
        self.pools.get(&route_index).map_or(0, |p| p.sockets.len())
    }

    /// The socket this peer's traffic must now use, if one has won.
    ///
    /// **This is the datapath migration point.** Once a peer's probe has
    /// arrived on a scratch socket, that socket holds the only mapping the peer
    /// can reach; sending from the one §4 nominates would use a mapping the
    /// peer's filter has never admitted.
    #[must_use]
    pub fn winner(&self, route_index: usize) -> Option<&UdpTransport> {
        let pool = self.pools.get(&route_index)?;
        pool.sockets.get(pool.winner?).map(AsRef::as_ref)
    }

    /// Send one scratch datagram from a **new** socket, bound beside `local`.
    ///
    /// Returns `false` when a cap refused it or the socket could not be bound —
    /// both are ordinary, neither is fatal, and the search simply covers fewer
    /// ports this round.
    pub fn send_scratch(&mut self, route_index: usize, datagram: &[u8], to: SocketAddr) -> bool {
        if self.total() >= GLOBAL_MAX {
            return false;
        }
        let pool = self.pools.entry(route_index).or_insert_with(|| Pool {
            sockets: Vec::new(),
            winner: None,
            published: None,
        });
        // A pool that has already won needs no more mappings: the point of the
        // others was to find this one.
        if pool.winner.is_some() {
            return false;
        }
        if pool.sockets.len() >= karst_disco::search::SCRATCH_MAX {
            return false;
        }
        // Bound on the same address as the datapath socket, ephemeral port.
        // The address matters — a mapping earned from a different interface is
        // a mapping toward the peer from somewhere the peer was never told
        // about.
        let bind = SocketAddr::new(local_ip(to), 0);
        let Ok(sock) = UdpTransport::bind(bind) else {
            return false;
        };
        if sock.set_nonblocking(true).is_err() {
            return false;
        }
        // A send failure is per-socket and not fatal: an unreachable candidate
        // must not stop the rest of the round.
        let sent = sock.send_to(datagram, to).is_ok();
        pool.sockets.push(Arc::new(sock));
        sent
    }

    /// Take whatever has arrived on any scratch socket.
    ///
    /// Non-blocking throughout, so this can be called from the daemon's timer
    /// tick without another thread or another `poll` set. The sockets are few
    /// and idle: on the overwhelming majority of ticks every one of them
    /// returns `WouldBlock` immediately.
    pub fn drain(&mut self) -> Vec<Arrival> {
        let mut out = Vec::new();
        let mut buf = [0u8; MAX_DATAGRAM];
        for (route_index, pool) in &mut self.pools {
            for (socket, sock) in pool.sockets.iter().enumerate() {
                // One datagram per socket per tick. A scratch socket carries a
                // probe and its answer, not a stream, so draining it to
                // exhaustion would only let a flood on one socket starve the
                // others.
                if let Ok((n, from)) = sock.recv_from(&mut buf) {
                    if let Some(datagram) = buf.get(..n) {
                        out.push(Arrival {
                            route_index: *route_index,
                            socket,
                            datagram: datagram.to_vec(),
                            from,
                        });
                    }
                }
            }
        }
        out
    }

    /// Keep one socket for this peer and close the rest.
    ///
    /// Called once a datagram has arrived: the others earned mappings nobody
    /// used, and holding them open is what makes the global cap bite for peers
    /// that have not connected yet.
    pub fn keep_only(&mut self, route_index: usize, socket: usize, dest: SocketAddr) {
        let Some(pool) = self.pools.get_mut(&route_index) else {
            return;
        };
        if socket >= pool.sockets.len() {
            return;
        }
        pool.sockets.swap(0, socket);
        pool.sockets.truncate(1);
        pool.winner = Some(0);
        if let Some(sock) = pool.sockets.first() {
            if let Some(old) = pool.published.replace(dest) {
                if old != dest {
                    self.winners.withdraw(old);
                }
            }
            self.winners.publish(dest, Arc::clone(sock));
        }
    }

    /// Drop every socket for a peer.
    ///
    /// Called when a peer reaches a direct path by any other route, or goes
    /// away. **Including the winner**: if discovery has chosen a different
    /// path, this pool is holding descriptors for a path nothing is using.
    pub fn release(&mut self, route_index: usize) {
        if let Some(pool) = self.pools.remove(&route_index) {
            if let Some(dest) = pool.published {
                // Withdrawn before the socket is dropped, or the send path
                // would keep an `Arc` to a socket nothing is receiving on.
                self.winners.withdraw(dest);
            }
        }
    }

    /// Drop every socket for every peer.
    pub fn release_all(&mut self) {
        let indices: Vec<usize> = self.pools.keys().copied().collect();
        for index in indices {
            self.release(index);
        }
    }
}

/// The local address to bind a scratch socket on, for a given destination.
///
/// Unspecified rather than a chosen interface: the kernel picks the source
/// address by route, exactly as it does for the datapath socket, so a node with
/// several interfaces earns its mapping on whichever one actually reaches the
/// peer. Choosing here would mean re-implementing the routing table.
fn local_ip(to: SocketAddr) -> IpAddr {
    if to.is_ipv6() {
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
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

    fn to() -> SocketAddr {
        "127.0.0.1:9".parse().expect("addr")
    }

    #[test]
    fn each_scratch_datagram_earns_its_own_socket() {
        // The mechanism, asserted directly. Sending several from one socket
        // would earn one mapping and waste the rest, and the whole technique
        // rests on the count of distinct mappings.
        let mut s = SearchSockets::new();
        for _ in 0..5 {
            assert!(s.send_scratch(0, b"x", to()));
        }
        assert_eq!(s.len_for(0), 5);
        assert_eq!(s.total(), 5);
    }

    #[test]
    fn the_per_peer_cap_is_the_one_the_spec_names() {
        let mut s = SearchSockets::new();
        for _ in 0..karst_disco::search::SCRATCH_MAX {
            assert!(s.send_scratch(0, b"x", to()));
        }
        assert!(
            !s.send_scratch(0, b"x", to()),
            "one peer went past SCRATCH_MAX"
        );
        assert_eq!(s.len_for(0), karst_disco::search::SCRATCH_MAX);
    }

    #[test]
    fn a_global_cap_stops_many_peers_exhausting_the_descriptors() {
        // `SCRATCH_MAX` bounds one peer and says so; a node with two hundred
        // peers would still run out. Losing every descriptor to chase a direct
        // path for one peer takes the tunnel down for all of them.
        let mut s = SearchSockets::new();
        let mut opened = 0;
        for peer in 0..40 {
            for _ in 0..karst_disco::search::SCRATCH_MAX {
                if s.send_scratch(peer, b"x", to()) {
                    opened += 1;
                }
            }
        }
        assert_eq!(s.total(), GLOBAL_MAX);
        assert_eq!(opened, GLOBAL_MAX);
        assert!(
            opened < 40 * karst_disco::search::SCRATCH_MAX,
            "the loop never pressed against the global cap, so this proves \
             nothing about it"
        );
    }

    #[test]
    fn a_won_pool_stops_opening_and_keeps_one_socket() {
        let mut s = SearchSockets::new();
        for _ in 0..4 {
            assert!(s.send_scratch(0, b"x", to()));
        }
        s.keep_only(0, 2, to());
        assert_eq!(s.len_for(0), 1, "the losers should be closed");
        assert!(s.winner(0).is_some());
        assert!(
            !s.send_scratch(0, b"x", to()),
            "a pool that has won needs no more mappings"
        );
    }

    #[test]
    fn keeping_a_socket_that_does_not_exist_changes_nothing() {
        // `socket` comes from an `Arrival`, which comes from this module — but
        // an index that has since been invalidated by a `release` must not
        // panic on the pre-authentication path's timer tick.
        let mut s = SearchSockets::new();
        assert!(s.send_scratch(0, b"x", to()));
        s.keep_only(0, 99, to());
        assert_eq!(s.len_for(0), 1);
        assert!(s.winner(0).is_none(), "nothing should have been declared");
        s.keep_only(7, 0, to());
    }

    #[test]
    fn releasing_a_peer_returns_its_descriptors() {
        let mut s = SearchSockets::new();
        for peer in 0..3 {
            assert!(s.send_scratch(peer, b"x", to()));
        }
        assert_eq!(s.total(), 3);
        s.release(1);
        assert_eq!(s.total(), 2);
        assert_eq!(s.len_for(1), 0);
        assert!(s.winner(1).is_none());
        s.release_all();
        assert_eq!(s.total(), 0);
    }

    #[test]
    fn an_idle_pool_drains_to_nothing_without_blocking() {
        // The sockets are polled from the daemon's timer tick. If a read ever
        // blocked, one idle scratch socket would stop the datapath.
        let mut s = SearchSockets::new();
        for _ in 0..8 {
            assert!(s.send_scratch(0, b"x", to()));
        }
        let started = std::time::Instant::now();
        assert!(s.drain().is_empty());
        assert!(
            started.elapsed() < std::time::Duration::from_millis(200),
            "drain blocked for {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_datagram_arriving_names_the_peer_and_the_socket_it_came_in_on() {
        // The migration depends on both: the peer says whose datapath moves,
        // and the socket index says which mapping it moves to.
        let mut s = SearchSockets::new();
        let listener = UdpTransport::bind("127.0.0.1:0".parse().expect("addr")).expect("bind");
        let target = listener.local_addr().expect("addr");
        assert!(s.send_scratch(3, b"probe", target));

        // Answer whatever arrived, from the listener, to its source.
        let mut buf = [0u8; MAX_DATAGRAM];
        let (_, from) = listener.recv_from(&mut buf).expect("the probe");
        listener.send_to(b"answer", from).expect("answer");

        let mut arrivals = Vec::new();
        for _ in 0..50 {
            arrivals = s.drain();
            if !arrivals.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let first = arrivals.first().expect("the answer should arrive");
        assert_eq!(first.route_index, 3);
        assert_eq!(first.socket, 0);
        assert_eq!(first.datagram, b"answer");
        assert_eq!(first.from, target);
    }
}
