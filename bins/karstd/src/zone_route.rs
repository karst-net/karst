// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! DNS-zone-scoped gateway affinity — ADR-0068.
//!
//! `routing::AllowedIps` answers "which peer owns this destination?" as a
//! pure, static function of an authenticated, conflict-free prefix set — by
//! design, two peers can never claim the same range (`AllowedIps::build`'s
//! own doc comment explains why a silent winner there is the wrong answer).
//! That is exactly right for an ordinary subnet or exit route, and exactly
//! wrong for a legacy network reachable through more than one Gateway
//! candidate whose address ranges are allowed to collide — two independent
//! legacy sites reusing the same RFC 1918 block behind two different
//! Gateways, say. Destination address alone cannot disambiguate those; only
//! the DNS zone a client actually asked about can.
//!
//! This module is the parallel, zone-keyed answer to that question, kept
//! deliberately separate from `AllowedIps` rather than folded into it:
//!
//! - [`ZoneRoutes`] is the authenticated, static half — built the same way
//!   `AllowedIps` is, from the current effective route offers, and just as
//!   intolerant of two Gateways claiming the same zone. A zone-scoped
//!   offer's `prefix` is carried here as an authorization *bound*, never
//!   inserted into `AllowedIps::build`'s own pairs — doing that would
//!   reintroduce the exact same-range conflict `AllowedIps` exists to
//!   reject, for ranges that are allowed to collide by construction.
//! - [`DnsAffinityCache`] is the runtime, learned half: when `karst-dns`
//!   answers a query that matched a bound zone, and the answer's address
//!   actually falls inside that zone's authorized bound, the resulting
//!   `(address -> Gateway)` pin is recorded here, bounded by the answer's
//!   own TTL. `Engine::outbound` consults it before falling through to
//!   `AllowedIps::route` (engine.rs).
//!
//! An address that was never resolved through a bound zone is simply
//! unrouted by this mechanism — not a fallback to `AllowedIps`'s own longest-
//! prefix match over the same (by design, overlapping) range, which would
//! silently reintroduce the ambiguity this module exists to remove. A
//! resolved address outside its zone's authorized bound is never pinned at
//! all: trusting an unbounded answer would let a compromised or merely
//! misconfigured resolver behind one legacy network redirect traffic to an
//! address another zone — or no zone — was ever authorized to serve.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::routing::{PeerIndex, Prefix};

/// A conflict found while building the table — the zone analog of
/// `routing::Conflict`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneConflict {
    /// The zone two peers both claim.
    pub zone: String,
    /// The peer that claimed it first.
    pub first: PeerIndex,
    /// The peer that claimed it again.
    pub second: PeerIndex,
}

impl std::fmt::Display for ZoneConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "peers {} and {} both claim dns_zone {:?}",
            self.first, self.second, self.zone
        )
    }
}

impl std::error::Error for ZoneConflict {}

/// One authenticated zone binding: the Gateway it resolves to, and the
/// address range a resolved answer must fall inside to be trusted.
#[derive(Debug, Clone, Copy)]
struct ZoneEntry {
    peer: PeerIndex,
    bound: Prefix,
}

/// Longest-suffix DNS-zone routing table, authenticated and conflict-checked
/// the same way `routing::AllowedIps` is. See the module doc for why this is
/// a separate table rather than more entries in that one.
#[derive(Debug, Default, Clone)]
pub struct ZoneRoutes {
    /// Sorted longest-zone-first (more labels first), so the first match is
    /// the most specific match — the same reasoning `split::RoutingTable`
    /// already documents for `KarstDNS`'s own suffix routing.
    entries: Vec<(String, ZoneEntry)>,
}

impl ZoneRoutes {
    /// Build a table from `(zone, peer, bound)` triples. `zone` must already
    /// be canonical (lower-case, no trailing dot) — `route_offer::Offer`'s
    /// `dns_zone` is validated into that form before it ever reaches here.
    ///
    /// # Errors
    /// [`ZoneConflict`] if two peers claim the identical zone. Unlike
    /// `AllowedIps::build`, two *different* zones are never a conflict even
    /// when their `bound`s are identical or overlapping — that collision is
    /// exactly what this table exists to allow.
    pub fn build(
        triples: impl IntoIterator<Item = (String, PeerIndex, Prefix)>,
    ) -> Result<Self, ZoneConflict> {
        let mut entries: Vec<(String, ZoneEntry)> = Vec::new();
        for (zone, peer, bound) in triples {
            if let Some((_, first)) = entries.iter().find(|(z, _)| *z == zone) {
                return Err(ZoneConflict {
                    zone,
                    first: first.peer,
                    second: peer,
                });
            }
            entries.push((zone, ZoneEntry { peer, bound }));
        }
        // Most labels first (dotted-segment count, then length as a
        // tiebreak for equal segment counts with different label lengths),
        // so `db.internal.example` is tried before `internal.example`.
        entries.sort_by(|(a, _), (b, _)| {
            b.matches('.')
                .count()
                .cmp(&a.matches('.').count())
                .then_with(|| b.len().cmp(&a.len()))
        });
        Ok(Self { entries })
    }

    /// The Gateway and authorized bound for `name`, by longest matching
    /// zone suffix. `name` should already be in canonical form (as
    /// `karst_dns::canonical_name` produces).
    fn matching(&self, name: &str) -> Option<&ZoneEntry> {
        self.entries
            .iter()
            .find(|(zone, _)| name == zone || name.ends_with(&format!(".{zone}")))
            .map(|(_, entry)| entry)
    }

    /// The Gateway `name` resolves to, and whether `addr` actually falls
    /// inside that zone's authorized bound. `None` either means no zone
    /// binding matched `name`, or `addr` fell outside the bound — the two
    /// are deliberately not distinguished to the caller, which must treat
    /// both as "do not pin" (see the module doc's last paragraph).
    #[must_use]
    pub fn resolve(&self, name: &str, addr: IpAddr) -> Option<PeerIndex> {
        let entry = self.matching(name)?;
        entry.bound.contains(addr).then_some(entry.peer)
    }

    /// Whether any zone binding exists at all — lets `karst-dns`'s wiring
    /// skip the per-answer bookkeeping entirely on the common case of a
    /// node with no legacy-network affinity configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The longest a learned pin is trusted for, regardless of the DNS answer's
/// own TTL. Bounds how long a destination keeps routing to a Gateway after
/// the control plane withdraws its zone binding or changes which Gateway
/// serves it — the netmap refresh that rebuilds `ZoneRoutes` takes effect on
/// `resolve` immediately, but the cache in [`DnsAffinityCache`] is this
/// module's own separately-timed state, so it needs an independent ceiling
/// rather than trusting an operator's upstream resolver to set a sane TTL.
const MAX_PIN: Duration = Duration::from_secs(3600);

/// A pinned destination can outlive at most this many entries before the
/// oldest is evicted on insert — a legacy network's resolved address set is
/// expected to be small and mostly stable, so this is a generous ceiling
/// against unbounded growth, not a cache meant to run full in practice.
const MAX_ENTRIES: usize = 4096;

/// Runtime, learned half of DNS-zone affinity: addresses a bound zone's
/// resolver has actually answered with, each pinned to the Gateway its zone
/// resolved to. See the module doc for how this is populated and consulted.
#[derive(Debug, Default)]
pub struct DnsAffinityCache {
    pins: Mutex<HashMap<IpAddr, (PeerIndex, Instant)>>,
}

impl DnsAffinityCache {
    /// Pin `addr` to `peer` for `ttl`, clamped to [`MAX_PIN`].
    pub fn pin(&self, addr: IpAddr, peer: PeerIndex, ttl: Duration) {
        let expires = Instant::now() + ttl.min(MAX_PIN);
        let mut pins = self
            .pins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pins.len() >= MAX_ENTRIES && !pins.contains_key(&addr) {
            if let Some(&oldest) = pins
                .iter()
                .min_by_key(|(_, (_, expires))| *expires)
                .map(|(addr, _)| addr)
            {
                pins.remove(&oldest);
            }
        }
        pins.insert(addr, (peer, expires));
    }

    /// The Gateway `addr` is currently pinned to, if any and not expired.
    /// Lazily evicts the entry on an expired hit, so a cache that is never
    /// pinned to again still bounds its own memory.
    #[must_use]
    pub fn lookup(&self, addr: IpAddr) -> Option<PeerIndex> {
        let mut pins = self
            .pins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match pins.get(&addr) {
            Some(&(peer, expires)) if expires > Instant::now() => Some(peer),
            Some(_) => {
                pins.remove(&addr);
                None
            }
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::net::Ipv4Addr;

    fn p(s: &str) -> Prefix {
        s.parse().expect("test prefix")
    }
    fn a(s: &str) -> IpAddr {
        s.parse().expect("test address")
    }

    #[test]
    fn longest_zone_suffix_wins() {
        let table = ZoneRoutes::build([
            ("internal.example".to_owned(), 0, p("10.0.0.0/8")),
            ("db.internal.example".to_owned(), 1, p("10.0.0.0/8")),
        ])
        .expect("no conflicts");
        assert_eq!(
            table.resolve("api.db.internal.example", a("10.0.0.5")),
            Some(1)
        );
        assert_eq!(
            table.resolve("web.internal.example", a("10.0.0.5")),
            Some(0)
        );
    }

    #[test]
    fn two_zones_may_share_an_identical_bound() {
        // The entire point of this table: ordinary `AllowedIps::build` would
        // hard-reject two peers claiming `10.0.0.0/8`. Two different zones
        // claiming it here must not conflict.
        let table = ZoneRoutes::build([
            ("site-a.legacy".to_owned(), 0, p("10.0.0.0/8")),
            ("site-b.legacy".to_owned(), 1, p("10.0.0.0/8")),
        ])
        .expect("overlapping bounds across zones are not a conflict");
        assert_eq!(table.resolve("host.site-a.legacy", a("10.0.0.5")), Some(0));
        assert_eq!(table.resolve("host.site-b.legacy", a("10.0.0.5")), Some(1));
    }

    #[test]
    fn the_same_zone_claimed_twice_is_a_conflict() {
        let err = ZoneRoutes::build([
            ("legacy.example".to_owned(), 0, p("10.0.0.0/8")),
            ("legacy.example".to_owned(), 1, p("10.0.0.0/8")),
        ])
        .unwrap_err();
        assert_eq!(err.zone, "legacy.example");
        assert_eq!(err.first, 0);
        assert_eq!(err.second, 1);
    }

    #[test]
    fn an_answer_outside_its_zones_bound_is_never_resolved() {
        let table = ZoneRoutes::build([("legacy.example".to_owned(), 0, p("10.0.0.0/8"))]).unwrap();
        assert_eq!(
            table.resolve("host.legacy.example", a("203.0.113.9")),
            None,
            "an address outside the authorized bound must not resolve, even \
             though the zone itself matched"
        );
    }

    #[test]
    fn an_unbound_name_resolves_to_nothing() {
        let table = ZoneRoutes::build([]).unwrap();
        assert!(table.is_empty());
        assert_eq!(table.resolve("anything.example", a("10.0.0.1")), None);
    }

    #[test]
    fn a_pin_is_returned_until_it_expires() {
        let cache = DnsAffinityCache::default();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(cache.lookup(addr), None);
        cache.pin(addr, 2, Duration::from_secs(60));
        assert_eq!(cache.lookup(addr), Some(2));
        cache.pin(addr, 2, Duration::from_millis(0));
        // A zero-TTL pin is already expired by the time `lookup` checks it.
        assert_eq!(cache.lookup(addr), None);
    }

    #[test]
    fn a_long_ttl_is_clamped_to_the_pin_ceiling() {
        let cache = DnsAffinityCache::default();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
        cache.pin(addr, 3, Duration::from_secs(u64::from(u32::MAX)));
        // Still present now; the real assertion here is only that `pin`
        // does not panic or overflow on an absurd TTL — `Instant` arithmetic
        // saturates rather than wraps, but clamping keeps it meaningful.
        assert_eq!(cache.lookup(addr), Some(3));
    }
}
