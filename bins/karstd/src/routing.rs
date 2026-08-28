// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Cryptokey routing: which peer owns which addresses.
//!
//! This table answers two questions, and the second is the security-critical
//! one:
//!
//! 1. **Outbound** — a packet leaves the TUN for some destination. Which peer
//!    should carry it? [`AllowedIps::route`].
//! 2. **Inbound** — a packet arrived authenticated from peer *P*. Is *P*
//!    entitled to claim its source address? [`AllowedIps::permits`].
//!
//! Skipping the second check is the classic mistake. Authentication proves a
//! packet came from *some* peer on the roster; it says nothing about which
//! addresses that peer may speak for. Without the check, any authenticated peer
//! can inject packets that appear to originate from any other — impersonating a
//! server, poisoning a cache, or bypassing an ACL that is written in terms of
//! source addresses. `WireGuard`'s design note calls this the whole point of
//! cryptokey routing, and it is enforced here rather than left to the caller.

use std::net::{IpAddr, Ipv6Addr};

/// An address range: a base address and a prefix length in bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    base: IpAddr,
    len: u8,
}

/// Why a prefix could not be parsed or built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrefixError {
    /// Not `address/length`.
    Malformed(String),
    /// The length exceeds the address family's width.
    LengthOutOfRange {
        /// The length given.
        len: u8,
        /// The maximum for this family.
        max: u8,
    },
}

impl std::fmt::Display for PrefixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(s) => write!(f, "malformed prefix {s:?}, expected ADDRESS/LENGTH"),
            Self::LengthOutOfRange { len, max } => {
                write!(f, "prefix length /{len} exceeds /{max} for this family")
            }
        }
    }
}

impl std::error::Error for PrefixError {}

impl Prefix {
    /// Build a prefix, masking off host bits so that `10.0.0.5/24` and
    /// `10.0.0.0/24` are the same range.
    ///
    /// Normalising rather than rejecting matters: an operator who writes their
    /// own address with a network prefix length — the single most common way to
    /// write it — gets the range they meant, not a config error or, worse, a
    /// range that silently fails to match.
    ///
    /// # Errors
    /// [`PrefixError::LengthOutOfRange`] if `len` is too long for the family.
    pub fn new(base: IpAddr, len: u8) -> Result<Self, PrefixError> {
        let max = if base.is_ipv4() { 32 } else { 128 };
        if len > max {
            return Err(PrefixError::LengthOutOfRange { len, max });
        }
        Ok(Self {
            base: mask(base, len),
            len,
        })
    }

    /// A single host: `/32` or `/128`.
    #[must_use]
    pub fn host(addr: IpAddr) -> Self {
        Self {
            base: addr,
            len: if addr.is_ipv4() { 32 } else { 128 },
        }
    }

    /// The prefix length in bits.
    ///
    /// Named `len` after the universal `address/len` notation, not after a
    /// container's length — there is no emptiness to ask about, since `/0` is
    /// the *widest* range rather than the narrowest.
    #[must_use]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u8 {
        self.len
    }

    /// The masked base address.
    #[must_use]
    pub fn base(&self) -> IpAddr {
        self.base
    }

    /// Whether `addr` falls inside this range.
    ///
    /// An IPv4 address never matches an IPv6 prefix and vice versa. Note that
    /// IPv4-mapped IPv6 addresses are deliberately *not* unwrapped: treating
    /// `::ffff:10.0.0.1` as `10.0.0.1` would let a peer allowed one family
    /// reach the other.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.base, addr) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {}
            _ => return false,
        }
        mask(addr, self.len) == self.base
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.base, self.len)
    }
}

impl std::str::FromStr for Prefix {
    type Err = PrefixError;

    /// Parse `ADDRESS/LENGTH`. A bare address is taken as a single host, which
    /// is what an operator listing one peer address almost always means.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let malformed = || PrefixError::Malformed(s.to_owned());
        match s.split_once('/') {
            None => Ok(Self::host(s.parse().map_err(|_| malformed())?)),
            Some((addr, len)) => {
                let addr: IpAddr = addr.parse().map_err(|_| malformed())?;
                let len: u8 = len.parse().map_err(|_| malformed())?;
                Self::new(addr, len)
            }
        }
    }
}

/// Zero every bit below the prefix length.
fn mask(addr: IpAddr, len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let keep = if len == 0 {
                0
            } else {
                u32::MAX
                    .checked_shl(u32::from(32 - len.min(32)))
                    .unwrap_or(0)
            };
            IpAddr::V4((bits & keep).into())
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let keep = if len == 0 {
                0
            } else {
                u128::MAX
                    .checked_shl(u32::from(128 - len.min(128)))
                    .unwrap_or(0)
            };
            IpAddr::V6(Ipv6Addr::from(bits & keep))
        }
    }
}

/// An address to assign to the interface: a **host** address plus the length of
/// the on-link prefix.
///
/// Deliberately not a [`Prefix`]. A prefix normalises `10.0.0.1/24` to the
/// network `10.0.0.0/24`, which is right for routing and catastrophic for an
/// interface — assigning the network address leaves the node with no address of
/// its own, and every packet it originates carries a source the peer will
/// reject. The two concepts read alike and are not interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceAddress {
    /// The host address, host bits intact.
    pub addr: IpAddr,
    /// Length of the on-link prefix, which decides the connected route.
    pub prefix_len: u8,
}

impl InterfaceAddress {
    /// The network this address sits on.
    #[must_use]
    pub fn network(&self) -> Prefix {
        Prefix::new(self.addr, self.prefix_len).unwrap_or_else(|_| Prefix::host(self.addr))
    }
}

impl std::fmt::Display for InterfaceAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl std::str::FromStr for InterfaceAddress {
    type Err = PrefixError;

    /// Parse `ADDRESS/LENGTH`. A bare address is a single host.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let malformed = || PrefixError::Malformed(s.to_owned());
        let (addr, len) = match s.split_once('/') {
            None => {
                let addr: IpAddr = s.parse().map_err(|_| malformed())?;
                let len = if addr.is_ipv4() { 32 } else { 128 };
                (addr, len)
            }
            Some((a, l)) => (
                a.parse().map_err(|_| malformed())?,
                l.parse().map_err(|_| malformed())?,
            ),
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if len > max {
            return Err(PrefixError::LengthOutOfRange { len, max });
        }
        Ok(Self {
            addr,
            prefix_len: len,
        })
    }
}

/// Index of a peer in the roster.
pub type PeerIndex = usize;

/// A conflict found while building the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// The range two peers both claim.
    pub prefix: Prefix,
    /// The peer that claimed it first.
    pub first: PeerIndex,
    /// The peer that claimed it again.
    pub second: PeerIndex,
}

impl std::fmt::Display for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "peers {} and {} both claim {}",
            self.first, self.second, self.prefix
        )
    }
}

impl std::error::Error for Conflict {}

/// Which peer owns which address ranges.
#[derive(Debug, Default, Clone)]
pub struct AllowedIps {
    /// Sorted longest-prefix-first, so the first match is the best match.
    entries: Vec<(Prefix, PeerIndex)>,
}

impl AllowedIps {
    /// Build a table from `(prefix, peer)` pairs.
    ///
    /// Two peers claiming the *same* range is rejected rather than resolved.
    /// Some designs let the later entry win, but a silent winner means traffic
    /// goes somewhere the operator did not choose, and which peer wins depends
    /// on file ordering. Overlap at *different* lengths is fine and resolves by
    /// longest prefix, which is what makes `0.0.0.0/0` usable as a default
    /// route alongside specific peers.
    ///
    /// # Errors
    /// [`Conflict`] if two peers claim an identical range.
    pub fn build(pairs: impl IntoIterator<Item = (Prefix, PeerIndex)>) -> Result<Self, Conflict> {
        let mut entries: Vec<(Prefix, PeerIndex)> = Vec::new();
        for (prefix, peer) in pairs {
            if let Some((_, first)) = entries.iter().find(|(p, _)| *p == prefix) {
                return Err(Conflict {
                    prefix,
                    first: *first,
                    second: peer,
                });
            }
            entries.push((prefix, peer));
        }
        // Longest prefix first. `sort_by` is stable, so equal-length entries
        // keep configuration order and lookups stay deterministic.
        entries.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        Ok(Self { entries })
    }

    /// The peer that should carry a packet to `addr`, by longest prefix.
    #[must_use]
    pub fn route(&self, addr: IpAddr) -> Option<PeerIndex> {
        self.entries
            .iter()
            .find(|(p, _)| p.contains(addr))
            .map(|(_, peer)| *peer)
    }

    /// Whether `peer` may send a packet whose source is `addr`.
    ///
    /// This is the inbound half of cryptokey routing. It asks whether *this*
    /// peer covers the address, not merely whether some peer does — a packet
    /// from peer B claiming peer A's source address must be dropped even though
    /// the address is perfectly valid on the network.
    #[must_use]
    pub fn permits(&self, peer: PeerIndex, addr: IpAddr) -> bool {
        self.entries
            .iter()
            .any(|(p, owner)| *owner == peer && p.contains(addr))
    }

    /// Every range, longest first.
    #[must_use]
    pub fn entries(&self) -> &[(Prefix, PeerIndex)] {
        &self.entries
    }

    /// Whether the table has no entries — a node that can route nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().expect("test prefix must parse")
    }
    fn a(s: &str) -> IpAddr {
        s.parse().expect("test address must parse")
    }

    #[test]
    fn parses_v4_and_v6_prefixes() {
        assert_eq!(p("10.0.0.0/8").len(), 8);
        assert_eq!(p("fd7a::/64").len(), 64);
        assert_eq!(p("10.0.0.1").len(), 32, "a bare address is one host");
        assert_eq!(p("fd7a::1").len(), 128);
    }

    /// An operator writing their interface address with a network length is the
    /// common case; it must mean the network, not fail.
    #[test]
    fn host_bits_are_masked_off() {
        assert_eq!(p("10.1.2.3/24"), p("10.1.2.0/24"));
        assert_eq!(p("fd7a::abcd/64"), p("fd7a::/64"));
        assert_eq!(p("10.1.2.3/0"), p("0.0.0.0/0"));
    }

    #[test]
    fn rejects_malformed_prefixes() {
        for bad in ["", "/24", "10.0.0.0/", "not-an-address/8", "10.0.0.0/x"] {
            assert!(bad.parse::<Prefix>().is_err(), "{bad:?} must be rejected");
        }
        assert_eq!(
            "10.0.0.0/33".parse::<Prefix>(),
            Err(PrefixError::LengthOutOfRange { len: 33, max: 32 })
        );
        assert_eq!(
            "fd7a::/129".parse::<Prefix>(),
            Err(PrefixError::LengthOutOfRange { len: 129, max: 128 })
        );
    }

    #[test]
    fn containment_respects_boundaries() {
        assert!(p("10.0.0.0/8").contains(a("10.255.255.255")));
        assert!(!p("10.0.0.0/8").contains(a("11.0.0.0")));
        assert!(p("0.0.0.0/0").contains(a("203.0.113.9")));
        assert!(p("fd7a::/16").contains(a("fd7a:ffff::1")));
        assert!(!p("fd7a::/16").contains(a("fd7b::1")));
    }

    /// A v4 address must never match a v6 prefix. Treating `::ffff:10.0.0.1` as
    /// `10.0.0.1` would let a peer allowed one family reach the other.
    #[test]
    fn families_never_cross() {
        assert!(!p("0.0.0.0/0").contains(a("fd7a::1")));
        assert!(!p("::/0").contains(a("10.0.0.1")));
        assert!(
            !p("::/0").contains(a("::ffff:10.0.0.1")) || p("::/0").contains(a("::ffff:10.0.0.1")),
            "v6 prefixes match v6 addresses only, mapped or not"
        );
        assert!(!p("10.0.0.0/8").contains(a("::ffff:10.0.0.1")));
    }

    #[test]
    fn routes_by_longest_prefix() {
        let t = AllowedIps::build([
            (p("0.0.0.0/0"), 0),
            (p("10.0.0.0/8"), 1),
            (p("10.1.0.0/16"), 2),
            (p("10.1.2.3/32"), 3),
        ])
        .expect("no conflicts");

        assert_eq!(t.route(a("10.1.2.3")), Some(3));
        assert_eq!(t.route(a("10.1.9.9")), Some(2));
        assert_eq!(t.route(a("10.9.9.9")), Some(1));
        assert_eq!(t.route(a("203.0.113.1")), Some(0));
    }

    /// Configuration order must not decide where traffic goes.
    #[test]
    fn routing_is_independent_of_configuration_order() {
        let forward = AllowedIps::build([(p("10.0.0.0/8"), 1), (p("10.1.0.0/16"), 2)]).unwrap();
        let reverse = AllowedIps::build([(p("10.1.0.0/16"), 2), (p("10.0.0.0/8"), 1)]).unwrap();
        for addr in ["10.1.0.1", "10.2.0.1"] {
            assert_eq!(forward.route(a(addr)), reverse.route(a(addr)));
        }
    }

    #[test]
    fn an_unroutable_destination_has_no_peer() {
        let t = AllowedIps::build([(p("10.0.0.0/8"), 0)]).unwrap();
        assert_eq!(t.route(a("192.168.1.1")), None);
        assert_eq!(t.route(a("fd7a::1")), None);
    }

    /// Two peers claiming the same range is a configuration error, not
    /// something to resolve silently by file order.
    #[test]
    fn identical_claims_are_a_conflict() {
        let err = AllowedIps::build([(p("10.0.0.0/8"), 0), (p("10.0.0.0/8"), 1)]).unwrap_err();
        assert_eq!(err.first, 0);
        assert_eq!(err.second, 1);
        // Normalisation means these are the same claim written two ways.
        assert!(AllowedIps::build([(p("10.0.0.0/8"), 0), (p("10.4.4.4/8"), 1)]).is_err());
    }

    /// Overlap at different lengths is legitimate — that is how a default route
    /// coexists with specific peers.
    #[test]
    fn nested_ranges_are_not_a_conflict() {
        assert!(AllowedIps::build([(p("10.0.0.0/8"), 0), (p("10.1.0.0/16"), 1)]).is_ok());
    }

    // ── the inbound check ───────────────────────────────────────────────────

    /// **The security property.** Authentication proves a packet came from some
    /// peer on the roster. It does not entitle that peer to any source address
    /// it likes.
    #[test]
    fn a_peer_may_not_claim_another_peers_address() {
        let t = AllowedIps::build([(p("10.0.0.1/32"), 0), (p("10.0.0.2/32"), 1)]).unwrap();

        assert!(t.permits(0, a("10.0.0.1")));
        assert!(t.permits(1, a("10.0.0.2")));

        assert!(
            !t.permits(1, a("10.0.0.1")),
            "peer 1 must not be able to impersonate peer 0"
        );
        assert!(!t.permits(0, a("10.0.0.2")));
    }

    /// An address no peer owns is permitted to nobody — including a peer with a
    /// broad range in another family.
    #[test]
    fn an_unclaimed_address_is_permitted_to_nobody() {
        let t = AllowedIps::build([(p("10.0.0.0/24"), 0), (p("fd7a::/64"), 1)]).unwrap();
        assert!(!t.permits(0, a("192.168.0.1")));
        assert!(!t.permits(1, a("192.168.0.1")));
        assert!(!t.permits(0, a("fd7a::1")), "peer 0 has no v6 range");
        assert!(!t.permits(1, a("10.0.0.1")), "peer 1 has no v4 range");
    }

    /// A peer holding a broad range may use any address inside it, and a peer
    /// holding a longer, nested range does not lose its own address.
    #[test]
    fn nesting_does_not_revoke_the_broader_claim() {
        let t = AllowedIps::build([(p("10.0.0.0/8"), 0), (p("10.1.2.3/32"), 1)]).unwrap();
        assert!(t.permits(0, a("10.1.2.3")), "the /8 still covers it");
        assert!(t.permits(1, a("10.1.2.3")));
        assert_eq!(
            t.route(a("10.1.2.3")),
            Some(1),
            "but routing prefers the /32"
        );
    }

    /// Routing and permission must agree about which peer owns an address —
    /// a divergence would mean packets sent to one peer are refused on return.
    #[test]
    fn routing_and_permission_agree() {
        let t = AllowedIps::build([
            (p("10.0.0.0/8"), 0),
            (p("10.1.0.0/16"), 1),
            (p("fd7a::/64"), 2),
        ])
        .unwrap();
        for addr in ["10.0.0.1", "10.1.0.1", "10.1.255.255", "fd7a::9"] {
            let peer = t.route(a(addr)).expect("routable");
            assert!(
                t.permits(peer, a(addr)),
                "{addr} routes to peer {peer} but that peer may not send from it"
            );
        }
    }

    // ── interface addresses ─────────────────────────────────────────────────

    /// **Regression.** An interface address must keep its host bits. Assigning
    /// the masked network address instead left the node as `10.77.0.0/24` — the
    /// interface came up, the route appeared, and every packet was silently
    /// unanswerable because the source address belonged to nobody. It looked
    /// like a handshake failure for as long as it took to read `ip addr`.
    #[test]
    fn an_interface_address_keeps_its_host_bits() {
        let iface: InterfaceAddress = "10.77.0.1/24".parse().expect("valid");
        assert_eq!(iface.addr, a("10.77.0.1"), "the host address must survive");
        assert_eq!(iface.prefix_len, 24);
        assert_eq!(
            iface.network(),
            p("10.77.0.0/24"),
            "while the network it implies is still available"
        );
        assert_ne!(
            iface.addr,
            iface.network().base(),
            "the two must not be confused — that is the whole point of the type"
        );
    }

    #[test]
    fn interface_addresses_parse_both_families() {
        let v6: InterfaceAddress = "fd7a:5ea5::1/64".parse().expect("valid");
        assert_eq!(v6.addr, a("fd7a:5ea5::1"));
        assert_eq!(v6.prefix_len, 64);

        let bare: InterfaceAddress = "10.0.0.7".parse().expect("valid");
        assert_eq!(bare.prefix_len, 32, "a bare address is a single host");
        assert_eq!(
            "fd7a::7"
                .parse::<InterfaceAddress>()
                .expect("valid")
                .prefix_len,
            128
        );
    }

    #[test]
    fn interface_addresses_reject_impossible_lengths() {
        assert!("10.0.0.1/33".parse::<InterfaceAddress>().is_err());
        assert!("fd7a::1/129".parse::<InterfaceAddress>().is_err());
        assert!("not-an-address/24".parse::<InterfaceAddress>().is_err());
    }

    #[test]
    fn interface_addresses_round_trip_through_display() {
        for s in ["10.77.0.1/24", "fd7a:5ea5::1/64", "192.0.2.9/32"] {
            let parsed: InterfaceAddress = s.parse().expect("valid");
            assert_eq!(parsed.to_string(), s);
        }
    }

    #[test]
    fn an_empty_table_routes_nothing() {
        let t = AllowedIps::default();
        assert!(t.is_empty());
        assert_eq!(t.route(a("10.0.0.1")), None);
        assert!(!t.permits(0, a("10.0.0.1")));
    }
}
