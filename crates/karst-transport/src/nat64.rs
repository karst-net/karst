// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! NAT64 address synthesis — RFC 6052's embedding, and RFC 7050's discovery.
//!
//! # Why this is in the transport crate
//!
//! A node on an IPv6-only network behind a NAT64 translator has no IPv4 route
//! and cannot send an IPv4 packet. Every address Karst hands it is nonetheless
//! an IPv4 literal: the control server from its own configuration, the relay
//! from the netmap, the peer from a call-me-maybe. The prefix is what turns
//! those into addresses it can reach — `prefix::v4` is the IPv6 address the
//! translator converts back to `v4` on the way out, and converts *to* on the
//! way back.
//!
//! That makes it the same category of fact as [`crate::canonical`]: a purely
//! local encoding of an IPv4 address, which everything above the socket must
//! never see. `::ffff:a.b.c.d` is the kernel's spelling and `prefix::a.b.c.d`
//! is the network's, and the daemon is entitled to know neither. So the
//! translation happens at the socket boundary, in both directions, and the
//! engine goes on comparing plain IPv4 addresses — which matters more than it
//! sounds, because a node that let a synthesised address escape into
//! `Pong.observed` would be advertising an address meaningful only inside its
//! own network (GitHub issue [#50](https://github.com/karst-net/karst/issues/50) is the same mistake in its other spelling).
//!
//! # What is not here
//!
//! **RFC 8781's PREF64 router-advertisement option**, which is the other way to
//! learn a prefix and the better one — it needs no DNS and no DNS64. It needs a
//! raw `ICMPv6` socket to read router advertisements, so it needs `CAP_NET_RAW`
//! in a daemon that otherwise wants only `CAP_NET_ADMIN`, and that trade is not
//! made here.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

/// The prefix lengths RFC 6052 §2.2 defines. Nothing else is a NAT64 prefix.
///
/// **Refusing the rest is the point.** A /96 assumption applied to a /64 prefix
/// does not fail — it synthesises a well-formed address for the wrong host, and
/// the only symptom is that nothing answers.
const LEGAL: [u8; 6] = [32, 40, 48, 56, 64, 96];

/// RFC 8781's PREF64 router-advertisement option — IANA ND option type 38.
const PREF64_OPTION: u8 = 38;

/// The IPv4 address RFC 7050 §3 reserves for prefix discovery. `ipv4only.arpa`
/// has exactly this A record and no AAAA of its own, so any AAAA a resolver
/// returns for it was synthesised — and the prefix is what is left when this is
/// taken back out.
pub const WKA: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 170);
/// The second reserved address. A resolver may return either or both, and RFC
/// 7050 §3 requires a client to accept an answer built from this one.
pub const WKA2: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 171);

/// An IPv6 prefix that a NAT64 translator maps onto the IPv4 internet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nat64Prefix {
    /// The prefix bits, with everything past `len` zeroed.
    base: [u8; 16],
    len: u8,
}

/// Why a prefix was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrefixError {
    /// A length RFC 6052 §2.2 does not define.
    Length(u8),
    /// Bits set beyond the prefix length, so the value is not a prefix.
    NotAPrefix,
    /// The text is not `<ipv6>/<len>`.
    Syntax,
}

impl fmt::Display for PrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length(n) => write!(
                f,
                "{n} is not a NAT64 prefix length — RFC 6052 §2.2 defines \
                 32, 40, 48, 56, 64 and 96, and assuming one of those for a \
                 prefix of any other length synthesises a valid address for \
                 the wrong host"
            ),
            Self::NotAPrefix => f.write_str("bits are set beyond the prefix length"),
            Self::Syntax => f.write_str("expected an IPv6 prefix in the form 64:ff9b::/96"),
        }
    }
}

impl std::error::Error for PrefixError {}

impl Nat64Prefix {
    /// The well-known prefix, RFC 6052 §2.1.
    ///
    /// **Only usable with global IPv4 addresses** — §3.1 forbids pairing it
    /// with private space, because a translator cannot know whose 10.0.0.0/8 is
    /// meant. Networks that translate to private destinations must use a
    /// network-specific prefix.
    #[must_use]
    pub fn well_known() -> Self {
        Self {
            base: [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            len: 96,
        }
    }

    /// Build a prefix from an address and a length.
    ///
    /// # Errors
    /// [`PrefixError::Length`] for a length RFC 6052 does not define, and
    /// [`PrefixError::NotAPrefix`] if any bit past the length is set.
    pub fn new(addr: Ipv6Addr, len: u8) -> Result<Self, PrefixError> {
        if !LEGAL.contains(&len) {
            return Err(PrefixError::Length(len));
        }
        let base = addr.octets();
        // The host part must be empty. A caller that passes a whole synthesised
        // address by mistake gets told, rather than getting a prefix whose low
        // bits silently corrupt every address built from it.
        let bits = usize::from(len);
        for (i, byte) in base.iter().enumerate() {
            let keep = bits.saturating_sub(i * 8).min(8);
            let mask = if keep >= 8 { 0u8 } else { 0xFFu8 >> keep };
            if byte & mask != 0 {
                return Err(PrefixError::NotAPrefix);
            }
        }
        Ok(Self { base, len })
    }

    /// The prefix length, in bits.
    ///
    /// Named `bits` rather than `len` because it is not a count of anything:
    /// a prefix has no elements, and `len`/`is_empty` would invite both.
    #[must_use]
    pub const fn bits(&self) -> u8 {
        self.len
    }

    /// Embed an IPv4 address in this prefix — RFC 6052 §2.2.
    ///
    /// The layout is not a simple concatenation for any length below 96: bits
    /// 64..72 are reserved and **must be zero**, so an address straddling them
    /// is split around the gap.
    #[must_use]
    pub fn synthesise(&self, v4: Ipv4Addr) -> Ipv6Addr {
        let mut out = self.base;
        let v4 = v4.octets();
        // Where each of the four IPv4 octets lands, per §2.2's diagram. Byte 8
        // is skipped in every layout that reaches past it, which is what the
        // gaps in these sequences are.
        for (src, dst) in v4.iter().zip(self.slots()) {
            if let Some(cell) = out.get_mut(dst) {
                *cell = *src;
            }
        }
        Ipv6Addr::from(out)
    }

    /// Recover the IPv4 address embedded in `addr`, if it is within this prefix.
    ///
    /// `None` for a genuine IPv6 address, which is the case that matters: a
    /// peer that really is on IPv6 must be left alone.
    #[must_use]
    pub fn extract(&self, addr: Ipv6Addr) -> Option<Ipv4Addr> {
        let octets = addr.octets();
        let bits = usize::from(self.len);
        for (i, (got, want)) in octets.iter().zip(self.base.iter()).enumerate() {
            let covered = bits.saturating_sub(i * 8).min(8);
            if covered == 0 {
                break;
            }
            let mask = 0xFFu8 << (8 - covered);
            if got & mask != want & mask {
                return None;
            }
        }
        let mut v4 = [0u8; 4];
        for (out, src) in v4.iter_mut().zip(self.slots()) {
            *out = *octets.get(src)?;
        }
        Some(Ipv4Addr::from(v4))
    }

    /// The four byte positions this prefix length embeds an IPv4 address at.
    fn slots(&self) -> [usize; 4] {
        match self.len {
            32 => [4, 5, 6, 7],
            40 => [5, 6, 7, 9],
            48 => [6, 7, 9, 10],
            56 => [7, 9, 10, 11],
            64 => [9, 10, 11, 12],
            // 96 is the only legal remaining value; `new` refuses the rest, and
            // a wrong answer here would be a wrong address rather than a panic.
            _ => [12, 13, 14, 15],
        }
    }

    /// Rewrite an address so this host can reach it, leaving IPv6 alone.
    #[must_use]
    pub fn synthesise_socket(&self, addr: SocketAddr) -> SocketAddr {
        match addr.ip() {
            std::net::IpAddr::V4(v4) => {
                SocketAddr::new(std::net::IpAddr::V6(self.synthesise(v4)), addr.port())
            }
            std::net::IpAddr::V6(_) => addr,
        }
    }

    /// Undo [`Self::synthesise_socket`], leaving anything else alone.
    #[must_use]
    pub fn extract_socket(&self, addr: SocketAddr) -> SocketAddr {
        match addr.ip() {
            std::net::IpAddr::V6(v6) => match self.extract(v6) {
                Some(v4) => SocketAddr::new(std::net::IpAddr::V4(v4), addr.port()),
                None => addr,
            },
            std::net::IpAddr::V4(_) => addr,
        }
    }

    /// Recover the prefix from a Router Advertisement's PREF64 option —
    /// RFC 8781.
    ///
    /// `msg` is the `ICMPv6` message, starting at the type byte, as a raw `ICMPv6`
    /// socket delivers it: the IPv6 header is not included.
    ///
    /// **This is the authoritative source and RFC 7050 is the fallback.** The
    /// prefix comes from the router that actually performs the translation,
    /// signed by nothing but delivered over link-local multicast that an
    /// off-link attacker cannot reach — where the DNS heuristic trusts whatever
    /// resolver answered. It also needs no DNS64 deployed at all.
    ///
    /// # The layout is not a concatenation
    ///
    /// §4 packs a 13-bit lifetime and a 3-bit *prefix length code* into one
    /// 16-bit word, and the code is an index into six lengths rather than the
    /// length itself. Reading it as a length would produce a prefix of 0, 1 or
    /// 2 bits — which `Nat64Prefix::new` refuses, so the mistake would show up
    /// as "no prefix found" rather than as a wrong address. That is the better
    /// failure, and it is still worth not making.
    ///
    /// A zero lifetime means the router is **withdrawing** the prefix (§4), so
    /// it is not a prefix this node may adopt.
    #[must_use]
    pub fn from_router_advertisement(msg: &[u8]) -> Option<Self> {
        // ICMPv6 type 134, ND_ROUTER_ADVERT. Anything else is not an RA, and
        // reading its bytes as one would find options where there are none.
        if *msg.first()? != 134 {
            return None;
        }
        // 4 bytes of ICMPv6 header, then 12 of RA fields, then options.
        let mut at = 16usize;
        while at < msg.len() {
            let kind = *msg.get(at)?;
            let units = usize::from(*msg.get(at.checked_add(1)?)?);
            // **A zero length is malformed and must not be walked past.** RFC
            // 4861 §4.6 gives every option a length of at least one unit; a
            // zero would advance this loop by nothing and spin forever on a
            // packet an attacker chose.
            if units == 0 {
                return None;
            }
            let end = at.checked_add(units.checked_mul(8)?)?;
            if end > msg.len() {
                return None;
            }
            if kind == PREF64_OPTION && units == 2 {
                if let Some(prefix) = Self::from_pref64_body(msg.get(at..end)?) {
                    return Some(prefix);
                }
            }
            at = end;
        }
        None
    }

    /// One 16-byte PREF64 option, header included.
    fn from_pref64_body(option: &[u8]) -> Option<Self> {
        let word = u16::from_be_bytes([*option.get(2)?, *option.get(3)?]);
        // 13 bits of lifetime in units of 8 seconds, then 3 bits of code.
        if word >> 3 == 0 {
            return None; // withdrawn
        }
        let len = match word & 0b111 {
            0 => 96,
            1 => 64,
            2 => 56,
            3 => 48,
            4 => 40,
            5 => 32,
            // 6 and 7 are reserved. §4 requires the option be ignored rather
            // than guessed at.
            _ => return None,
        };
        let mut base = [0u8; 16];
        base.get_mut(..12)?.copy_from_slice(option.get(4..16)?);
        // The option always carries 96 bits; the code says how many of them
        // count. §4 has the receiver ignore the rest, and `new` refuses a value
        // with bits set past its length, so they are cleared rather than
        // rejected — a router that leaves them set is not worth failing over.
        let bits = usize::from(len);
        for (i, byte) in base.iter_mut().enumerate() {
            let keep = bits.saturating_sub(i * 8).min(8);
            let mask = if keep >= 8 { 0xFFu8 } else { !(0xFFu8 >> keep) };
            *byte &= mask;
        }
        Self::new(Ipv6Addr::from(base), len).ok()
    }

    /// Recover the prefix from an AAAA record for `ipv4only.arpa` — RFC 7050 §3.
    ///
    /// The name has A records for [`WKA`] and [`WKA2`] and no AAAA of its own,
    /// so any AAAA answer is a DNS64 synthesis and the prefix is what remains
    /// once one of those two addresses is taken back out.
    ///
    /// **Every legal length is tried, longest first.** The record does not say
    /// which was used, and the well-known address can appear at more than one
    /// offset in a contrived answer; §3 resolves that by preferring the longest
    /// match, which is the most specific claim the answer supports.
    #[must_use]
    pub fn from_ipv4only_arpa(answer: Ipv6Addr) -> Option<Self> {
        let mut lengths = LEGAL;
        lengths.reverse();
        for len in lengths {
            let base = Self {
                base: [0u8; 16],
                len,
            };
            // Zero the host part before comparing, so a candidate prefix is
            // built from exactly the bits its length covers.
            let mut trial = answer.octets();
            for slot in base.slots() {
                if let Some(cell) = trial.get_mut(slot) {
                    *cell = 0;
                }
            }
            let Ok(candidate) = Self::new(Ipv6Addr::from(trial), len) else {
                continue;
            };
            match candidate.extract(answer) {
                Some(v4) if v4 == WKA || v4 == WKA2 => return Some(candidate),
                _ => {}
            }
        }
        None
    }
}

impl fmt::Display for Nat64Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv6Addr::from(self.base), self.len)
    }
}

impl FromStr for Nat64Prefix {
    type Err = PrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = s.split_once('/').ok_or(PrefixError::Syntax)?;
        let addr: Ipv6Addr = addr.parse().map_err(|_| PrefixError::Syntax)?;
        let len: u8 = len.parse().map_err(|_| PrefixError::Syntax)?;
        Self::new(addr, len)
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

    /// RFC 6052 §2.4's worked example, verbatim.
    ///
    /// **The table is copied from the RFC rather than computed here**, which is
    /// the whole value of it: an implementation that derives its expectations
    /// from its own bit-shifting agrees with itself and proves nothing. The
    /// reserved byte 8 is what these cases exist to pin — every length below 96
    /// steps over it, and the two the standard prints with a `0` in the middle
    /// are the ones an obvious implementation gets wrong.
    #[test]
    fn the_standards_own_worked_example_round_trips() {
        let v4: Ipv4Addr = "192.0.2.33".parse().unwrap();
        for (prefix, want) in [
            ("2001:db8::/32", "2001:db8:c000:221::"),
            ("2001:db8:100::/40", "2001:db8:1c0:2:21::"),
            ("2001:db8:122::/48", "2001:db8:122:c000:2:2100::"),
            ("2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"),
            ("2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100::"),
            ("2001:db8:122:344::/96", "2001:db8:122:344::192.0.2.33"),
        ] {
            let p: Nat64Prefix = prefix.parse().unwrap();
            let got = p.synthesise(v4);
            let want: Ipv6Addr = want.parse().unwrap();
            assert_eq!(got, want, "{prefix} synthesised {got}, expected {want}");
            assert_eq!(
                p.extract(got),
                Some(v4),
                "{prefix} could not recover the address it had just embedded"
            );
        }
    }

    /// The reserved byte stays zero at every length, which is the constraint
    /// that forces the split layouts in the first place.
    #[test]
    fn bits_64_to_71_are_always_zero() {
        for len in [32u8, 40, 48, 56, 64] {
            let p = Nat64Prefix::new(Ipv6Addr::from_str("2001:db8::").unwrap(), len)
                .or_else(|_| Nat64Prefix::new(Ipv6Addr::UNSPECIFIED, len))
                .unwrap();
            let got = p.synthesise(Ipv4Addr::new(255, 255, 255, 255));
            assert_eq!(
                got.octets().get(8),
                Some(&0u8),
                "the {len}-bit layout put an address octet in the reserved byte"
            );
        }
    }

    /// A prefix length the standard does not define is refused rather than
    /// rounded to one that is.
    #[test]
    fn an_undefined_prefix_length_is_refused() {
        let err = Nat64Prefix::new(Ipv6Addr::from_str("2001:db8::").unwrap(), 80).unwrap_err();
        assert_eq!(err, PrefixError::Length(80));
        assert!(err.to_string().contains("wrong host"));
        // And the same through the text form an operator actually types.
        assert_eq!(
            "64:ff9b::/48".parse::<Nat64Prefix>().unwrap().bits(),
            48,
            "48 is legal and must still parse"
        );
        assert_eq!(
            "64:ff9b::/80".parse::<Nat64Prefix>().unwrap_err(),
            PrefixError::Length(80)
        );
    }

    /// A whole synthesised address passed where a prefix was meant.
    #[test]
    fn an_address_with_a_host_part_is_not_a_prefix() {
        assert_eq!(
            "64:ff9b::1.2.3.4/96".parse::<Nat64Prefix>().unwrap_err(),
            PrefixError::NotAPrefix
        );
        assert_eq!(
            "2001:db8:122:344::/48".parse::<Nat64Prefix>().unwrap_err(),
            PrefixError::NotAPrefix,
            "0x0344 lies past bit 48, so this address is not a /48 prefix"
        );
        // **`64:ff9b::/32` is not an error**, which is worth pinning because it
        // looks like one. The well-known prefix is assigned as a /96, but the
        // address has no bits set past bit 32, so as *text* it is a perfectly
        // well-formed /32 prefix — and it means something entirely different.
        // Nothing here can catch that; only the operator knows which their
        // network runs.
        assert_eq!("64:ff9b::/32".parse::<Nat64Prefix>().unwrap().bits(), 32);
    }

    /// An address outside the prefix is not a translated IPv4 address, and
    /// saying so is what keeps a real IPv6 peer from being rewritten into a
    /// nonsense IPv4 one.
    #[test]
    fn an_address_outside_the_prefix_is_left_alone() {
        let p = Nat64Prefix::well_known();
        let real: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(p.extract(real), None);
        let sock: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        assert_eq!(p.extract_socket(sock), sock);
        // And an IPv4 address is not synthesisable twice.
        let v4: SocketAddr = "51.75.10.20:51820".parse().unwrap();
        assert_eq!(p.extract_socket(v4), v4);
    }

    /// The two halves are each other's inverse over a whole socket address,
    /// port included.
    #[test]
    fn synthesis_and_extraction_are_inverses() {
        for prefix in ["64:ff9b::/96", "2001:db8::/32", "2001:db8:122:344::/64"] {
            let p: Nat64Prefix = prefix.parse().unwrap();
            let v4: SocketAddr = "51.75.10.20:51820".parse().unwrap();
            let synth = p.synthesise_socket(v4);
            assert!(synth.is_ipv6(), "{prefix} did not produce an IPv6 address");
            assert_eq!(synth.port(), 51820, "{prefix} lost the port");
            assert_eq!(p.extract_socket(synth), v4, "{prefix} did not round-trip");
        }
    }

    /// Build a Router Advertisement carrying `options`.
    fn advertisement(options: &[u8]) -> Vec<u8> {
        let mut m = vec![134u8, 0, 0, 0]; // type, code, checksum
        m.extend_from_slice(&[64, 0]); // cur hop limit, flags
        m.extend_from_slice(&1800u16.to_be_bytes()); // router lifetime
        m.extend_from_slice(&0u32.to_be_bytes()); // reachable time
        m.extend_from_slice(&0u32.to_be_bytes()); // retrans timer
        m.extend_from_slice(options);
        m
    }

    /// One PREF64 option, from a lifetime in seconds and a prefix-length code.
    fn pref64(seconds: u16, plc: u16, prefix: &str) -> Vec<u8> {
        let mut o = vec![38u8, 2];
        o.extend_from_slice(&(((seconds / 8) << 3) | plc).to_be_bytes());
        let addr: Ipv6Addr = prefix.parse().unwrap();
        o.extend_from_slice(&addr.octets()[..12]);
        o
    }

    /// **All six prefix-length codes**, which is the table the whole option
    /// turns on. The code is an index, not a length: reading it as a length
    /// gives a 0-, 1- or 2-bit prefix.
    #[test]
    fn every_prefix_length_code_maps_to_the_length_the_standard_assigns() {
        for (plc, len, prefix) in [
            (0u16, 96u8, "64:ff9b::"),
            (1, 64, "2001:db8:122:344::"),
            (2, 56, "2001:db8:122:300::"),
            (3, 48, "2001:db8:122::"),
            (4, 40, "2001:db8:100::"),
            (5, 32, "2001:db8::"),
        ] {
            let ra = advertisement(&pref64(600, plc, prefix));
            let got = Nat64Prefix::from_router_advertisement(&ra)
                .unwrap_or_else(|| panic!("code {plc} yielded no prefix"));
            assert_eq!(got.bits(), len, "code {plc} is a /{len}");
            assert_eq!(got.to_string(), format!("{prefix}/{len}"));
        }
    }

    /// The reserved codes are ignored rather than guessed at — §4.
    #[test]
    fn a_reserved_prefix_length_code_is_ignored() {
        for plc in [6u16, 7] {
            let ra = advertisement(&pref64(600, plc, "64:ff9b::"));
            assert_eq!(
                Nat64Prefix::from_router_advertisement(&ra),
                None,
                "code {plc} is reserved and must not be interpreted"
            );
        }
    }

    /// A zero lifetime is a **withdrawal**, not an advertisement.
    #[test]
    fn a_withdrawn_prefix_is_not_adopted() {
        let ra = advertisement(&pref64(0, 0, "64:ff9b::"));
        assert_eq!(Nat64Prefix::from_router_advertisement(&ra), None);
        // One tick of lifetime is still an advertisement.
        let live = advertisement(&pref64(8, 0, "64:ff9b::"));
        assert_eq!(
            Nat64Prefix::from_router_advertisement(&live),
            Some(Nat64Prefix::well_known())
        );
    }

    /// PREF64 is found among the options a real router actually sends, at any
    /// position — not only when it is first.
    #[test]
    fn the_option_is_found_among_the_others() {
        // Source link-layer address (type 1), MTU (type 5), prefix information
        // (type 3), then PREF64.
        let mut options = vec![1u8, 1, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        options.extend_from_slice(&[5u8, 1, 0, 0, 0, 0, 0x05, 0xdc]);
        let mut pio = vec![3u8, 4, 64, 0xc0];
        pio.extend_from_slice(&[0u8; 28]);
        options.extend_from_slice(&pio);
        options.extend_from_slice(&pref64(600, 0, "64:ff9b::"));
        let ra = advertisement(&options);
        assert_eq!(
            Nat64Prefix::from_router_advertisement(&ra),
            Some(Nat64Prefix::well_known()),
            "the option was not found behind the ones every router sends"
        );
    }

    /// An RA with no PREF64 yields nothing, and so does a message that is not
    /// an RA at all — a Neighbour Advertisement's bytes are not options.
    #[test]
    fn only_a_router_advertisement_carrying_the_option_yields_a_prefix() {
        assert_eq!(
            Nat64Prefix::from_router_advertisement(&advertisement(&[])),
            None
        );
        let mut not_an_ra = advertisement(&pref64(600, 0, "64:ff9b::"));
        not_an_ra[0] = 136; // Neighbour Advertisement
        assert_eq!(Nat64Prefix::from_router_advertisement(&not_an_ra), None);
    }

    /// **A zero-length option must not spin the walk forever**, and every
    /// truncation must return rather than read past the end. This input comes
    /// off a raw socket and nothing has vouched for it.
    #[test]
    fn a_malformed_advertisement_is_refused_without_hanging() {
        // Length 0 is illegal (RFC 4861 §4.6) and advances the cursor by
        // nothing.
        let mut zero = advertisement(&[38u8, 0, 0, 0]);
        zero.extend_from_slice(&[0u8; 12]);
        assert_eq!(Nat64Prefix::from_router_advertisement(&zero), None);

        // An option claiming more bytes than the message holds.
        let lying = advertisement(&[38u8, 9, 0x02, 0x00]);
        assert_eq!(Nat64Prefix::from_router_advertisement(&lying), None);

        // And every prefix of a well-formed message.
        let full = advertisement(&pref64(600, 0, "64:ff9b::"));
        for cut in 0..full.len() {
            let _ = Nat64Prefix::from_router_advertisement(&full[..cut]);
        }
    }

    /// Bits past the prefix length are cleared rather than refused — §4 has the
    /// receiver ignore them, and a router that leaves them set is not worth
    /// failing over.
    #[test]
    fn bits_past_the_prefix_length_are_ignored() {
        // A /32 code with a full 96 bits of prefix set.
        let mut o = vec![38u8, 2];
        o.extend_from_slice(&(((600u16 / 8) << 3) | 5).to_be_bytes());
        o.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ]);
        let got = Nat64Prefix::from_router_advertisement(&advertisement(&o))
            .expect("the option is well formed; only its low bits are noise");
        assert_eq!(got, "2001:db8::/32".parse::<Nat64Prefix>().unwrap());
    }

    /// RFC 7050 §3: the prefix is whatever is left when the well-known address
    /// is taken out of a synthesised AAAA for `ipv4only.arpa`.
    #[test]
    fn a_prefix_is_recovered_from_a_synthesised_ipv4only_arpa_answer() {
        for (prefix, wka) in [
            ("64:ff9b::/96", WKA),
            ("64:ff9b::/96", WKA2),
            ("2001:db8::/32", WKA),
            ("2001:db8:122:344::/64", WKA2),
            ("2001:db8:122::/48", WKA),
        ] {
            let p: Nat64Prefix = prefix.parse().unwrap();
            let answer = p.synthesise(wka);
            assert_eq!(
                Nat64Prefix::from_ipv4only_arpa(answer),
                Some(p),
                "{prefix} was not recovered from {answer}, which it had just \
                 produced for {wka}"
            );
        }
    }

    /// An AAAA that embeds neither reserved address is not a DNS64 synthesis,
    /// and believing it would hand the daemon a prefix that translates nothing.
    #[test]
    fn an_unsynthesised_answer_yields_no_prefix() {
        let real: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(Nat64Prefix::from_ipv4only_arpa(real), None);
        // A synthesis of some *other* address is equally not an answer: the
        // whole method rests on knowing which IPv4 address went in.
        let p = Nat64Prefix::well_known();
        let decoy = p.synthesise(Ipv4Addr::new(192, 0, 0, 172));
        assert_eq!(Nat64Prefix::from_ipv4only_arpa(decoy), None);
    }

    /// The well-known prefix as a constant and as parsed text are the same
    /// thing — cheap, and it is the value every default path uses.
    #[test]
    fn the_well_known_prefix_is_what_the_standard_says() {
        assert_eq!(
            Nat64Prefix::well_known(),
            "64:ff9b::/96".parse::<Nat64Prefix>().unwrap()
        );
        assert_eq!(Nat64Prefix::well_known().to_string(), "64:ff9b::/96");
    }
}
