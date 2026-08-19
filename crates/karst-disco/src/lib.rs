// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! AVEN v1 — NAT traversal: probing, reflexive discovery, path selection.
//!
//! Implements `spec/aven-v1.md`. **Sans-io**: this crate turns bytes into typed
//! values and back, and decides which of several known paths to use. It opens
//! no socket, reads no clock and enumerates no interface. Time arrives as a
//! millisecond stamp, addresses arrive from the caller.
//!
//! The decoder is on the **pre-authentication path** — it parses arbitrary
//! bytes from an unfiltered UDP port before any MAC is checked — so it is
//! written to be panic-free: no indexing, no slicing, no `unwrap`.

pub mod engine;
pub mod key;
pub mod msg;
pub mod path;

pub use engine::{Action, Engine};
pub use key::{DiscoKey, TagTable};
pub use msg::{Endpoint, Message, TxId};
pub use path::{PathKind, PathSet, Selection};

pub mod consts {
    //! Normative constants — `spec/aven-v1.md` §6 and §7.5.

    /// Discriminates AVEN from PHREATIC on a shared socket — §4.
    ///
    /// A **hint, not a decision.** `phreatic-v1.md` §5 begins every datagram
    /// with a CSPRNG-drawn `reassembly_id`, so one PHREATIC datagram in 2³²
    /// starts with these bytes by chance. What actually separates the two
    /// protocols is that both are authenticated; the magic only makes the
    /// common case cost one MAC instead of two.
    pub const MAGIC: [u8; 4] = *b"KAVN";

    /// Protocol version.
    pub const VERSION: u8 = 1;

    /// magic, version, type, `peer_tag`, epoch.
    pub const HEADER: usize = 4 + 1 + 1 + TAG_LEN + 4;

    /// HMAC-SHA-512 truncated, as `phreatic-v1.md` §9.2's fragment MAC.
    pub const MAC_LEN: usize = 16;

    /// Sender tag — §5.2. Eight bytes, not a node id.
    pub const TAG_LEN: usize = 8;

    /// Per-pair disco key.
    pub const KEY_LEN: usize = 32;

    /// Probe transaction id.
    pub const TX_ID_LEN: usize = 12;

    /// Wire size of one endpoint — §6.2.
    pub const ENDPOINT_LEN: usize = 1 + 16 + 2;

    /// Most candidates one `CallMeMaybe` may carry.
    ///
    /// A receiver rejects a larger count rather than truncating: a truncating
    /// receiver and a non-truncating sender disagree about what was said.
    pub const MAX_CANDIDATES: usize = 16;

    /// Most candidate paths remembered for one peer.
    ///
    /// `MAX_CANDIDATES` limits one advertisement, not the number of distinct
    /// addresses an authenticated but malicious peer can name over time. This
    /// cap bounds the state and the scheduler work that peer can cause. When
    /// full, `PathSet::add_candidate` evicts the oldest unconfirmed candidate,
    /// falling back to the stalest confirmed path; the path currently in use is
    /// never evicted.
    ///
    /// **A confirmed path is not exempt.** It is stronger evidence and is
    /// preferred, but exempting it made "answer one probe" the price of a
    /// permanent slot, which is no price at all to the malicious peer §1.1 puts
    /// inside the tailnet.
    ///
    /// The relay path is the one addition outside this bound: `set_relay`
    /// keeps at most one entry and it is the last resort every other path is
    /// measured against, so a peer cannot multiply it.
    pub const MAX_PATHS_PER_PEER: usize = 64;

    /// Largest legal datagram: a sixteen-candidate `CallMeMaybe`.
    ///
    /// Checked before anything else, so a length field never sizes an
    /// allocation.
    pub const DATAGRAM_MAX: usize = HEADER + 1 + MAX_CANDIDATES * ENDPOINT_LEN + MAC_LEN;

    /// `Ping` on the wire.
    pub const PING_LEN: usize = HEADER + TX_ID_LEN + MAC_LEN;
    /// `Pong` on the wire.
    pub const PONG_LEN: usize = HEADER + TX_ID_LEN + ENDPOINT_LEN + MAC_LEN;

    /// Zero padding in a `Reflect` — §6.1.
    ///
    /// Exactly the width of the `observed` endpoint the answer carries, so a
    /// request and its reply are the same size. See [`REFLECT_LEN`].
    pub const REFLECT_PAD_LEN: usize = ENDPOINT_LEN;

    /// `Reflect` on the wire — §6.1.
    pub const REFLECT_LEN: usize = HEADER + TX_ID_LEN + REFLECT_PAD_LEN + MAC_LEN;
    /// `Reflection` on the wire — §6.1.
    pub const REFLECTION_LEN: usize = HEADER + TX_ID_LEN + ENDPOINT_LEN + MAC_LEN;

    /// Reflect key — §5.3. Same width as a disco key; a different secret.
    pub const REFLECT_KEY_LEN: usize = KEY_LEN;

    // §7.6's amplification argument, asserted rather than asserted-in-prose.
    // A reflector answers a datagram it did not solicit, so a reply larger than
    // its request is a contribution to somebody else's attack. `REFLECT_PAD_LEN`
    // exists solely to hold this equality, and a change to either message that
    // breaks it must not compile.
    const _: () = {
        assert!(REFLECT_LEN == REFLECTION_LEN);
    };

    // Asserted at compile time. Discovery has to be cheap relative to what it
    // is discovering a path for, and it must never need fragmenting — AVEN has
    // no reassembly layer and is not getting one.
    const _: () = {
        assert!(PING_LEN < 64);
        assert!(DATAGRAM_MAX < 1232);
    };

    /// An outstanding `tx_id` expires after this — §7.1.
    pub const TX_TIMEOUT_MS: u64 = 5_000;

    /// Most outstanding probes per peer. They are state a peer's behaviour
    /// causes us to allocate, so they are counted.
    pub const MAX_OUTSTANDING: usize = 16;

    /// How many recently answered `tx_id`s a responder remembers per peer —
    /// §7.4.
    ///
    /// Bounded, so the guarantee is "answered at most once within the window"
    /// rather than "at most once ever". An unbounded cache would be a
    /// memory-exhaustion vector reachable by the very replay it exists to
    /// stop, which is trading one flaw for a worse one.
    pub const ANSWERED_WINDOW: usize = 64;

    /// A path with no `Pong` inside this window is not eligible — §8.
    pub const PATH_STALE_MS: u64 = 15_000;

    /// Keepalive on the chosen path — §7.5.
    pub const KEEPALIVE_MS: u64 = 5_000;

    /// Re-probe alternatives this often — §7.5.
    pub const REPROBE_MS: u64 = 30_000;

    /// Backoff for a new candidate: probe now, then after each of these — §7.5.
    ///
    /// Four probes and then stop. A candidate that never answers is an address
    /// a peer named, and it may not be a peer at all; probing it forever would
    /// make any node able to point every one of its peers at a third party.
    pub const PROBE_BACKOFF_MS: [u64; 3] = [100, 300, 900];

    /// A `CallMeMaybe` per peer at most this often — §7.5.
    pub const ADVERTISE_MIN_INTERVAL_MS: u64 = 5_000;

    /// Ask each reflector for our mapped address this often — §7.5, §7.6.
    ///
    /// Repeated rather than asked once, because a NAT rebinds: a mapping
    /// learned at connect time and never refreshed becomes a candidate that
    /// *used to be* true, which is worse than no candidate, since a stale
    /// address consumes an advertisement slot and a peer's probe budget.
    ///
    /// **Ten seconds, not thirty, and the reason is the kernel rather than the
    /// protocol.** Linux's `nf_conntrack_udp_timeout` is **30 seconds**, and
    /// most consumer NATs are in the same range or shorter. Refreshing at the
    /// timeout is a race with it: the binding sometimes survives and sometimes
    /// is rebuilt with a different external port, so the address a node
    /// advertises changes under it while peers are probing the old one. That
    /// was observed rather than predicted — `tests/tailnet.rs`'s doubly-NATed
    /// row never converged at thirty seconds, and a packet capture showed the
    /// mapped port moving between reflections on an otherwise idle flow.
    ///
    /// This is the same argument [`KEEPALIVE_MS`] makes for a chosen path, one
    /// step earlier: a reflexive address is only true while the binding that
    /// produced it is alive, and the binding's lifetime is not something the
    /// protocol is told.
    pub const REFLECT_INTERVAL_MS: u64 = 10_000;

    /// Hysteresis: an alternative must beat the chosen path by at least this
    /// much — §8.2.
    pub const HYSTERESIS_MS: u64 = 20;

    /// …or by this fraction, whichever is larger.
    pub const HYSTERESIS_PERCENT: u64 = 20;

    /// …sustained across this many consecutive measurements.
    pub const HYSTERESIS_SAMPLES: u32 = 3;
}

/// Why a datagram was not accepted.
///
/// `spec/aven-v1.md` §10: every one of these is a **silent drop**. AVEN has no
/// error messages, because emitting one would make a node an oracle for which
/// peers it holds keys for — and because a log line per dropped datagram is a
/// disk-filling primitive available to anyone who can reach an unfiltered UDP
/// port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Not AVEN: wrong magic, or shorter than a header and MAC.
    NotAven,
    /// Longer than [`consts::DATAGRAM_MAX`]. Rejected before anything else.
    TooLong(usize),
    /// A version this implementation does not speak.
    BadVersion(u8),
    /// Not a type AVEN v1 defines.
    UnknownType(u8),
    /// The length is wrong for the type.
    BadLength {
        /// The type byte.
        msg_type: u8,
        /// The length that arrived.
        got: usize,
    },
    /// `count` outside 1..=16, or an address family that is neither 4 nor 6,
    /// or IPv4 padding that is not zero.
    Malformed,
    /// No disco key is held for this tag. Indistinguishable, to the sender,
    /// from [`Self::BadMac`].
    UnknownTag,
    /// The MAC did not verify.
    BadMac,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAven => f.write_str("not an AVEN datagram"),
            Self::TooLong(n) => write!(f, "datagram of {n} bytes exceeds the cap"),
            Self::BadVersion(v) => write!(f, "unsupported AVEN version {v}"),
            Self::UnknownType(t) => write!(f, "unknown AVEN message type {t:#04x}"),
            Self::BadLength { msg_type, got } => {
                write!(f, "type {msg_type:#04x} cannot have length {got}")
            }
            Self::Malformed => f.write_str("malformed AVEN body"),
            Self::UnknownTag => f.write_str("no disco key for this tag"),
            Self::BadMac => f.write_str("MAC did not verify"),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::consts::*;

    #[test]
    fn wire_sizes_match_the_spec() {
        // spec/aven-v1.md §6.1. A change should show up as a diff against the
        // specification rather than as drift.
        assert_eq!(HEADER, 18);
        assert_eq!(PING_LEN, 46);
        assert_eq!(PONG_LEN, 65);
        assert_eq!(ENDPOINT_LEN, 19);
        assert_eq!(DATAGRAM_MAX, 339);
        assert_eq!(REFLECT_LEN, 65);
        assert_eq!(REFLECTION_LEN, 65);
        // The smallest CallMeMaybe, one candidate.
        assert_eq!(HEADER + 1 + ENDPOINT_LEN + MAC_LEN, 54);
    }
}
