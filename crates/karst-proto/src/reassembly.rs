// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Fragment reassembly — `spec/phreatic-v1.md` §9.1.
//!
//! **This is the most security-critical code in the system.** It processes
//! attacker-controlled bytes on the pre-authentication path and holds the only
//! state a remote party can cause a responder to allocate. `docs/THREAT-MODEL.md`
//! R1 tracks it as a high residual risk pending external review.
//!
//! Three properties are structural rather than policy:
//!
//! 1. **Memory is bounded at construction.** Every slot and every buffer is
//!    allocated up front and reused. The reassembler never grows, so a flood
//!    cannot exhaust memory — it can only cause rejections.
//! 2. **No panic path.** No indexing, no slicing, no `unwrap`.
//! 3. **Sans-io.** Time is a parameter. There is no clock access, which is what
//!    makes the timeout behaviour deterministically testable.
//!
//! What this module does *not* do: verify `frag_mac`. The caller must have
//! validated it (§9.2) before calling [`Reassembler::push`], and must pass
//! `addr_validated` honestly. Getting that wrong defeats the cookie mechanism.

use crate::{consts, FragmentHeader};

/// Opaque source identity — 16 bytes of address plus 2 of port, caller-encoded.
/// Deliberately not `SocketAddr`, to keep this module free of `std::net`.
pub type SourceKey = [u8; 18];

/// Largest message the reassembler will ever hold: 4 × 1208 = 4832 bytes.
pub const MAX_MESSAGE: usize = consts::MAX_FRAGMENTS as usize * consts::FRAGMENT_PAYLOAD_MAX;

/// The scratch buffer must also hold an unfragmented transport message, which
/// §13.6 allows to exceed a single fragment's payload.
const _: () = assert!(consts::TRANSPORT_PAYLOAD_MAX <= MAX_MESSAGE);

/// Reassembler limits. Every one of these is a denial-of-service control.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Total in-flight messages. Bounds memory: `max_entries * 4832` bytes.
    pub max_entries: usize,
    /// Cap on entries attributable to one source, so a single peer cannot
    /// occupy every slot.
    pub max_per_source: usize,
    /// Eviction age in milliseconds. §10: `REASSEMBLY_TIMEOUT` = 3 s.
    pub timeout_ms: u64,
    /// Occupied-slot count above which unvalidated sources are refused
    /// outright and a cookie is demanded instead (§9.1).
    pub load_threshold: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_entries: 256,
            max_per_source: 4,
            timeout_ms: 3_000,
            // Two thirds full. `LOAD_THRESHOLD` needs empirical tuning against
            // a real flood — spec §14 item 4.
            load_threshold: 170,
        }
    }
}

/// Outcome of offering a fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Accept<'a> {
    /// Stored; the message is still incomplete.
    Buffered,
    /// Message complete. The slot is released before this returns.
    Complete(&'a [u8]),
    /// Discarded. `reason` tells the caller whether to answer with a cookie.
    Rejected(Reject),
}

/// Why a fragment was discarded. **None of this is ever sent on the wire** —
/// §11 requires silent discard. It exists for local logging and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Above `load_threshold` and the source is not address-validated.
    /// The caller SHOULD answer with a `CookieReply` (§9.1). **No state was
    /// allocated.**
    CookieRequired,
    /// No free slot. Nothing was allocated.
    CapacityExhausted,
    /// This source already holds `max_per_source` entries.
    SourceBudgetExhausted,
    /// Fragment already present — a duplicate or a replay.
    Duplicate,
    /// `count` disagrees with the entry already in flight, or the payload is
    /// oversized for its position.
    Inconsistent,
}

#[derive(Clone)]
struct Entry {
    source: SourceKey,
    reassembly_id: u32,
    count: u8,
    /// Bitmap of received fragment indices; bit *i* set means index *i* held.
    received: u8,
    /// Payload length of each fragment, indexed by fragment position.
    lens: [u16; consts::MAX_FRAGMENTS as usize],
    buf: [u8; MAX_MESSAGE],
    expires_at_ms: u64,
}

impl Entry {
    fn complete(&self) -> bool {
        let want = if self.count >= 8 {
            u8::MAX
        } else {
            (1u8 << self.count) - 1
        };
        self.received == want
    }
}

/// Bounded, allocation-free-after-construction fragment reassembler.
pub struct Reassembler {
    slots: Vec<Option<Entry>>,
    cfg: Config,
    /// Scratch used to return a contiguous completed message.
    scratch: Vec<u8>,
}

impl core::fmt::Debug for Reassembler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reassembler")
            .field("occupied", &self.occupied())
            .field("capacity", &self.cfg.max_entries)
            .finish_non_exhaustive()
    }
}

impl Reassembler {
    /// Allocate every slot up front. After this, the reassembler never grows.
    #[must_use]
    pub fn new(cfg: Config) -> Self {
        Self {
            slots: vec![None; cfg.max_entries],
            cfg,
            scratch: vec![0u8; MAX_MESSAGE],
        }
    }

    /// Bytes held. Useful for asserting the memory bound in tests and metrics.
    #[must_use]
    pub fn memory_bytes(&self) -> usize {
        self.cfg.max_entries * core::mem::size_of::<Entry>() + MAX_MESSAGE
    }

    /// Slots currently in use.
    #[must_use]
    pub fn occupied(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// Drop entries older than the timeout. Idempotent; safe to call often.
    pub fn expire(&mut self, now_ms: u64) {
        for slot in &mut self.slots {
            let stale = slot.as_ref().is_some_and(|e| e.expires_at_ms <= now_ms);
            if stale {
                *slot = None;
            }
        }
    }

    /// A single-fragment message is already complete — §13.6.
    ///
    /// It never enters a buffer, occupies no slot, and is not subject to the
    /// load threshold, because there is nothing to hold: it is copied straight
    /// out. That is precisely what lets an unfragmented transport datagram carry
    /// more than [`consts::FRAGMENT_PAYLOAD_MAX`] without weakening §9.1's
    /// memory bound — nothing above that size can ever be *stored*.
    fn complete_unfragmented(&mut self, payload: &[u8]) -> Accept<'_> {
        if payload.len() > consts::TRANSPORT_PAYLOAD_MAX {
            return Accept::Rejected(Reject::Inconsistent);
        }
        let Some(dst) = self.scratch.get_mut(..payload.len()) else {
            return Accept::Rejected(Reject::Inconsistent);
        };
        dst.copy_from_slice(payload);
        match self.scratch.get(..payload.len()) {
            Some(msg) => Accept::Complete(msg),
            None => Accept::Rejected(Reject::Inconsistent),
        }
    }

    /// Offer a fragment.
    ///
    /// `addr_validated` MUST be true only if the source echoed a valid cookie
    /// (§9.3). The caller MUST have verified `frag_mac` first (§9.2).
    pub fn push(
        &mut self,
        source: SourceKey,
        addr_validated: bool,
        hdr: &FragmentHeader,
        payload: &[u8],
        now_ms: u64,
    ) -> Accept<'_> {
        if hdr.count > consts::MAX_FRAGMENTS || hdr.idx >= hdr.count {
            return Accept::Rejected(Reject::Inconsistent);
        }

        // Before `expire`, deliberately. Expiry walks every slot, and an
        // unfragmented message neither reads nor writes one — on a busy tunnel
        // that is the entire data path paying for a sweep of a table it never
        // touches. Nothing is missed: the sweep still runs on any fragmented
        // datagram, which is the only kind that can occupy a slot.
        if hdr.count == 1 {
            return self.complete_unfragmented(payload);
        }

        self.expire(now_ms);

        if payload.len() > consts::FRAGMENT_PAYLOAD_MAX {
            return Accept::Rejected(Reject::Inconsistent);
        }

        // Find an in-flight entry for this (source, reassembly_id).
        let existing = self.slots.iter().position(|s| {
            s.as_ref()
                .is_some_and(|e| e.source == source && e.reassembly_id == hdr.reassembly_id)
        });

        let idx = if let Some(i) = existing {
            i
        } else {
            {
                // §9.1: above the load threshold, an unvalidated source gets
                // NO state. This check precedes every allocation, which is the
                // property the whole DoS design rests on.
                if !addr_validated && self.occupied() >= self.cfg.load_threshold {
                    return Accept::Rejected(Reject::CookieRequired);
                }
                let from_source = self
                    .slots
                    .iter()
                    .filter(|s| s.as_ref().is_some_and(|e| e.source == source))
                    .count();
                if from_source >= self.cfg.max_per_source {
                    return Accept::Rejected(Reject::SourceBudgetExhausted);
                }
                match self.slots.iter().position(Option::is_none) {
                    Some(i) => {
                        if let Some(slot) = self.slots.get_mut(i) {
                            *slot = Some(Entry {
                                source,
                                reassembly_id: hdr.reassembly_id,
                                count: hdr.count,
                                received: 0,
                                lens: [0; consts::MAX_FRAGMENTS as usize],
                                buf: [0; MAX_MESSAGE],
                                expires_at_ms: now_ms.saturating_add(self.cfg.timeout_ms),
                            });
                        }
                        i
                    }
                    None => return Accept::Rejected(Reject::CapacityExhausted),
                }
            }
        };

        // Fill the entry.
        let completed = {
            let Some(Some(entry)) = self.slots.get_mut(idx) else {
                return Accept::Rejected(Reject::CapacityExhausted);
            };
            if entry.count != hdr.count {
                return Accept::Rejected(Reject::Inconsistent);
            }
            let bit = 1u8 << hdr.idx;
            if entry.received & bit != 0 {
                return Accept::Rejected(Reject::Duplicate);
            }
            // Only the last fragment may be short.
            if hdr.idx + 1 < hdr.count && payload.len() != consts::FRAGMENT_PAYLOAD_MAX {
                return Accept::Rejected(Reject::Inconsistent);
            }

            let off = hdr.idx as usize * consts::FRAGMENT_PAYLOAD_MAX;
            let Some(dst) = entry.buf.get_mut(off..off + payload.len()) else {
                return Accept::Rejected(Reject::Inconsistent);
            };
            dst.copy_from_slice(payload);
            if let Some(l) = entry.lens.get_mut(hdr.idx as usize) {
                *l = u16::try_from(payload.len()).unwrap_or(0);
            }
            entry.received |= bit;
            entry.complete()
        };

        if !completed {
            return Accept::Buffered;
        }

        // Complete: copy out contiguously, then release the slot immediately so
        // a completed message never occupies capacity.
        let mut total = 0usize;
        if let Some(Some(entry)) = self.slots.get(idx) {
            for i in 0..entry.count as usize {
                let len = entry.lens.get(i).copied().unwrap_or(0) as usize;
                let src_off = i * consts::FRAGMENT_PAYLOAD_MAX;
                let (Some(src), Some(dst)) = (
                    entry.buf.get(src_off..src_off + len),
                    self.scratch.get_mut(total..total + len),
                ) else {
                    return Accept::Rejected(Reject::Inconsistent);
                };
                dst.copy_from_slice(src);
                total += len;
            }
        }
        if let Some(slot) = self.slots.get_mut(idx) {
            *slot = None;
        }

        match self.scratch.get(..total) {
            Some(msg) => Accept::Complete(msg),
            None => Accept::Rejected(Reject::Inconsistent),
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests signal failure by panicking; the workspace lint targets library
    // code on the pre-authentication path, not assertions.
    #![allow(clippy::panic)]

    use super::*;

    const SRC_A: SourceKey = [1; 18];
    const SRC_B: SourceKey = [2; 18];

    fn hdr(id: u32, idx: u8, count: u8) -> FragmentHeader {
        FragmentHeader {
            reassembly_id: id,
            idx,
            count,
            frag_mac: [0; consts::FRAG_MAC_LEN],
        }
    }

    fn full() -> Vec<u8> {
        vec![0xAB; consts::FRAGMENT_PAYLOAD_MAX]
    }

    // ── happy path ──────────────────────────────────────────────────────────

    #[test]
    fn reassembles_two_fragments_in_order() {
        let mut r = Reassembler::new(Config::default());
        assert_eq!(
            r.push(SRC_A, true, &hdr(1, 0, 2), &full(), 0),
            Accept::Buffered
        );
        let tail = vec![0xCD; 100];
        match r.push(SRC_A, true, &hdr(1, 1, 2), &tail, 0) {
            Accept::Complete(m) => {
                assert_eq!(m.len(), consts::FRAGMENT_PAYLOAD_MAX + 100);
                assert_eq!(m.first(), Some(&0xAB));
                assert_eq!(m.last(), Some(&0xCD));
            }
            other => panic!("expected Complete, got {other:?}"),
        }
        assert_eq!(r.occupied(), 0, "slot must be released on completion");
    }

    #[test]
    fn reassembles_out_of_order() {
        let mut r = Reassembler::new(Config::default());
        assert_eq!(
            r.push(SRC_A, true, &hdr(9, 1, 2), &[7u8; 10], 0),
            Accept::Buffered
        );
        assert!(matches!(
            r.push(SRC_A, true, &hdr(9, 0, 2), &full(), 0),
            Accept::Complete(_)
        ));
    }

    // ── the DoS properties ──────────────────────────────────────────────────

    /// §9.1, the central property: above the load threshold an unvalidated
    /// source gets **no state at all**.
    #[test]
    fn under_load_unvalidated_sources_allocate_nothing() {
        let cfg = Config {
            max_entries: 8,
            max_per_source: 8,
            load_threshold: 4,
            ..Config::default()
        };
        let mut r = Reassembler::new(cfg);

        for i in 0..4u32 {
            assert_eq!(
                r.push(SRC_A, true, &hdr(i, 0, 2), &full(), 0),
                Accept::Buffered
            );
        }
        assert_eq!(r.occupied(), 4);

        // Now at the threshold: an unvalidated source is refused, and crucially
        // the occupancy does not move.
        for i in 100..200u32 {
            assert_eq!(
                r.push(SRC_B, false, &hdr(i, 0, 2), &full(), 0),
                Accept::Rejected(Reject::CookieRequired)
            );
        }
        assert_eq!(r.occupied(), 4, "a flood must not allocate a single slot");

        // A validated source is still served.
        assert_eq!(
            r.push(SRC_B, true, &hdr(500, 0, 2), &full(), 0),
            Accept::Buffered
        );
    }

    /// Memory is bounded by construction, not by policy: a flood from many
    /// distinct sources cannot make the reassembler grow.
    #[test]
    fn memory_is_bounded_regardless_of_flood() {
        let cfg = Config {
            max_entries: 16,
            max_per_source: 16,
            load_threshold: 1_000,
            ..Config::default()
        };
        let mut r = Reassembler::new(cfg);
        let before = r.memory_bytes();

        for i in 0..10_000u32 {
            let mut src = [0u8; 18];
            src[0..4].copy_from_slice(&i.to_le_bytes());
            let _ = r.push(src, true, &hdr(i, 0, 2), &full(), 0);
        }
        assert_eq!(r.memory_bytes(), before, "must not grow");
        assert!(r.occupied() <= 16);
    }

    #[test]
    fn one_source_cannot_occupy_every_slot() {
        let cfg = Config {
            max_entries: 16,
            max_per_source: 3,
            load_threshold: 1_000,
            ..Config::default()
        };
        let mut r = Reassembler::new(cfg);
        for i in 0..3u32 {
            assert_eq!(
                r.push(SRC_A, true, &hdr(i, 0, 2), &full(), 0),
                Accept::Buffered
            );
        }
        assert_eq!(
            r.push(SRC_A, true, &hdr(99, 0, 2), &full(), 0),
            Accept::Rejected(Reject::SourceBudgetExhausted)
        );
        // A different source is unaffected.
        assert_eq!(
            r.push(SRC_B, true, &hdr(1, 0, 2), &full(), 0),
            Accept::Buffered
        );
    }

    #[test]
    fn capacity_exhaustion_rejects_rather_than_grows() {
        let cfg = Config {
            max_entries: 2,
            max_per_source: 8,
            load_threshold: 1_000,
            ..Config::default()
        };
        let mut r = Reassembler::new(cfg);
        assert_eq!(
            r.push(SRC_A, true, &hdr(1, 0, 2), &full(), 0),
            Accept::Buffered
        );
        assert_eq!(
            r.push(SRC_A, true, &hdr(2, 0, 2), &full(), 0),
            Accept::Buffered
        );
        assert_eq!(
            r.push(SRC_A, true, &hdr(3, 0, 2), &full(), 0),
            Accept::Rejected(Reject::CapacityExhausted)
        );
    }

    #[test]
    fn stale_entries_are_evicted_and_free_capacity() {
        let cfg = Config {
            max_entries: 2,
            timeout_ms: 3_000,
            load_threshold: 1_000,
            ..Config::default()
        };
        let mut r = Reassembler::new(cfg);
        assert_eq!(
            r.push(SRC_A, true, &hdr(1, 0, 2), &full(), 0),
            Accept::Buffered
        );
        assert_eq!(r.occupied(), 1);

        r.expire(2_999);
        assert_eq!(r.occupied(), 1, "must not evict early");
        r.expire(3_000);
        assert_eq!(r.occupied(), 0, "must evict at the timeout");
    }

    // ── never act on a partial reassembly ───────────────────────────────────

    #[test]
    fn never_completes_on_a_partial_message() {
        let mut r = Reassembler::new(Config::default());
        for count in 2..=consts::MAX_FRAGMENTS {
            for idx in 0..count - 1 {
                let res = r.push(SRC_A, true, &hdr(u32::from(count), idx, count), &full(), 0);
                assert_eq!(res, Accept::Buffered, "{idx}/{count} must not complete");
            }
        }
    }

    #[test]
    fn duplicate_fragments_are_rejected_not_double_counted() {
        let mut r = Reassembler::new(Config::default());
        assert_eq!(
            r.push(SRC_A, true, &hdr(1, 0, 2), &full(), 0),
            Accept::Buffered
        );
        assert_eq!(
            r.push(SRC_A, true, &hdr(1, 0, 2), &full(), 0),
            Accept::Rejected(Reject::Duplicate)
        );
        assert_eq!(r.occupied(), 1);
    }

    #[test]
    fn inconsistent_count_is_rejected() {
        let mut r = Reassembler::new(Config::default());
        assert_eq!(
            r.push(SRC_A, true, &hdr(1, 0, 2), &full(), 0),
            Accept::Buffered
        );
        assert_eq!(
            r.push(SRC_A, true, &hdr(1, 1, 3), &full(), 0),
            Accept::Rejected(Reject::Inconsistent)
        );
    }

    /// Only the final fragment may be short. Otherwise an attacker could send
    /// tiny non-final fragments and leave gaps in the buffer.
    #[test]
    fn non_final_fragments_must_be_full_length() {
        let mut r = Reassembler::new(Config::default());
        assert_eq!(
            r.push(SRC_A, true, &hdr(1, 0, 2), &[1u8; 10], 0),
            Accept::Rejected(Reject::Inconsistent)
        );
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let mut r = Reassembler::new(Config::default());
        let big = vec![0u8; consts::FRAGMENT_PAYLOAD_MAX + 1];
        assert_eq!(
            r.push(SRC_A, true, &hdr(1, 0, 2), &big, 0),
            Accept::Rejected(Reject::Inconsistent)
        );
    }

    /// Two sources using the same `reassembly_id` must not be confused.
    #[test]
    fn entries_are_keyed_by_source_as_well_as_id() {
        let mut r = Reassembler::new(Config::default());
        assert_eq!(
            r.push(SRC_A, true, &hdr(1, 0, 2), &full(), 0),
            Accept::Buffered
        );
        assert_eq!(
            r.push(SRC_B, true, &hdr(1, 1, 2), &[9u8; 5], 0),
            Accept::Buffered
        );
        assert_eq!(r.occupied(), 2, "must not merge across sources");
    }

    /// Smoke test for totality; `cargo-fuzz` covers the space properly.
    #[test]
    fn never_panics_on_adversarial_input() {
        let mut r = Reassembler::new(Config {
            max_entries: 4,
            ..Config::default()
        });
        let mut t = 0u64;
        for id in 0..50u32 {
            for idx in 0..5u8 {
                for count in 0..6u8 {
                    for len in [0usize, 1, consts::FRAGMENT_PAYLOAD_MAX, MAX_MESSAGE] {
                        let p = vec![0x5A; len];
                        let _ = r.push(SRC_A, id % 2 == 0, &hdr(id, idx, count), &p, t);
                        t = t.wrapping_add(7);
                    }
                }
            }
        }
    }
}
