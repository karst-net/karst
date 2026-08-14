// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! `virtio_net` headers and TCP segmentation — the receive half of TUN offload.
//!
//! With `IFF_VNET_HDR` and `TUNSETOFFLOAD`, one `read` from the TUN device can
//! return a **coalesced super-segment**: tens of kilobytes of TCP payload behind
//! a single IP and TCP header, with the original segment size in the
//! `virtio_net_hdr`. That is what removes the per-packet read syscall the
//! datapath is currently bound by (PLAN.md §3.4).
//!
//! The kernel does the coalescing; splitting it back into wire-legal packets is
//! ours. That means, per segment, rewriting:
//!
//! - the IPv4 total length **or** IPv6 payload length;
//! - the IPv4 identification field, and its header checksum;
//! - the TCP sequence number;
//! - `PSH` and `FIN`, which belong only on the last segment;
//! - the TCP checksum, which the kernel did **not** compute — `NEEDS_CSUM` says
//!   so, and leaves only a pseudo-header partial sum in the field.
//!
//! Every one of those is silent when wrong: a bad checksum is dropped by the
//! far end's stack with no error anywhere, and a bad sequence number stalls a
//! connection rather than failing it. So this module is pure — no syscalls, no
//! device — and tested directly.

use core::net::{Ipv4Addr, Ipv6Addr};

/// `virtio_net_hdr` — 10 bytes, the size `IFF_VNET_HDR` uses by default.
pub const VNET_HDR_LEN: usize = 10;

/// No segmentation: the buffer is one packet.
pub const GSO_NONE: u8 = 0;
/// TCP over `IPv4`.
pub const GSO_TCPV4: u8 = 1;
/// TCP over `IPv6`.
pub const GSO_TCPV6: u8 = 4;
/// ECN bit, or-ed into `gso_type`; it does not change how we split.
pub const GSO_ECN: u8 = 0x80;

/// The checksum is **not** computed; `csum_start`/`csum_offset` say where it
/// goes and the field holds a partial sum.
pub const F_NEEDS_CSUM: u8 = 1;

/// A parsed `virtio_net_hdr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VnetHdr {
    /// `VIRTIO_NET_HDR_F_*`.
    pub flags: u8,
    /// `VIRTIO_NET_HDR_GSO_*`, possibly with [`GSO_ECN`].
    pub gso_type: u8,
    /// Length of the combined L2/L3/L4 headers.
    pub hdr_len: u16,
    /// Size of each original segment's payload.
    pub gso_size: u16,
    /// Offset at which checksumming starts.
    pub csum_start: u16,
    /// Offset within that at which the checksum field sits.
    pub csum_offset: u16,
}

impl VnetHdr {
    /// Parse the 10-byte header from the front of a read buffer.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let h = buf.first_chunk::<VNET_HDR_LEN>()?;
        let [flags, gso_type, h0, h1, g0, g1, s0, s1, o0, o1] = *h;
        Some(Self {
            flags,
            gso_type,
            hdr_len: u16::from_le_bytes([h0, h1]),
            gso_size: u16::from_le_bytes([g0, g1]),
            csum_start: u16::from_le_bytes([s0, s1]),
            csum_offset: u16::from_le_bytes([o0, o1]),
        })
    }

    /// The all-zero header, which is what a plain packet is written with.
    #[must_use]
    pub fn encode(&self) -> [u8; VNET_HDR_LEN] {
        let [h0, h1] = self.hdr_len.to_le_bytes();
        let [g0, g1] = self.gso_size.to_le_bytes();
        let [s0, s1] = self.csum_start.to_le_bytes();
        let [o0, o1] = self.csum_offset.to_le_bytes();
        [self.flags, self.gso_type, h0, h1, g0, g1, s0, s1, o0, o1]
    }

    /// Whether this buffer needs splitting at all.
    #[must_use]
    pub fn is_segmented(&self) -> bool {
        self.gso_type & !GSO_ECN != GSO_NONE && self.gso_size > 0
    }
}

// ── checksums ───────────────────────────────────────────────────────────────

/// One's-complement sum of 16-bit big-endian words, as RFC 1071 defines it.
///
/// Returned unfolded so callers can accumulate across regions.
fn sum16(bytes: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for c in &mut chunks {
        if let [hi, lo] = *c {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hi, lo])));
        }
    }
    // An odd trailing byte is the high half of a zero-padded word.
    if let Some(&last) = chunks.remainder().first() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([last, 0])));
    }
    sum
}

/// Fold carries and complement — the final step of every Internet checksum.
fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    #[allow(clippy::cast_possible_truncation)]
    let folded = sum as u16;
    !folded
}

/// IPv4 header checksum, computed with the field itself treated as zero.
fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for (i, c) in header.chunks_exact(2).enumerate() {
        // Bytes 10..12 are the checksum field.
        if i == 5 {
            continue;
        }
        if let [hi, lo] = *c {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hi, lo])));
        }
    }
    fold(sum)
}

/// TCP checksum over the IPv4 pseudo-header plus the segment.
fn tcp_checksum_v4(src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> u16 {
    let mut sum = sum16(&src.octets()).wrapping_add(sum16(&dst.octets()));
    sum = sum.wrapping_add(u32::from(6u16)); // protocol
    sum = sum.wrapping_add(u32::from(u16::try_from(segment.len()).unwrap_or(u16::MAX)));
    fold(sum.wrapping_add(sum16(segment)))
}

/// TCP checksum over the IPv6 pseudo-header plus the segment.
fn tcp_checksum_v6(src: Ipv6Addr, dst: Ipv6Addr, segment: &[u8]) -> u16 {
    let mut sum = sum16(&src.octets()).wrapping_add(sum16(&dst.octets()));
    let len = u32::try_from(segment.len()).unwrap_or(u32::MAX);
    sum = sum.wrapping_add(len >> 16).wrapping_add(len & 0xFFFF);
    sum = sum.wrapping_add(u32::from(6u16)); // next header
    fold(sum.wrapping_add(sum16(segment)))
}

// ── splitting ───────────────────────────────────────────────────────────────

/// Field offsets shared by both IP versions' TCP headers.
mod tcp {
    pub(super) const SEQ: usize = 4;
    pub(super) const DATA_OFFSET: usize = 12;
    pub(super) const FLAGS: usize = 13;
    pub(super) const CHECKSUM: usize = 16;
    /// `FIN` and `PSH`, which belong only on the final segment.
    pub(super) const FIN: u8 = 0x01;
    pub(super) const PSH: u8 = 0x08;
}

/// Why a coalesced buffer could not be split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitError {
    /// Truncated, or shorter than the headers it claims.
    Malformed,
    /// A `gso_type` this implementation does not produce or expect.
    UnsupportedGso(u8),
    /// Splitting would produce more segments than the caller allowed.
    TooManySegments,
}

/// Split a coalesced TCP super-segment into wire-legal packets.
///
/// `packet` is the IP packet as read from the device, *without* the
/// `virtio_net_hdr`. Each returned packet is a complete, checksummed IP packet
/// carrying at most `hdr.gso_size` bytes of TCP payload.
///
/// An unsegmented buffer is returned unchanged as a single packet, so callers
/// need no special case.
///
/// # Errors
/// [`SplitError`] if the buffer is malformed or the segmentation type is not
/// TCP over IPv4 or IPv6.
pub fn split_gso(
    packet: &[u8],
    hdr: &VnetHdr,
    max_segments: usize,
) -> Result<Vec<Vec<u8>>, SplitError> {
    if !hdr.is_segmented() {
        // **Not necessarily a finished packet.** With `TUN_F_CSUM` the kernel
        // declines to compute L4 checksums for locally generated traffic and
        // sets `NEEDS_CSUM` on *every* packet, coalesced or not — leaving only
        // a pseudo-header partial sum in the field. Passing such a packet
        // through unchanged puts a wrong checksum on the wire, and the far end
        // discards it silently: ICMP keeps working (never offloaded) while TCP
        // never completes a handshake. That is exactly how this was found.
        let mut one = packet.to_vec();
        if hdr.flags & F_NEEDS_CSUM != 0 {
            complete_checksum(&mut one, hdr)?;
        }
        return Ok(vec![one]);
    }
    match hdr.gso_type & !GSO_ECN {
        GSO_TCPV4 => split_tcp(packet, hdr, max_segments, true),
        GSO_TCPV6 => split_tcp(packet, hdr, max_segments, false),
        other => Err(SplitError::UnsupportedGso(other)),
    }
}

/// Finish a checksum the kernel left partial — the virtio `NEEDS_CSUM` contract.
///
/// The field at `csum_start + csum_offset` already holds the pseudo-header sum,
/// so summing the region from `csum_start` onwards — the field included —
/// and folding yields the complete checksum. A result of zero is transmitted as
/// `0xFFFF` for UDP, where zero means "no checksum"; TCP has no such rule but
/// the substitution is harmless there.
fn complete_checksum(packet: &mut [u8], hdr: &VnetHdr) -> Result<(), SplitError> {
    let start = usize::from(hdr.csum_start);
    let offset = usize::from(hdr.csum_offset);
    let field = start.checked_add(offset).ok_or(SplitError::Malformed)?;
    if field.checked_add(2).ok_or(SplitError::Malformed)? > packet.len() {
        return Err(SplitError::Malformed);
    }
    let sum = packet.get(start..).ok_or(SplitError::Malformed)?;
    let mut csum = fold(sum16(sum));
    if csum == 0 {
        csum = 0xFFFF;
    }
    let slot = packet
        .get_mut(field..field + 2)
        .ok_or(SplitError::Malformed)?;
    slot.copy_from_slice(&csum.to_be_bytes());
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn split_tcp(
    packet: &[u8],
    hdr: &VnetHdr,
    max_segments: usize,
    v4: bool,
) -> Result<Vec<Vec<u8>>, SplitError> {
    let ip_hdr_len = if v4 {
        let first = *packet.first().ok_or(SplitError::Malformed)?;
        let len = usize::from(first & 0x0F) * 4;
        if len < 20 {
            return Err(SplitError::Malformed);
        }
        len
    } else {
        40
    };

    let tcp_off = ip_hdr_len;
    let tcp_hdr = packet.get(tcp_off..).ok_or(SplitError::Malformed)?;
    let data_offset =
        usize::from((*tcp_hdr.get(tcp::DATA_OFFSET).ok_or(SplitError::Malformed)? >> 4) & 0x0F) * 4;
    if data_offset < 20 {
        return Err(SplitError::Malformed);
    }
    let header_len = tcp_off
        .checked_add(data_offset)
        .ok_or(SplitError::Malformed)?;
    let headers = packet.get(..header_len).ok_or(SplitError::Malformed)?;
    let payload = packet.get(header_len..).ok_or(SplitError::Malformed)?;

    let gso = usize::from(hdr.gso_size);
    if gso == 0 {
        return Err(SplitError::Malformed);
    }
    let count = payload.len().div_ceil(gso).max(1);
    if count > max_segments {
        return Err(SplitError::TooManySegments);
    }

    // Addresses and the starting sequence number, read once.
    let (src4, dst4, src6, dst6) = if v4 {
        (
            Ipv4Addr::from(
                *packet
                    .get(12..16)
                    .and_then(|s| s.first_chunk::<4>())
                    .ok_or(SplitError::Malformed)?,
            ),
            Ipv4Addr::from(
                *packet
                    .get(16..20)
                    .and_then(|s| s.first_chunk::<4>())
                    .ok_or(SplitError::Malformed)?,
            ),
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::UNSPECIFIED,
        )
    } else {
        (
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv6Addr::from(
                *packet
                    .get(8..24)
                    .and_then(|s| s.first_chunk::<16>())
                    .ok_or(SplitError::Malformed)?,
            ),
            Ipv6Addr::from(
                *packet
                    .get(24..40)
                    .and_then(|s| s.first_chunk::<16>())
                    .ok_or(SplitError::Malformed)?,
            ),
        )
    };
    let base_seq = u32::from_be_bytes(
        *tcp_hdr
            .get(tcp::SEQ..tcp::SEQ + 4)
            .and_then(|s| s.first_chunk::<4>())
            .ok_or(SplitError::Malformed)?,
    );
    let base_flags = *tcp_hdr.get(tcp::FLAGS).ok_or(SplitError::Malformed)?;
    let base_id = if v4 {
        u16::from_be_bytes(
            *packet
                .get(4..6)
                .and_then(|s| s.first_chunk::<2>())
                .ok_or(SplitError::Malformed)?,
        )
    } else {
        0
    };

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let start = i.checked_mul(gso).ok_or(SplitError::Malformed)?;
        let end = start
            .checked_add(gso)
            .ok_or(SplitError::Malformed)?
            .min(payload.len());
        let chunk = payload.get(start..end).ok_or(SplitError::Malformed)?;
        let last = i + 1 == count;

        let mut seg = Vec::with_capacity(header_len + chunk.len());
        seg.extend_from_slice(headers);
        seg.extend_from_slice(chunk);

        let total = seg.len();

        // ── IP header ──
        if v4 {
            let total16 = u16::try_from(total).map_err(|_| SplitError::Malformed)?;
            if let Some(f) = seg.get_mut(2..4) {
                f.copy_from_slice(&total16.to_be_bytes());
            }
            // A distinct identification per segment, as the kernel would have
            // produced had it sent them separately.
            let id = base_id.wrapping_add(u16::try_from(i).unwrap_or(0));
            if let Some(f) = seg.get_mut(4..6) {
                f.copy_from_slice(&id.to_be_bytes());
            }
            if let Some(f) = seg.get_mut(10..12) {
                f.copy_from_slice(&[0, 0]);
            }
            let sum = seg
                .get(..ip_hdr_len)
                .map(ipv4_header_checksum)
                .ok_or(SplitError::Malformed)?;
            if let Some(f) = seg.get_mut(10..12) {
                f.copy_from_slice(&sum.to_be_bytes());
            }
        } else {
            // IPv6 carries the payload length, excluding the fixed header.
            let payload_len =
                u16::try_from(total.saturating_sub(40)).map_err(|_| SplitError::Malformed)?;
            if let Some(f) = seg.get_mut(4..6) {
                f.copy_from_slice(&payload_len.to_be_bytes());
            }
        }

        // ── TCP header ──
        let seq = base_seq.wrapping_add(u32::try_from(start).unwrap_or(0));
        if let Some(f) = seg.get_mut(tcp_off + tcp::SEQ..tcp_off + tcp::SEQ + 4) {
            f.copy_from_slice(&seq.to_be_bytes());
        }
        // PSH and FIN belong to the end of the original stream only. Repeating
        // FIN on every segment would close the connection early; repeating PSH
        // is harmless but wrong.
        if !last {
            if let Some(f) = seg.get_mut(tcp_off + tcp::FLAGS) {
                *f = base_flags & !(tcp::FIN | tcp::PSH);
            }
        }

        // ── TCP checksum ──
        // Zeroed first: the kernel left a pseudo-header partial sum here, and
        // summing over it would double-count.
        if let Some(f) = seg.get_mut(tcp_off + tcp::CHECKSUM..tcp_off + tcp::CHECKSUM + 2) {
            f.copy_from_slice(&[0, 0]);
        }
        let sum = {
            let segment = seg.get(tcp_off..).ok_or(SplitError::Malformed)?;
            if v4 {
                tcp_checksum_v4(src4, dst4, segment)
            } else {
                tcp_checksum_v6(src6, dst6, segment)
            }
        };
        if let Some(f) = seg.get_mut(tcp_off + tcp::CHECKSUM..tcp_off + tcp::CHECKSUM + 2) {
            f.copy_from_slice(&sum.to_be_bytes());
        }

        out.push(seg);
    }
    Ok(out)
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

    /// Build a TCP-over-IPv4 packet with `payload_len` bytes of payload.
    fn v4_tcp(payload_len: usize, seq: u32, flags: u8) -> Vec<u8> {
        let mut p = vec![0u8; 20 + 20 + payload_len];
        p[0] = 0x45;
        let total = u16::try_from(p.len()).unwrap();
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // identification
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[20..22].copy_from_slice(&1234u16.to_be_bytes()); // src port
        p[22..24].copy_from_slice(&80u16.to_be_bytes()); // dst port
        p[24..28].copy_from_slice(&seq.to_be_bytes());
        p[32] = 5 << 4; // data offset = 5 words
        p[33] = flags;
        for (i, b) in p[40..].iter_mut().enumerate() {
            *b = u8::try_from(i % 251).unwrap();
        }
        p
    }

    fn gso(size: u16, ty: u8) -> VnetHdr {
        VnetHdr {
            flags: F_NEEDS_CSUM,
            gso_type: ty,
            hdr_len: 40,
            gso_size: size,
            csum_start: 20,
            csum_offset: 16,
        }
    }

    #[test]
    fn the_header_round_trips() {
        let h = gso(1400, GSO_TCPV4);
        assert_eq!(VnetHdr::parse(&h.encode()), Some(h));
        assert_eq!(VnetHdr::parse(&[0u8; VNET_HDR_LEN - 1]), None);
    }

    #[test]
    fn an_unsegmented_buffer_passes_through_untouched() {
        let p = v4_tcp(100, 1000, tcp::PSH);
        let out = split_gso(&p, &VnetHdr::default(), 64).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], p, "a plain packet must not be rewritten");
    }

    /// The headline property: N segments, each carrying `gso_size` payload.
    #[test]
    fn a_coalesced_segment_splits_into_wire_legal_packets() {
        let p = v4_tcp(4000, 1000, tcp::PSH);
        let out = split_gso(&p, &gso(1000, GSO_TCPV4), 64).unwrap();

        assert_eq!(out.len(), 4);
        for (i, seg) in out.iter().enumerate() {
            assert_eq!(seg.len(), 40 + 1000, "segment {i} has the wrong size");
            let total = u16::from_be_bytes([seg[2], seg[3]]);
            assert_eq!(usize::from(total), seg.len(), "IPv4 total length");
        }
    }

    /// Sequence numbers must advance by the payload carried, or the receiver
    /// sees a hole and the connection stalls.
    #[test]
    fn sequence_numbers_advance_by_the_payload_length() {
        let p = v4_tcp(3000, 5000, 0);
        let out = split_gso(&p, &gso(1000, GSO_TCPV4), 64).unwrap();
        for (i, seg) in out.iter().enumerate() {
            let seq = u32::from_be_bytes([seg[24], seg[25], seg[26], seg[27]]);
            assert_eq!(
                seq,
                5000 + u32::try_from(i).unwrap() * 1000,
                "segment {i} sequence"
            );
        }
    }

    /// `FIN` on every segment would close the connection at the first one.
    #[test]
    fn fin_and_psh_appear_only_on_the_last_segment() {
        let p = v4_tcp(3000, 1, tcp::FIN | tcp::PSH | 0x10);
        let out = split_gso(&p, &gso(1000, GSO_TCPV4), 64).unwrap();
        for seg in out.iter().take(out.len() - 1) {
            assert_eq!(seg[33] & tcp::FIN, 0, "FIN must not repeat");
            assert_eq!(seg[33] & tcp::PSH, 0, "PSH must not repeat");
            assert_eq!(seg[33] & 0x10, 0x10, "ACK must survive");
        }
        let last = out.last().unwrap();
        assert_eq!(last[33] & tcp::FIN, tcp::FIN, "FIN belongs on the last");
        assert_eq!(last[33] & tcp::PSH, tcp::PSH);
    }

    /// A wrong checksum is dropped silently by the far end, so it is verified
    /// the way a receiver would: summing the whole segment must yield zero.
    #[test]
    fn every_segment_carries_a_valid_tcp_checksum() {
        let p = v4_tcp(2500, 77, tcp::PSH);
        let out = split_gso(&p, &gso(1000, GSO_TCPV4), 64).unwrap();
        for (i, seg) in out.iter().enumerate() {
            let src = Ipv4Addr::new(seg[12], seg[13], seg[14], seg[15]);
            let dst = Ipv4Addr::new(seg[16], seg[17], seg[18], seg[19]);
            // Recomputing over a segment that already contains its checksum
            // must fold to zero — the standard receiver-side check.
            let mut sum = sum16(&src.octets()).wrapping_add(sum16(&dst.octets()));
            sum = sum.wrapping_add(6);
            sum = sum.wrapping_add(u32::try_from(seg.len() - 20).unwrap());
            sum = sum.wrapping_add(sum16(&seg[20..]));
            assert_eq!(fold(sum), 0, "segment {i} has a bad TCP checksum");
        }
    }

    #[test]
    fn every_segment_carries_a_valid_ipv4_header_checksum() {
        let p = v4_tcp(2500, 1, 0);
        let out = split_gso(&p, &gso(1000, GSO_TCPV4), 64).unwrap();
        for (i, seg) in out.iter().enumerate() {
            let mut sum = 0u32;
            for c in seg[..20].chunks_exact(2) {
                sum = sum.wrapping_add(u32::from(u16::from_be_bytes([c[0], c[1]])));
            }
            assert_eq!(fold(sum), 0, "segment {i} has a bad IPv4 checksum");
        }
    }

    /// Each segment needs its own identification, or a middlebox reassembling
    /// IP fragments could conflate them.
    #[test]
    fn identification_differs_per_segment() {
        let p = v4_tcp(3000, 1, 0);
        let out = split_gso(&p, &gso(1000, GSO_TCPV4), 64).unwrap();
        let ids: Vec<u16> = out
            .iter()
            .map(|s| u16::from_be_bytes([s[4], s[5]]))
            .collect();
        assert_eq!(ids, vec![0x1234, 0x1235, 0x1236]);
    }

    /// A trailing partial segment is normal and must not be padded.
    #[test]
    fn a_short_final_segment_keeps_its_true_length() {
        let p = v4_tcp(2500, 1, 0);
        let out = split_gso(&p, &gso(1000, GSO_TCPV4), 64).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[2].len(), 40 + 500, "the tail must not be padded");
        let total = u16::from_be_bytes([out[2][2], out[2][3]]);
        assert_eq!(usize::from(total), out[2].len());
    }

    /// The payload must survive the round trip byte-for-byte.
    #[test]
    fn concatenated_payloads_reproduce_the_original() {
        let p = v4_tcp(3333, 1, 0);
        let out = split_gso(&p, &gso(1000, GSO_TCPV4), 64).unwrap();
        let rebuilt: Vec<u8> = out.iter().flat_map(|s| s[40..].to_vec()).collect();
        assert_eq!(rebuilt, p[40..], "payload must be preserved exactly");
    }

    #[test]
    fn ipv6_segments_carry_the_right_payload_length() {
        let mut p = vec![0u8; 40 + 20 + 2500];
        p[0] = 0x60;
        p[6] = 6; // next header = TCP
        p[8..24].copy_from_slice(&Ipv6Addr::new(0xfd7a, 0, 0, 0, 0, 0, 0, 1).octets());
        p[24..40].copy_from_slice(&Ipv6Addr::new(0xfd7a, 0, 0, 0, 0, 0, 0, 2).octets());
        p[52] = 5 << 4; // data offset
        let out = split_gso(&p, &gso(1000, GSO_TCPV6), 64).unwrap();

        assert_eq!(out.len(), 3);
        for seg in &out {
            let plen = u16::from_be_bytes([seg[4], seg[5]]);
            assert_eq!(usize::from(plen), seg.len() - 40, "IPv6 payload length");
        }
    }

    #[test]
    fn a_segment_count_over_the_cap_is_refused() {
        // 20 segments against a cap of 8. The payload stays under 65535 so the
        // IPv4 total-length field can still express the coalesced buffer.
        let p = v4_tcp(20_000, 1, 0);
        assert_eq!(
            split_gso(&p, &gso(1000, GSO_TCPV4), 8),
            Err(SplitError::TooManySegments)
        );
    }

    #[test]
    fn unsupported_segmentation_is_refused_rather_than_guessed_at() {
        let p = v4_tcp(1000, 1, 0);
        // UDP fragmentation offload: a type this never produces.
        assert_eq!(
            split_gso(&p, &gso(1000, 3), 64),
            Err(SplitError::UnsupportedGso(3))
        );
    }

    /// The kernel is trusted, but the buffer still arrives from a device and a
    /// malformed one must not panic.
    #[test]
    fn malformed_buffers_are_rejected_not_panicked_on() {
        for len in 0..80 {
            let p = vec![0x45u8; len];
            let _ = split_gso(&p, &gso(100, GSO_TCPV4), 64);
            let _ = split_gso(&p, &gso(100, GSO_TCPV6), 64);
        }
        let mut state = 0x243F_6A88_85A3_08D3u64;
        for len in [40usize, 60, 100, 500] {
            for _ in 0..200 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let p: Vec<u8> = state
                    .to_le_bytes()
                    .iter()
                    .copied()
                    .cycle()
                    .take(len)
                    .collect();
                let _ = split_gso(&p, &gso(64, GSO_TCPV4), 64);
                let _ = split_gso(&p, &gso(64, GSO_TCPV6), 64);
            }
        }
    }

    /// **Regression for the `NEEDS_CSUM` trap.** An unsegmented packet whose
    /// checksum the kernel left partial must be completed, not passed through.
    ///
    /// Missing this broke TCP through the tunnel entirely while leaving ICMP
    /// working, because ICMP is never checksum-offloaded — `ping` succeeded and
    /// `iperf3` hung.
    #[test]
    fn an_unsegmented_packet_with_a_partial_checksum_is_completed() {
        let mut p = v4_tcp(200, 42, tcp::PSH);
        // What the kernel hands over: the pseudo-header sum in the field, the
        // rest uncomputed.
        let partial = {
            let mut sum = sum16(&[10, 0, 0, 1]).wrapping_add(sum16(&[10, 0, 0, 2]));
            sum = sum.wrapping_add(6);
            sum = sum.wrapping_add(u32::try_from(p.len() - 20).unwrap());
            !fold(sum) // the un-complemented partial, as virtio specifies
        };
        p[36..38].copy_from_slice(&partial.to_be_bytes());

        let hdr = VnetHdr {
            flags: F_NEEDS_CSUM,
            gso_type: GSO_NONE,
            hdr_len: 40,
            gso_size: 0,
            csum_start: 20,
            csum_offset: 16,
        };
        let out = split_gso(&p, &hdr, 64).unwrap();
        assert_eq!(out.len(), 1);

        // Verified the way a receiver does: the whole segment must fold to zero.
        let seg = &out[0];
        let mut sum = sum16(&[10, 0, 0, 1]).wrapping_add(sum16(&[10, 0, 0, 2]));
        sum = sum.wrapping_add(6);
        sum = sum.wrapping_add(u32::try_from(seg.len() - 20).unwrap());
        sum = sum.wrapping_add(sum16(&seg[20..]));
        assert_eq!(fold(sum), 0, "the completed checksum must be valid");
    }

    /// Without `NEEDS_CSUM` the packet is already finished and must not be
    /// touched — recomputing over a valid checksum would invalidate it.
    #[test]
    fn a_packet_without_needs_csum_is_left_alone() {
        let p = v4_tcp(200, 42, tcp::PSH);
        let hdr = VnetHdr {
            flags: 0,
            gso_type: GSO_NONE,
            csum_start: 20,
            csum_offset: 16,
            ..VnetHdr::default()
        };
        assert_eq!(split_gso(&p, &hdr, 64).unwrap()[0], p);
    }

    /// ECN is or-ed into the type and must not change how splitting works.
    #[test]
    fn the_ecn_bit_does_not_change_the_split() {
        let p = v4_tcp(2000, 1, 0);
        let plain = split_gso(&p, &gso(1000, GSO_TCPV4), 64).unwrap();
        let ecn = split_gso(&p, &gso(1000, GSO_TCPV4 | GSO_ECN), 64).unwrap();
        assert_eq!(plain, ecn);
    }
}
