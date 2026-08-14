// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Batched socket I/O over real sockets — `sendmmsg`, `recvmmsg`, UDP GSO.
//!
//! This is the FFI the datapath depends on and the only place in the crate with
//! `unsafe`. The kernel writes through pointers into buffers this code owns, so
//! the tests are about *where the bytes land*: right buffer, right length, right
//! source address, nothing written past the end.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use karst_transport::{Received, UdpTransport, BATCH, MAX_DATAGRAM};

fn pair() -> (UdpTransport, UdpTransport, SocketAddr, SocketAddr) {
    let a = UdpTransport::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let b = UdpTransport::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let (aa, ba) = (a.local_addr().unwrap(), b.local_addr().unwrap());
    b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    a.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    (a, b, aa, ba)
}

fn buffers() -> Vec<[u8; MAX_DATAGRAM]> {
    vec![[0u8; MAX_DATAGRAM]; BATCH]
}

/// Collect exactly `want` datagrams, batching as they arrive.
fn drain(sock: &UdpTransport, want: usize) -> Vec<Vec<u8>> {
    let mut bufs = buffers();
    let mut meta: Vec<Received> = Vec::new();
    let mut got = Vec::new();
    while got.len() < want {
        let n = sock.recv_batch(&mut bufs, &mut meta).unwrap();
        if n == 0 {
            break;
        }
        for (i, m) in meta.iter().enumerate() {
            got.push(bufs[i][..m.len].to_vec());
        }
    }
    got
}

#[test]
fn a_batch_of_datagrams_arrives_intact_and_in_order() {
    let (a, b, _, ba) = pair();

    // Distinct lengths and contents, so a mixed-up iovec shows as wrong bytes
    // rather than as a plausible-looking result.
    let payloads: Vec<Vec<u8>> = (0..8u8)
        .map(|i| vec![i; 100 + usize::from(i) * 37])
        .collect();
    let batch: Vec<(&[u8], SocketAddr)> = payloads.iter().map(|p| (p.as_slice(), ba)).collect();

    let sent = a.send_batch(&batch).unwrap();
    assert_eq!(
        sent,
        payloads.len(),
        "one syscall must take the whole batch"
    );

    let got = drain(&b, payloads.len());
    assert_eq!(got.len(), payloads.len());
    for (i, (want, have)) in payloads.iter().zip(got.iter()).enumerate() {
        assert_eq!(want, have, "datagram {i} came back wrong");
    }
}

/// The source address the kernel writes back must be parsed correctly, or
/// inbound datagrams get attributed to the wrong peer.
#[test]
fn the_source_address_survives_the_round_trip() {
    let (a, b, aa, ba) = pair();
    let payload = [0xABu8; 64];
    a.send_batch(&[(&payload[..], ba)]).unwrap();

    let mut bufs = buffers();
    let mut meta = Vec::new();
    assert_eq!(b.recv_batch(&mut bufs, &mut meta).unwrap(), 1);
    assert_eq!(meta[0].from, aa, "source address must match the sender");
    assert_eq!(meta[0].len, payload.len());
}

#[test]
fn ipv6_addresses_round_trip_too() {
    let Ok(a) = UdpTransport::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))) else {
        return; // no IPv6 on this host
    };
    let b = UdpTransport::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))).unwrap();
    b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let (aa, ba) = (a.local_addr().unwrap(), b.local_addr().unwrap());

    let payload = [0xCDu8; 32];
    a.send_batch(&[(&payload[..], ba)]).unwrap();

    let mut bufs = buffers();
    let mut meta = Vec::new();
    assert_eq!(b.recv_batch(&mut bufs, &mut meta).unwrap(), 1);
    assert!(meta[0].from.is_ipv6(), "family must be preserved");
    assert_eq!(meta[0].from.port(), aa.port());
}

/// A full batch, at full datagram size — the shape the datapath actually
/// produces, and the one where a buffer-length mistake would overflow.
#[test]
fn a_full_batch_of_full_size_datagrams_is_exact() {
    let (a, b, _, ba) = pair();
    let payload = vec![0x5Au8; MAX_DATAGRAM];
    let batch: Vec<(&[u8], SocketAddr)> = (0..BATCH).map(|_| (payload.as_slice(), ba)).collect();

    let sent = a.send_batch(&batch).unwrap();
    assert!(sent > 0);

    let got = drain(&b, sent);
    for d in &got {
        assert_eq!(
            d.len(),
            MAX_DATAGRAM,
            "a full-size datagram must not truncate"
        );
        assert!(d.iter().all(|&x| x == 0x5A));
    }
}

/// Nothing may be written past a receive buffer. Sentinel bytes after each
/// buffer would be clobbered by an off-by-one in the `iovec` length.
#[test]
fn the_kernel_never_writes_past_a_receive_buffer() {
    let (a, b, _, ba) = pair();
    let payload = vec![0xFFu8; MAX_DATAGRAM];
    a.send_batch(&[(payload.as_slice(), ba)]).unwrap();

    // One extra buffer, pre-filled with a sentinel that must survive.
    let mut bufs = vec![[0u8; MAX_DATAGRAM]; BATCH];
    bufs[1] = [0x42u8; MAX_DATAGRAM];
    let mut meta = Vec::new();
    assert_eq!(b.recv_batch(&mut bufs, &mut meta).unwrap(), 1);

    assert_eq!(meta[0].len, MAX_DATAGRAM);
    assert!(
        bufs[1].iter().all(|&x| x == 0x42),
        "a datagram was written into the wrong buffer"
    );
}

/// Over-sized datagrams are refused before any syscall, on the batched path
/// exactly as on the single-datagram one — the kernel would IP-fragment them,
/// defeating spec §5.
#[test]
fn oversized_datagrams_are_refused_on_the_batched_path() {
    let (a, _b, _, ba) = pair();
    let too_big = vec![0u8; MAX_DATAGRAM + 1];
    let ok = vec![0u8; 64];

    let err = a
        .send_batch(&[(ok.as_slice(), ba), (too_big.as_slice(), ba)])
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("fragment it first"), "{err}");
}

#[test]
fn an_empty_batch_is_not_an_error() {
    let (a, _b, _, _) = pair();
    assert_eq!(a.send_batch(&[]).unwrap(), 0);
}

/// A batch longer than `BATCH` is truncated rather than rejected, and the
/// caller learns how many went — the contract that makes the loop in the run
/// loop correct.
#[test]
fn a_batch_larger_than_the_limit_reports_what_it_sent() {
    let (a, b, _, ba) = pair();
    let payload = vec![7u8; 64];
    let batch: Vec<(&[u8], SocketAddr)> =
        (0..BATCH * 2).map(|_| (payload.as_slice(), ba)).collect();

    let sent = a.send_batch(&batch).unwrap();
    assert!(sent <= BATCH, "must not exceed one batch, sent {sent}");
    assert!(sent > 0);
    let got = drain(&b, sent);
    assert_eq!(got.len(), sent, "every reported datagram must arrive");
}

// ── UDP GSO ─────────────────────────────────────────────────────────────────

/// One syscall, many datagrams. Segmentation is not available on every path, so
/// an error is tolerated — but if it succeeds, the datagrams must arrive
/// individually and intact.
#[test]
fn segmented_sends_arrive_as_separate_datagrams() {
    const SEGMENT: usize = 1200;
    const COUNT: usize = 4;

    let (a, b, _, ba) = pair();
    let mut payload = Vec::with_capacity(SEGMENT * COUNT);
    for i in 0..COUNT {
        payload.extend(std::iter::repeat_n(u8::try_from(i).unwrap(), SEGMENT));
    }

    let Ok(sent) = a.send_segmented(&payload, u16::try_from(SEGMENT).unwrap(), ba) else {
        // No GSO on this path. The caller's contract is to fall back, so this
        // is a supported outcome rather than a failure.
        return;
    };
    assert_eq!(sent, payload.len());

    let got = drain(&b, COUNT);
    assert_eq!(got.len(), COUNT, "one write must yield {COUNT} datagrams");
    for (i, d) in got.iter().enumerate() {
        assert_eq!(d.len(), SEGMENT, "segment {i} has the wrong length");
        assert!(
            d.iter().all(|&x| x == u8::try_from(i).unwrap()),
            "segment {i} carries the wrong bytes"
        );
    }
}

/// A trailing short segment is legal and must not be padded out.
#[test]
fn a_short_final_segment_is_preserved() {
    const SEGMENT: usize = 800;

    let (a, b, _, ba) = pair();
    let mut payload = vec![1u8; SEGMENT];
    payload.extend(std::iter::repeat_n(2u8, 100)); // short tail

    let Ok(_) = a.send_segmented(&payload, u16::try_from(SEGMENT).unwrap(), ba) else {
        return;
    };
    let got = drain(&b, 2);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].len(), SEGMENT);
    assert_eq!(got[1].len(), 100, "the short tail must not be padded");
}

#[test]
fn a_segment_size_over_the_datagram_limit_is_refused() {
    let (a, _b, _, ba) = pair();
    let payload = vec![0u8; 4096];
    let err = a
        .send_segmented(&payload, u16::try_from(MAX_DATAGRAM + 1).unwrap(), ba)
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

/// The batched and single-datagram paths must agree — the same bytes to the
/// same place, whichever is used.
#[test]
fn batched_and_single_sends_are_indistinguishable_on_the_wire() {
    let (a, b, _, ba) = pair();
    let payload = [0x9Cu8; 512];

    a.send_to(&payload, ba).unwrap();
    let single = drain(&b, 1);

    a.send_batch(&[(&payload[..], ba)]).unwrap();
    let batched = drain(&b, 1);

    assert_eq!(single, batched);
    assert_eq!(single[0], payload.to_vec());
}

/// **A single datagram must return immediately, not after a timeout.**
///
/// `recvmmsg` without `MSG_WAITFORONE` blocks until every slot in the batch is
/// filled. That is invisible in a test that only checks *what* arrives — the
/// call eventually times out and returns what it has, so the assertions pass
/// and the suite merely runs slowly. On a real link it is fatal: a tunnel
/// carrying one packet at a time never fills 32 slots, and nothing flows.
///
/// This asserts the timing, because timing was the only observable difference.
#[test]
fn one_datagram_returns_without_waiting_for_a_full_batch() {
    let (a, b, _, ba) = pair();
    // A generous read timeout: if the batch waits for more datagrams, it can
    // only end by hitting this, and the elapsed time gives it away.
    b.set_read_timeout(Some(Duration::from_secs(4))).unwrap();

    let payload = [0x11u8; 64];
    a.send_batch(&[(&payload[..], ba)]).unwrap();

    let mut bufs = buffers();
    let mut meta = Vec::new();
    let start = std::time::Instant::now();
    let n = b.recv_batch(&mut bufs, &mut meta).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(n, 1);
    assert!(
        elapsed < Duration::from_millis(500),
        "a lone datagram took {elapsed:?} — recvmmsg is waiting for a full batch"
    );
}

/// A partial batch is returned as soon as it is available, in full.
#[test]
fn a_partial_batch_returns_everything_available() {
    let (a, b, _, ba) = pair();
    b.set_read_timeout(Some(Duration::from_secs(4))).unwrap();

    let payload = [0x22u8; 128];
    let batch: Vec<(&[u8], SocketAddr)> = (0..3).map(|_| (&payload[..], ba)).collect();
    a.send_batch(&batch).unwrap();

    let mut bufs = buffers();
    let mut meta = Vec::new();
    let start = std::time::Instant::now();
    let n = b.recv_batch(&mut bufs, &mut meta).unwrap();

    assert!((1..=3).contains(&n), "got {n}");
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "a partial batch must not wait for the rest"
    );
}
