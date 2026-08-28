// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! One UDP exchange, from inside whatever namespace it is run in.
//!
//! `tests/gateway.rs` drives a real `miniupnpd` and needs the socket to be
//! **created** in the client namespace — a socket bound in one namespace and
//! used from another is on the wrong stack, which is the same mistake
//! `aven-v1.md` §7.6 warns about for reflections. Rust has no `setns` without
//! a libc dependency this crate does not otherwise need, so the I/O happens
//! here, under `ip netns exec`, and the codec stays in the test process where
//! a failure produces a useful assertion rather than a hex dump.
//!
//! This is the same split `karst-disco`'s `natprobe` example uses.
//!
//! ```text
//! pmprobe <bind-ip> <gateway-ip:port> <hex-request>
//! ```
//!
//! Prints `REPLY <hex>` or `TIMEOUT`.

#![allow(clippy::print_stdout, clippy::expect_used, clippy::indexing_slicing)]

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex digit"))
        .collect()
}

fn hex_encode(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, byte| {
        let _ = write!(s, "{byte:02x}");
        s
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(
        args.len() == 4,
        "usage: pmprobe <bind-ip> <gateway-ip:port> <hex-request>"
    );
    let bind: SocketAddr = format!("{}:0", args[1]).parse().expect("bind address");
    let to: SocketAddr = args[2].parse().expect("gateway address");
    let request = hex_decode(&args[3]);

    let sock = UdpSocket::bind(bind).expect("bind");
    sock.set_read_timeout(Some(Duration::from_millis(1500)))
        .expect("timeout");

    // Both protocols specify retransmission; three attempts covers the
    // gateway's startup rather than any real loss on a veth.
    for _ in 0..3 {
        sock.send_to(&request, to).expect("send");
        let mut buf = [0u8; 1500];
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            assert_eq!(from.ip(), to.ip(), "answered by {from}, not the gateway");
            println!("REPLY {}", hex_encode(&buf[..n]));
            return;
        }
    }
    println!("TIMEOUT");
}
