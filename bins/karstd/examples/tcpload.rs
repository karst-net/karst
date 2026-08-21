// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! **One instrument for both sides of ADR-0012's gate 1.**
//!
//! The gate asks for throughput and latency "for the same Karst topology and
//! payload as the privileged baseline". The two modes are reached differently —
//! the privileged path through a TUN device and an ordinary socket, userspace
//! mode through a loopback SOCKS5 `CONNECT` — and `iperf3` cannot speak the
//! second. Measuring one mode with `iperf3` and the other with anything else
//! would produce two numbers that are not comparable, which is worse than no
//! number: the difference would include the instrument.
//!
//! So this is the instrument for both, and the *only* difference between the
//! two runs is `--socks5`.
//!
//! ```text
//! tcpload serve  <bind:port>
//! tcpload sink   <target:port> [--socks5 <proxy:port>] [--seconds N]
//! tcpload rtt    <target:port> [--socks5 <proxy:port>] [--count N]
//! ```
//!
//! **Throughput is counted by the receiver**, not the sender: a sender counts
//! bytes it has handed to a socket buffer, which at the end of a run is bytes
//! that have not crossed anything. The server returns its own count and the
//! client reports that.
//!
//! Output is `key<TAB>value` lines, for a script to read.

#![allow(
    clippy::print_stdout,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_precision_loss
)]

use std::io::{Read as _, Write as _};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

/// Sent by the client as the first byte, so one server serves both modes.
const MODE_SINK: u8 = b'S';
const MODE_RTT: u8 = b'R';

/// One write, and the buffer the server reads into. 64 KiB is ~51 tunnel MTUs,
/// so a run is dominated by steady-state segmentation rather than by the first
/// window.
const CHUNK: usize = 64 * 1024;

/// The round-trip payload. Deliberately small: this measures the path's
/// latency, and a message that needed segmenting would measure its bandwidth
/// again.
const PING: usize = 64;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: tcpload serve <bind> | sink <target> [--socks5 P] [--seconds N] \
                 | rtt <target> [--socks5 P] [--count N]";
    let command = args.first().map_or("", String::as_str);
    let addr: SocketAddr = args
        .get(1)
        .unwrap_or_else(|| panic!("{usage}"))
        .parse()
        .expect("address as ip:port");
    let socks5 = flag(&args, "--socks5").map(|s| s.parse().expect("proxy as ip:port"));
    let seconds = flag(&args, "--seconds").map_or(10, |s| s.parse().expect("seconds"));
    let count = flag(&args, "--count").map_or(200, |s| s.parse().expect("count"));

    match command {
        "serve" => serve(addr),
        "sink" => sink(addr, socks5, Duration::from_secs(seconds)),
        "rtt" => rtt(addr, socks5, count),
        _ => panic!("{usage}"),
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let at = args.iter().position(|a| a == name)?;
    args.get(at + 1).cloned()
}

/// Serve until killed. One connection at a time, which is all either mode needs.
fn serve(bind: SocketAddr) {
    let listener = TcpListener::bind(bind).expect("bind");
    println!("listening\t{bind}");
    let _ = std::io::stdout().flush();
    loop {
        let Ok((mut stream, _)) = listener.accept() else {
            continue;
        };
        let mut mode = [0u8; 1];
        if stream.read_exact(&mut mode).is_err() {
            continue;
        }
        match mode[0] {
            MODE_SINK => {
                let mut buffer = vec![0u8; CHUNK];
                let mut total = 0u64;
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => total += n as u64,
                    }
                }
                // The client is waiting for this, and it is the number the run
                // reports. Sent after the read side has closed, so it counts
                // only what actually arrived.
                let _ = stream.write_all(&total.to_be_bytes());
                let _ = stream.flush();
            }
            MODE_RTT => {
                let mut buffer = [0u8; PING];
                while stream.read_exact(&mut buffer).is_ok() {
                    if stream.write_all(&buffer).is_err() {
                        break;
                    }
                    let _ = stream.flush();
                }
            }
            other => eprintln!("tcpload: unknown mode byte {other:#04x}"),
        }
    }
}

/// Push for `duration`, and report what the far end says it received.
fn sink(target: SocketAddr, socks5: Option<SocketAddr>, duration: Duration) {
    let mut stream = connect(target, socks5);
    stream.set_nodelay(true).expect("nodelay");
    stream.write_all(&[MODE_SINK]).expect("mode byte");

    let buffer = vec![0x5au8; CHUNK];
    let start = Instant::now();
    let mut offered = 0u64;
    while start.elapsed() < duration {
        stream.write_all(&buffer).expect("send");
        offered += CHUNK as u64;
    }
    let elapsed = start.elapsed();
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("half-close");

    let mut received = [0u8; 8];
    stream
        .read_exact(&mut received)
        .expect("the receiver's count");
    let received = u64::from_be_bytes(received);

    // Against `elapsed` measured at the sender, which includes the drain the
    // half-close waits for only in `offered`. Both are printed so a large gap
    // between them is visible rather than averaged away.
    let seconds = elapsed.as_secs_f64();
    println!("received_bytes\t{received}");
    println!("offered_bytes\t{offered}");
    println!("seconds\t{seconds:.3}");
    println!(
        "mbps\t{:.1}",
        (received as f64 * 8.0) / seconds / 1_000_000.0
    );
}

/// `count` round trips of [`PING`] bytes, reported as a distribution.
///
/// The distribution rather than the mean: a userspace stack's cost shows up as
/// a tail — a poll loop that misses a wakeup moves the 90th percentile and
/// leaves the mean where it was.
fn rtt(target: SocketAddr, socks5: Option<SocketAddr>, count: usize) {
    let mut stream = connect(target, socks5);
    stream.set_nodelay(true).expect("nodelay");
    stream.write_all(&[MODE_RTT]).expect("mode byte");

    let out = [0x5au8; PING];
    let mut back = [0u8; PING];
    let mut samples = Vec::with_capacity(count);
    for _ in 0..count {
        let at = Instant::now();
        stream.write_all(&out).expect("send");
        stream.flush().expect("flush");
        stream.read_exact(&mut back).expect("receive");
        samples.push(at.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(f64::total_cmp);

    // Nearest-rank, computed in integers: a float index into a sorted vector
    // is one rounding rule away from an off-by-one at the ends.
    let pick = |numerator: usize, denominator: usize| {
        samples[(samples.len() - 1) * numerator / denominator]
    };
    println!("samples\t{}", samples.len());
    println!("rtt_min_ms\t{:.3}", pick(0, 100));
    println!("rtt_p50_ms\t{:.3}", pick(50, 100));
    println!("rtt_p90_ms\t{:.3}", pick(90, 100));
    println!("rtt_p99_ms\t{:.3}", pick(99, 100));
    println!("rtt_max_ms\t{:.3}", pick(100, 100));
}

fn connect(target: SocketAddr, socks5: Option<SocketAddr>) -> TcpStream {
    match socks5 {
        None => TcpStream::connect(target).expect("connect"),
        Some(proxy) => socks_connect(proxy, target),
    }
}

/// RFC 1928, no authentication, IPv4 literal.
///
/// Deliberately a literal address: `karstd`'s listener refuses names, because
/// resolving one through the host resolver would be a path around Karst's
/// packet and policy boundary.
fn socks_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).expect("connect to the SOCKS5 listener");
    stream.write_all(&[0x05, 0x01, 0x00]).expect("greeting");
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).expect("greeting reply");
    assert_eq!(greeting, [0x05, 0x00], "the proxy refused no-auth");

    let IpAddr::V4(v4) = target.ip() else {
        panic!("this instrument uses IPv4 literals");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&v4.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).expect("connect request");

    // 4-byte header, then a bound address the client does not use. IPv4 only,
    // matching the request.
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).expect("connect reply");
    assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT failed: reply {reply:?}");
    stream
}
