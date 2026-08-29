// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]
//! A minimal UDP probe, for validating NAT topologies.
//!
//! Not part of the product. `tests/nat_matrix.rs` runs copies of this inside
//! network namespaces to establish that each NAT in the matrix behaves the way
//! its name says — before any Karst code is measured through it.
//!
//! That ordering is the point. A matrix whose "symmetric" NAT is quietly
//! endpoint-independent produces a confident direct-connection percentage that
//! means nothing, and the mistake is invisible once the thing under test is a
//! VPN rather than a two-line probe.
//!
//! It is deliberately not `karst-disco`: this measures the *network*, so it
//! must not share code with the thing whose behavior on that network is in
//! question.

use std::env;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "\
natprobe — UDP probe for NAT topology validation

    natprobe reflect <bind>              answer every datagram with the source it came from
    natprobe probe   <bind> <target>     send one datagram, print the reflected source
    natprobe open    <bind> <target>     send one datagram, do not wait (opens a mapping)
    natprobe listen  <bind> <timeout_ms> print RECV <src> or TIMEOUT
";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();

    let result = match refs.as_slice() {
        ["reflect", bind] => reflect(bind),
        ["probe", bind, target] => probe(bind, target),
        ["open", bind, target] => open(bind, target),
        ["listen", bind, timeout] => listen(bind, timeout),
        _ => {
            eprint!("{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("natprobe: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Answer every datagram with the source address it appeared to come from.
///
/// This is `spec/aven-v1.md` §7.2's reflexive function reduced to its smallest
/// form: whatever the NAT rewrote the source to is what comes back.
fn reflect(bind: &str) -> io::Result<()> {
    let sock = UdpSocket::bind(bind)?;
    let mut buf = [0u8; 64];
    loop {
        let (n, src) = sock.recv_from(&mut buf)?;
        let _ = n;
        let reply = format!("{src}");
        sock.send_to(reply.as_bytes(), src)?;
    }
}

/// Send one datagram and print what the reflector saw.
fn probe(bind: &str, target: &str) -> io::Result<()> {
    let sock = UdpSocket::bind(bind)?;
    sock.set_read_timeout(Some(Duration::from_millis(1500)))?;
    let dst: SocketAddr = target
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad target"))?;

    // Three attempts. A first datagram lost to an ARP resolution or a cold
    // conntrack entry would otherwise read as "this NAT blocks traffic", which
    // is exactly the wrong conclusion to draw silently.
    for _ in 0..3 {
        sock.send_to(b"p", dst)?;
        let mut buf = [0u8; 64];
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                let seen = String::from_utf8_lossy(buf.get(..n).unwrap_or_default());
                println!("OBSERVED {seen}");
                return Ok(());
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            }
            Err(e) => return Err(e),
        }
    }
    println!("TIMEOUT");
    Ok(())
}

/// Send one datagram and return, so the NAT holds a mapping afterwards.
fn open(bind: &str, target: &str) -> io::Result<()> {
    let sock = UdpSocket::bind(bind)?;
    let dst: SocketAddr = target
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad target"))?;
    sock.send_to(b"p", dst)?;
    println!("SENT");
    Ok(())
}

/// Wait for one datagram and report whether it arrived.
fn listen(bind: &str, timeout: &str) -> io::Result<()> {
    let ms: u64 = timeout
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad timeout"))?;
    let sock = UdpSocket::bind(bind)?;
    sock.set_read_timeout(Some(Duration::from_millis(ms)))?;
    let mut buf = [0u8; 64];
    match sock.recv_from(&mut buf) {
        Ok((_, src)) => println!("RECV {src}"),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            println!("TIMEOUT");
        }
        Err(e) => return Err(e),
    }
    Ok(())
}
