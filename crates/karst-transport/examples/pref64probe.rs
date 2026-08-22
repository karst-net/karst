// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Solicit routers on one interface and print the NAT64 prefix they advertise.
//!
//! The helper `tests/pref64.rs` runs inside a network namespace, in the same
//! way `karst-disco`'s `natprobe` does: the test process cannot enter a
//! namespace without `setns`, so the thing under test is a small program that
//! `ip netns exec` can launch there.
//!
//! Prints the prefix on success and `none` otherwise, so the caller reads one
//! line rather than parsing a log.

use std::time::{Duration, Instant};

use karst_transport::{Nat64Prefix, RouterSocket};

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(interface) = args.next() else {
        eprintln!("usage: pref64probe <interface>");
        std::process::exit(2);
    };
    let Some(index) = index_of(&interface) else {
        eprintln!("no such IPv6 interface: {interface}");
        std::process::exit(2);
    };

    let socket = match RouterSocket::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot open an ICMPv6 socket: {e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = socket.solicit(index) {
        eprintln!("cannot solicit on {interface}: {e}");
        std::process::exit(2);
    }

    let mut buf = [0u8; 1280];
    let deadline = Instant::now() + Duration::from_secs(5);
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        let Ok(n) = socket.recv_advertisement(&mut buf, left) else {
            break;
        };
        if let Some(prefix) = buf
            .get(..n)
            .and_then(Nat64Prefix::from_router_advertisement)
        {
            println!("{prefix}");
            return;
        }
    }
    println!("none");
}

/// The kernel index of an interface with an IPv6 address, from
/// `/proc/net/if_inet6` — which gives the index directly, where an address
/// alone would not.
fn index_of(name: &str) -> Option<u32> {
    let text = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    text.lines().find_map(|line| {
        let mut f = line.split_whitespace();
        let _address = f.next()?;
        let index = u32::from_str_radix(f.next()?, 16).ok()?;
        (f.nth(3)? == name).then_some(index)
    })
}
