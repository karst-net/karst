// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! `local_addresses` against a real kernel.
//!
//! The unit tests in `sys.rs` build netlink messages the way the kernel is
//! documented to lay them out, which is exactly the assumption a hand-written
//! parser can get wrong — a mis-sized `ifaddrmsg`, an attribute walked with the
//! wrong stride, an `IFA_*` constant off by one. Every one of those produces a
//! parser that agrees with its own fixtures and returns nothing on a real host.
//!
//! So this asks the running kernel. It needs no privileges: `RTM_GETADDR` is a
//! read, and a dump of the host's own addresses is not restricted.
//!
//! It asserts **invariants rather than contents**, because the addresses a CI
//! runner or container has are not knowable here. What is knowable is that
//! nothing unreachable may come back — every machine has a loopback address, so
//! a parser returning it would be caught anywhere this runs.

#![cfg(target_os = "linux")]
#![allow(clippy::panic, clippy::expect_used)]

#[test]
fn the_hosts_own_addresses_are_readable_without_privileges() {
    let addresses = karst_tun::local_addresses().expect("RTM_GETADDR dump");

    for addr in &addresses {
        assert!(
            !addr.is_loopback(),
            "loopback {addr} was offered as a candidate; every host has one, so \
             a peer probing it would be probing itself"
        );
        assert!(!addr.is_unspecified(), "the unspecified address {addr}");
        match addr {
            std::net::IpAddr::V4(v4) => assert!(
                !v4.is_link_local(),
                "IPv4 link-local {v4} is reachable from one link and nowhere else"
            ),
            std::net::IpAddr::V6(v6) => {
                assert!(!v6.is_multicast(), "multicast {v6} is not an endpoint");
                assert!(
                    v6.segments().first().is_none_or(|s| s & 0xffc0 != 0xfe80),
                    "IPv6 link-local {v6} is reachable from one link and nowhere else"
                );
            }
        }
    }

    // Not an assertion, because a container with only loopback is a legitimate
    // environment and this test must not fail there. Printed so a run that
    // found nothing is visible rather than silently vacuous.
    if addresses.is_empty() {
        eprintln!(
            "note: no globally scoped addresses on this host, so the dump was \
             parsed but proved nothing about its contents"
        );
    }
}
