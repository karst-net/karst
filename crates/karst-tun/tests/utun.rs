// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Tests against a **real macOS `utun` device**.
//!
//! The macOS counterpart to `tests/device.rs`, split the same way and for the
//! same reason: creating an interface needs root, an ordinary test runner does
//! not have it, and a test that always passes because it never runs is worse
//! than no test.
//!
//! - The unprivileged tests run everywhere macOS runs and assert what an
//!   unprivileged process must observe: a clean, named error rather than a
//!   panic or a half-built interface.
//! - The privileged tests are `#[ignore]`d and run explicitly:
//!   `sudo cargo test -p karst-tun --test utun -- --ignored --test-threads=1`.
//!
//! `--test-threads=1` matters: each of these creates a real interface, and the
//! kernel hands out the units in order.
//!
//! # What the assertions may and may not assume
//!
//! **Not the interface name.** macOS allocates it, so these tests check its
//! *shape* — `utunN` — and then use whatever they were given. A test that
//! hard-coded `utun3` would pass on a bare CI runner and fail on any developer
//! machine with a VPN already running, which is the failure mode the name
//! audit in `plans/phase-5/06-macos-client.md` §2 exists to prevent.

#![cfg(target_os = "macos")]
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::process::Command;

use karst_tun::{Tun, TunConfig, TunError};

/// Whether this run can create an interface at all.
///
/// Returns false so a developer running `--ignored` without `sudo` gets a skip
/// rather than a wall of failures. **CI sets
/// `KARST_REQUIRE_PREREQUISITES=1`**, which turns that skip into a failure —
/// the same arrangement the Linux privileged suites use, and for the same
/// reason: a suite that quietly skips reports success for work it never did.
fn have_prerequisites() -> bool {
    if Tun::create(&TunConfig::default()).is_ok() {
        return true;
    }
    assert!(
        std::env::var_os("KARST_REQUIRE_PREREQUISITES").is_none(),
        "KARST_REQUIRE_PREREQUISITES is set, so skipping is not allowed — \
         creating a utun interface needs root and this run does not have it"
    );
    false
}

/// `ifconfig <name>`, as the kernel's own account of the interface. Reading
/// our own return values back would be circular.
fn ifconfig(name: &str) -> String {
    let out = Command::new("/sbin/ifconfig")
        .arg(name)
        .output()
        .expect("ifconfig runs on every macOS install");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

// ── unprivileged ────────────────────────────────────────────────────────────

/// Without root the failure must be a named error, not a panic and not a
/// half-built interface.
///
/// The refusal arrives at a different point than on Linux, and that is the
/// thing worth pinning: the `PF_SYSTEM` socket opens for anyone, and it is the
/// `connect` that creates the interface which is refused. An error naming the
/// open would mean the operation was misattributed.
#[test]
fn an_unprivileged_create_fails_cleanly() {
    match Tun::create(&TunConfig::default()) {
        Ok(tun) => {
            // Running as root. Verify the success path instead of asserting a
            // failure that cannot happen here.
            assert!(
                tun.name().starts_with("utun"),
                "macOS names the interface: {}",
                tun.name()
            );
            assert_eq!(tun.mtu(), 1280);
        }
        Err(TunError::Ioctl { op, source }) => {
            assert!(
                op.contains("connect"),
                "the failing operation must be named, got {op:?}"
            );
            assert_eq!(
                source.kind(),
                std::io::ErrorKind::PermissionDenied,
                "unexpected error: {source}"
            );
        }
        Err(e) => panic!("unexpected error variant: {e}"),
    }
}

/// Configuration errors must be caught before any syscall, so a bad config
/// fails identically whether or not the caller is privileged — and identically
/// to Linux, which is what lets one config file serve both.
#[test]
fn invalid_configuration_is_rejected_before_touching_the_kernel() {
    let bad_mtu = Tun::create(&TunConfig {
        mtu: 1500,
        ..TunConfig::default()
    });
    assert!(matches!(bad_mtu, Err(TunError::InvalidMtu { .. })));

    let bad_name = Tun::create(&TunConfig {
        name: "karst/0".to_owned(),
        ..TunConfig::default()
    });
    assert!(matches!(bad_name, Err(TunError::InvalidName(_))));
}

/// `local_addresses` is a read of the host's own configuration and needs no
/// privileges. It asserts **invariants rather than contents**, because the
/// addresses a CI runner has are not knowable here — but every machine has a
/// loopback address, so a filter that let one through would be caught anywhere
/// this runs.
#[test]
fn the_hosts_own_addresses_are_readable_without_privileges() {
    let addresses = karst_tun::local_addresses().expect("getifaddrs");
    for addr in &addresses {
        assert!(
            !addr.is_loopback(),
            "loopback {addr} was offered as a candidate"
        );
        assert!(!addr.is_unspecified(), "unspecified {addr} was offered");
        assert!(!addr.is_multicast(), "multicast {addr} was offered");
    }
}

/// The routing table is readable unprivileged too. A runner may legitimately
/// have no default route, so the assertion is on the *shape* of the answer:
/// whatever comes back must be a real next hop, never the wildcard that the
/// destination of a default route is encoded with. Returning `0.0.0.0` here
/// would be the signature of the `sockaddr` walk being off by one slot.
#[test]
fn the_default_gateway_is_readable_without_privileges() {
    let gateway = karst_tun::default_gateway().expect("sysctl(NET_RT_DUMP)");
    if let Some(gateway) = gateway {
        assert!(
            !gateway.is_unspecified(),
            "{gateway} is the wildcard destination, not a next hop — the \
             sockaddr walk is reading the wrong slot"
        );
        assert!(!gateway.is_multicast(), "{gateway} cannot be a next hop");
    }
}

// ── privileged ──────────────────────────────────────────────────────────────

/// The interface exists and the kernel agrees about its MTU — checked through
/// `ifconfig` rather than through our own return values.
#[test]
#[ignore = "needs root"]
fn creates_an_interface_the_kernel_agrees_exists() {
    if !have_prerequisites() {
        return;
    }
    let tun = Tun::create(&TunConfig::default()).expect("create");

    assert!(
        tun.name().starts_with("utun"),
        "macOS names the interface: {}",
        tun.name()
    );
    let described = ifconfig(tun.name());
    assert!(
        described.contains("mtu 1280"),
        "the kernel must hold the MTU we set: {described}"
    );
    assert!(
        described.contains("UP"),
        "the interface must be up: {described}"
    );
}

/// The configured name is a **preference** on macOS, and `karst0` is one the
/// platform cannot honor. The contract is that this is not an error and that
/// `name()` reports the truth — anything downstream reading the config value
/// instead would be looking at an interface that does not exist.
#[test]
#[ignore = "needs root"]
fn the_configured_name_is_a_preference_the_platform_may_decline() {
    if !have_prerequisites() {
        return;
    }
    let tun = Tun::create(&TunConfig {
        name: "karst0".to_owned(),
        ..TunConfig::default()
    })
    .expect("a Linux-shaped name must not stop the daemon starting");

    assert_ne!(tun.name(), "karst0");
    assert!(tun.name().starts_with("utun"), "got {}", tun.name());
    assert!(
        !ifconfig(tun.name()).is_empty(),
        "the name reported must be one the kernel knows"
    );
    assert!(tun.ifindex().expect("if_nametoindex") > 0);
}

/// Dropping the handle must remove the interface. `utun` has no persistence
/// flag, but the property is the one that matters and is worth pinning: a
/// crashed daemon must not leave a live interface black-holing every packet
/// the kernel still routes to it.
#[test]
#[ignore = "needs root"]
fn dropping_the_handle_removes_the_interface() {
    if !have_prerequisites() {
        return;
    }
    let name = {
        let tun = Tun::create(&TunConfig::default()).expect("create");
        let name = tun.name().to_owned();
        assert!(!ifconfig(&name).is_empty(), "{name} must exist while held");
        name
    };
    assert!(
        ifconfig(&name).is_empty(),
        "{name} outlived the handle that made it"
    );
}

/// Addressing goes through `ifconfig`, so this is the test that the arguments
/// are the ones macOS wants — a point-to-point interface needs a destination
/// as well as a source, and omitting it is a usage error `ifconfig` reports
/// rather than a wrong address it silently assigns.
#[test]
#[ignore = "needs root"]
fn an_address_and_its_on_link_route_reach_the_kernel() {
    if !have_prerequisites() {
        return;
    }
    let tun = Tun::create(&TunConfig::default()).expect("create");
    let addr = Ipv4Addr::new(10, 77, 0, 1);
    tun.set_ipv4(addr, 24).expect("set_ipv4");

    let described = ifconfig(tun.name());
    assert!(
        described.contains("10.77.0.1"),
        "the address must be on the interface: {described}"
    );

    // The connected route is what makes a peer outside the host address
    // reachable. Without it the kernel sends 10.77.0.2 to the default gateway.
    let routes = Command::new("/usr/sbin/netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .expect("netstat");
    let routes = String::from_utf8_lossy(&routes.stdout);
    assert!(
        routes.contains(tun.name()),
        "the on-link prefix must route over {}: {routes}",
        tun.name()
    );
}

/// Adding a route twice must succeed. A daemon restart re-applies the netmap
/// over routes it left behind, and `set_ipv4`'s connected route overlaps a
/// netmap entry for the same prefix — both would fail if `EEXIST` were fatal.
#[test]
#[ignore = "needs root"]
fn adding_a_route_that_already_exists_succeeds() {
    if !have_prerequisites() {
        return;
    }
    let tun = Tun::create(&TunConfig::default()).expect("create");
    tun.set_ipv4(Ipv4Addr::new(10, 77, 1, 1), 24)
        .expect("set_ipv4");

    let dst = std::net::IpAddr::V4(Ipv4Addr::new(10, 77, 9, 0));
    tun.add_route(dst, 24).expect("first add");
    tun.add_route(dst, 24)
        .expect("adding twice must be idempotent");
    tun.remove_route(dst, 24).expect("first remove");
    tun.remove_route(dst, 24)
        .expect("removing an absent route is not a failure");
}

/// The whole point of the address-family header, end to end: a packet written
/// by the host arrives here as a bare IP packet with the prefix already gone.
///
/// If the prefix were left on, `ip::version` would read `0x00` and refuse. If
/// it were stripped when it was not there, the first four bytes of the IP
/// header would be gone instead.
#[test]
#[ignore = "needs root"]
fn carries_a_real_outbound_packet_from_the_host() {
    use std::net::UdpSocket;

    if !have_prerequisites() {
        return;
    }
    let tun = Tun::create(&TunConfig::default()).expect("create");
    tun.set_ipv4(Ipv4Addr::new(10, 77, 2, 1), 24)
        .expect("set_ipv4");

    // Send to a peer address inside the tunnel's prefix. Nothing answers; the
    // point is that the kernel hands the packet to the interface.
    let socket = UdpSocket::bind("10.77.2.1:0").expect("bind inside the prefix");
    socket.send_to(b"karst", "10.77.2.9:9").expect("send");

    let mut buf = [0u8; 1280];
    let n = tun.recv(&mut buf).expect("a packet from the host");
    let packet = buf.get(..n).expect("in bounds");

    assert_eq!(
        karst_tun::ip::version(packet),
        Some(karst_tun::ip::Version::V4),
        "the address-family prefix must be stripped before the caller sees it"
    );
    let addresses = karst_tun::ip::addresses(packet).expect("addresses");
    assert_eq!(
        addresses.source,
        std::net::IpAddr::V4(Ipv4Addr::new(10, 77, 2, 1))
    );
    assert_eq!(
        addresses.destination,
        std::net::IpAddr::V4(Ipv4Addr::new(10, 77, 2, 9))
    );
}

/// The write direction of the same contract. A packet handed to `send` must
/// reach the host's stack, which means the prefix was prepended — macOS
/// discards a frame without one and reports no error at all.
#[test]
#[ignore = "needs root"]
fn injects_a_packet_the_host_stack_accepts() {
    use std::net::UdpSocket;
    use std::time::Duration;

    if !have_prerequisites() {
        return;
    }
    let tun = Tun::create(&TunConfig::default()).expect("create");
    tun.set_ipv4(Ipv4Addr::new(10, 77, 3, 1), 24)
        .expect("set_ipv4");

    let socket = UdpSocket::bind("10.77.3.1:4242").expect("bind inside the prefix");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");

    // A UDP datagram from a peer inside the prefix to the local socket.
    let packet = udp_packet(
        Ipv4Addr::new(10, 77, 3, 9),
        Ipv4Addr::new(10, 77, 3, 1),
        4242,
        b"karst",
    );
    tun.send(&packet).expect("inject");

    let mut buf = [0u8; 64];
    let (n, from) = socket.recv_from(&mut buf).expect(
        "the host stack must accept the injected packet; a silent drop here is \
         the signature of a missing address-family prefix",
    );
    assert_eq!(buf.get(..n), Some(&b"karst"[..]));
    assert_eq!(from.ip(), std::net::IpAddr::V4(Ipv4Addr::new(10, 77, 3, 9)));
}

#[test]
#[ignore = "needs root"]
fn refuses_to_inject_an_over_mtu_packet() {
    if !have_prerequisites() {
        return;
    }
    let tun = Tun::create(&TunConfig::default()).expect("create");
    let oversized = vec![0x45u8; 1281];
    assert!(matches!(
        tun.send(&oversized),
        Err(TunError::PacketTooLarge {
            len: 1281,
            mtu: 1280
        })
    ));
}

/// One IPv4 UDP datagram, checksums included. The host stack drops a packet
/// whose IP checksum is wrong, so a helper that got this wrong would make the
/// injection test above fail for a reason that has nothing to do with `utun`.
fn udp_packet(src: Ipv4Addr, dst: Ipv4Addr, port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut p = Vec::with_capacity(total);

    p.push(0x45); // IPv4, 5-word header
    p.push(0);
    p.extend_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes()); // identification
    p.extend_from_slice(&0u16.to_be_bytes()); // flags, fragment offset
    p.push(64); // TTL
    p.push(17); // UDP
    p.extend_from_slice(&0u16.to_be_bytes()); // checksum, filled below
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());

    let checksum = ones_complement(p.get(..20).unwrap());
    p.get_mut(10..12)
        .unwrap()
        .copy_from_slice(&checksum.to_be_bytes());

    p.extend_from_slice(&port.to_be_bytes()); // source port
    p.extend_from_slice(&port.to_be_bytes()); // destination port
    p.extend_from_slice(&u16::try_from(udp_len).unwrap().to_be_bytes());
    // A zero UDP checksum is legal for IPv4 and means "not computed".
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

fn ones_complement(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        let word = match pair {
            [hi, lo] => u32::from(u16::from_be_bytes([*hi, *lo])),
            [hi] => u32::from(u16::from_be_bytes([*hi, 0])),
            _ => 0,
        };
        sum += word;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum & 0xffff).unwrap()
}
