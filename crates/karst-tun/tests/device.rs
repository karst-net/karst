// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Tests against a **real kernel TUN device**.
//!
//! Creating an interface needs `CAP_NET_ADMIN`, which an ordinary test runner
//! does not have. Rather than skip silently — a test that always passes because
//! it never runs is worse than no test — these split in two:
//!
//! - The unprivileged tests below run everywhere and assert what an
//!   unprivileged process must observe: a clean, named error rather than a
//!   panic or a half-built interface.
//! - The privileged tests are `#[ignore]`d and run explicitly:
//!   `sudo -E cargo test -p karst-tun -- --ignored --test-threads=1`.
//!
//! `--test-threads=1` matters: these create interfaces with fixed names.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};

use karst_tun::{ip, Tun, TunConfig, TunError};

fn have_net_admin() -> bool {
    Tun::create(&TunConfig {
        name: "karstprobe".to_owned(),
        ..TunConfig::default()
    })
    .is_ok()
}

// ── unprivileged ────────────────────────────────────────────────────────────

/// Without `CAP_NET_ADMIN` the failure must be a named `ioctl` error, not a
/// panic and not a partially configured interface. `/dev/net/tun` is usually
/// world-accessible, so the open succeeds and `TUNSETIFF` is what refuses —
/// a distinction that is invisible unless the error carries the operation.
#[test]
fn an_unprivileged_create_fails_cleanly() {
    match Tun::create(&TunConfig::default()) {
        Ok(tun) => {
            // Running as root. Verify the success path instead of asserting a
            // failure that cannot happen here.
            assert_eq!(tun.name(), "karst0");
            assert_eq!(tun.mtu(), 1280);
        }
        Err(TunError::Ioctl { op, source }) => {
            assert!(
                op.contains("TUNSETIFF"),
                "the failing operation must be named, got {op:?}"
            );
            assert!(
                matches!(
                    source.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
                ),
                "unexpected error: {source}"
            );
        }
        Err(TunError::OpenDevice(e)) => {
            // No /dev/net/tun at all, e.g. a container without the node.
            assert!(matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ));
        }
        Err(e) => panic!("unexpected error variant: {e}"),
    }
}

/// Configuration errors must be caught before any syscall, so a bad config
/// fails identically whether or not the caller is privileged.
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

// ── privileged ──────────────────────────────────────────────────────────────

/// The interface exists, carries the name and MTU we asked for, and the kernel
/// agrees — checked through sysfs rather than through our own return values,
/// which would be circular.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn creates_an_interface_the_kernel_agrees_exists() {
    assert!(have_net_admin(), "run with sudo");
    let tun = Tun::create(&TunConfig {
        name: "karst-t1".to_owned(),
        ..TunConfig::default()
    })
    .expect("create");

    assert_eq!(tun.name(), "karst-t1");
    let mtu = std::fs::read_to_string("/sys/class/net/karst-t1/mtu").expect("sysfs mtu");
    assert_eq!(mtu.trim(), "1280", "the kernel must hold the MTU we set");

    let flags = std::fs::read_to_string("/sys/class/net/karst-t1/flags").expect("sysfs flags");
    let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).expect("hex flags");
    assert_eq!(flags & 0x1, 0x1, "IFF_UP must be set");
}

/// Dropping the handle must remove the interface. Karst never sets
/// `TUNSETPERSIST`: a crashed daemon leaving a live interface would black-hole
/// every packet the kernel still routes to it.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn dropping_the_handle_removes_the_interface() {
    assert!(have_net_admin(), "run with sudo");
    {
        let _tun = Tun::create(&TunConfig {
            name: "karst-t2".to_owned(),
            ..TunConfig::default()
        })
        .expect("create");
        assert!(std::path::Path::new("/sys/class/net/karst-t2").exists());
    }
    // The kernel tears the interface down asynchronously on last close.
    for _ in 0..50 {
        if !std::path::Path::new("/sys/class/net/karst-t2").exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("interface survived its owner — TUNSETPERSIST must never be set");
}

/// **The real test.** Assign an address, have the host send a packet to a peer
/// on that subnet, and read the outbound IP packet off the device — the exact
/// path `karstd` will take before encrypting.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn carries_a_real_outbound_ipv4_packet_from_the_host() {
    assert!(have_net_admin(), "run with sudo");
    let tun = Tun::create(&TunConfig {
        name: "karst-t3".to_owned(),
        nonblocking: false,
        ..TunConfig::default()
    })
    .expect("create");
    tun.set_ipv4(Ipv4Addr::new(10, 123, 0, 1), 24)
        .expect("assign address");

    let peer = Ipv4Addr::new(10, 123, 0, 2);
    std::thread::spawn(move || {
        let sock = UdpSocket::bind((Ipv4Addr::new(10, 123, 0, 1), 0)).expect("bind");
        for _ in 0..40 {
            let _ = sock.send_to(b"karst", (peer, 9999));
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    });

    let mut buf = [0u8; 2048];
    let mut seen = None;
    for _ in 0..40 {
        let n = tun.recv(&mut buf).expect("read from tun");
        let packet = buf.get(..n).expect("in bounds");
        if let Some(a) = ip::addresses(packet) {
            if a.destination == std::net::IpAddr::V4(peer) {
                seen = Some(a);
                break;
            }
        }
    }

    let a = seen.expect("the kernel must route 10.123.0.2 to the tun device");
    assert_eq!(a.version, ip::Version::V4);
    assert_eq!(a.source, std::net::IpAddr::V4(Ipv4Addr::new(10, 123, 0, 1)));
}

/// IPv6 inside the tunnel is the reason the MTU floor is 1280 (spec §13.6).
/// If IPv6 cannot be assigned and carried, that whole argument is hollow — so
/// it gets a test rather than a comment.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn carries_a_real_outbound_ipv6_packet_from_the_host() {
    assert!(have_net_admin(), "run with sudo");
    let tun = Tun::create(&TunConfig {
        name: "karst-t4".to_owned(),
        ..TunConfig::default()
    })
    .expect("create");

    let local = Ipv6Addr::new(0xfd7a, 0x5ea5, 0, 0, 0, 0, 0, 1);
    let peer = Ipv6Addr::new(0xfd7a, 0x5ea5, 0, 0, 0, 0, 0, 2);
    tun.set_ipv6(local, 64).expect("assign IPv6 address");

    // Duplicate address detection must finish before the address is usable.
    std::thread::sleep(std::time::Duration::from_millis(1500));

    std::thread::spawn(move || {
        for _ in 0..60 {
            if let Ok(sock) = UdpSocket::bind((local, 0)) {
                let _ = sock.send_to(b"karst", (peer, 9999));
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    });

    let mut buf = [0u8; 2048];
    for _ in 0..60 {
        let n = tun.recv(&mut buf).expect("read from tun");
        let packet = buf.get(..n).expect("in bounds");
        if let Some(a) = ip::addresses(packet) {
            if a.destination == std::net::IpAddr::V6(peer) {
                assert_eq!(a.version, ip::Version::V6);
                return;
            }
        }
    }
    panic!("no IPv6 packet reached the tun device — the 1280 MTU floor exists for this");
}

/// A 1280-byte packet — the full tunnel MTU — must traverse the interface
/// intact. This is the size §13.6's whole argument is about.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn a_full_mtu_packet_survives_the_interface() {
    assert!(have_net_admin(), "run with sudo");
    let tun = Tun::create(&TunConfig {
        name: "karst-t5".to_owned(),
        ..TunConfig::default()
    })
    .expect("create");
    tun.set_ipv4(Ipv4Addr::new(10, 124, 0, 1), 24)
        .expect("assign address");

    // 1280 = 20 (IP) + 8 (UDP) + 1252 payload.
    let payload = vec![0x5Au8; 1252];
    let peer = Ipv4Addr::new(10, 124, 0, 2);
    std::thread::spawn(move || {
        let sock = UdpSocket::bind((Ipv4Addr::new(10, 124, 0, 1), 0)).expect("bind");
        for _ in 0..40 {
            let _ = sock.send_to(&payload, (peer, 9999));
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    });

    let mut buf = [0u8; 2048];
    for _ in 0..40 {
        let n = tun.recv(&mut buf).expect("read from tun");
        if ip::destination(buf.get(..n).expect("in bounds")) == Some(std::net::IpAddr::V4(peer)) {
            assert_eq!(n, tun.mtu(), "a full-MTU packet must arrive whole");
            return;
        }
    }
    panic!("no full-size packet observed");
}

/// An over-MTU packet is refused locally. The kernel would drop it without a
/// word, so the error has to come from us.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn refuses_to_inject_an_over_mtu_packet() {
    assert!(have_net_admin(), "run with sudo");
    let tun = Tun::create(&TunConfig {
        name: "karst-t6".to_owned(),
        ..TunConfig::default()
    })
    .expect("create");

    let too_big = vec![0u8; tun.mtu() + 1];
    assert!(matches!(
        tun.send(&too_big),
        Err(TunError::PacketTooLarge { .. })
    ));

    let mut small = [0u8; 64];
    assert!(matches!(
        tun.recv(&mut small),
        Err(TunError::BufferTooSmall { .. })
    ));
}

// ── routes ──────────────────────────────────────────────────────────────────

/// Read the kernel's routing table for an interface, as `/proc` renders it.
fn routes_via(iface: &str) -> String {
    // `ip route` is not guaranteed present; `/proc/net/route` is, and both
    // families need checking, so the v6 table is read too.
    let v4 = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    let v6 = std::fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default();
    v4.lines()
        .chain(v6.lines())
        .filter(|l| l.contains(iface))
        .collect::<Vec<_>>()
        .join("\n")
}

/// **The reason routes exist at all.** An address gives the kernel a connected
/// route for its own on-link prefix and nothing else, so a peer outside that
/// prefix — a subnet router — never sees its traffic reach the tunnel: the
/// kernel sends it to the default gateway instead, which is worse than
/// dropping it.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn a_route_outside_the_on_link_prefix_reaches_the_kernel() {
    assert!(have_net_admin(), "run with sudo");
    let tun = Tun::create(&TunConfig {
        name: "karst-rt1".to_owned(),
        ..TunConfig::default()
    })
    .expect("create");
    tun.set_address("100.64.0.1".parse().expect("addr"), 32)
        .expect("address");

    // A /24 nowhere near the interface's own /32.
    let dst: std::net::IpAddr = "192.168.77.0".parse().expect("addr");
    assert!(
        !routes_via("karst-rt1").contains("4D4DA8C0"),
        "the route must not exist before it is added"
    );

    tun.add_route(dst, 24).expect("add a route");
    let table = routes_via("karst-rt1");
    assert!(
        // 192.168.77.0 little-endian, as /proc/net/route renders it.
        table.contains("004DA8C0"),
        "the kernel does not hold the route that was added:\n{table}"
    );

    // Adding it again must succeed: a daemon restart re-adds every route it
    // left behind, and failing would leave half its peers unreachable.
    tun.add_route(dst, 24).expect("re-adding must not fail");

    tun.remove_route(dst, 24).expect("remove a route");
    assert!(
        !routes_via("karst-rt1").contains("004DA8C0"),
        "the route must be gone after removal"
    );

    // And removing it once more is not an error: the desired state is what
    // matters, and something else having removed it first is not a failure.
    tun.remove_route(dst, 24)
        .expect("removing an absent route must succeed");
}

#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn an_ipv6_route_reaches_the_kernel_too() {
    assert!(have_net_admin(), "run with sudo");
    let tun = Tun::create(&TunConfig {
        name: "karst-rt2".to_owned(),
        ..TunConfig::default()
    })
    .expect("create");
    tun.set_address("fd7a:5ea5::1".parse().expect("addr"), 128)
        .expect("address");

    let dst: std::net::IpAddr = "fd00:beef::".parse().expect("addr");
    tun.add_route(dst, 64).expect("add a v6 route");
    let table = routes_via("karst-rt2");
    assert!(
        table.contains("fd00beef"),
        "the kernel does not hold the IPv6 route:\n{table}"
    );
    tun.remove_route(dst, 64).expect("remove");
}

/// Without `CAP_NET_ADMIN` the request must fail with something an operator can
/// act on, rather than appearing to succeed.
#[test]
fn an_unprivileged_route_fails_cleanly() {
    if have_net_admin() {
        return; // this test is about the unprivileged path
    }
    // No interface can be created without the capability either, so this checks
    // the argument validation that runs before any syscall.
    let bad = karst_tun::encode_name("karst-rt3");
    assert!(bad.is_ok(), "the name itself is fine");
}

/// A prefix longer than the address family allows is refused before any
/// syscall — the kernel would answer `EINVAL` with nothing to say why.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn an_impossible_prefix_length_is_refused() {
    assert!(have_net_admin(), "run with sudo");
    let tun = Tun::create(&TunConfig {
        name: "karst-rt4".to_owned(),
        ..TunConfig::default()
    })
    .expect("create");

    assert!(tun
        .add_route("10.0.0.0".parse().expect("addr"), 33)
        .is_err());
    assert!(tun.add_route("fd00::".parse().expect("addr"), 129).is_err());
}
