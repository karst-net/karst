// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The NAT matrix, and the tests that establish it is real.
//!
//! PLAN.md §6 sets a **≥90% direct-connection rate across the matrix** as
//! Phase 4's exit criterion. Before any Karst code is measured against that
//! number, the matrix itself has to be shown to behave the way its labels say.
//! A "symmetric" NAT that is quietly endpoint-independent yields a confident
//! percentage that means nothing, and once the thing under test is a VPN rather
//! than a two-line probe, the mistake is invisible.
//!
//! So these tests measure the *network*, using `examples/natprobe.rs` and no
//! Karst code at all. What they establish is the instrument, not the product.
//!
//! # Topology
//!
//! ```text
//!   inner ns            nat ns                     outer ns
//!   10.10.1.2  --veth--  10.10.1.1 | 10.10.2.1  --veth--  10.10.2.2
//!                        (masquerade)                     10.10.2.3
//! ```
//!
//! Two addresses on the outer side, because telling endpoint-independent
//! mapping from endpoint-dependent mapping requires probing two *different*
//! destinations and comparing what each one saw.
//!
//! # Requires root
//!
//! `#[ignore]`d, like `karstd`'s two-node tests. Run with
//! `just test-nat-matrix`.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::process::Command;

const NS_INNER: &str = "karst-nat-inner";
const NS_NAT: &str = "karst-nat-mid";
const NS_OUTER: &str = "karst-nat-outer";

const INNER_IP: &str = "10.10.1.2";
const NAT_INNER_IP: &str = "10.10.1.1";
const NAT_OUTER_IP: &str = "10.10.2.1";
const OUTER_IP_A: &str = "10.10.2.2";
const OUTER_IP_B: &str = "10.10.2.3";

const PORT_A: u16 = 19001;
const PORT_B: u16 = 19002;

/// Which NAT behaviour the middle namespace is configured for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Nat {
    /// Linux conntrack's default masquerade: one external port reused across
    /// destinations, and return traffic accepted only for the exact flow.
    PortRestrictedCone,
    /// A fresh external port per destination — `fully-random`.
    Symmetric,
    /// UDP does not traverse at all.
    UdpBlocked,
}

fn effective_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))?
                .split_whitespace()
                .nth(2)?
                .parse()
                .ok()
        })
        .unwrap_or(1)
}

fn have_net_admin() -> bool {
    effective_uid() == 0
        && Command::new("ip")
            .args(["netns", "list"])
            .output()
            .is_ok_and(|o| o.status.success())
        && Command::new("nft")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
}

fn sh(args: &[&str]) -> bool {
    Command::new(args[0])
        .args(&args[1..])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn must(args: &[&str]) {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .unwrap_or_else(|e| panic!("failed to run {args:?}: {e}"));
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn nsx(ns: &str, args: &[&str]) -> Vec<String> {
    let mut v = vec!["ip", "netns", "exec", ns];
    v.extend_from_slice(args);
    v.into_iter().map(str::to_owned).collect()
}

fn run_in(ns: &str, args: &[&str]) -> String {
    let full = nsx(ns, args);
    let refs: Vec<&str> = full.iter().map(String::as_str).collect();
    let out = Command::new(refs[0])
        .args(&refs[1..])
        .output()
        .unwrap_or_else(|e| panic!("failed to run {refs:?}: {e}"));
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn teardown() {
    for ns in [NS_INNER, NS_NAT, NS_OUTER] {
        let _ = sh(&["ip", "netns", "del", ns]);
    }
}

/// Build the three namespaces and wire them together.
fn build(nat: Nat) {
    teardown();

    for ns in [NS_INNER, NS_NAT, NS_OUTER] {
        must(&["ip", "netns", "add", ns]);
        must(&nsr(ns, &["ip", "link", "set", "lo", "up"]));
    }

    // inner <-> nat
    must(&[
        "ip", "link", "add", "kn-i", "type", "veth", "peer", "name", "kn-ni",
    ]);
    must(&["ip", "link", "set", "kn-i", "netns", NS_INNER]);
    must(&["ip", "link", "set", "kn-ni", "netns", NS_NAT]);
    // nat <-> outer
    must(&[
        "ip", "link", "add", "kn-no", "type", "veth", "peer", "name", "kn-o",
    ]);
    must(&["ip", "link", "set", "kn-no", "netns", NS_NAT]);
    must(&["ip", "link", "set", "kn-o", "netns", NS_OUTER]);

    let inner_cidr = format!("{INNER_IP}/24");
    let nat_i_cidr = format!("{NAT_INNER_IP}/24");
    let nat_o_cidr = format!("{NAT_OUTER_IP}/24");
    let out_a_cidr = format!("{OUTER_IP_A}/24");
    let out_b_cidr = format!("{OUTER_IP_B}/24");

    must(&nsr(
        NS_INNER,
        &["ip", "addr", "add", &inner_cidr, "dev", "kn-i"],
    ));
    must(&nsr(NS_INNER, &["ip", "link", "set", "kn-i", "up"]));
    must(&nsr(
        NS_INNER,
        &["ip", "route", "add", "default", "via", NAT_INNER_IP],
    ));

    must(&nsr(
        NS_NAT,
        &["ip", "addr", "add", &nat_i_cidr, "dev", "kn-ni"],
    ));
    must(&nsr(NS_NAT, &["ip", "link", "set", "kn-ni", "up"]));
    must(&nsr(
        NS_NAT,
        &["ip", "addr", "add", &nat_o_cidr, "dev", "kn-no"],
    ));
    must(&nsr(NS_NAT, &["ip", "link", "set", "kn-no", "up"]));
    must(&nsr(NS_NAT, &["sysctl", "-qw", "net.ipv4.ip_forward=1"]));

    must(&nsr(
        NS_OUTER,
        &["ip", "addr", "add", &out_a_cidr, "dev", "kn-o"],
    ));
    // A second address on the same interface: two distinct destinations is
    // what makes endpoint-dependent mapping observable at all.
    must(&nsr(
        NS_OUTER,
        &["ip", "addr", "add", &out_b_cidr, "dev", "kn-o"],
    ));
    must(&nsr(NS_OUTER, &["ip", "link", "set", "kn-o", "up"]));
    must(&nsr(
        NS_OUTER,
        &["ip", "route", "add", "default", "via", NAT_OUTER_IP],
    ));

    apply_nat(nat);
}

fn nsr(ns: &str, args: &[&str]) -> Vec<&'static str> {
    // `must` needs &[&str]; leak the composed argv rather than fight lifetimes
    // in a test helper. Bounded by the number of setup commands.
    let full = nsx(ns, args);
    full.into_iter()
        .map(|s| &*Box::leak(s.into_boxed_str()))
        .collect()
}

fn apply_nat(nat: Nat) {
    must(&nsr(NS_NAT, &["nft", "add", "table", "ip", "karst"]));

    match nat {
        Nat::PortRestrictedCone | Nat::Symmetric => {
            must(&nsr(
                NS_NAT,
                &[
                    "nft",
                    "add",
                    "chain",
                    "ip",
                    "karst",
                    "post",
                    "{ type nat hook postrouting priority 100 ; }",
                ],
            ));
            // Linux conntrack gives endpoint-independent *mapping* by default —
            // one external port reused across destinations — and
            // endpoint-dependent *filtering*, which is a port-restricted cone.
            // `fully-random` allocates a fresh port per flow, which is what
            // makes it symmetric.
            let rule = match nat {
                Nat::Symmetric => "oifname kn-no masquerade fully-random",
                _ => "oifname kn-no masquerade",
            };
            must(&nsr(
                NS_NAT,
                &["nft", "add", "rule", "ip", "karst", "post", rule],
            ));
        }
        Nat::UdpBlocked => {
            must(&nsr(
                NS_NAT,
                &[
                    "nft",
                    "add",
                    "chain",
                    "ip",
                    "karst",
                    // Not `fwd`: that is a reserved word in nft and the chain
                    // creation fails with a syntax error pointing at the name.
                    "block",
                    "{ type filter hook forward priority 0 ; }",
                ],
            ));
            must(&nsr(
                NS_NAT,
                &[
                    "nft",
                    "add",
                    "rule",
                    "ip",
                    "karst",
                    "block",
                    "meta l4proto udp drop",
                ],
            ));
        }
    }
}

/// Path to the `natprobe` example, built by the caller.
fn natprobe() -> String {
    // The test binary lives in target/<profile>/deps/; the example is two
    // directories up. Derived rather than hard-coded so a `--release` run works.
    let exe = std::env::current_exe().expect("test binary path");
    let dir = exe
        .parent()
        .and_then(std::path::Path::parent)
        .expect("target/<profile>");
    let p = dir.join("examples").join("natprobe");
    assert!(
        p.exists(),
        "{} is missing — build it with `cargo build -p karst-disco --example natprobe`",
        p.display()
    );
    p.to_string_lossy().into_owned()
}

struct Reflectors {
    children: Vec<std::process::Child>,
}

impl Drop for Reflectors {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Start a reflector on each outer address.
fn start_reflectors(probe: &str) -> Reflectors {
    let mut children = Vec::new();
    for (ip, port) in [(OUTER_IP_A, PORT_A), (OUTER_IP_B, PORT_B)] {
        let bind = format!("{ip}:{port}");
        let child = Command::new("ip")
            .args(["netns", "exec", NS_OUTER, probe, "reflect", &bind])
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn reflector");
        children.push(child);
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    Reflectors { children }
}

/// Probe one reflector from the inner namespace; return what it observed.
fn observed(probe: &str, target_ip: &str, target_port: u16) -> Option<String> {
    let target = format!("{target_ip}:{target_port}");
    let out = run_in(NS_INNER, &[probe, "probe", "0.0.0.0:0", &target]);
    out.strip_prefix("OBSERVED ").map(str::to_owned)
}

fn port_of(addr: &str) -> u16 {
    addr.rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(0)
}

fn ip_of(addr: &str) -> String {
    addr.rsplit_once(':')
        .map(|(i, _)| i.to_owned())
        .unwrap_or_default()
}

// ── the tests ───────────────────────────────────────────────────────────────

#[test]
#[ignore = "needs root and network namespaces"]
fn the_topology_carries_traffic_at_all() {
    if !have_net_admin() {
        eprintln!("skipping: not root");
        return;
    }
    let probe = natprobe();
    build(Nat::PortRestrictedCone);
    let _r = start_reflectors(&probe);

    let seen = observed(&probe, OUTER_IP_A, PORT_A).expect("no reply through the NAT");
    // The source must have been rewritten to the NAT's outer address, or the
    // topology is not doing NAT and every result below would be meaningless.
    assert_eq!(
        ip_of(&seen),
        NAT_OUTER_IP,
        "source was not translated: {seen}"
    );
    teardown();
}

#[test]
#[ignore = "needs root and network namespaces"]
fn a_cone_nat_reuses_one_port_across_destinations() {
    // Endpoint-independent mapping. This is what makes a reflexive address
    // learned from one peer usable by another, and it is the property that
    // makes hole punching easy.
    if !have_net_admin() {
        eprintln!("skipping: not root");
        return;
    }
    let probe = natprobe();
    build(Nat::PortRestrictedCone);
    let _r = start_reflectors(&probe);

    let a = observed(&probe, OUTER_IP_A, PORT_A).expect("reply from A");
    let b = observed(&probe, OUTER_IP_B, PORT_B).expect("reply from B");
    // Different sockets get different ports; what matters is that the *same*
    // socket keeps one mapping. The probe binds a fresh socket each time, so
    // this is asserted by re-probing from one process below.
    let _ = (&a, &b);

    let out = run_in(
        NS_INNER,
        &[
            &probe,
            "probe",
            "0.0.0.0:19555",
            &format!("{OUTER_IP_A}:{PORT_A}"),
        ],
    );
    let first = out.strip_prefix("OBSERVED ").expect("reply A").to_owned();
    let out = run_in(
        NS_INNER,
        &[
            &probe,
            "probe",
            "0.0.0.0:19555",
            &format!("{OUTER_IP_B}:{PORT_B}"),
        ],
    );
    let second = out.strip_prefix("OBSERVED ").expect("reply B").to_owned();

    assert_eq!(
        port_of(&first),
        port_of(&second),
        "a cone NAT gave two different external ports: {first} vs {second}"
    );
    teardown();
}

#[test]
#[ignore = "needs root and network namespaces"]
fn a_symmetric_nat_uses_a_different_port_per_destination() {
    // The hard case, and the one PLAN.md §6's exit criterion names explicitly:
    // a peer behind symmetric CGNAT reaching a peer behind a different one.
    // If this assertion does not hold, the "symmetric" row of the matrix is
    // measuring a cone NAT and every number from it is worthless.
    if !have_net_admin() {
        eprintln!("skipping: not root");
        return;
    }
    let probe = natprobe();
    build(Nat::Symmetric);
    let _r = start_reflectors(&probe);

    // `fully-random` allocates each flow a random port, so two destinations can
    // collide by chance — roughly one run in 28,000, which over enough CI runs
    // is a flake rather than a impossibility. Three attempts, needing only one
    // to differ, drops that to nothing while still failing loudly if the NAT is
    // genuinely reusing one mapping.
    let mut differed = false;
    let mut seen = Vec::new();
    for port in [19556u16, 19557, 19558] {
        let bind = format!("0.0.0.0:{port}");
        let out = run_in(
            NS_INNER,
            &[&probe, "probe", &bind, &format!("{OUTER_IP_A}:{PORT_A}")],
        );
        let first = out.strip_prefix("OBSERVED ").expect("reply A").to_owned();
        let out = run_in(
            NS_INNER,
            &[&probe, "probe", &bind, &format!("{OUTER_IP_B}:{PORT_B}")],
        );
        let second = out.strip_prefix("OBSERVED ").expect("reply B").to_owned();
        seen.push((first.clone(), second.clone()));
        if port_of(&first) != port_of(&second) {
            differed = true;
            break;
        }
    }

    assert!(
        differed,
        "the symmetric NAT reused one port on every attempt — it is behaving \
         as a cone: {seen:?}"
    );
    teardown();
}

#[test]
#[ignore = "needs root and network namespaces"]
fn a_udp_blocked_path_carries_nothing() {
    // The relay-only row. A node here must fall back and stay there, so the
    // matrix needs a configuration where discovery cannot possibly succeed.
    if !have_net_admin() {
        eprintln!("skipping: not root");
        return;
    }
    let probe = natprobe();
    build(Nat::UdpBlocked);
    let _r = start_reflectors(&probe);

    let out = run_in(
        NS_INNER,
        &[
            &probe,
            "probe",
            "0.0.0.0:0",
            &format!("{OUTER_IP_A}:{PORT_A}"),
        ],
    );
    assert_eq!(out, "TIMEOUT", "UDP crossed a path that blocks UDP: {out}");
    teardown();
}

#[test]
#[ignore = "needs root and network namespaces"]
fn an_unsolicited_datagram_does_not_cross() {
    // Endpoint-dependent *filtering* — the other half of what makes a NAT a
    // NAT. Without this the inner host is simply reachable, and a "direct
    // connection" through the matrix would prove nothing about traversal.
    if !have_net_admin() {
        eprintln!("skipping: not root");
        return;
    }
    let probe = natprobe();
    build(Nat::PortRestrictedCone);

    // Nobody inside has sent anything, so no mapping exists. Listen inside and
    // fire at the NAT's outer address from outside.
    let listener = Command::new("ip")
        .args([
            "netns",
            "exec",
            NS_INNER,
            &probe,
            "listen",
            "0.0.0.0:19557",
            "1200",
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn listener");

    std::thread::sleep(std::time::Duration::from_millis(200));
    let _ = run_in(
        NS_OUTER,
        &[
            &probe,
            "open",
            &format!("{OUTER_IP_A}:0"),
            &format!("{NAT_OUTER_IP}:19557"),
        ],
    );

    let out = listener.wait_with_output().expect("listener finished");
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    assert_eq!(
        text, "TIMEOUT",
        "an unsolicited datagram crossed the NAT: {text}"
    );
    teardown();
}
