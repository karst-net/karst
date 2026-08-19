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
use std::sync::{Mutex, OnceLock};

const NS_INNER: &str = "karst-nat-inner";
const NS_NAT: &str = "karst-nat-mid";
const NS_OUTER: &str = "karst-nat-outer";
/// The carrier's NAT, for the double-NAT row only.
const NS_CGNAT: &str = "karst-nat-cgn";

const INNER_IP: &str = "10.10.1.2";
const NAT_INNER_IP: &str = "10.10.1.1";
const NAT_OUTER_IP: &str = "10.10.2.1";
const OUTER_IP_A: &str = "10.10.2.2";
const OUTER_IP_B: &str = "10.10.2.3";

const PORT_A: u16 = 19001;
const PORT_B: u16 = 19002;

/// The inner host's own port, for the rows that turn on *filtering* rather than
/// mapping. Those need a port known in advance: the question they ask is whether
/// an unsolicited datagram addressed to the mapping crosses, and a mapping on an
/// ephemeral port is one the test cannot address.
const INNER_PORT: u16 = 19100;

/// The same topology, addressed over IPv6. A ULA rather than a documentation
/// prefix because these are configured with `nodad` on a point-to-point veth,
/// and the row is about routing rather than about address policy.
const INNER_IP6: &str = "fd00:1::2";
const NAT_INNER_IP6: &str = "fd00:1::1";
const NAT_OUTER_IP6: &str = "fd00:2::1";
const OUTER_IP6_A: &str = "fd00:2::2";

/// RFC 6598 shared address space: what a subscriber actually gets between
/// their own NAT and the carrier's, and the thing that makes the row a *CGNAT*
/// rather than two arbitrary NATs in a line.
const NAT_CG_IP: &str = "100.64.0.2";
const CGNAT_INNER_IP: &str = "100.64.0.1";
/// A reflector inside the carrier network, so the test can see the address
/// after *one* translation as well as after two.
const PORT_CG: u16 = 19003;

/// All matrix rows deliberately use the same small, inspectable namespace
/// names. The Rust test harness runs tests in parallel by default, so without
/// this lock two otherwise independent rows race while creating and deleting
/// those shared kernel objects.
fn matrix_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Which NAT behaviour the middle namespace is configured for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Nat {
    /// Linux conntrack's default masquerade: one external port reused across
    /// destinations, and return traffic accepted only for the exact flow.
    PortRestrictedCone,
    /// Endpoint-independent mapping *and* filtering: once the mapping exists,
    /// anyone may use it. The easiest NAT to traverse.
    FullCone,
    /// Endpoint-independent mapping, address-dependent filtering: an address
    /// the inside has contacted may reply from any port; one it has not
    /// contacted cannot reach it at all.
    AddressRestrictedCone,
    /// A fresh external port per destination — `fully-random`.
    Symmetric,
    /// UDP does not traverse at all.
    UdpBlocked,
    /// IPv6 end to end with no translation at all.
    ///
    /// Not a NAT, and in the matrix for exactly that reason: it is the row
    /// where a direct connection needs no hole punching, so a traversal rate
    /// measured without it is measured against a harder network than many users
    /// are on.
    Ipv6Direct,
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
    for ns in [NS_INNER, NS_NAT, NS_OUTER, NS_CGNAT] {
        let _ = sh(&["ip", "netns", "del", ns]);
    }
}

/// Ensures a failing assertion or setup command cannot strand the fixed-name
/// namespaces for the next test invocation.
struct Topology;

impl Drop for Topology {
    fn drop(&mut self) {
        teardown();
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

    if nat == Nat::Ipv6Direct {
        add_ipv6();
    }
    apply_nat(nat);
}

/// Give the same three namespaces IPv6 addresses and a router between them.
///
/// `nodad` throughout: duplicate address detection has nothing to detect on a
/// point-to-point veth and costs a second per address, which across a
/// privileged suite is the difference between a test that runs on every commit
/// and one that does not.
fn add_ipv6() {
    for (ns, dev, addr) in [
        (NS_INNER, "kn-i", INNER_IP6),
        (NS_NAT, "kn-ni", NAT_INNER_IP6),
        (NS_NAT, "kn-no", NAT_OUTER_IP6),
        (NS_OUTER, "kn-o", OUTER_IP6_A),
    ] {
        let cidr = format!("{addr}/64");
        must(&nsr(
            ns,
            &["ip", "-6", "addr", "add", &cidr, "dev", dev, "nodad"],
        ));
    }
    must(&nsr(
        NS_NAT,
        &["sysctl", "-qw", "net.ipv6.conf.all.forwarding=1"],
    ));
    must(&nsr(
        NS_INNER,
        &["ip", "-6", "route", "add", "default", "via", NAT_INNER_IP6],
    ));
    must(&nsr(
        NS_OUTER,
        &["ip", "-6", "route", "add", "default", "via", NAT_OUTER_IP6],
    ));
}

/// Four namespaces: a subscriber behind their own NAT, behind a carrier's.
///
/// **The exit criterion names this row by name** — "a peer behind symmetric
/// CGNAT reaches a peer behind a different symmetric CGNAT" — so a matrix
/// without it cannot answer the question the phase is judged on.
///
/// Built separately rather than as another arm of [`build`] because it is a
/// different shape, not a different NAT: one more namespace and one more
/// translation stage. Folding it in would have made `build` take a topology
/// *and* a NAT behaviour and pretend they were one parameter.
///
/// The subscriber NAT keeps the interface name `kn-no` on its outward side, so
/// [`apply_nat`]'s rules apply to it unchanged.
fn build_double_nat() {
    teardown();

    for ns in [NS_INNER, NS_NAT, NS_CGNAT, NS_OUTER] {
        must(&["ip", "netns", "add", ns]);
        must(&nsr(ns, &["ip", "link", "set", "lo", "up"]));
    }
    for (a, b, ns_a, ns_b) in [
        ("kn-i", "kn-ni", NS_INNER, NS_NAT),
        ("kn-no", "kn-cn", NS_NAT, NS_CGNAT),
        ("kn-co", "kn-o", NS_CGNAT, NS_OUTER),
    ] {
        must(&["ip", "link", "add", a, "type", "veth", "peer", "name", b]);
        must(&["ip", "link", "set", a, "netns", ns_a]);
        must(&["ip", "link", "set", b, "netns", ns_b]);
    }

    for (ns, dev, addr) in [
        (NS_INNER, "kn-i", INNER_IP),
        (NS_NAT, "kn-ni", NAT_INNER_IP),
        (NS_NAT, "kn-no", NAT_CG_IP),
        (NS_CGNAT, "kn-cn", CGNAT_INNER_IP),
        (NS_CGNAT, "kn-co", NAT_OUTER_IP),
        (NS_OUTER, "kn-o", OUTER_IP_A),
        (NS_OUTER, "kn-o", OUTER_IP_B),
    ] {
        let cidr = format!("{addr}/24");
        must(&nsr(ns, &["ip", "addr", "add", &cidr, "dev", dev]));
        must(&nsr(ns, &["ip", "link", "set", dev, "up"]));
    }

    for ns in [NS_NAT, NS_CGNAT] {
        must(&nsr(ns, &["sysctl", "-qw", "net.ipv4.ip_forward=1"]));
    }
    must(&nsr(
        NS_INNER,
        &["ip", "route", "add", "default", "via", NAT_INNER_IP],
    ));
    must(&nsr(
        NS_NAT,
        &["ip", "route", "add", "default", "via", CGNAT_INNER_IP],
    ));
    must(&nsr(
        NS_OUTER,
        &["ip", "route", "add", "default", "via", NAT_OUTER_IP],
    ));
    // The carrier has to know where the subscriber prefix lives, or the
    // reflector inside it cannot answer the one-translation probe.
    must(&nsr(
        NS_CGNAT,
        &["ip", "route", "add", "10.10.1.0/24", "via", NAT_CG_IP],
    ));

    // Stage one: the subscriber's own NAT, an ordinary cone.
    apply_nat(Nat::PortRestrictedCone);
    // Stage two: the carrier's, symmetric — which is what makes this the hard
    // row rather than merely a long one.
    must(&nsr(NS_CGNAT, &["nft", "add", "table", "ip", "karst"]));
    must(&nsr(
        NS_CGNAT,
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
    must(&nsr(
        NS_CGNAT,
        &[
            "nft",
            "add",
            "rule",
            "ip",
            "karst",
            "post",
            "oifname kn-co masquerade fully-random",
        ],
    ));
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
        Nat::PortRestrictedCone | Nat::Symmetric | Nat::FullCone | Nat::AddressRestrictedCone => {
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
            if matches!(nat, Nat::FullCone | Nat::AddressRestrictedCone) {
                open_the_mapping();
            }
            if nat == Nat::AddressRestrictedCone {
                restrict_to_contacted_addresses();
            }
        }
        // Nothing to apply. The row's whole content is the absence of a NAT,
        // and adding an empty table would only make it look like there is one.
        Nat::Ipv6Direct => {}
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

/// Make the mapping reachable from outside, which is what "cone" means.
///
/// **A `dnat` rather than an out-of-tree conntrack module**, and that is worth
/// stating because PLAN.md previously recorded these two rows as unbuildable
/// for want of one. Netfilter gives endpoint-independent *mapping* natively —
/// masquerade reuses the source port when it is free — but not
/// endpoint-independent *filtering*: return traffic is admitted per flow. A
/// static `dnat` on the mapped port supplies exactly the missing half.
///
/// **Where this over-approximates, stated rather than hidden.** A real full
/// cone opens the mapping when the inside first sends; this one is open before
/// that too. The property the matrix measures is what happens *after* an
/// outbound datagram, and there the two are identical — but a test that
/// asserted reachability with no prior outbound would be testing a port
/// forward, so none of them does.
fn open_the_mapping() {
    must(&nsr(
        NS_NAT,
        &[
            "nft",
            "add",
            "chain",
            "ip",
            "karst",
            "pre",
            "{ type nat hook prerouting priority -100 ; }",
        ],
    ));
    let rule = format!("iifname kn-no udp dport {INNER_PORT} dnat to {INNER_IP}");
    must(&nsr(
        NS_NAT,
        &["nft", "add", "rule", "ip", "karst", "pre", &rule],
    ));
}

/// Narrow a full cone to an address-restricted one.
///
/// The set remembers every address the inside has sent to, and inbound is
/// admitted only from one of those — from **any** port, which is the whole
/// difference from the port-restricted row conntrack gives natively.
fn restrict_to_contacted_addresses() {
    must(&nsr(
        NS_NAT,
        &[
            "nft",
            "add",
            "set",
            "ip",
            "karst",
            "seen",
            "{ type ipv4_addr ; flags timeout ; timeout 60s ; }",
        ],
    ));
    must(&nsr(
        NS_NAT,
        &[
            "nft",
            "add",
            "chain",
            "ip",
            "karst",
            "filt",
            "{ type filter hook forward priority 0 ; }",
        ],
    ));
    for rule in [
        "iifname kn-ni update @seen { ip daddr } accept",
        "iifname kn-no ip saddr @seen accept",
        "iifname kn-no drop",
    ] {
        must(&nsr(
            NS_NAT,
            &["nft", "add", "rule", "ip", "karst", "filt", rule],
        ));
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

/// Probe from a *known* inner port, so the mapping it opens can be addressed.
fn observed_from(probe: &str, bind_port: u16, target_ip: &str, target_port: u16) -> Option<String> {
    let bind = format!("0.0.0.0:{bind_port}");
    let target = format!("{target_ip}:{target_port}");
    let out = run_in(NS_INNER, &[probe, "probe", &bind, &target]);
    out.strip_prefix("OBSERVED ").map(str::to_owned)
}

/// Whether an unsolicited datagram from `from` reaches the inside.
///
/// The inner host listens on [`INNER_PORT`] and the outer one sends to the
/// NAT's address on the same port — so this asks the only question that
/// separates the cone rows from one another: **who is allowed to use a mapping
/// once it exists.**
fn unsolicited_crosses(probe: &str, from_ip: &str, from_port: u16) -> bool {
    let listen = nsx(
        NS_INNER,
        &[probe, "listen", &format!("0.0.0.0:{INNER_PORT}"), "2500"],
    );
    let refs: Vec<&str> = listen.iter().map(String::as_str).collect();
    let child = Command::new(refs[0])
        .args(&refs[1..])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn listener");

    // The listener needs its socket bound before anything is sent to it, or a
    // pass would depend on scheduling rather than on the NAT.
    std::thread::sleep(std::time::Duration::from_millis(400));
    let from = format!("{from_ip}:{from_port}");
    let to = format!("{NAT_OUTER_IP}:{INNER_PORT}");
    let _ = run_in(NS_OUTER, &[probe, "open", &from, &to]);

    let out = child.wait_with_output().expect("listener exit");
    String::from_utf8_lossy(&out.stdout).starts_with("RECV")
}

fn port_of(addr: &str) -> u16 {
    addr.rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(0)
}

/// The address half of `host:port`, for both families.
///
/// IPv6 is bracketed — `[fd00:1::2]:19100` — so splitting on the last colon
/// works for it too, but the brackets have to come off or the result compares
/// unequal to the constant it came from.
fn ip_of(addr: &str) -> String {
    let host = addr.rsplit_once(':').map(|(i, _)| i).unwrap_or_default();
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned()
}

// ── the tests ───────────────────────────────────────────────────────────────

#[test]
#[ignore = "needs root and network namespaces"]
fn the_topology_carries_traffic_at_all() {
    if !have_net_admin() {
        eprintln!("skipping: not root");
        return;
    }
    let _lock = matrix_lock().lock().expect("matrix lock");
    let _topology = Topology;
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
    let _lock = matrix_lock().lock().expect("matrix lock");
    let _topology = Topology;
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
    let _lock = matrix_lock().lock().expect("matrix lock");
    let _topology = Topology;
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
    let _lock = matrix_lock().lock().expect("matrix lock");
    let _topology = Topology;
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
    let _lock = matrix_lock().lock().expect("matrix lock");
    let _topology = Topology;
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
}

/// **Full cone: endpoint-independent mapping *and* filtering.** The easiest
/// topology to traverse, and the one whose absence made the matrix report a
/// harder network than most users are on.
#[test]
#[ignore = "needs root and network namespaces"]
fn a_full_cone_admits_an_address_it_never_contacted() {
    if !have_net_admin() {
        eprintln!("skipping: not root");
        return;
    }
    let _lock = matrix_lock().lock().expect("matrix lock");
    let _topology = Topology;
    let probe = natprobe();
    build(Nat::FullCone);
    let _r = start_reflectors(&probe);

    // Mapping first: the port is preserved, and it is the same for two
    // destinations, which is the endpoint-independent half.
    let a = observed_from(&probe, INNER_PORT, OUTER_IP_A, PORT_A).expect("no reply through NAT");
    let b = observed_from(&probe, INNER_PORT, OUTER_IP_B, PORT_B).expect("no reply through NAT");
    assert_eq!(port_of(&a), port_of(&b), "mapping is endpoint-dependent");
    assert_eq!(
        port_of(&a),
        INNER_PORT,
        "the mapped port is not the one the test addresses: {a}"
    );

    // And the filtering half, which is what makes it a *full* cone: a datagram
    // from an address the inside has never contacted still crosses.
    assert!(
        unsolicited_crosses(&probe, OUTER_IP_B, PORT_B + 400),
        "a full cone refused an unsolicited datagram"
    );
}

/// **Address-restricted: the middle row, and the one that distinguishes the
/// two either side of it.** An address the inside has contacted may answer from
/// any port; an address it has not contacted may not reach it at all.
///
/// Both halves are asserted here, because either alone is satisfied by a
/// neighbouring row: the first is also true of a full cone, and the second is
/// also true of a port-restricted one.
#[test]
#[ignore = "needs root and network namespaces"]
fn an_address_restricted_cone_admits_a_new_port_but_not_a_new_address() {
    if !have_net_admin() {
        eprintln!("skipping: not root");
        return;
    }
    let _lock = matrix_lock().lock().expect("matrix lock");
    let _topology = Topology;
    let probe = natprobe();
    build(Nat::AddressRestrictedCone);
    let _r = start_reflectors(&probe);

    observed_from(&probe, INNER_PORT, OUTER_IP_A, PORT_A).expect("no reply through NAT");

    assert!(
        unsolicited_crosses(&probe, OUTER_IP_A, PORT_A + 400),
        "a contacted address was refused on a different port — that is \
         port-restricted, not address-restricted"
    );
    // `PORT_B + 400`, not `PORT_B`: the reflector already holds that port, so a
    // sender binding it would fail and the datagram would never leave — and
    // this assertion is a *negative* one, which would then pass for the wrong
    // reason. It did, until removing the filter altogether failed to fail.
    assert!(
        !unsolicited_crosses(&probe, OUTER_IP_B, PORT_B + 400),
        "an address the inside never contacted crossed — that is a full cone, \
         not address-restricted"
    );
}

/// **IPv6, end to end, with nothing translating.** The row where the address a
/// peer sees is the address the node has, so a direct connection needs no hole
/// punching at all.
///
/// It earns its place by being the easy case. A traversal rate measured only
/// across NATs is measured against a harder network than many users are on, and
/// omitting this row would understate the result in a way that looks
/// conservative and is simply wrong.
#[test]
#[ignore = "needs root and network namespaces"]
fn an_ipv6_path_is_not_translated() {
    if !have_net_admin() {
        eprintln!("skipping: not root");
        return;
    }
    let _lock = matrix_lock().lock().expect("matrix lock");
    let _topology = Topology;
    let probe = natprobe();
    build(Nat::Ipv6Direct);

    let bind = format!("[{OUTER_IP6_A}]:{PORT_A}");
    let reflector = Command::new("ip")
        .args(["netns", "exec", NS_OUTER, &probe, "reflect", &bind])
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn reflector");
    let _guard = Reflectors {
        children: vec![reflector],
    };
    std::thread::sleep(std::time::Duration::from_millis(300));

    let target = format!("[{OUTER_IP6_A}]:{PORT_A}");
    let listen = format!("[::]:{INNER_PORT}");
    let out = run_in(NS_INNER, &[&probe, "probe", &listen, &target]);
    let seen = out
        .strip_prefix("OBSERVED ")
        .unwrap_or_else(|| panic!("no reply over IPv6: {out}"));

    assert_eq!(
        ip_of(seen),
        INNER_IP6,
        "the source was rewritten on a path with no NAT: {seen}"
    );
    assert_eq!(
        port_of(seen),
        INNER_PORT,
        "the port was rewritten on a path with no NAT: {seen}"
    );
}

/// **Two translation stages, the outer one symmetric — the subscriber-behind-
/// CGNAT row the exit criterion is written against.**
///
/// The distinguishing assertion is not that traffic crosses, which a single NAT
/// also manages. It is that the source is rewritten **twice**, seen by placing
/// a reflector inside the carrier network as well as beyond it: one hop shows
/// the subscriber NAT's shared-space address, two hops show the carrier's. A
/// topology that quietly collapsed to one NAT would pass every
/// traffic-crosses check and report the wrong difficulty for the whole matrix.
#[test]
#[ignore = "needs root and network namespaces"]
fn a_subscriber_behind_a_carrier_nat_is_translated_twice() {
    if !have_net_admin() {
        eprintln!("skipping: not root");
        return;
    }
    let _lock = matrix_lock().lock().expect("matrix lock");
    let _topology = Topology;
    let probe = natprobe();
    build_double_nat();

    let mut children = Vec::new();
    for (ns, ip, port) in [
        (NS_CGNAT, CGNAT_INNER_IP, PORT_CG),
        (NS_OUTER, OUTER_IP_A, PORT_A),
        (NS_OUTER, OUTER_IP_B, PORT_B),
    ] {
        let bind = format!("{ip}:{port}");
        children.push(
            Command::new("ip")
                .args(["netns", "exec", ns, &probe, "reflect", &bind])
                .stdout(std::process::Stdio::null())
                .spawn()
                .expect("spawn reflector"),
        );
    }
    let _guard = Reflectors { children };
    std::thread::sleep(std::time::Duration::from_millis(400));

    let one_hop = observed(&probe, CGNAT_INNER_IP, PORT_CG).expect("no reply from the carrier");
    assert_eq!(
        ip_of(&one_hop),
        NAT_CG_IP,
        "after one translation the source should be the subscriber NAT's \
         shared-space address: {one_hop}"
    );

    // **Both probes bind the same inner port**, or the comparison below proves
    // nothing: two `0.0.0.0:0` binds are two different source ports, and the
    // external ports would differ under any NAT at all. That mistake made this
    // assertion vacuous until making the carrier a cone failed to fail.
    //
    // Three attempts, as the single-stage symmetric row: `fully-random` can
    // hand two destinations the same port by chance, about one run in 28,000.
    let mut differed = None;
    for bind in [19560u16, 19561, 19562] {
        let a = observed_from(&probe, bind, OUTER_IP_A, PORT_A).expect("no reply through 2 NATs");
        let b = observed_from(&probe, bind, OUTER_IP_B, PORT_B).expect("no reply through 2 NATs");
        assert_eq!(
            ip_of(&a),
            NAT_OUTER_IP,
            "after two translations the source should be the carrier's: {a}"
        );
        assert_ne!(
            ip_of(&one_hop),
            ip_of(&a),
            "the two stages produced the same source address, so this is one \
             NAT and not two"
        );
        if port_of(&a) != port_of(&b) {
            differed = Some((a, b));
            break;
        }
    }

    // The carrier stage is symmetric, which is what makes the row hard: the
    // mapping a peer learns for one destination is useless for another.
    assert!(
        differed.is_some(),
        "the carrier reused one port across destinations on every attempt — \
         that is a cone, not a symmetric CGNAT"
    );
}
