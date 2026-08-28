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
/// A second host behind the *same* NAT, for the hairpinning rows only.
const NS_PEER: &str = "karst-nat-peer";

const INNER_IP: &str = "10.10.1.2";
const NAT_INNER_IP: &str = "10.10.1.1";
const NAT_OUTER_IP: &str = "10.10.2.1";
const OUTER_IP_A: &str = "10.10.2.2";
const OUTER_IP_B: &str = "10.10.2.3";
/// The second inside host, on the same private segment as [`INNER_IP`].
const PEER_IP: &str = "10.10.1.3";
/// Its own port, so the hairpin rows can address it the way they address
/// [`INNER_PORT`].
const PEER_PORT: u16 = 19101;

/// A source port on the outer side that **no reflector is bound to**.
///
/// `PORT_A` and `PORT_B` are held by the reflectors for the whole of every row,
/// so a probe that tries to bind one of them fails to start and sends nothing —
/// and a test whose negative result depends on a datagram *not* arriving then
/// passes for the most uninteresting reason available. That is not
/// hypothetical: the carrier-filtering row below was written that way first and
/// only the defect check found it.
const UNSOLICITED_PORT: u16 = 19200;

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

/// The NAT64 row's IPv6-only inside.
const NAT64_CLIENT_IP6: &str = "fd00:11::2";
const NAT64_GW_IP6: &str = "fd00:11::1";
/// The translation prefix.
///
/// **Not the well-known `64:ff9b::/96`.** RFC 6052 §3.1 forbids pairing that
/// prefix with private IPv4 addresses, and `tayga` enforces it — every probe is
/// dropped with a note in its log and the row looks like a product failure. A
/// prefix from this fixture's own ULA space is what the RFC says to use, and
/// the outer addresses here are RFC 1918.
const NAT64_PREFIX: &str = "fd00:6464::/96";
/// `OUTER_IP_A` and `OUTER_IP_B` embedded in that prefix — 10.10.2.2 and
/// 10.10.2.3 are `0a0a:0202` and `0a0a:0203`.
const NAT64_OUTER_A: &str = "fd00:6464::a0a:202";
const NAT64_OUTER_B: &str = "fd00:6464::a0a:203";
/// `tayga`'s own two addresses and the pool it draws client mappings from.
const NAT64_TAYGA_V4: &str = "192.168.255.1";
const NAT64_TAYGA_V6: &str = "fd00:64::1";
const NAT64_POOL: &str = "192.168.255.0/24";
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
    let ok = effective_uid() == 0
        && Command::new("ip")
            .args(["netns", "list"])
            .output()
            .is_ok_and(|o| o.status.success())
        && Command::new("nft")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
    if !ok {
        refuse_to_skip("root, ip and nft");
    }
    ok
}

/// Whether a tool this row needs is installed — **and a refusal to be quietly
/// green without it**.
///
/// Skipping is for a developer without the tooling. In CI it must fail instead:
/// a privileged suite that skips itself is a suite that passes while testing
/// nothing. `bins/karstd/tests/aquifer.rs` has enforced this since 2026-08-20
/// and this file did not, which is FINDINGS.md 48 — the NAT64 row skipped on
/// every CI run from the day it was written, because the job that runs it never
/// installed `tayga`, and it reported success each time.
fn have_tool(name: &str) -> bool {
    let ok = sh(&["sh", "-c", &format!("command -v {name}")]);
    if !ok {
        refuse_to_skip(name);
    }
    ok
}

/// `KARST_REQUIRE_PREREQUISITES` is how CI says "these are supposed to be
/// here", so a runner image that stops shipping one turns the matrix red
/// instead of turning it into a no-op.
fn refuse_to_skip(what: &str) {
    assert!(
        std::env::var_os("KARST_REQUIRE_PREREQUISITES").is_none(),
        "KARST_REQUIRE_PREREQUISITES is set, so skipping is not allowed — \
         missing: {what}"
    );
    eprintln!("skipping: {what} is not available");
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
    for ns in [NS_INNER, NS_NAT, NS_OUTER, NS_CGNAT, NS_PEER] {
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

/// Two hosts behind the **same** NAT, each of which can only name the other by
/// the NAT's external address.
///
/// The shape matters to Karst directly. Two nodes on one home network both
/// learn a reflexive address from the relay (`aven-v1.md` §7.6), advertise it,
/// and then probe each other *at the NAT's own outer address*. Whether that
/// works is the hairpinning question, and it is not a property Karst can
/// choose — so the matrix has to establish which way this fixture goes before
/// any conclusion is drawn about the product.
///
/// The two inside hosts hang off a bridge rather than two routed subnets,
/// because a hairpin is specifically about one NAT with one inside segment. Two
/// subnets behind one router would make the datagram merely *forwarded*, which
/// is a different and much easier thing that would pass while proving nothing.
fn build_hairpin() {
    teardown();

    for ns in [NS_INNER, NS_PEER, NS_NAT, NS_OUTER] {
        must(&["ip", "netns", "add", ns]);
        must(&nsr(ns, &["ip", "link", "set", "lo", "up"]));
    }

    // The inside segment: a bridge in the NAT namespace holding both hosts.
    must(&nsr(
        NS_NAT,
        &["ip", "link", "add", "kn-br", "type", "bridge"],
    ));
    must(&nsr(NS_NAT, &["ip", "link", "set", "kn-br", "up"]));
    let nat_i_cidr = format!("{NAT_INNER_IP}/24");
    must(&nsr(
        NS_NAT,
        &["ip", "addr", "add", &nat_i_cidr, "dev", "kn-br"],
    ));

    for (host_ns, host_dev, br_dev, addr) in [
        (NS_INNER, "kn-i", "kn-ni", INNER_IP),
        (NS_PEER, "kn-p", "kn-np", PEER_IP),
    ] {
        must(&[
            "ip", "link", "add", host_dev, "type", "veth", "peer", "name", br_dev,
        ]);
        must(&["ip", "link", "set", host_dev, "netns", host_ns]);
        must(&["ip", "link", "set", br_dev, "netns", NS_NAT]);
        must(&nsr(
            NS_NAT,
            &["ip", "link", "set", br_dev, "master", "kn-br"],
        ));
        must(&nsr(NS_NAT, &["ip", "link", "set", br_dev, "up"]));
        let cidr = format!("{addr}/24");
        must(&nsr(
            host_ns,
            &["ip", "addr", "add", &cidr, "dev", host_dev],
        ));
        must(&nsr(host_ns, &["ip", "link", "set", host_dev, "up"]));
        must(&nsr(
            host_ns,
            &["ip", "route", "add", "default", "via", NAT_INNER_IP],
        ));
    }

    // The outside, exactly as [`build`] wires it.
    must(&[
        "ip", "link", "add", "kn-no", "type", "veth", "peer", "name", "kn-o",
    ]);
    must(&["ip", "link", "set", "kn-no", "netns", NS_NAT]);
    must(&["ip", "link", "set", "kn-o", "netns", NS_OUTER]);
    let nat_o_cidr = format!("{NAT_OUTER_IP}/24");
    must(&nsr(
        NS_NAT,
        &["ip", "addr", "add", &nat_o_cidr, "dev", "kn-no"],
    ));
    must(&nsr(NS_NAT, &["ip", "link", "set", "kn-no", "up"]));
    must(&nsr(NS_NAT, &["sysctl", "-qw", "net.ipv4.ip_forward=1"]));
    for addr in [OUTER_IP_A, OUTER_IP_B] {
        let cidr = format!("{addr}/24");
        must(&nsr(NS_OUTER, &["ip", "addr", "add", &cidr, "dev", "kn-o"]));
    }
    must(&nsr(NS_OUTER, &["ip", "link", "set", "kn-o", "up"]));
    must(&nsr(
        NS_OUTER,
        &["ip", "route", "add", "default", "via", NAT_OUTER_IP],
    ));

    apply_nat(Nat::PortRestrictedCone);
}

/// Turn hairpinning on, which Linux does not do by default.
///
/// Two rules, and **both** are required by RFC 4787 REQ-9. The `dnat` sends a
/// datagram addressed to the NAT's own external address back to the mapping's
/// owner. The `snat` rewrites the source to that same external address, which
/// is the half that is easy to omit and that makes the difference between
/// hairpinning and a leak: without it the receiver sees the *private* address
/// of a peer it believes is on the public internet, replies to it directly, and
/// the two ends disagree about what address the conversation is on.
fn enable_hairpin(external_port: u16) {
    must(&nsr(
        NS_NAT,
        &[
            "nft",
            "add",
            "chain",
            "ip",
            "karst",
            "hairpre",
            "{ type nat hook prerouting priority -100 ; }",
        ],
    ));
    let dnat = format!(
        "iifname kn-br ip daddr {NAT_OUTER_IP} udp dport {external_port} \
         dnat to {INNER_IP}:{INNER_PORT}"
    );
    must(&nsr(
        NS_NAT,
        &["nft", "add", "rule", "ip", "karst", "hairpre", &dnat],
    ));
    let snat = format!("iifname kn-br oifname kn-br snat to {NAT_OUTER_IP}");
    must(&nsr(
        NS_NAT,
        &["nft", "add", "rule", "ip", "karst", "post", &snat],
    ));
}

/// An IPv6-only inside, an IPv4-only outside, and `tayga` between them.
///
/// A **topology** rather than a NAT behaviour, so it gets its own builder like
/// `build_double_nat` and no `Nat` variant — `apply_nat` configures a middle
/// namespace, and there is nothing here it could configure.
///
/// Built from `tayga` plus nftables rather than from a stateful NAT64
/// implementation, and the split is deliberate. `tayga` does the protocol
/// translation; the **port sharing comes from the same masquerade every other
/// row in this file is built on**, so the NAT semantics being measured are ones
/// this matrix has already pinned rather than ones taken on trust from a second
/// implementation. It also keeps an out-of-tree kernel module out of CI.
/// FINDINGS.md 27 records the alternatives.
///
/// A stateless translator *alone* would be the wrong instrument: one IPv4
/// address per client with ports preserved is barely distinguishable from
/// [`Nat::Ipv6Direct`], and a row built that way would report a comfortable
/// result about a topology nobody is on.
///
/// Returns the running translator, which must be kept alive for the row's
/// duration and killed after it.
fn build_nat64(dir: &std::path::Path) -> std::process::Child {
    teardown();
    for ns in [NS_INNER, NS_NAT, NS_OUTER] {
        must(&["ip", "netns", "add", ns]);
        must(&nsr(ns, &["ip", "link", "set", "lo", "up"]));
    }

    // Outside: IPv4 only, two addresses so endpoint-independence is observable.
    must(&[
        "ip", "link", "add", "kn-no", "type", "veth", "peer", "name", "kn-o",
    ]);
    must(&["ip", "link", "set", "kn-no", "netns", NS_NAT]);
    must(&["ip", "link", "set", "kn-o", "netns", NS_OUTER]);
    let nat_o = format!("{NAT_OUTER_IP}/24");
    must(&nsr(NS_NAT, &["ip", "addr", "add", &nat_o, "dev", "kn-no"]));
    must(&nsr(NS_NAT, &["ip", "link", "set", "kn-no", "up"]));
    for addr in [OUTER_IP_A, OUTER_IP_B] {
        let cidr = format!("{addr}/24");
        must(&nsr(NS_OUTER, &["ip", "addr", "add", &cidr, "dev", "kn-o"]));
    }
    must(&nsr(NS_OUTER, &["ip", "link", "set", "kn-o", "up"]));
    must(&nsr(
        NS_OUTER,
        &["ip", "route", "add", "default", "via", NAT_OUTER_IP],
    ));

    // Inside: IPv6 only. No IPv4 address at all on the client, which is what
    // makes the row a NAT64 row rather than a dual-stack one.
    must(&[
        "ip", "link", "add", "kn-i", "type", "veth", "peer", "name", "kn-ni",
    ]);
    must(&["ip", "link", "set", "kn-i", "netns", NS_INNER]);
    must(&["ip", "link", "set", "kn-ni", "netns", NS_NAT]);
    let gw = format!("{NAT64_GW_IP6}/64");
    let cl = format!("{NAT64_CLIENT_IP6}/64");
    must(&nsr(
        NS_NAT,
        &["ip", "-6", "addr", "add", &gw, "dev", "kn-ni", "nodad"],
    ));
    must(&nsr(NS_NAT, &["ip", "link", "set", "kn-ni", "up"]));
    must(&nsr(
        NS_INNER,
        &["ip", "-6", "addr", "add", &cl, "dev", "kn-i", "nodad"],
    ));
    must(&nsr(NS_INNER, &["ip", "link", "set", "kn-i", "up"]));
    must(&nsr(
        NS_INNER,
        &["ip", "-6", "route", "add", "default", "via", NAT64_GW_IP6],
    ));

    must(&nsr(NS_NAT, &["sysctl", "-qw", "net.ipv4.ip_forward=1"]));
    must(&nsr(
        NS_NAT,
        &["sysctl", "-qw", "net.ipv6.conf.all.forwarding=1"],
    ));

    start_translator(dir)
}

/// Configure and start `tayga` in the already-wired NAT namespace.
fn start_translator(dir: &std::path::Path) -> std::process::Child {
    // **The tun device name is per-process, not the literal `nat64`.**
    // `tayga --mktun` creates a *persistent* device, so a fixed name is shared
    // with any other tayga on the machine — including one left behind by a
    // crashed run. This row failed reproducibly while a stray tayga from an
    // unrelated experiment was alive and passed once it was gone; the exact
    // interaction was never established, which is precisely why the shared name
    // is removed rather than reasoned about.
    let tun = format!("nat64-{}", std::process::id());
    let data = dir.join("tayga-data");
    std::fs::create_dir_all(&data).expect("tayga data dir");
    let conf = dir.join("tayga.conf");
    std::fs::write(
        &conf,
        format!(
            "tun-device {tun}\n\
             ipv4-addr {NAT64_TAYGA_V4}\n\
             ipv6-addr {NAT64_TAYGA_V6}\n\
             prefix {NAT64_PREFIX}\n\
             dynamic-pool {NAT64_POOL}\n\
             data-dir {}\n",
            data.display()
        ),
    )
    .expect("write tayga config");
    let conf_path = conf.to_string_lossy().into_owned();

    must(&nsr(NS_NAT, &["tayga", "--mktun", "-c", &conf_path]));
    must(&nsr(NS_NAT, &["ip", "link", "set", &tun, "up"]));
    must(&nsr(
        NS_NAT,
        &["ip", "addr", "add", NAT64_TAYGA_V4, "dev", &tun],
    ));
    must(&nsr(
        NS_NAT,
        &["ip", "route", "add", NAT64_POOL, "dev", &tun],
    ));
    must(&nsr(
        NS_NAT,
        &["ip", "-6", "route", "add", NAT64_PREFIX, "dev", &tun],
    ));

    // **The port sharing, and the reason this row is built this way.** `tayga`
    // is stateless: it hands each IPv6 client its own address out of the pool,
    // ports untouched. An ordinary masquerade behind it collapses the pool onto
    // one address and shares it by port — which is what a carrier does, and
    // which is a behaviour the other rows in this file already characterise.
    must(&nsr(NS_NAT, &["nft", "add", "table", "ip", "karst"]));
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
    must(&nsr(
        NS_NAT,
        &[
            "nft",
            "add",
            "rule",
            "ip",
            "karst",
            "post",
            "oifname kn-no masquerade",
        ],
    ));

    let child = Command::new("ip")
        .args(["netns", "exec", NS_NAT, "tayga", "-d", "-c", &conf_path])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn tayga");
    std::thread::sleep(std::time::Duration::from_millis(600));
    child
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
        //
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
    unsolicited_crosses_at(probe, from_ip, from_port, INNER_PORT)
}

/// As [`unsolicited_crosses`], but for a mapping whose external port is not the
/// inside one.
///
/// A cone preserves the port, so every row using the short form may assume it.
/// A **symmetric** NAT does not, so the double-NAT row learns the mapped port
/// from a reflection and passes it in — guessing [`INNER_PORT`] there addresses
/// a mapping that does not exist, and the row then reports "nothing crossed"
/// whatever the NAT would really have done.
fn unsolicited_crosses_at(probe: &str, from_ip: &str, from_port: u16, mapped: u16) -> bool {
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
    let to = format!("{NAT_OUTER_IP}:{mapped}");
    let sent = run_in(NS_OUTER, &[probe, "open", &from, &to]);
    // **The sender has to have run.** `PORT_A` and `PORT_B` are held by
    // reflectors for the whole of every row, so a caller passing one as
    // `from_port` gets a bind failure, no datagram, and a confident `false` — a
    // negative result manufactured by the fixture rather than by the NAT. The
    // carrier row was written that way first and only its defect check found it.
    assert!(
        sent.contains("SENT"),
        "the probe never left {from}: {sent:?}"
    );

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
/// **Two stages of translation filter as well as map, which is the half the
/// row above leaves out.**
///
/// `a_subscriber_behind_a_carrier_nat_is_translated_twice` establishes that the
/// carrier's *mapping* is endpoint-dependent — a different external port per
/// destination. That alone does not say whether a punched hole admits anyone
/// else, and the two answers lead to opposite conclusions about the exit
/// criterion. A carrier that filtered by address only would make a CGNAT
/// subscriber reachable the way row 5 of the topology table is reachable, from
/// any port, and symmetric-CGNAT-to-anything would stop being the hard case.
///
/// So this asserts the pair that actually characterises the row: the mapping
/// **does** carry the reply it was opened for, and **does not** carry a
/// datagram from an address the inside never contacted. Both halves are needed;
/// the negative one alone would also pass against a topology that carries
/// nothing at all, which is the failure finding 23 was.
#[test]
#[ignore = "needs root and network namespaces"]
fn a_carrier_nat_admits_the_reply_it_opened_and_nothing_else() {
    if !have_net_admin() {
        return;
    }
    let _lock = matrix_lock().lock().expect("matrix lock");
    let _topology = Topology;
    let probe = natprobe();
    build_double_nat();
    let _r = start_reflectors(&probe);

    // The positive half: a mapping opened toward A carries A's reply back
    // through both stages. `observed_from` returning at all is that assertion.
    let opened = observed_from(&probe, INNER_PORT, OUTER_IP_A, PORT_A)
        .expect("a reply from the address the mapping was opened toward should cross both stages");
    assert_eq!(
        ip_of(&opened),
        NAT_OUTER_IP,
        "after two translations the source should be the carrier's: {opened}"
    );
    let external = port_of(&opened);

    // The negative half, through the helper the cone rows already exercise in
    // both directions — `a_full_cone_admits_an_address_it_never_contacted`
    // shows it can return true, so a false here is a fact about this topology
    // rather than about the plumbing. The mapped port is passed in because the
    // carrier is symmetric and did not preserve it.
    assert!(
        !unsolicited_crosses_at(&probe, OUTER_IP_B, UNSOLICITED_PORT, external),
        "an outer host the inside never contacted reached it through two \
         translations"
    );
}

/// Run one host's hairpin attempt and return what the mapping's owner saw.
///
/// Returns `None` when nothing arrived, and `Some(source)` when it did — the
/// source being the interesting half, because RFC 4787 REQ-9 requires a
/// hairpinned datagram to arrive from the NAT's **external** address.
fn hairpin_attempt(probe: &str, hairpin: bool) -> Option<String> {
    // The mapping's owner opens it the way a real node does: an outbound
    // datagram to a reflector, which reports the external address back.
    let observed = observed_from(probe, INNER_PORT, OUTER_IP_A, PORT_A)
        .expect("the inside host should be able to reach the reflector");
    let external = port_of(&observed);
    assert_eq!(
        ip_of(&observed),
        NAT_OUTER_IP,
        "the reflector saw {observed}, which is not this NAT's outer address"
    );

    if hairpin {
        enable_hairpin(external);
    }

    // The owner waits on the mapping; the second host addresses it by the
    // NAT's external address, which is the only address it could have learned
    // from a relay.
    let listen = nsx(
        NS_INNER,
        &[probe, "listen", &format!("0.0.0.0:{INNER_PORT}"), "2500"],
    );
    let refs: Vec<&str> = listen.iter().map(String::as_str).collect();
    let child = Command::new(refs[0])
        .args(&refs[1..])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the listener");
    std::thread::sleep(std::time::Duration::from_millis(300));

    let target = format!("{NAT_OUTER_IP}:{external}");
    let _ = run_in(
        NS_PEER,
        &[probe, "open", &format!("0.0.0.0:{PEER_PORT}"), &target],
    );

    let out = child.wait_with_output().expect("listener output");
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    text.strip_prefix("RECV ").map(str::to_owned)
}

/// **Linux does not hairpin, and a node cannot assume otherwise.**
///
/// Two hosts on one home network, each holding the other's reflexive address
/// from a relay, probe each other at the NAT's external address — and nothing
/// arrives. The datagram is addressed to an address the NAT owns, so it is
/// delivered locally rather than translated, and the NAT has no listener.
///
/// The consequence for Karst is specific and load-bearing: **the interface-
/// address tier of `aven-v1.md` §7.2 is what carries the same-LAN case.** If a
/// node advertised only reflexive addresses — which is the tempting
/// simplification once §7.6 exists, because they are the ones that work
/// everywhere else — two machines on the same desk would be relayed through the
/// internet. That tier is not a fallback; on this row it is the only thing that
/// works.
#[test]
#[ignore = "needs root and network namespaces"]
fn a_masquerading_nat_does_not_hairpin() {
    if !have_net_admin() {
        return;
    }
    let _lock = matrix_lock().lock().expect("matrix lock");
    let _topology = Topology;
    let probe = natprobe();
    build_hairpin();
    let _r = start_reflectors(&probe);

    let got = hairpin_attempt(&probe, false);
    assert!(
        got.is_none(),
        "the datagram came back from {got:?} — this NAT hairpins, and the row \
         below is the one that should be asserting it"
    );
}

/// **…and when it is configured to, the source address is the external one.**
///
/// This row exists twice over. It records that hairpinning is a configuration
/// rather than an impossibility, so the row above is read as "not by default"
/// rather than "never". And it is the defect check for that row: with these two
/// rules added, the datagram arrives, so the row above is asserting the absence
/// of something this fixture is demonstrably capable of.
///
/// The source assertion is the substantive one. RFC 4787 REQ-9 requires a
/// hairpinned datagram to arrive from the NAT's **external** address, and a
/// `dnat` without the matching `snat` delivers it from the sender's *private*
/// address instead. A node that accepted that would learn a candidate its peer
/// can never be reached at from anywhere else, and — worse for AVEN — would
/// have `Pong.observed` report a private address as the peer's reflexive one.
#[test]
#[ignore = "needs root and network namespaces"]
fn a_nat_configured_for_hairpinning_rewrites_the_source_too() {
    if !have_net_admin() {
        return;
    }
    let _lock = matrix_lock().lock().expect("matrix lock");
    let _topology = Topology;
    let probe = natprobe();
    build_hairpin();
    let _r = start_reflectors(&probe);

    let got = hairpin_attempt(&probe, true).expect(
        "with the hairpin rules in place the datagram should arrive; if it does \
         not, the fixture cannot hairpin and the row above proves nothing",
    );
    assert_eq!(
        ip_of(&got),
        NAT_OUTER_IP,
        "hairpinned datagram arrived from {got}, not from the NAT's external \
         address — RFC 4787 REQ-9 requires the source to be rewritten too, and \
         a private source here would be advertised as a reflexive address"
    );
}

/// Probe from the IPv6-only inside — the v4 helpers cannot bind there.
fn observed_from6(probe: &str, bind_port: u16, target6: &str, target_port: u16) -> Option<String> {
    let bind = format!("[{NAT64_CLIENT_IP6}]:{bind_port}");
    let target = format!("[{target6}]:{target_port}");
    let out = run_in(NS_INNER, &[probe, "probe", &bind, &target]);
    out.strip_prefix("OBSERVED ").map(str::to_owned)
}

/// **An IPv6-only node reaches IPv4, and the path behaves like a cone.**
///
/// Two things are established and the second is the one that matters to AVEN.
///
/// The client has no IPv4 address at all, so reaching an IPv4-only host proves
/// the translation happened; the reflector sees the NAT's outer v4 address,
/// which is two translations — `tayga` into the pool, masquerade onto the one
/// outer address.
///
/// Then the same socket addresses two *different* IPv4 hosts and is seen at the
/// **same external port**. That is endpoint-independent mapping, so a NAT64
/// client's reflexive address (`aven-v1.md` §7.6) is the same address every
/// peer sees and discovery works on it unchanged. Had it come out
/// endpoint-*dependent*, an IPv6-only node would have been in §7.7's hard
/// class, and the row would be saying something very different about what
/// Karst does for mobile networks.
#[test]
#[ignore = "needs root, network namespaces and tayga"]
fn a_nat64_path_carries_ipv6_to_ipv4_and_shares_one_port_space() {
    if !have_net_admin() {
        return;
    }
    if !have_tool("tayga") {
        return;
    }
    let _lock = matrix_lock().lock().expect("matrix lock");
    let _topology = Topology;
    let probe = natprobe();
    let dir = std::env::temp_dir().join(format!("karst-nat64-{}", std::process::id()));
    let tayga = build_nat64(&dir);
    let _guard = Reflectors {
        children: vec![tayga],
    };
    let _reflectors = start_reflectors(&probe);

    let a = observed_from6(&probe, 19570, NAT64_OUTER_A, PORT_A)
        .expect("an IPv6-only client should reach an IPv4 host through the translator");
    assert_eq!(
        ip_of(&a),
        NAT_OUTER_IP,
        "the reflector saw {a}, which is not the NAT's outer IPv4 address — one \
         of the two translations did not happen"
    );

    let b = observed_from6(&probe, 19570, NAT64_OUTER_B, PORT_B)
        .expect("the second destination should also be reachable");
    assert_eq!(
        port_of(&a),
        port_of(&b),
        "the same socket was seen at {a} and {b} — this NAT64 path allocates \
         per destination, which would put every IPv6-only node in §7.7's hard \
         class"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "needs root and network namespaces"]
fn a_subscriber_behind_a_carrier_nat_is_translated_twice() {
    if !have_net_admin() {
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
