// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! RFC 8781 against a router that is not ours.
//!
//! The option parser is unit-tested from the standard's own field definitions,
//! and that is most of the correctness — but a parser fed by nothing is a
//! parser that has never seen a packet. What is untested there is the half that
//! only a socket can exercise: that the `ICMP6_FILTER` really admits Router
//! Advertisements, that a solicitation goes to the right multicast group out of
//! the right interface, and that what comes back begins at the byte the parser
//! expects.
//!
//! **The router is a Python script**, deliberately. It builds the advertisement
//! from RFC 8781 §4's field layout independently of any Rust in this tree, so a
//! misreading of the standard shows up as a disagreement rather than as two
//! copies of the same mistake agreeing. `karst-portmap`'s `gateway` suite uses
//! `miniupnpd` for the same reason, and finding 23 is what skipping it costs.
//!
//! Needs root: `CAP_NET_RAW` for both ends, and a network namespace so the
//! solicitation cannot reach a real router or a colleague's desk.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::process::{Command, Stdio};
use std::time::Duration;

const NS: &str = "karst-pref64";
/// Both ends of one veth, in one namespace: the probe solicits on `kp-b` and
/// the Python router answers on `kp-a`. A pair is its own link, so link-local
/// multicast reaches across it with no addressing to configure — the kernel
/// gives each end a link-local address on its own.
const ROUTER_LEG: &str = "kp-a";
const PROBE_LEG: &str = "kp-b";
/// Not the well-known prefix, and not a /96 — so a probe that guessed either
/// default instead of reading the option would fail rather than pass.
const PREFIX: &str = "2001:db8:122:344::/64";

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

/// Whether to run, **and a refusal to be quietly green** — the rule
/// `nat_matrix.rs` acquired as GitHub issue [#53](https://github.com/karst-net/karst/issues/53).
fn have_prerequisites() -> bool {
    let mut missing = Vec::new();
    if effective_uid() != 0 {
        missing.push("root");
    }
    for (tool, probe) in [("ip", "-Version"), ("python3", "--version")] {
        if Command::new(tool).arg(probe).output().is_err() {
            missing.push(tool);
        }
    }
    if missing.is_empty() {
        return true;
    }
    assert!(
        std::env::var_os("KARST_REQUIRE_PREREQUISITES").is_none(),
        "KARST_REQUIRE_PREREQUISITES is set, so skipping is not allowed — \
         missing: {missing:?}"
    );
    eprintln!("skipping: missing {missing:?}");
    false
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

fn nsr(args: &[&str]) -> Vec<String> {
    let mut argv = vec!["netns".to_owned(), "exec".to_owned(), NS.to_owned()];
    argv.extend(args.iter().map(|s| (*s).to_owned()));
    argv
}

fn run_in_ns(args: &[&str]) {
    let argv = nsr(args);
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let mut full = vec!["ip"];
    full.extend(refs);
    must(&full);
}

/// Where `cargo` put the example, derived rather than hard-coded so a
/// `--release` run finds it too. The same shape `nat_matrix.rs` uses for
/// `natprobe`.
fn probe_binary() -> String {
    let exe = std::env::current_exe().expect("test binary path");
    let dir = exe
        .parent()
        .and_then(std::path::Path::parent)
        .expect("target/<profile>");
    let p = dir.join("examples").join("pref64probe");
    assert!(
        p.exists(),
        "{} is missing — build it with \
         `cargo build -p karst-transport --example pref64probe`",
        p.display()
    );
    p.to_string_lossy().into_owned()
}

struct Namespace;

impl Drop for Namespace {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", NS]).output();
    }
}

/// The router, in a language that has never read this crate.
///
/// Waits for a Router Solicitation and answers with an advertisement carrying
/// one PREF64 option, built from §4's layout: a 13-bit lifetime in units of
/// eight seconds and a 3-bit prefix-length code, then the top 96 bits of the
/// prefix.
const ROUTER: &str = r#"
import socket, struct, sys, ipaddress

iface, prefix, plc = sys.argv[1], sys.argv[2], int(sys.argv[3])
s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
idx = socket.if_nametoindex(iface)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, struct.pack("I", idx))
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
# Pass only Router Solicitations (type 133). RFC 3542 3.2: a set bit BLOCKS,
# so this is block-all with one bit cleared.
filt = [0xFFFFFFFF] * 8
filt[133 >> 5] &= ~(1 << (133 & 31)) & 0xFFFFFFFF
s.setsockopt(socket.IPPROTO_ICMPV6, 1, struct.pack("8I", *filt))
s.settimeout(20)

# RFC 8781 §4. Scaled Lifetime is in units of 8 seconds, so 600s is 75.
lifetime, plen = 600 // 8, 96
word = (lifetime << 3) | plc
option = struct.pack("!BBH", 38, 2, word) + ipaddress.IPv6Address(prefix).packed[:12]
# ICMPv6 header (checksum left to the kernel) then the RA fields of RFC 4861 §4.2.
ra = struct.pack("!BBH", 134, 0, 0) + struct.pack("!BBHII", 64, 0, 1800, 0, 0) + option

print("ready", flush=True)
while True:
    try:
        s.recv(1280)
    except socket.timeout:
        sys.exit(1)
    s.sendto(ra, ("ff02::1%" + iface, 0))
"#;

/// **The whole mechanism, end to end, against an independent router.**
///
/// A probe with no IPv6 prefix knowledge solicits, a Python router answers with
/// a PREF64 option, and the probe must print the prefix that was advertised —
/// a `/64`, so a reader that assumed the common `/96` gets a different answer
/// rather than the right one by luck.
#[test]
#[ignore = "needs root, network namespaces and python3"]
fn a_solicited_router_advertisement_yields_the_prefix_it_advertised() {
    if !have_prerequisites() {
        return;
    }
    let _ = Command::new("ip").args(["netns", "del", NS]).output();
    must(&["ip", "netns", "add", NS]);
    let _ns = Namespace;

    run_in_ns(&["ip", "link", "set", "lo", "up"]);
    // **The router end has to actually be a router.** `ff02::2` is the
    // all-routers group and a host does not join it — so without forwarding
    // enabled the solicitation is delivered nowhere and the Python side waits
    // for a packet the kernel dropped. Set before the links exist, so they join
    // the group as they come up.
    run_in_ns(&[
        "sh",
        "-c",
        "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding",
    ]);
    run_in_ns(&[
        "ip", "link", "add", ROUTER_LEG, "type", "veth", "peer", "name", PROBE_LEG,
    ]);
    for leg in [ROUTER_LEG, PROBE_LEG] {
        run_in_ns(&["ip", "link", "set", leg, "up"]);
    }
    // The kernel assigns each end a link-local address, which is all a
    // solicitation needs — but not instantly, and a `sendto` before it exists
    // fails with `EADDRNOTAVAIL`. Wait for both to leave `tentative`.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let out = Command::new("ip")
            .args(nsr(&["ip", "-6", "addr", "show"]))
            .output()
            .expect("ip -6 addr");
        let text = String::from_utf8_lossy(&out.stdout);
        let ready = [ROUTER_LEG, PROBE_LEG]
            .iter()
            .all(|leg| text.contains(leg) && text.matches("fe80::").count() >= 2);
        if ready && !text.contains("tentative") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the veth pair never acquired link-local addresses:\n{text}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let script = std::env::temp_dir().join(format!("karst-pref64-{}.py", std::process::id()));
    std::fs::write(&script, ROUTER).expect("write the router script");

    // Prefix-length code 1 is a /64 — see `PREFIX`.
    let mut router = Command::new("ip")
        .args(nsr(&[
            "python3",
            &script.to_string_lossy(),
            ROUTER_LEG,
            "2001:db8:122:344::",
            "1",
        ]))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the router");

    // Wait for it to say it is listening; soliciting first would race it.
    {
        use std::io::{BufRead as _, BufReader};
        let stdout = router.stdout.take().expect("stdout");
        let mut line = String::new();
        BufReader::new(stdout)
            .read_line(&mut line)
            .expect("the router never signalled readiness");
        assert!(line.starts_with("ready"), "the router said {line:?}");
    }

    let probe = probe_binary();
    let out = Command::new("ip")
        .args(nsr(&[&probe, PROBE_LEG]))
        .output()
        .expect("run the probe");
    let _ = router.kill();
    let router_err = router
        .stderr
        .take()
        .map(|mut e| {
            use std::io::Read as _;
            let mut s = String::new();
            let _ = e.read_to_string(&mut s);
            s
        })
        .unwrap_or_default();
    let _ = router.wait();
    let _ = std::fs::remove_file(&script);

    let found = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    assert_eq!(
        found,
        PREFIX,
        "the probe read {found:?} from an advertisement carrying {PREFIX}.\n\
         probe stderr:\n{}\nrouter stderr:\n{router_err}",
        String::from_utf8_lossy(&out.stderr)
    );
}
