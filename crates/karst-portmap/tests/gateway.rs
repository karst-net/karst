// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! **The codec against a gateway we did not write.**
//!
//! Every other test in this crate checks the encoder against the decoder, which
//! proves they agree with each other and nothing about whether either agrees
//! with RFC 6886 or RFC 6887. A round-trip test passes just as happily when
//! both halves share a misreading — and a misreading is the likely failure
//! here, because these are byte-offset protocols with no length fields and no
//! self-description.
//!
//! So this drives **miniupnpd**, an independent implementation of both
//! protocols with a nftables backend, in a network namespace. It is the same
//! argument `crates/karst-disco/tests/nat_matrix.rs` makes about NAT
//! behaviour, one layer up: an instrument that only agrees with itself is not
//! an instrument.
//!
//! Needs `CAP_NET_ADMIN` and `miniupnpd` on `PATH`, so it is `#[ignore]`d:
//!
//! ```text
//! sudo -E cargo test -p karst-portmap --test gateway -- --ignored
//! ```

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use karst_portmap::{natpmp, pcp, Protocol, Transport, SERVER_PORT};

const NS_GW: &str = "kpm-gw";
const NS_IN: &str = "kpm-in";

/// The gateway's outside address — what it should report as external.
///
/// **Deliberately not a documentation range.** miniupnpd refuses to serve any
/// of the port-mapping protocols when its external address is reserved or
/// private, and every RFC 5737 documentation prefix is reserved by definition,
/// so `192.0.2.x` and `203.0.113.x` are both rejected — as are RFC 1918,
/// CGNAT and the benchmarking range. It insists on something globally routable
/// because a mapping toward a private address cannot work, which is a correct
/// check that happens to be inconvenient here.
///
/// So this is an arbitrary routable-looking address on a **dummy** interface in
/// a namespace with no route out of it. Nothing is ever sent to it; it exists
/// so the gateway has an answer when asked what its external address is.
const EXTERNAL: &str = "51.75.10.2";
/// The gateway's inside address, and the client's default route.
const GATEWAY: &str = "10.96.1.1";
/// The client.
const CLIENT: &str = "10.96.1.2";

/// The port a node would actually be mapping.
const DATA_PORT: u16 = 51820;

fn have_prerequisites() -> bool {
    let root = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))?
                .split_whitespace()
                .nth(2)?
                .parse::<u32>()
                .ok()
        })
        .unwrap_or(1)
        == 0;
    root && Command::new("miniupnpd")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success() || !o.stdout.is_empty())
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

fn nsr<'a>(ns: &'a str, args: &[&'a str]) -> Vec<&'a str> {
    let mut v = vec!["ip", "netns", "exec", ns];
    v.extend_from_slice(args);
    v
}

/// Tears the topology down however the test ended.
struct Gateway {
    daemon: Option<Child>,
    conf: std::path::PathBuf,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        if let Some(mut c) = self.daemon.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        for ns in [NS_IN, NS_GW] {
            let _ = sh(&["ip", "netns", "del", ns]);
        }
        let _ = std::fs::remove_file(&self.conf);
    }
}

/// Build the two namespaces and start miniupnpd on the gateway.
fn start() -> Gateway {
    for ns in [NS_IN, NS_GW] {
        let _ = sh(&["ip", "netns", "del", ns]);
        must(&["ip", "netns", "add", ns]);
        must(&nsr(ns, &["ip", "link", "set", "lo", "up"]));
    }

    // The gateway's outside leg. Nothing is on the far end — the tests never
    // send through it, they only ask the gateway what it is. A dummy device
    // rather than a veth, so there is no peer namespace to leak.
    must(&nsr(
        NS_GW,
        &["ip", "link", "add", "kpm-ext", "type", "dummy"],
    ));
    let ext = format!("{EXTERNAL}/24");
    must(&nsr(NS_GW, &["ip", "addr", "add", &ext, "dev", "kpm-ext"]));
    must(&nsr(NS_GW, &["ip", "link", "set", "kpm-ext", "up"]));

    // Gateway to client.
    must(&[
        "ip", "link", "add", "kpm-int", "netns", NS_GW, "type", "veth", "peer", "name", "kpm-cli",
        "netns", NS_IN,
    ]);
    let gw = format!("{GATEWAY}/24");
    must(&nsr(NS_GW, &["ip", "addr", "add", &gw, "dev", "kpm-int"]));
    must(&nsr(NS_GW, &["ip", "link", "set", "kpm-int", "up"]));
    let cli = format!("{CLIENT}/24");
    must(&nsr(NS_IN, &["ip", "addr", "add", &cli, "dev", "kpm-cli"]));
    must(&nsr(NS_IN, &["ip", "link", "set", "kpm-cli", "up"]));
    must(&nsr(
        NS_IN,
        &["ip", "route", "add", "default", "via", GATEWAY],
    ));
    must(&nsr(
        NS_GW,
        &["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"],
    ));

    // The chains miniupnpd expects to find and will add rules into. Created
    // here rather than by shipping `nft_init.sh` into the namespace, because
    // that script's `policy drop` on the forward chain would black-hole the
    // very traffic the surrounding topology carries, and this test does not
    // need the filtering half at all — it is checking what the gateway *says*.
    let table = "inet miniupnpd";
    must(&nsr(NS_GW, &["nft", "add", "table", "inet", "miniupnpd"]));
    for (chain, spec) in [
        ("prerouting", "{ type nat hook prerouting priority -100 ; }"),
        (
            "postrouting",
            "{ type nat hook postrouting priority 100 ; }",
        ),
        ("forward", "{ type filter hook forward priority 0 ; }"),
        ("miniupnpd", ""),
        ("prerouting-miniupnpd", ""),
        ("postrouting-miniupnpd", ""),
    ] {
        let mut args = vec!["nft", "add", "chain", "inet", "miniupnpd", chain];
        if !spec.is_empty() {
            args.push(spec);
        }
        must(&nsr(NS_GW, &args));
    }
    let _ = table;

    let conf = std::env::temp_dir().join(format!("karst-portmap-{}.conf", std::process::id()));
    let body = format!(
        "ext_ifname=kpm-ext\n\
         listening_ip=kpm-int\n\
         enable_natpmp=yes\n\
         enable_upnp=no\n\
         secure_mode=no\n\
         system_uptime=yes\n\
         upnp_table_name=miniupnpd\n\
         upnp_nat_table_name=miniupnpd\n\
         upnp_forward_chain=miniupnpd\n\
         upnp_nat_chain=prerouting-miniupnpd\n\
         upnp_nat_postrouting_chain=postrouting-miniupnpd\n\
         allow 1024-65535 {CLIENT}/32 1024-65535\n\
         deny 0-65535 0.0.0.0/0 0-65535\n"
    );
    let mut f = std::fs::File::create(&conf).expect("write the miniupnpd config");
    f.write_all(body.as_bytes()).expect("write");
    drop(f);

    let path = conf.to_string_lossy().into_owned();
    let daemon = Command::new("ip")
        .args(["netns", "exec", NS_GW, "miniupnpd", "-d", "-f", &path])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn miniupnpd");
    // It binds and reads its lease file before it answers.
    std::thread::sleep(Duration::from_millis(800));

    Gateway {
        daemon: Some(daemon),
        conf,
    }
}

/// Path to the `pmprobe` example, which does the socket work.
fn pmprobe() -> String {
    // The test binary lives in target/<profile>/deps/; the example is two
    // directories up. Derived rather than hard-coded so a `--release` run works.
    let exe = std::env::current_exe().expect("test binary path");
    let dir = exe
        .parent()
        .and_then(std::path::Path::parent)
        .expect("target/<profile>");
    let p = dir.join("examples").join("pmprobe");
    assert!(
        p.exists(),
        "{} is missing — build it with `cargo build -p karst-portmap --example pmprobe`",
        p.display()
    );
    p.to_string_lossy().into_owned()
}

fn hex_encode(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, byte| {
        let _ = write!(s, "{byte:02x}");
        s
    })
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex from pmprobe: {s:?}");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex digit"))
        .collect()
}

/// One request/response exchange, with the socket created inside `NS_IN`.
///
/// The socket must be *created* in the client namespace — one bound in another
/// namespace is on the wrong stack, which is the same mistake `aven-v1.md`
/// §7.6 warns about for reflections. Hence a helper process under
/// `ip netns exec` rather than a thread: the codec stays here, where a failure
/// is an assertion rather than a hex dump.
fn exchange(request: &[u8]) -> Option<Vec<u8>> {
    let probe = pmprobe();
    let gateway = format!("{GATEWAY}:{SERVER_PORT}");
    let hex = hex_encode(request);
    let out = Command::new("ip")
        .args(["netns", "exec", NS_IN, &probe, CLIENT, &gateway, &hex])
        .output()
        .expect("run pmprobe");
    assert!(
        out.status.success(),
        "pmprobe failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.trim();
    line.strip_prefix("REPLY ").map(hex_decode)
}

#[test]
#[ignore = "needs root, network namespaces and miniupnpd"]
fn natpmp_reports_the_external_address_the_gateway_actually_has() {
    if !have_prerequisites() {
        eprintln!("skipping: needs root and miniupnpd");
        return;
    }
    let _gw = start();

    let reply = exchange(&natpmp::encode_public_address()).expect("a NAT-PMP answer");
    let got = natpmp::decode(&reply, natpmp::OP_PUBLIC_ADDRESS).expect("decodes");
    let natpmp::Response::PublicAddress { address, .. } = got else {
        panic!("expected an address, got {got:?}");
    };
    assert_eq!(
        address,
        EXTERNAL.parse::<Ipv4Addr>().expect("external address"),
        "the gateway named an address that is not the one it holds"
    );
}

#[test]
#[ignore = "needs root, network namespaces and miniupnpd"]
fn natpmp_installs_a_mapping_a_third_party_gateway_agrees_with() {
    if !have_prerequisites() {
        eprintln!("skipping: needs root and miniupnpd");
        return;
    }
    let _gw = start();

    // **The suggested external port is deliberately not the internal one.**
    // Asking for the same number on both sides makes a transposed pair of
    // fields invisible — the gateway echoes back what looks like the right
    // answer either way. Mutating the encoder to swap them fails this test
    // only because the two differ here.
    let req = natpmp::encode_map(
        Transport::Udp,
        DATA_PORT,
        DATA_PORT + 7,
        natpmp::DEFAULT_LIFETIME,
    );
    let reply = exchange(&req).expect("a NAT-PMP answer");
    let got = natpmp::decode(&reply, natpmp::OP_MAP_UDP).expect("decodes");
    let natpmp::Response::Mapped(m) = got else {
        panic!("expected a mapping, got {got:?}");
    };
    assert_eq!(m.protocol, Protocol::NatPmp);
    assert_eq!(m.transport, Transport::Udp);
    assert_eq!(m.internal_port, DATA_PORT);
    assert_ne!(m.external_port, 0, "a mapping with no external port");
    assert!(
        !m.lifetime.is_zero(),
        "a zero lifetime is a deletion, not a mapping"
    );
    // **The point of the whole test.** miniupnpd trims a two-hour request to
    // its own maximum, and this is the assertion that a round-trip test cannot
    // make: the granted lifetime is the gateway's number, not ours.
    assert!(
        m.lifetime <= natpmp::DEFAULT_LIFETIME,
        "granted {:?} exceeds the {:?} requested",
        m.lifetime,
        natpmp::DEFAULT_LIFETIME
    );
    assert_eq!(
        m.renew_after(),
        Some(m.lifetime / 2),
        "renewal is computed against what was granted"
    );
}

#[test]
#[ignore = "needs root, network namespaces and miniupnpd"]
fn pcp_installs_a_mapping_and_names_the_external_address_in_one_exchange() {
    if !have_prerequisites() {
        eprintln!("skipping: needs root and miniupnpd");
        return;
    }
    let _gw = start();

    let nonce = pcp::Nonce([7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6]);
    let client: IpAddr = CLIENT.parse().expect("client address");
    let req = pcp::encode_map(
        nonce,
        Transport::Udp,
        DATA_PORT,
        DATA_PORT,
        client,
        pcp::DEFAULT_LIFETIME,
    );
    let reply = exchange(&req).expect("a PCP answer");
    let m = pcp::decode_map(&reply, nonce).expect("decodes");

    assert_eq!(m.protocol, Protocol::Pcp);
    assert_eq!(m.transport, Transport::Udp);
    assert_eq!(m.internal_port, DATA_PORT);
    assert_ne!(m.external_port, 0);
    // The improvement over NAT-PMP that justifies trying PCP first: one
    // exchange yields the address as well as the port.
    assert_eq!(
        m.external_address,
        Some(IpAddr::V4(EXTERNAL.parse().expect("external"))),
        "PCP should name the external address in the mapping response"
    );
    assert!(!m.lifetime.is_zero());
}

#[test]
#[ignore = "needs root, network namespaces and miniupnpd"]
fn a_pcp_response_carries_back_the_nonce_that_was_sent() {
    if !have_prerequisites() {
        eprintln!("skipping: needs root and miniupnpd");
        return;
    }
    let _gw = start();

    let nonce = pcp::Nonce([0xAB; pcp::NONCE_LEN]);
    let client: IpAddr = CLIENT.parse().expect("client address");
    let req = pcp::encode_map(
        nonce,
        Transport::Udp,
        DATA_PORT + 1,
        0,
        client,
        pcp::DEFAULT_LIFETIME,
    );
    let reply = exchange(&req).expect("a PCP answer");

    // Decoding with the right nonce works; decoding the *same bytes* with any
    // other nonce must not. That is the check that the nonce is really being
    // compared against the wire rather than against itself — and a real
    // gateway echoing a real nonce is the only way to make it convincing.
    assert!(pcp::decode_map(&reply, nonce).is_ok());
    let other = pcp::Nonce([0xCD; pcp::NONCE_LEN]);
    assert_eq!(
        pcp::decode_map(&reply, other),
        Err(karst_portmap::Error::NonceMismatch)
    );
}
