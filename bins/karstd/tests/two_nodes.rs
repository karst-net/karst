// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! **Two daemons, two real TUN interfaces, real IP traffic.**
//!
//! `tests/datapath.rs` drives the engines directly. This runs the whole thing:
//! two `karstd` instances in separate network namespaces, each with a kernel
//! TUN device, exchanging packets the host stack generated.
//!
//! Needs `CAP_NET_ADMIN`, so these are `#[ignore]`d. Run them with:
//!
//! ```text
//! just test-karstd
//! ```
//!
//! Network namespaces are what make this possible on one machine: two
//! interfaces cannot otherwise hold overlapping addresses, and both nodes want
//! to be `10.77.0.x` on an interface called `karst0`.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use karst_crypto::kem::{keypair_from_seed, KemKind};
use karstd::config::encode_hex;

const NETNS_A: &str = "karst-test-a";
const NETNS_B: &str = "karst-test-b";

fn have_net_admin() -> bool {
    Command::new("ip")
        .args(["netns", "list"])
        .output()
        .is_ok_and(|o| o.status.success())
        && effective_uid() == 0
}

/// Root check without `unsafe`: `/proc/self/status` reports the effective UID.
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

fn sh(args: &[&str]) -> bool {
    Command::new(args[0])
        .args(&args[1..])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn public_of(n: u8) -> String {
    let (_, kem_pk) = keypair_from_seed(KemKind::MlKem1024, &[n; 64]);

    encode_hex(&kem_pk.to_bytes())
}

/// Build the two namespaces joined by a veth pair, so the daemons' UDP sockets
/// can reach each other while their TUN interfaces stay isolated.
fn setup_namespaces() -> bool {
    teardown_namespaces();
    sh(&["ip", "netns", "add", NETNS_A])
        && sh(&["ip", "netns", "add", NETNS_B])
        && sh(&[
            "ip",
            "link",
            "add",
            "karstveth-a",
            "type",
            "veth",
            "peer",
            "name",
            "karstveth-b",
        ])
        && sh(&["ip", "link", "set", "karstveth-a", "netns", NETNS_A])
        && sh(&["ip", "link", "set", "karstveth-b", "netns", NETNS_B])
        && sh(&[
            "ip",
            "netns",
            "exec",
            NETNS_A,
            "ip",
            "addr",
            "add",
            "192.0.2.1/24",
            "dev",
            "karstveth-a",
        ])
        && sh(&[
            "ip",
            "netns",
            "exec",
            NETNS_B,
            "ip",
            "addr",
            "add",
            "192.0.2.2/24",
            "dev",
            "karstveth-b",
        ])
        && sh(&[
            "ip",
            "netns",
            "exec",
            NETNS_A,
            "ip",
            "link",
            "set",
            "karstveth-a",
            "up",
        ])
        && sh(&[
            "ip",
            "netns",
            "exec",
            NETNS_B,
            "ip",
            "link",
            "set",
            "karstveth-b",
            "up",
        ])
        && sh(&[
            "ip", "netns", "exec", NETNS_A, "ip", "link", "set", "lo", "up",
        ])
        && sh(&[
            "ip", "netns", "exec", NETNS_B, "ip", "link", "set", "lo", "up",
        ])
}

fn teardown_namespaces() {
    let _ = sh(&["ip", "netns", "del", NETNS_A]);
    let _ = sh(&["ip", "netns", "del", NETNS_B]);
    let _ = sh(&["ip", "link", "del", "karstveth-a"]);
}

struct Node {
    dir: PathBuf,
    socket: PathBuf,
    child: std::process::Child,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Write a config and start `karstd` inside a namespace.
fn start(tag: &str, netns: &str, me: u8, peer: u8, my_ip: u8, peer_endpoint: Option<&str>) -> Node {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("karstd-two-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");

    let key = dir.join("node.key");
    let seed = [me; 64];

    std::fs::write(&key, encode_hex(&seed)).expect("write key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("chmod");

    let kem = public_of(peer);
    let endpoint = peer_endpoint.map_or_else(String::new, |e| format!("endpoint = \"{e}\"\n"));
    let peer_ip = 3 - my_ip;
    let toml = format!(
        r#"
[node]
listen = "0.0.0.0:51820"
interface = "karst0"
addresses = ["10.77.0.{my_ip}/24"]
private_key_file = "node.key"

[[peer]]
name = "other"
kem_public_key = "{kem}"
{endpoint}allowed_ips = ["10.77.0.{peer_ip}/32"]
"#
    );
    let config = dir.join("karstd.toml");
    std::fs::write(&config, toml).expect("write config");
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).expect("chmod");

    let socket = dir.join("karstd.sock");
    let bin = env!("CARGO_BIN_EXE_karstd");
    let child = Command::new("ip")
        .args(["netns", "exec", netns, bin, "--config"])
        .arg(&config)
        .arg("--socket")
        .arg(&socket)
        .spawn()
        .expect("spawn karstd");

    Node { dir, socket, child }
}

/// Path to the `karst` CLI.
///
/// `CARGO_BIN_EXE_*` is only defined for binaries in the *same* package, and
/// `karst` lives in `karst-cli`. Both land in the same output directory, so it
/// is derived from this package's binary rather than guessed from the manifest.
fn karst_bin() -> PathBuf {
    let karstd = PathBuf::from(env!("CARGO_BIN_EXE_karstd"));
    let bin = karstd.with_file_name("karst");
    assert!(
        bin.exists(),
        "{} is missing — build the workspace, not just this package",
        bin.display()
    );
    bin
}

/// Run `karst` against a node's control socket, returning its stdout.
fn karst(node: &Node, command: &str) -> String {
    let out = Command::new(karst_bin())
        .args([command, "--socket"])
        .arg(&node.socket)
        .output()
        .expect("run karst");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Wait for a condition, polling — handshakes take a moment.
fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("timed out waiting for {what}");
}

/// **The Phase 2 exit criterion, in miniature.** Two hosts route real IP traffic
/// through Karst.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn two_daemons_carry_real_ip_traffic() {
    assert!(have_net_admin(), "run as root");
    assert!(setup_namespaces(), "could not build the test namespaces");

    let _a = start("a", NETNS_A, 0xA1, 0xB1, 1, Some("192.0.2.2:51820"));
    let _b = start("b", NETNS_B, 0xB1, 0xA1, 2, None);

    wait_for("both interfaces to appear", || {
        sh(&[
            "ip", "netns", "exec", NETNS_A, "ip", "link", "show", "karst0",
        ]) && sh(&[
            "ip", "netns", "exec", NETNS_B, "ip", "link", "show", "karst0",
        ])
    });

    // A ping crosses the tunnel: kernel → TUN → PHREATIC → UDP → veth → …
    wait_for("a ping to traverse the tunnel", || {
        sh(&[
            "ip",
            "netns",
            "exec",
            NETNS_A,
            "ping",
            "-c",
            "1",
            "-W",
            "2",
            "10.77.0.2",
        ])
    });

    // And back the other way, which exercises the responder's send path.
    assert!(
        sh(&[
            "ip",
            "netns",
            "exec",
            NETNS_B,
            "ping",
            "-c",
            "3",
            "-W",
            "2",
            "10.77.0.1",
        ]),
        "the responder must be able to originate traffic too"
    );

    teardown_namespaces();
}

/// A full-MTU ping is the case spec §13.6 exists for. 1280 bytes of IP packet
/// must cross in one unfragmented datagram and arrive whole.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn a_full_mtu_packet_crosses_the_tunnel() {
    assert!(have_net_admin(), "run as root");
    assert!(setup_namespaces(), "could not build the test namespaces");

    let _a = start("mtu-a", NETNS_A, 0xA1, 0xB1, 1, Some("192.0.2.2:51820"));
    let _b = start("mtu-b", NETNS_B, 0xB1, 0xA1, 2, None);

    wait_for("the tunnel to come up", || {
        sh(&[
            "ip",
            "netns",
            "exec",
            NETNS_A,
            "ping",
            "-c",
            "1",
            "-W",
            "2",
            "10.77.0.2",
        ])
    });

    // 1280 = 20 (IP) + 8 (ICMP) + 1252 payload. `-M do` sets DF, so a packet
    // that needed fragmenting anywhere would fail rather than quietly succeed.
    assert!(
        sh(&[
            "ip",
            "netns",
            "exec",
            NETNS_A,
            "ping",
            "-c",
            "3",
            "-W",
            "2",
            "-s",
            "1252",
            "-M",
            "do",
            "10.77.0.2",
        ]),
        "a full-MTU packet must cross without IP fragmentation (spec §13.6)"
    );

    teardown_namespaces();
}

/// The interface must carry IPv6, because that is the entire reason the tunnel
/// MTU cannot drop below 1280 (spec §13.6). If this fails, the argument for the
/// larger transport datagram collapses.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn the_tunnel_mtu_satisfies_rfc_8200() {
    assert!(have_net_admin(), "run as root");
    assert!(setup_namespaces(), "could not build the test namespaces");

    let _a = start("v6-a", NETNS_A, 0xA1, 0xB1, 1, Some("192.0.2.2:51820"));
    wait_for("the interface to appear", || {
        sh(&[
            "ip", "netns", "exec", NETNS_A, "ip", "link", "show", "karst0",
        ])
    });

    let mtu = Command::new("ip")
        .args(["netns", "exec", NETNS_A, "cat", "/sys/class/net/karst0/mtu"])
        .output()
        .expect("read mtu");
    let mtu: usize = String::from_utf8_lossy(&mtu.stdout)
        .trim()
        .parse()
        .expect("numeric mtu");
    assert!(
        mtu >= 1280,
        "RFC 8200 §5 requires 1280 on any link carrying IPv6; found {mtu}"
    );

    // An IPv6 address can only be assigned to a link that meets the minimum.
    assert!(
        sh(&[
            "ip",
            "netns",
            "exec",
            NETNS_A,
            "ip",
            "-6",
            "addr",
            "add",
            "fd7a:5ea5::1/64",
            "dev",
            "karst0",
        ]),
        "the interface must accept an IPv6 address"
    );

    teardown_namespaces();
}

/// `karst status` must report a running tunnel, and §13.6 requires the tunnel
/// MTU be among what it reports: a path that black-holes full-size packets is
/// otherwise very hard to diagnose from the outside.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn the_cli_reports_a_live_tunnel() {
    assert!(have_net_admin(), "run as root");
    assert!(setup_namespaces(), "could not build the test namespaces");

    let a = start("cli-a", NETNS_A, 0xA1, 0xB1, 1, Some("192.0.2.2:51820"));
    let _b = start("cli-b", NETNS_B, 0xB1, 0xA1, 2, None);

    wait_for("the tunnel to come up", || {
        sh(&[
            "ip",
            "netns",
            "exec",
            NETNS_A,
            "ping",
            "-c",
            "1",
            "-W",
            "2",
            "10.77.0.2",
        ])
    });

    let status = karst(&a, "status");
    assert!(status.contains("mtu = 1280"), "spec §13.6: {status}");
    assert!(status.contains(r#"interface = "karst0""#), "{status}");
    assert!(status.contains(r#"state = "established""#), "{status}");
    assert!(status.contains("192.0.2.2:51820"), "{status}");
    assert!(status.contains("tx_packets"), "{status}");

    // Nothing secret may appear. A status command is exactly what ends up
    // pasted into a bug report (THREAT-MODEL R5).
    let private = encode_hex(&[0xA1u8; 64]);
    assert!(!status.contains(&private), "private key material in status");
    assert!(!status.to_lowercase().contains("psk = "), "PSK in status");

    // And the bug report, over the same socket. This is the artifact most
    // likely to be pasted somewhere public, so it is checked on a *running*
    // node rather than only in the unit scan — the two catch different
    // mistakes, and this one covers the path the socket actually serves.
    let report = karst(&a, "bugreport");
    assert!(report.contains("no key material"), "{report}");
    assert!(report.contains("[interface]"), "{report}");
    assert!(report.contains("[stats]"), "{report}");
    assert!(report.contains("kernel = "), "the host facts: {report}");
    assert!(report.contains("psk_epoch"), "{report}");
    assert!(report.contains("established = true"), "{report}");

    assert!(
        !report.contains(&private),
        "private key material in the bug report"
    );
    assert!(
        !report.to_lowercase().contains("psk = \""),
        "a PSK value in the bug report"
    );

    teardown_namespaces();
}

/// `karst down` must actually stop the daemon and leave nothing behind — no
/// interface, no socket file. A leftover interface would black-hole every
/// packet the kernel still routes to it.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn the_cli_stops_the_daemon_cleanly() {
    assert!(have_net_admin(), "run as root");
    assert!(setup_namespaces(), "could not build the test namespaces");

    let a = start("down-a", NETNS_A, 0xA1, 0xB1, 1, Some("192.0.2.2:51820"));
    wait_for("the interface to appear", || {
        sh(&[
            "ip", "netns", "exec", NETNS_A, "ip", "link", "show", "karst0",
        ])
    });

    let reply = karst(&a, "down");
    assert!(reply.contains("stopping"), "got {reply:?}");

    wait_for("the interface to disappear", || {
        !sh(&[
            "ip", "netns", "exec", NETNS_A, "ip", "link", "show", "karst0",
        ])
    });
    wait_for("the control socket to be removed", || !a.socket.exists());

    teardown_namespaces();
}

/// **Process restart recovery** — a Phase 2 exit criterion.
///
/// A node that is killed and restarted must rebuild its tunnel without help.
/// The far end still believes it has a session, so this also exercises the case
/// where a fresh handshake arrives for a peer that is already established.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn a_node_recovers_from_a_process_restart() {
    assert!(have_net_admin(), "run as root");
    assert!(setup_namespaces(), "could not build the test namespaces");

    let a = start("restart-a", NETNS_A, 0xA1, 0xB1, 1, Some("192.0.2.2:51820"));
    let _b = start("restart-b", NETNS_B, 0xB1, 0xA1, 2, None);

    wait_for("the tunnel to come up", || {
        sh(&[
            "ip",
            "netns",
            "exec",
            NETNS_A,
            "ping",
            "-c",
            "1",
            "-W",
            "2",
            "10.77.0.2",
        ])
    });

    // Kill A outright — no shutdown command, no chance to tidy up. This is the
    // crash case, not the graceful one.
    drop(a);
    wait_for("A's interface to disappear", || {
        !sh(&[
            "ip", "netns", "exec", NETNS_A, "ip", "link", "show", "karst0",
        ])
    });

    // Restart it with the same identity and configuration.
    let a2 = start("restart-a", NETNS_A, 0xA1, 0xB1, 1, Some("192.0.2.2:51820"));
    wait_for("the tunnel to come back", || {
        sh(&[
            "ip",
            "netns",
            "exec",
            NETNS_A,
            "ping",
            "-c",
            "1",
            "-W",
            "2",
            "10.77.0.2",
        ])
    });

    let status = karst(&a2, "status");
    assert!(
        status.contains(r#"state = "established""#),
        "the restarted node must re-establish: {status}"
    );

    // A stale control socket from the killed process must not have blocked
    // startup — if it had, the daemon would not be answering at all.
    assert!(a2.socket.exists());

    teardown_namespaces();
}

// ── interface flaps ─────────────────────────────────────────────────────────

/// Whether a ping crosses the tunnel right now.
fn tunnel_up(netns: &str, target: &str) -> bool {
    sh(&[
        "ip", "netns", "exec", netns, "ping", "-c", "1", "-W", "2", target,
    ])
}

/// **The underlay goes away and comes back.** A cable pulled, a switch
/// rebooted, Wi-Fi roaming — the case PLAN.md's exit criterion calls an
/// interface flap.
///
/// What must hold: traffic stops while the link is down (nothing else is
/// possible), the daemon survives rather than treating `ENETUNREACH` as fatal,
/// and the tunnel resumes on its own when the link returns — with no restart
/// and no operator action.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn the_tunnel_recovers_from_an_underlay_interface_flap() {
    assert!(have_net_admin(), "run as root");
    assert!(setup_namespaces(), "could not build the test namespaces");

    let _a = start("flap-a", NETNS_A, 0xA1, 0xB1, 1, Some("192.0.2.2:51820"));
    let _b = start("flap-b", NETNS_B, 0xB1, 0xA1, 2, None);
    wait_for("the tunnel to come up", || tunnel_up(NETNS_A, "10.77.0.2"));

    // Pull the underlay out from under it.
    assert!(
        sh(&[
            "ip",
            "netns",
            "exec",
            NETNS_A,
            "ip",
            "link",
            "set",
            "karstveth-a",
            "down",
        ]),
        "could not take the underlay down"
    );
    wait_for("traffic to stop", || !tunnel_up(NETNS_A, "10.77.0.2"));

    // The daemon must still be alive and answering: a send failing with
    // ENETUNREACH is an ordinary event, not a reason to exit.
    assert!(
        sh(&["ip", "netns", "exec", NETNS_A, "ip", "link", "show", "karst0",]),
        "the tunnel interface vanished when the underlay went down"
    );

    // Put it back.
    assert!(sh(&[
        "ip",
        "netns",
        "exec",
        NETNS_A,
        "ip",
        "link",
        "set",
        "karstveth-a",
        "up",
    ]));
    // A veth keeps its address across an admin down/up, but re-asserting it
    // makes the test independent of that detail.
    let _ = sh(&[
        "ip",
        "netns",
        "exec",
        NETNS_A,
        "ip",
        "addr",
        "add",
        "192.0.2.1/24",
        "dev",
        "karstveth-a",
    ]);

    wait_for("the tunnel to recover on its own", || {
        tunnel_up(NETNS_A, "10.77.0.2")
    });

    // And it must still be a working tunnel, not merely one ping that got
    // through on a session about to expire.
    assert!(
        sh(&[
            "ip",
            "netns",
            "exec",
            NETNS_A,
            "ping",
            "-c",
            "5",
            "-W",
            "2",
            "10.77.0.2",
        ]),
        "the tunnel must carry sustained traffic after the flap"
    );

    teardown_namespaces();
}

/// The **tunnel** interface itself is taken down and brought back — an
/// administrator running `ip link set karst0 down`, or a network manager doing
/// it on their behalf.
///
/// The daemon holds the device's descriptor throughout, so the interface must
/// come back carrying traffic without the daemon noticing anything happened.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn the_tunnel_recovers_from_a_tun_interface_flap() {
    assert!(have_net_admin(), "run as root");
    assert!(setup_namespaces(), "could not build the test namespaces");

    let a = start("tunflap-a", NETNS_A, 0xA1, 0xB1, 1, Some("192.0.2.2:51820"));
    let _b = start("tunflap-b", NETNS_B, 0xB1, 0xA1, 2, None);
    wait_for("the tunnel to come up", || tunnel_up(NETNS_A, "10.77.0.2"));

    assert!(
        sh(&["ip", "netns", "exec", NETNS_A, "ip", "link", "set", "karst0", "down",]),
        "could not take karst0 down"
    );
    wait_for("traffic to stop", || !tunnel_up(NETNS_A, "10.77.0.2"));

    assert!(sh(&[
        "ip", "netns", "exec", NETNS_A, "ip", "link", "set", "karst0", "up",
    ]));
    wait_for("the tunnel to recover on its own", || {
        tunnel_up(NETNS_A, "10.77.0.2")
    });

    // The daemon should never have noticed: the session it had before the flap
    // is the one it has after, because nothing about the keys changed.
    let status = karst(&a, "status");
    assert!(
        status.contains(r#"state = "established""#),
        "the session must survive an administrative link flap: {status}"
    );

    teardown_namespaces();
}

/// **A flap long enough to outlive the session.** Past `REJECT_AFTER_TIME` the
/// keys must not be used, so the session closes — and the peer must then be
/// re-dialled rather than left idle forever.
///
/// This is the path that `connect_all`-at-startup left broken: without a
/// re-dial on the timer, an outage longer than three minutes ended the tunnel
/// permanently.
#[test]
#[ignore = "needs CAP_NET_ADMIN, takes ~4 minutes"]
fn the_tunnel_recovers_from_an_outage_that_outlives_the_session() {
    assert!(have_net_admin(), "run as root");
    assert!(setup_namespaces(), "could not build the test namespaces");

    let a = start("long-a", NETNS_A, 0xA1, 0xB1, 1, Some("192.0.2.2:51820"));
    let _b = start("long-b", NETNS_B, 0xB1, 0xA1, 2, None);
    wait_for("the tunnel to come up", || tunnel_up(NETNS_A, "10.77.0.2"));

    assert!(sh(&[
        "ip",
        "netns",
        "exec",
        NETNS_A,
        "ip",
        "link",
        "set",
        "karstveth-a",
        "down",
    ]));

    // REJECT_AFTER_TIME is 180 s; wait past it so the session genuinely expires
    // rather than merely idling.
    std::thread::sleep(Duration::from_secs(200));
    let status = karst(&a, "status");
    assert!(
        !status.contains(r#"state = "established""#),
        "the session should have expired during a 200 s outage: {status}"
    );

    assert!(sh(&[
        "ip",
        "netns",
        "exec",
        NETNS_A,
        "ip",
        "link",
        "set",
        "karstveth-a",
        "up",
    ]));
    let _ = sh(&[
        "ip",
        "netns",
        "exec",
        NETNS_A,
        "ip",
        "addr",
        "add",
        "192.0.2.1/24",
        "dev",
        "karstveth-a",
    ]);

    wait_for("the tunnel to rebuild itself", || {
        tunnel_up(NETNS_A, "10.77.0.2")
    });

    teardown_namespaces();
}
