// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! **ADR-0012's second implementation gate**: a TCP conversation that crosses
//! userspace mode, carried by a daemon that could not create a TUN device if it
//! tried.
//!
//! The gate asks for "a no-`CAP_NET_ADMIN` end-to-end TCP conversation through
//! userspace mode, run as an unprivileged process", and it was recorded as
//! never produced — so until this file existed, the one claim userspace mode
//! makes was the one thing nothing tested. `karst-tun`'s own unit test drives
//! two smoltcp stacks against each other in one process; that proves smoltcp
//! speaks TCP, not that Karst carries it.
//!
//! The shape here is the deployment ADR-0012 describes: an **unprivileged
//! sidecar** attached over the loopback SOCKS5 listener, talking to an ordinary
//! mesh node on the privileged path. So the peer wants a TUN device and the
//! suite as a whole wants root — but the node under test does not, and that is
//! asserted rather than asserted-in-prose: it is launched under `setpriv` with
//! a non-root uid and an **empty capability bounding set**, and the test reads
//! `/proc/<pid>/status` back to confirm it. An empty bounding set is the strong
//! form of the claim, because a capability absent from it cannot be regained by
//! any means the process has.
//!
//! `a_tun_is_impossible_for_the_process_under_test` is the instrument check.
//! Without it, "no `CAP_NET_ADMIN`" would rest on the belief that `setpriv` did
//! what it was asked; with it, the same launcher demonstrably cannot bring up a
//! kernel interface. Finding 23's lesson, applied to a privilege boundary
//! rather than to a NAT.
//!
//! Needs root, so these are `#[ignore]`d. Run them with:
//!
//! ```text
//! just test-userspace
//! ```

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use karst_crypto::kem::{Kem, MlKem768Backend as MlKem};
use karstd::config::encode_hex;

/// The overlay address of the node under test. It exists only inside smoltcp —
/// no host interface anywhere carries it, which is the point.
const OVERLAY_USERSPACE: &str = "10.88.0.1";
/// The overlay address of the ordinary peer, on a real TUN device.
const OVERLAY_PEER: &str = "10.88.0.2";
/// Deliberately not `karst0`: `tests/two_nodes.rs` uses that name, and a
/// half-cleaned interface from another suite must not be mistaken for this one.
const PEER_INTERFACE: &str = "karstu0";

const LISTEN_USERSPACE: u16 = 51841;
const LISTEN_PEER: u16 = 51842;
const LISTEN_UNUSED: u16 = 51843;
const SOCKS_PORT: u16 = 11080;
const SERVICE_PORT: u16 = 19000;

/// A second pair, for the half-close row. Its own ports, overlay addresses and
/// interface name: the tests run one at a time, but a TUN device outlives the
/// process that made it by a moment, and a second row that reused the name
/// would fail with `Device or resource busy` for a reason having nothing to do
/// with what it measures.
const OVERLAY_USERSPACE_2: &str = "10.88.1.1";
const OVERLAY_PEER_2: &str = "10.88.1.2";
const PEER_INTERFACE_2: &str = "karstu2";
const LISTEN_USERSPACE_2: u16 = 51845;
const LISTEN_PEER_2: u16 = 51846;
const SOCKS_PORT_2: u16 = 11082;
const SERVICE_PORT_2: u16 = 19002;

/// `nobody`. Chosen because it exists on every distribution this is likely to
/// run on and owns nothing worth reaching.
const UNPRIVILEGED_UID: u32 = 65534;

/// 64 KiB each way: **fifty-odd tunnel MTUs**, not one.
///
/// A payload that fits in a single segment would pass with a stack that could
/// not segment, could not reassemble, and had no working window — which is most
/// of what a TCP implementation is. ADR-0012's risk is precisely that smoltcp's
/// TCP is partial, so the gate has to move enough bytes to exercise it.
const PAYLOAD: usize = 64 * 1024;

// ── prerequisites ───────────────────────────────────────────────────────────

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

/// Whether to run, **and a refusal to be quietly green**.
///
/// `setpriv` is the one that matters. Without it this file cannot drop the
/// privilege, and a version of `have_prerequisites` that merely skipped would
/// let ADR-0012's gate report success by not running — for a claim whose whole
/// content is "this ran without the capability".
/// `KARST_REQUIRE_PREREQUISITES=1`, which CI sets, turns that skip into a
/// failure.
fn have_prerequisites() -> bool {
    let mut missing = Vec::new();
    if effective_uid() != 0 {
        missing.push("root");
    }
    if !Path::new("/dev/net/tun").exists() {
        missing.push("/dev/net/tun");
    }
    if !Command::new("setpriv")
        .arg("--help")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        missing.push("setpriv");
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

// ── keys ────────────────────────────────────────────────────────────────────

/// The public halves of the deterministic seed a node is started with.
fn public_of(n: u8) -> (String, String) {
    let (_, kem_pk) = MlKem::keypair_from_seed(&[n; 64]);
    let dh = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([n; 32]));
    (
        encode_hex(&MlKem::public_key_bytes(&kem_pk)),
        encode_hex(dh.as_bytes()),
    )
}

// ── the two daemons ─────────────────────────────────────────────────────────

/// A running `karstd`, its files, and its log.
struct Node {
    tag: &'static str,
    dir: PathBuf,
    socket: PathBuf,
    log: PathBuf,
    child: Child,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
        // Non-recursive, so it takes the shared parent only once the last node
        // in this run has gone and leaves anything still in use alone.
        let _ = std::fs::remove_dir(root_dir());
    }
}

impl Node {
    /// What the daemon has said so far. Read on failure, because a daemon that
    /// refused its configuration explains itself here and nowhere else.
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The uid and capability sets the kernel currently attributes to it.
    fn credentials(&self) -> String {
        std::fs::read_to_string(format!("/proc/{}/status", self.child.id()))
            .unwrap_or_default()
            .lines()
            .filter(|l| l.starts_with("Uid:") || l.starts_with("Cap"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn credential(&self, key: &str) -> Option<String> {
        self.credentials()
            .lines()
            .find(|l| l.starts_with(key))
            .map(|l| l.trim_start_matches(key).trim().to_owned())
    }
}

/// Which side of ADR-0012's boundary a daemon is on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Userspace mode, launched with no capabilities and a non-root uid.
    UnprivilegedUserspace,
    /// The ordinary privileged path, for the peer.
    PrivilegedTun,
    /// TUN mode launched through the *unprivileged* launcher. Used only to show
    /// that the launcher really does remove the privilege.
    UnprivilegedTun,
}

impl Mode {
    fn unprivileged(self) -> bool {
        !matches!(self, Self::PrivilegedTun)
    }
}

struct Spec {
    tag: &'static str,
    mode: Mode,
    seed: u8,
    peer_seed: u8,
    address: &'static str,
    peer_address: &'static str,
    listen: u16,
    peer_listen: u16,
    interface: &'static str,
    /// Where userspace mode offers its SOCKS5 listener. Ignored by the two TUN
    /// modes, which have no attachment surface of their own.
    socks: u16,
}

fn root_dir() -> PathBuf {
    std::env::temp_dir().join(format!("karstd-userspace-{}", std::process::id()))
}

/// Write a node's configuration and key, then start it.
fn start(spec: &Spec) -> Node {
    use std::os::unix::fs::PermissionsExt;

    let dir = root_dir().join(spec.tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");

    let key = dir.join("node.key");
    std::fs::write(&key, encode_hex(&[spec.seed; 96])).expect("write key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("chmod key");

    let (kem, dh) = public_of(spec.peer_seed);
    // Userspace mode has no host interface and no route table, so the whole
    // difference between the two configurations is these two lines.
    let attachment = match spec.mode {
        Mode::UnprivilegedUserspace => format!(
            "network_mode = \"userspace\"\nuserspace_socks5_listen = \"127.0.0.1:{}\"\n",
            spec.socks
        ),
        Mode::PrivilegedTun | Mode::UnprivilegedTun => String::new(),
    };
    let toml = format!(
        r#"
[node]
listen = "0.0.0.0:{listen}"
interface = "{interface}"
addresses = ["{address}/24"]
private_key_file = "node.key"
{attachment}
[[peer]]
name = "other"
kem_public_key = "{kem}"
dh_public_key = "{dh}"
endpoint = "127.0.0.1:{peer_listen}"
allowed_ips = ["{peer_address}/32"]
"#,
        listen = spec.listen,
        interface = spec.interface,
        address = spec.address,
        peer_listen = spec.peer_listen,
        peer_address = spec.peer_address,
    );
    let config = dir.join("karstd.toml");
    std::fs::write(&config, toml).expect("write config");
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600))
        .expect("chmod config");

    let socket = dir.join("karstd.sock");
    let log = dir.join("karstd.log");
    let out = std::fs::File::create(&log).expect("log file");
    let err = out.try_clone().expect("log file");

    if spec.mode.unprivileged() {
        // The daemon must be able to read its own configuration and create its
        // control socket after it has stopped being root.
        for path in [dir.as_path(), config.as_path(), key.as_path()] {
            std::os::unix::fs::chown(path, Some(UNPRIVILEGED_UID), Some(UNPRIVILEGED_UID))
                .expect("chown");
        }
    }

    let mut command = if spec.mode.unprivileged() {
        let mut c = Command::new("setpriv");
        c.args([
            "--reuid",
            &UNPRIVILEGED_UID.to_string(),
            "--regid",
            &UNPRIVILEGED_UID.to_string(),
            "--clear-groups",
            // **The load-bearing argument.** Clearing the bounding set makes
            // the absence permanent: a capability that is not in it cannot be
            // acquired by execve, by a file capability, or by any other route.
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--no-new-privs",
            "--",
            env!("CARGO_BIN_EXE_karstd"),
        ]);
        c
    } else {
        Command::new(env!("CARGO_BIN_EXE_karstd"))
    };
    let child = command
        .arg("--config")
        .arg(&config)
        .arg("--socket")
        .arg(&socket)
        .current_dir(&dir)
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawn karstd");

    Node {
        tag: spec.tag,
        dir,
        socket,
        log,
        child,
    }
}

/// Path to the `karst` CLI, which lives in a different package.
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

fn status(node: &Node) -> String {
    Command::new(karst_bin())
        .args(["status", "--socket"])
        .arg(&node.socket)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

fn field(status: &str, key: &str) -> Option<String> {
    status
        .lines()
        .find(|l| l.starts_with(&format!("{key} = ")))
        .map(|l| {
            l.trim_start_matches(&format!("{key} = "))
                .trim_matches('"')
                .to_owned()
        })
}

/// Everything that might explain a failure, for both daemons.
///
/// **The diagnostic is the point.** Two processes, one of which has no
/// privileges and therefore fails in ways an assertion message cannot
/// anticipate, and a temporary directory that is gone by the time anyone reads
/// the output.
fn report(nodes: &[&Node]) -> String {
    let mut out = String::new();
    for node in nodes {
        let _ = write!(
            out,
            "\n── {tag} status ──\n{}\n── {tag} log ──\n{}\n── {tag} credentials ──\n{}\n",
            status(node),
            node.log(),
            node.credentials(),
            tag = node.tag,
        );
    }
    out
}

/// Poll until `f` holds, failing with both daemons' status and logs.
fn wait_for(nodes: &[&Node], what: &str, timeout: Duration, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!(
        "timed out after {timeout:?} waiting for {what}{}",
        report(nodes)
    );
}

// ── the workload on the far side ────────────────────────────────────────────

/// Deterministic bytes. The two directions use different seeds so neither can
/// be mistaken for a reflection of the other.
fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| {
            u8::try_from(i % 251)
                .unwrap_or(0)
                .wrapping_mul(31)
                .wrapping_add(seed)
        })
        .collect()
}

/// A one-shot service on the peer's overlay address: read the request, check
/// it, answer with a different payload.
fn serve_once(
    listener: TcpListener,
    request: Vec<u8>,
    reply: Vec<u8>,
) -> std::thread::JoinHandle<Result<(), String>> {
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .map_err(|e| format!("read timeout: {e}"))?;
        let mut received = vec![0u8; request.len()];
        stream
            .read_exact(&mut received)
            .map_err(|e| format!("reading the request: {e}"))?;
        if received != request {
            return Err("the request arrived corrupted".to_owned());
        }
        stream
            .write_all(&reply)
            .map_err(|e| format!("writing the reply: {e}"))?;
        stream.flush().map_err(|e| format!("flush: {e}"))?;
        Ok(())
    })
}

/// Bind the service to the peer's overlay address, retrying while the TUN
/// device is still being created.
///
/// Bound to the overlay address rather than `0.0.0.0` deliberately: a wildcard
/// bind would also be reachable over loopback, and a test that could pass
/// without the tunnel is not a test of the tunnel.
fn bind_service(nodes: &[&Node], address: &str) -> TcpListener {
    let address: SocketAddr = address.parse().expect("service address");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match TcpListener::bind(address) {
            Ok(listener) => return listener,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => panic!("could not bind {address}: {e}{}", report(nodes)),
        }
    }
}

// ── the SOCKS5 client, which is the whole attachment surface ────────────────

/// Speak RFC 1928 to the daemon's loopback listener and return the tunnelled
/// stream. This is exactly what a sidecar's workload does.
fn socks_connect(proxy: SocketAddr, target: SocketAddr) -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect(proxy).map_err(|e| format!("connecting to SOCKS: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|e| format!("read timeout: {e}"))?;
    stream
        .write_all(&[5, 1, 0])
        .map_err(|e| format!("greeting: {e}"))?;
    let mut chosen = [0u8; 2];
    stream
        .read_exact(&mut chosen)
        .map_err(|e| format!("method selection: {e}"))?;
    if chosen != [5, 0] {
        return Err(format!("SOCKS method selection was {chosen:?}"));
    }
    let mut request = vec![5, 1, 0];
    match target.ip() {
        IpAddr::V4(v4) => {
            request.push(1);
            request.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            request.push(4);
            request.extend_from_slice(&v6.octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream
        .write_all(&request)
        .map_err(|e| format!("CONNECT: {e}"))?;
    let mut reply = [0u8; 10];
    stream
        .read_exact(&mut reply)
        .map_err(|e| format!("CONNECT reply: {e}"))?;
    if reply[1] != 0 {
        // 0x04 is the daemon's "the overlay peer did not answer in time".
        return Err(format!("SOCKS CONNECT was refused with 0x{:02x}", reply[1]));
    }
    Ok(stream)
}

/// Keep asking until the SOCKS listener is accepting: the daemon's accept loop
/// starts a moment after the process does, and a refused connect in that window
/// is a race with startup rather than a failure of the gate.
fn socks_connect_when_ready(proxy: SocketAddr, target: SocketAddr, nodes: &[&Node]) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match socks_connect(proxy, target) {
            Ok(stream) => return stream,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => panic!("SOCKS CONNECT never succeeded: {e}{}", report(nodes)),
        }
    }
}

// ── the gate ────────────────────────────────────────────────────────────────

/// The kernel's own record of what the node under test may do.
///
/// Nothing the gate asserts means anything if this process is quietly still
/// privileged, so it is read from `/proc` rather than assumed from the way the
/// process was launched.
fn assert_unprivileged(node: &Node) {
    assert_eq!(
        node.credential("Uid:").as_deref(),
        Some("65534\t65534\t65534\t65534"),
        "the node under test is not running unprivileged\n{}",
        node.credentials()
    );
    for set in ["CapEff:", "CapPrm:", "CapBnd:", "CapAmb:", "CapInh:"] {
        assert_eq!(
            node.credential(set).as_deref(),
            Some("0000000000000000"),
            "{set} is not empty, so CAP_NET_ADMIN was not ruled out\n{}",
            node.credentials()
        );
    }
}

/// Both directions really moved through the tunnel rather than around it.
///
/// A payload of `PAYLOAD` bytes cannot cross a `TUNNEL_MTU` datapath in fewer
/// than this many packets, whatever else happens — so a counter below it means
/// the conversation took some other path.
fn assert_carried_the_payload(node: &Node) {
    let stats = status(node);
    let count = |key| -> u64 {
        field(&stats, key)
            .and_then(|v| v.parse().ok())
            .unwrap_or_default()
    };
    let (tx, rx) = (count("tx_packets"), count("rx_packets"));
    let least = (PAYLOAD / karst_proto::consts::TUNNEL_MTU) as u64;
    assert!(
        tx >= least && rx >= least,
        "userspace mode reported tx={tx} rx={rx}, fewer than the {least} packets \
         {PAYLOAD} B cannot avoid at a {} B MTU\n{stats}",
        karst_proto::consts::TUNNEL_MTU
    );
}

/// **ADR-0012, implementation gate 2.**
///
/// A daemon with no capabilities and a non-root uid carries 64 KiB of TCP in
/// each direction, between a local workload attached over SOCKS5 and a service
/// on an ordinary mesh node's overlay address. Every byte crosses smoltcp,
/// PHREATIC's AEAD, a UDP socket, the peer's TUN device and the host stack.
///
/// Break the userspace packet bridge — drop what `Userspace::send` is given, or
/// return nothing from `recv_segments` — and this cannot pass: the SOCKS
/// `CONNECT` reply never arrives, because the overlay handshake it waits for
/// has no path.
#[test]
#[ignore = "needs root to give the peer a TUN device"]
fn a_tcp_conversation_crosses_userspace_mode_without_cap_net_admin() {
    if !have_prerequisites() {
        return;
    }

    let userspace = start(&Spec {
        tag: "userspace",
        mode: Mode::UnprivilegedUserspace,
        seed: 11,
        peer_seed: 12,
        address: OVERLAY_USERSPACE,
        peer_address: OVERLAY_PEER,
        listen: LISTEN_USERSPACE,
        peer_listen: LISTEN_PEER,
        // Userspace mode never creates this; it is here because the field is
        // required, and asserting on the reported name below is what shows it
        // was ignored rather than quietly honoured.
        interface: PEER_INTERFACE,
        socks: SOCKS_PORT,
    });
    let peer = start(&Spec {
        tag: "peer",
        mode: Mode::PrivilegedTun,
        seed: 12,
        peer_seed: 11,
        address: OVERLAY_PEER,
        peer_address: OVERLAY_USERSPACE,
        listen: LISTEN_PEER,
        peer_listen: LISTEN_USERSPACE,
        interface: PEER_INTERFACE,
        socks: SOCKS_PORT,
    });
    let both = [&userspace, &peer];

    assert_unprivileged(&userspace);

    wait_for(
        &both,
        "both nodes to establish",
        Duration::from_secs(30),
        || {
            field(&status(&userspace), "state").as_deref() == Some("established")
                && field(&status(&peer), "state").as_deref() == Some("established")
        },
    );

    // ADR-0012's isolation claim: the unprivileged node reports no host
    // interface, because it has none.
    assert_eq!(
        field(&status(&userspace), "interface").as_deref(),
        Some("userspace"),
        "the node under test is not on the userspace device\n{}",
        status(&userspace)
    );
    assert_eq!(
        field(&status(&peer), "interface").as_deref(),
        Some(PEER_INTERFACE),
        "the peer is not on its TUN device\n{}",
        status(&peer)
    );

    let request = pattern(0x5a, PAYLOAD);
    let reply = pattern(0xa5, PAYLOAD);
    let service = serve_once(
        bind_service(&both, &format!("{OVERLAY_PEER}:{SERVICE_PORT}")),
        request.clone(),
        reply.clone(),
    );

    let proxy: SocketAddr = format!("127.0.0.1:{SOCKS_PORT}").parse().expect("proxy");
    let target: SocketAddr = format!("{OVERLAY_PEER}:{SERVICE_PORT}")
        .parse()
        .expect("target");
    let mut tunnelled = socks_connect_when_ready(proxy, target, &both);

    tunnelled.write_all(&request).expect("send the request");
    tunnelled.flush().expect("flush the request");
    let mut received = vec![0u8; PAYLOAD];
    tunnelled
        .read_exact(&mut received)
        .unwrap_or_else(|e| panic!("reading the reply through userspace mode: {e}"));

    assert_eq!(
        received, reply,
        "the reply that crossed userspace mode does not match what was sent"
    );
    service
        .join()
        .expect("service thread")
        .unwrap_or_else(|e| panic!("the overlay service reported: {e}"));

    assert_carried_the_payload(&userspace);
}

/// **A request that ends by closing, and the reply that comes after it.**
///
/// TCP is two independent half-duplex streams, and a large family of clients
/// uses that: send the request, close the write half, read the answer until
/// EOF. `curl` does it, `nc -N` does it, and any protocol that delimits a
/// message by closing does it. Found by ADR-0012's gate-1 measurement, which
/// could not complete a run for this reason — FINDINGS.md 39.
///
/// The service here reads **to EOF** rather than a known length, so the row
/// fails in a different place for each half of the bug: if the FIN never
/// crosses, the service blocks and this times out; if the FIN crosses but the
/// reverse direction is torn down with it, the reply never arrives.
///
/// The client reads to EOF as well, which is the *other* half of the same rule:
/// it returns only once the proxy has closed the workload's side after the
/// overlay end finished. A relay that propagated the client's FIN and then sat
/// on the far end's would hang here rather than truncate.
#[test]
#[ignore = "needs root to give the peer a TUN device"]
fn a_half_closed_request_still_receives_its_reply() {
    if !have_prerequisites() {
        return;
    }

    let userspace = start(&Spec {
        tag: "half-close",
        mode: Mode::UnprivilegedUserspace,
        seed: 21,
        peer_seed: 22,
        address: OVERLAY_USERSPACE_2,
        peer_address: OVERLAY_PEER_2,
        listen: LISTEN_USERSPACE_2,
        peer_listen: LISTEN_PEER_2,
        interface: PEER_INTERFACE_2,
        socks: SOCKS_PORT_2,
    });
    let peer = start(&Spec {
        tag: "half-close-peer",
        mode: Mode::PrivilegedTun,
        seed: 22,
        peer_seed: 21,
        address: OVERLAY_PEER_2,
        peer_address: OVERLAY_USERSPACE_2,
        listen: LISTEN_PEER_2,
        peer_listen: LISTEN_USERSPACE_2,
        interface: PEER_INTERFACE_2,
        socks: SOCKS_PORT_2,
    });
    let both = [&userspace, &peer];

    wait_for(
        &both,
        "both nodes to establish",
        Duration::from_secs(30),
        || {
            field(&status(&userspace), "state").as_deref() == Some("established")
                && field(&status(&peer), "state").as_deref() == Some("established")
        },
    );

    let request = pattern(0x3c, PAYLOAD);
    let reply = pattern(0xc3, PAYLOAD);
    let listener = bind_service(&both, &format!("{OVERLAY_PEER_2}:{SERVICE_PORT_2}"));
    let expected = request.clone();
    let answer = reply.clone();
    let service = std::thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .map_err(|e| format!("read timeout: {e}"))?;
        // **To EOF, not to a length.** This is what makes the row a test of the
        // half-close: the service learns the request has ended because the
        // client closed, which is the only signal it is given.
        let mut received = Vec::new();
        stream
            .read_to_end(&mut received)
            .map_err(|e| format!("reading the request: {e}"))?;
        if received != expected {
            return Err(format!(
                "the request arrived as {} bytes, not {}",
                received.len(),
                expected.len()
            ));
        }
        stream
            .write_all(&answer)
            .map_err(|e| format!("writing the reply: {e}"))?;
        stream.flush().map_err(|e| format!("flush: {e}"))?;
        Ok(())
    });

    let proxy: SocketAddr = format!("127.0.0.1:{SOCKS_PORT_2}").parse().expect("proxy");
    let target: SocketAddr = format!("{OVERLAY_PEER_2}:{SERVICE_PORT_2}")
        .parse()
        .expect("target");
    let mut tunnelled = socks_connect_when_ready(proxy, target, &both);

    tunnelled.write_all(&request).expect("send the request");
    tunnelled.flush().expect("flush the request");
    tunnelled
        .shutdown(std::net::Shutdown::Write)
        .expect("half-close the request");

    let mut received = Vec::new();
    tunnelled
        .read_to_end(&mut received)
        .unwrap_or_else(|e| panic!("reading the reply after a half-close: {e}{}", report(&both)));
    assert_eq!(
        received.len(),
        reply.len(),
        "the reply was truncated after the half-close{}",
        report(&both)
    );
    assert_eq!(received, reply, "the reply that crossed does not match");
    service
        .join()
        .expect("service thread")
        .unwrap_or_else(|e| panic!("the overlay service reported: {e}{}", report(&both)));
}

/// **The instrument check.** The launcher above must really remove the
/// privilege, so the same launcher is pointed at TUN mode and must fail.
///
/// Without this, the gate's whole claim rests on `setpriv` having been asked
/// correctly. A misspelled argument, a `setpriv` that ignored the bounding set,
/// or a future edit that drops the wrapper would all leave the gate passing for
/// the wrong reason — it would simply be testing the privileged path twice.
#[test]
#[ignore = "needs root"]
fn a_tun_is_impossible_for_the_process_under_test() {
    if !have_prerequisites() {
        return;
    }

    let mut attempt = start(&Spec {
        tag: "no-privilege",
        mode: Mode::UnprivilegedTun,
        seed: 13,
        peer_seed: 14,
        address: OVERLAY_USERSPACE,
        peer_address: OVERLAY_PEER,
        listen: LISTEN_UNUSED,
        peer_listen: LISTEN_UNUSED + 1,
        interface: "karstu1",
        socks: SOCKS_PORT,
    });

    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        match attempt.child.try_wait().expect("wait") {
            Some(status) => break status,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            None => panic!(
                "a daemon with no capabilities brought up a TUN device and kept running\n{}",
                attempt.log()
            ),
        }
    };

    assert!(
        !status.success(),
        "TUN mode exited cleanly without CAP_NET_ADMIN\n{}",
        attempt.log()
    );
    let log = attempt.log();
    assert!(
        log.contains("TUNSETIFF"),
        "the refusal was not the missing capability; it said:\n{log}"
    );
    assert!(
        !Command::new("ip")
            .args(["link", "show", "karstu1"])
            .output()
            .is_ok_and(|o| o.status.success()),
        "the interface exists, so the capability was not actually removed"
    );
}
