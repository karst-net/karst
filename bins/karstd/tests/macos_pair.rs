// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Two daemons on one Mac, a real `utun` on the datapath, and a TCP
//! conversation across it — `plans/phase-5/06-macos-client.md` §8, W4.
//!
//! # Why this is not `two_nodes.rs`
//!
//! `two_nodes.rs` puts each daemon in its own network namespace, which is what
//! lets both hold an overlay address and still have to use the tunnel to reach
//! each other. **macOS has no namespaces**, and one IP stack cannot be made to
//! route between two of its own addresses through anything: give one `utun`
//! 10.89.0.1 and the other 10.89.0.2 and a packet between them never reaches
//! either interface, because the kernel owns both ends and delivers it locally.
//! A test built that way would pass with the datapath deleted.
//!
//! So the pair here is **one node on a real `utun` and one in userspace mode**
//! — the arrangement ADR-0012 describes, and the only two-daemon shape on a
//! single Mac where every byte has to cross the tunnel. The userspace node owns
//! its overlay address inside smoltcp, where the host stack cannot see it, so
//! the host's only route to it is through the `utun` node. That puts a real
//! `utun` on the path in **both** directions: the request is written to it and
//! the reply is read back out of it.
//!
//! What this does not reach is a second kernel interface. Two Macs are what
//! prove that, and `scripts/two-host-test.sh` is where it belongs; §8's
//! cross-platform row says so.
//!
//! # Why the file compiles on Linux
//!
//! Nothing here is a macOS API — it is two child processes, TCP, and SOCKS5 —
//! and gating the file behind `#[cfg(target_os = "macos")]` would mean the only
//! machine that ever type-checks it is the release runner. It compiles
//! everywhere, skips at run time anywhere but macOS, and `cargo check
//! --all-targets` on any host is what catches a rename that would otherwise
//! break the macOS job. The same reasoning as `karst_dns::host::macos` and
//! `karst_tun::macos_wire`.
//!
//! # ACLs
//!
//! §8's row asks for "TCP under an ACL". A static roster has no ACL table —
//! port-scoped ACLs arrive with a netmap, and `two_nodes.rs` measures them
//! against a real coordination server on Linux, over the same
//! platform-independent [`karstd::PacketFilter`]. What a roster *does* carry is
//! `allowed_ips`, which is the address-level half of the same decision, and the
//! second row below asserts it on this datapath: an overlay address no peer
//! owns is dropped rather than carried.
//!
//! Needs root, because creating a `utun` does. Run them with:
//!
//! ```text
//! just macos-test-pair
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
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use karst_crypto::kem::{keypair_from_seed, KemKind};
use karstd::config::encode_hex;

/// The overlay address of the node on the real `utun`.
const OVERLAY_TUN: &str = "10.89.0.2";
/// The overlay address of the userspace node. No host interface carries it,
/// which is what forces the traffic through the tunnel.
const OVERLAY_USERSPACE: &str = "10.89.0.1";

/// Deliberately its own name, and deliberately one macOS will not honour: the
/// kernel assigns `utunN` regardless, and asserting on the reported name is how
/// W3's "the configured name is a preference" stops being a claim in a comment.
const INTERFACE: &str = "karstm0";

const LISTEN_TUN: u16 = 51861;
const LISTEN_USERSPACE: u16 = 51862;
const SOCKS_PORT: u16 = 11085;
const SERVICE_PORT: u16 = 19010;

/// The second row's own pair. Separate ports, addresses and interface name for
/// the reason `userspace.rs` gives: a `utun` outlives the process that made it
/// by a moment, and a row that reused another's would fail for a reason having
/// nothing to do with what it measures.
const OVERLAY_TUN_2: &str = "10.89.1.2";
const OVERLAY_USERSPACE_2: &str = "10.89.1.1";
const INTERFACE_2: &str = "karstm2";
const LISTEN_TUN_2: u16 = 51863;
const LISTEN_USERSPACE_2: u16 = 51864;
const SERVICE_PORT_2: u16 = 19011;
/// Inside the `utun`'s on-link prefix, so the host routes it to the tunnel, and
/// outside every peer's `allowed_ips`, so nothing should carry it.
const OVERLAY_UNOWNED: &str = "10.89.1.9";

/// 64 KiB each way: fifty-odd tunnel MTUs, not one. A payload that fitted in a
/// single segment would pass against a datapath that could neither segment nor
/// reassemble.
const PAYLOAD: usize = 64 * 1024;

// ── prerequisites ───────────────────────────────────────────────────────────

fn effective_uid() -> u32 {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(1)
}

/// Whether to run.
///
/// **Not being macOS is not a missing prerequisite.** It is the wrong machine,
/// and no amount of `KARST_REQUIRE_PREREQUISITES` can install one — so that
/// variable governs only the things a macOS runner could be missing, and the
/// platform check skips unconditionally. Getting this backwards would turn
/// every Linux CI job red for a suite that was never meant to run there.
fn have_prerequisites() -> bool {
    if !cfg!(target_os = "macos") {
        eprintln!("skipping: the utun pair needs macOS");
        return false;
    }
    if effective_uid() == 0 {
        return true;
    }
    assert!(
        std::env::var_os("KARST_REQUIRE_PREREQUISITES").is_none(),
        "KARST_REQUIRE_PREREQUISITES is set, so skipping is not allowed — \
         creating a utun needs root"
    );
    eprintln!("skipping: creating a utun needs root");
    false
}

// ── keys ────────────────────────────────────────────────────────────────────

/// The public halves of the deterministic seed a node is started with.
fn public_of(n: u8) -> (String, String) {
    let (_, kem_pk) = keypair_from_seed(KemKind::MlKem768, &[n; 64]);
    let dh = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([n; 32]));
    (encode_hex(&kem_pk.to_bytes()), encode_hex(dh.as_bytes()))
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
        // Killing the daemon closes its `utun` descriptor, and that is what
        // removes the interface — Karst never makes one persistent.
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
        let _ = std::fs::remove_dir(root_dir());
    }
}

impl Node {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

/// Which side of the pair a daemon is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// A real `utun`, created by this process because it is root.
    Utun,
    /// smoltcp, with no host interface at all.
    Userspace,
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
    /// Where userspace mode offers its SOCKS5 listener, if it offers one.
    socks: Option<u16>,
}

fn root_dir() -> PathBuf {
    std::env::temp_dir().join(format!("karstd-macos-pair-{}", std::process::id()))
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
    let mut attachment = String::new();
    if spec.mode == Mode::Userspace {
        attachment.push_str("network_mode = \"userspace\"\n");
        if let Some(port) = spec.socks {
            let _ = writeln!(attachment, "userspace_socks5_listen = \"127.0.0.1:{port}\"");
        }
    }
    // **`host_integration = "none"`, explicitly.** `auto` on macOS now selects
    // the `/etc/resolver` mechanism, and a test that started a daemon with it
    // would sweep the *runner's* resolver directory for Karst's own leftovers.
    // That is the right thing for a daemon to do at startup and the wrong thing
    // for a test to do to the machine it is running on.
    let toml = format!(
        r#"
[node]
listen = "0.0.0.0:{listen}"
interface = "{interface}"
addresses = ["{address}/24"]
private_key_file = "node.key"
{attachment}
[dns]
host_integration = "none"

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

    let child = Command::new(env!("CARGO_BIN_EXE_karstd"))
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

/// Everything that might explain a failure, for both daemons. A `utun` that
/// could not be created explains itself in the log and nowhere else.
fn report(nodes: &[&Node]) -> String {
    let mut out = String::new();
    for node in nodes {
        let _ = write!(
            out,
            "\n── {tag} status ──\n{}\n── {tag} log ──\n{}\n",
            status(node),
            node.log(),
            tag = node.tag,
        );
    }
    out
}

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

fn wait_for_established(nodes: &[&Node]) {
    wait_for(
        nodes,
        "both nodes to establish",
        Duration::from_secs(30),
        || {
            nodes
                .iter()
                .all(|n| field(&status(n), "state").as_deref() == Some("established"))
        },
    );
}

// ── the workload ────────────────────────────────────────────────────────────

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

/// A one-shot service: read the request, check it, answer with a different
/// payload.
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

/// Bind the service to the `utun` node's overlay address, retrying while the
/// interface is still being created.
///
/// **Bound to the overlay address, never `0.0.0.0`.** A wildcard bind would
/// also be reachable over loopback, and a test that could pass without the
/// tunnel is not a test of the tunnel.
fn bind_service(nodes: &[&Node], address: &str) -> TcpListener {
    let address: SocketAddr = address.parse().expect("service address");
    let deadline = Instant::now() + Duration::from_secs(30);
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

// ── the SOCKS5 client, which is how the userspace side sends ────────────────

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
        return Err(format!("SOCKS CONNECT was refused with 0x{:02x}", reply[1]));
    }
    Ok(stream)
}

/// Keep asking until the SOCKS listener accepts: the daemon's accept loop
/// starts a moment after the process does, and a refusal in that window is a
/// race with startup rather than a failure of the row.
fn socks_connect_when_ready(proxy: SocketAddr, target: SocketAddr, nodes: &[&Node]) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(30);
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

/// The payload really crossed the tunnel rather than going around it.
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
        "the utun node reported tx={tx} rx={rx}, fewer than the {least} packets \
         {PAYLOAD} B cannot avoid at a {} B MTU\n{stats}",
        karst_proto::consts::TUNNEL_MTU
    );
}

// ── the rows ────────────────────────────────────────────────────────────────

/// **W4's gate.** 64 KiB of TCP in each direction between a workload attached
/// over SOCKS5 and a service on the `utun` node's overlay address. Every byte
/// crosses smoltcp, PHREATIC's AEAD, a UDP socket, a real `utun` — including
/// its four-byte address-family prefix, in both directions — and the host
/// stack.
///
/// Get the AF prefix wrong in either direction and this cannot pass: leave it
/// on and macOS drops every packet the daemon writes as malformed; strip a byte
/// too many and the host stack sees garbage. `macos_wire`'s unit tests assert
/// the encoding; this is the row that puts a kernel behind it.
#[test]
#[ignore = "needs macOS and root; run with just macos-test-pair"]
fn a_tcp_conversation_crosses_a_real_utun_in_both_directions() {
    if !have_prerequisites() {
        return;
    }

    let userspace = start(&Spec {
        tag: "userspace",
        mode: Mode::Userspace,
        seed: 21,
        peer_seed: 22,
        address: OVERLAY_USERSPACE,
        peer_address: OVERLAY_TUN,
        listen: LISTEN_USERSPACE,
        peer_listen: LISTEN_TUN,
        interface: INTERFACE,
        socks: Some(SOCKS_PORT),
    });
    let tun = start(&Spec {
        tag: "utun",
        mode: Mode::Utun,
        seed: 22,
        peer_seed: 21,
        address: OVERLAY_TUN,
        peer_address: OVERLAY_USERSPACE,
        listen: LISTEN_TUN,
        peer_listen: LISTEN_USERSPACE,
        interface: INTERFACE,
        socks: None,
    });
    let both = [&userspace, &tun];
    wait_for_established(&both);

    // W3's decision, asserted rather than asserted-in-prose: `TunConfig::name`
    // is a *preference*, macOS declines it, and everything downstream reads the
    // name the interface actually got. A daemon that reported the configured
    // name here would be reporting a name no tool on the machine can find.
    let name = field(&status(&tun), "interface").unwrap_or_default();
    assert!(
        name.starts_with("utun"),
        "the reported interface is {name:?}, not the utunN the kernel assigns\n{}",
        status(&tun)
    );
    assert_ne!(
        name, INTERFACE,
        "the configured name was reported back, so something is repeating the \
         request instead of reading the result"
    );

    let request = pattern(0x5a, PAYLOAD);
    let reply = pattern(0xa5, PAYLOAD);
    let service = serve_once(
        bind_service(&both, &format!("{OVERLAY_TUN}:{SERVICE_PORT}")),
        request.clone(),
        reply.clone(),
    );

    let proxy: SocketAddr = format!("127.0.0.1:{SOCKS_PORT}").parse().expect("proxy");
    let target: SocketAddr = format!("{OVERLAY_TUN}:{SERVICE_PORT}")
        .parse()
        .expect("target");
    let mut tunnelled = socks_connect_when_ready(proxy, target, &both);

    tunnelled.write_all(&request).expect("send the request");
    tunnelled.flush().expect("flush the request");
    let mut received = vec![0u8; PAYLOAD];
    tunnelled.read_exact(&mut received).unwrap_or_else(|e| {
        panic!(
            "reading the reply back through the utun: {e}{}",
            report(&both)
        )
    });
    assert!(
        received == reply,
        "the reply came back corrupted{}",
        report(&both)
    );
    service.join().expect("service thread").unwrap_or_else(|e| {
        panic!(
            "the service on the utun address failed: {e}{}",
            report(&both)
        )
    });

    assert_carried_the_payload(&tun);
}

/// The address-level half of §8's ACL row.
///
/// The `utun`'s on-link prefix sends the whole /24 to the tunnel, so the host
/// hands the daemon a packet for an address no peer owns. It must be dropped.
/// A datapath that guessed — sent it to the only peer it has, say — would carry
/// traffic for an address the roster never authorised, which is the same defect
/// a missing ACL is.
///
/// The positive control is the row above: the same host, the same daemon and
/// the same prefix carry a conversation to an address that *is* in
/// `allowed_ips`, so a failure here is about the address and not about the
/// tunnel being down.
#[test]
#[ignore = "needs macOS and root; run with just macos-test-pair"]
fn an_overlay_address_no_peer_owns_is_not_carried() {
    if !have_prerequisites() {
        return;
    }

    let userspace = start(&Spec {
        tag: "userspace-acl",
        mode: Mode::Userspace,
        seed: 23,
        peer_seed: 24,
        address: OVERLAY_USERSPACE_2,
        peer_address: OVERLAY_TUN_2,
        listen: LISTEN_USERSPACE_2,
        peer_listen: LISTEN_TUN_2,
        interface: INTERFACE_2,
        socks: None,
    });
    let tun = start(&Spec {
        tag: "utun-acl",
        mode: Mode::Utun,
        seed: 24,
        peer_seed: 23,
        address: OVERLAY_TUN_2,
        peer_address: OVERLAY_USERSPACE_2,
        listen: LISTEN_TUN_2,
        peer_listen: LISTEN_USERSPACE_2,
        interface: INTERFACE_2,
        socks: None,
    });
    let both = [&userspace, &tun];
    wait_for_established(&both);

    // The interface has to exist before the route to its prefix does, and the
    // row means nothing until the host is actually sending to the tunnel.
    let _ = bind_service(&both, &format!("{OVERLAY_TUN_2}:{SERVICE_PORT_2}"));

    let unowned: SocketAddr = format!("{OVERLAY_UNOWNED}:{SERVICE_PORT_2}")
        .parse()
        .expect("unowned address");
    let outcome = TcpStream::connect_timeout(&unowned, Duration::from_secs(5));
    assert!(
        outcome.is_err(),
        "a TCP connection completed to {unowned}, which no peer's allowed_ips \
         covers{}",
        report(&both)
    );
}
