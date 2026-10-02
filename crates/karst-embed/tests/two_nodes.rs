// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Two embedded nodes, a real Go coordination server, and no `karstd`
//! process anywhere — GitHub issue #214's own acceptance criterion, proven
//! rather than described.
//!
//! Mirrors `bins/karstd/tests/control.rs`'s fixture shape (build the real Go
//! server on the fly, run it on plain loopback, no namespaces, no root) —
//! not `aquifer.rs`'s heavier netns fixture, which this does not need:
//! `NetworkMode::Userspace` creates no kernel device.
//!
//! `#[ignore]`d by default because it needs a Go toolchain. Run with:
//!
//! ```sh
//! cargo test -p karst-embed --test two_nodes -- --ignored
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{BufRead, BufReader, Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64ct::{Base64, Base64UrlUnpadded, Encoding as _};
use karst_control_client::transport::Signer as _;

struct TestServer {
    child: Child,
    address: String,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Pins {
    kem: String,
    verify: String,
}

/// A real `karst-relay` process — direct candidate punching between two
/// nodes that share one host's actual network interfaces (no namespaces,
/// unlike `aquifer.rs`) is not something this test can assume will converge
/// quickly, if at all; the relay is the one documented, proven fallback
/// path, so this test uses it rather than relying on direct connectivity.
///
/// Its identity/TLS/config are prepared before any node exists
/// ([`RelaySetup::prepare`]) — `start_server`'s `--relay` flag needs the
/// relay's address and public key before either node has enrolled — but the
/// process itself is not spawned ([`RelaySetup::spawn`]) until the roster
/// can name both nodes' real identities, known only after they enroll.
struct RelaySetup {
    address: String,
    public_key_hex: String,
    /// The self-signed cert's own PEM — every node's invitation must carry
    /// this as `relay_ca` (see `invitation`'s own doc comment), or
    /// `rustls` refuses the relay with `UnknownIssuer`: a cert nothing
    /// trusts is not a connectable relay, real or in a test.
    cert_pem: String,
    roster_path: PathBuf,
    relay_conf: PathBuf,
}

struct Relay {
    child: Child,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

impl RelaySetup {
    fn prepare(dir: &Path, port: u16) -> Self {
        let cert_path = dir.join("relay.crt");
        let key_path = dir.join("relay.pem");
        let cert = rcgen::generate_simple_self_signed(vec!["relay.test".to_owned()])
            .expect("self-signed certificate");
        let cert_pem = cert.cert.pem();
        std::fs::write(&cert_path, &cert_pem).expect("write cert");
        std::fs::write(&key_path, cert.signing_key.serialize_pem()).expect("write key");

        let relay_key_path = dir.join("relay.key");
        let relay_identity =
            karst_relay::sign::Identity::load_or_create(&relay_key_path).expect("relay identity");
        let public_key_hex = hex(relay_identity.public_key());

        let address = format!("127.0.0.1:{port}");
        let roster_path = dir.join("roster.toml");
        let relay_conf = dir.join("relay.toml");
        // **`[reflect]` turned out not to be optional here.** This host's
        // own docker bridges rewrite the apparent source address of a
        // "local" UDP send (confirmed directly: a socket bound to
        // 172.17.0.1 was observed by its peer as 192.168.68.121) — the same
        // shape a real NAT presents. Disco's hole-punching needs AVEN's own
        // reflector (`ponor-v1.md` §7.7) to learn that real, reachable
        // address; without it, candidates are exchanged but no pair of them
        // actually reaches the other side, and the handshake never
        // completes. Found by testing, not anticipated — see the ADR.
        std::fs::write(
            &relay_conf,
            format!(
                "listen = \"{address}\"\nidentity_key = \"{}\"\nroster = \"{}\"\ntls_cert = \"{}\"\ntls_key = \"{}\"\n\n[reflect]\nlisten = \"127.0.0.1:{}\"\n",
                relay_key_path.display(),
                roster_path.display(),
                cert_path.display(),
                key_path.display(),
                port + 1,
            ),
        )
        .expect("write relay.toml");

        Self {
            address,
            public_key_hex,
            cert_pem,
            roster_path,
            relay_conf,
        }
    }

    /// Write the roster admitting `identity_pks` (each this test's own
    /// node's ML-DSA control-plane identity — `bins/karst-relay/src/roster.rs`'s
    /// `identity_pk`, not a Noise session key) into one aquifer, `"t1"`,
    /// matching `bins/karstd/tests/aquifer.rs`'s own convention — then spawn
    /// the real `karst-relay` binary against it.
    fn spawn(&self, identity_pks: &[Vec<u8>]) -> Relay {
        let repo = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        let relay_bin = format!("{repo}/target/debug/karst-relay");
        let build = Command::new("cargo")
            .args(["build", "-p", "karst-relay"])
            .current_dir(repo)
            .output()
            .expect("run `cargo build -p karst-relay`");
        assert!(
            build.status.success(),
            "building karst-relay failed: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let mut roster = String::new();
        for pk in identity_pks {
            use std::fmt::Write as _;
            let _ = write!(
                roster,
                "[[client]]\nidentity_pk = \"{}\"\naquifer = \"t1\"\n\n",
                Base64::encode_string(pk)
            );
        }
        std::fs::write(&self.roster_path, roster).expect("write roster");
        // **Not optional past `roster::MAX_AGE` (90s).** Found directly in
        // the relay's own stderr log after this test ran long enough to hit
        // it: "roster lease expired; admitting nobody until a valid
        // reload" — real disco convergence on this host's own networking
        // (see the ADR) takes longer than that, so without a renewal the
        // relay stops admitting anyone well before either node would fall
        // back to it. Mirrors `bins/karstd/tests/aquifer.rs`'s own
        // `relay_roster` renewal thread.
        let renewing = self.roster_path.clone();
        std::thread::spawn(move || {
            while renewing.exists() {
                std::thread::sleep(Duration::from_secs(20));
                if let Ok(contents) = std::fs::read(&renewing) {
                    let _ = std::fs::write(&renewing, contents);
                }
            }
        });

        // A file, not `Stdio::piped()`: nothing in this test drains the
        // pipe continuously, and an OS pipe nobody reads fills and blocks
        // the writer — a real relay under real disco traffic logs enough to
        // hit that, which read, before this fix, as the whole test hanging
        // rather than as what it was.
        let stderr_log = self.relay_conf.with_file_name("relay-stderr.log");
        let child = Command::new(&relay_bin)
            .args(["--config", &self.relay_conf.to_string_lossy()])
            .stderr(Stdio::from(
                std::fs::File::create(&stderr_log).expect("relay stderr log"),
            ))
            .spawn()
            .expect("spawn karst-relay");
        // No readiness handshake from the relay binary itself to wait on; a
        // short, fixed sleep before nodes start is simpler than a retry loop
        // for a process that either binds its listener almost immediately or
        // not at all, and this is `#[ignore]`d, hand-run test fixture code,
        // not a startup path real deployments go through.
        std::thread::sleep(Duration::from_millis(200));

        Relay { child }
    }
}

/// Build and start the real Go coordination server on loopback, with no
/// peers preloaded — both nodes in this test self-enroll. Mirrors
/// `bins/karstd/tests/control.rs`'s own `start_server`/`TestServer`, plus a
/// `--relay` flag so nodes are handed a relay they can actually reach
/// instead of `testserver`'s own unreachable synthetic default.
fn start_server(relay: &RelaySetup) -> (TestServer, Pins) {
    let repo = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let bin = format!("{repo}/target/karst-embed-testserver");

    let build = Command::new("go")
        .args([
            "build",
            "-o",
            &bin,
            "./management/internals/karst/testserver/",
        ])
        .current_dir(format!("{repo}/server"))
        .output()
        .expect("run `go build` (is the Go toolchain installed?)");
    assert!(
        build.status.success(),
        "go build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    // `stderr` goes to a file, not a pipe: nothing here drains a pipe
    // continuously, and a long test run risks the same
    // nobody-is-reading-this-OS-pipe stall `RelaySetup::spawn`'s own comment
    // explains for the identical reason.
    let stderr_log = PathBuf::from(format!("{repo}/target/karst-embed-testserver-stderr.log"));
    let mut child = Command::new(&bin)
        .args([
            "--netmap",
            "0",
            "--relay",
            &relay.address,
            &relay.public_key_hex,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::from(
            std::fs::File::create(&stderr_log).expect("testserver stderr log"),
        ))
        .spawn()
        .expect("spawn the test server");

    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read the server's pins");
    let v: serde_json::Value = serde_json::from_str(&line).unwrap_or_else(|err| {
        let stderr = std::fs::read_to_string(&stderr_log).unwrap_or_default();
        panic!("pins are not JSON: {err}; server stderr: {stderr}");
    });
    // Drain the rest of stdout for the test's whole life, for the same
    // pipe-backpressure reason `stderr` is a file above — `testserver`
    // writes only the one JSON line today, but a future log line added
    // there should not be able to deadlock this test.
    std::thread::spawn(move || {
        let mut sink = std::io::sink();
        let _ = std::io::copy(&mut stdout, &mut sink);
    });

    (
        TestServer {
            child,
            address: v["address"].as_str().expect("address").to_owned(),
        },
        Pins {
            kem: v["static_kem"].as_str().expect("static_kem").to_owned(),
            verify: v["verify_key"].as_str().expect("verify_key").to_owned(),
        },
    )
}

/// A `karst-invite-v1:` bundle an administrator would paste — the same
/// shape `crates/karst-ffi`'s own tests and `bins/karstd/tests/control.rs`'s
/// `pasted_invitation_enrolls_without_a_credential_file` construct.
///
/// Carries `relay_ca`, the relay's own self-signed cert PEM, for the same
/// reason that test carries one: without it, `rustls` refuses the relay
/// with `UnknownIssuer` — a trust anchor has to come from *somewhere*, and
/// the invitation's trusted delivery is where a real deployment's own
/// self-hosted relay CA comes from too (`enrollment-process.md`'s "server
/// trust" section).
fn invitation(server: &TestServer, pins: &Pins, relay_ca: &str, setup_key: &str) -> String {
    let payload = serde_json::json!({
        "server": format!("http://{}", server.address),
        "server_kem_pin": pins.kem,
        "server_verify_pin": pins.verify,
        "setup_key": setup_key,
        "control_minimum_version": 1,
        "relay_ca": relay_ca,
    });
    format!(
        "karst-invite-v1:{}",
        Base64UrlUnpadded::encode_string(payload.to_string().as_bytes())
    )
}

/// `enroll_invitation` writes only `[node] listen`/`interface`/
/// `private_key_file` (`bins/karstd/src/enrollment.rs`) — `network_mode`
/// defaults to `Tun` on load, and `listen` is always the same literal
/// `"0.0.0.0:51820"`, which is fine for one daemon per host but not for two
/// embedded nodes sharing this test's one process. `validate_userspace` also
/// requires at least one attachment (a SOCKS5 listener or a published port)
/// even though this test's nodes never use either — they attach directly via
/// `MeshNode`'s own TCP/UDP calls. The dummy publish entry exists only to
/// satisfy that validation.
///
/// **`exit_node_state_file` is the one setting every embedding caller needs
/// to override, not just this test.** Left absent, `karstd::control::load_config`
/// defaults it to `crate::exit_node::DEFAULT_STATE_FILE` —
/// `/var/lib/karst/exit-route` on Linux — a root-owned, fixed host path
/// `config.rs`'s own doc comment says exists for "more than one `karstd` on
/// the same host... which would otherwise all share one root's worth of
/// exit-route state." Two embedded nodes in one process are exactly that
/// case, and so, in general, is any non-root embedding process on a host
/// where that path is not theirs to read — `run_engine` treats anything but
/// `NotFound` opening it as a fatal startup error (`exit_node::Selection::load`),
/// not an optional feature it skips. Pointing it inside each node's own state
/// directory is the documented escape hatch, not a workaround.
fn make_userspace(config_path: &Path, state_dir: &Path, listen_port: u16) {
    use std::fmt::Write as _;
    let mut text = std::fs::read_to_string(config_path).expect("read config");
    text = text.replacen("[node]\n", "[node]\nnetwork_mode = \"userspace\"\n", 1);
    text = text.replacen(
        "listen = \"0.0.0.0:51820\"\n",
        &format!("listen = \"0.0.0.0:{listen_port}\"\n"),
        1,
    );
    let exit_route = state_dir.join("exit-route");
    let _ = writeln!(text, "exit_node_state_file = \"{}\"", exit_route.display());
    text.push_str("\n[[node.userspace_publish]]\nport = 65000\nto = \"127.0.0.1:1\"\n");
    std::fs::write(config_path, text).expect("write config");
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!(
            "karst-embed-two-nodes-{tag}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("scratch dir permissions");
        Self(dir)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if std::env::var_os("KARST_EMBED_KEEP_SCRATCH").is_some() {
            eprintln!("keeping scratch dir: {}", self.0.display());
            return;
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One node's own scratch paths, shared between its enroll and start steps.
struct NodePaths {
    scratch: Scratch,
    config: PathBuf,
    state: PathBuf,
    socket: PathBuf,
}

/// Enroll one node against the real server — split from starting it so this
/// test can read back the real identity ML-DSA public key `enroll` just
/// created and put it in the relay's roster before any node tries to use
/// the relay.
fn enroll_node(server: &TestServer, pins: &Pins, relay_ca: &str, tag: &str) -> NodePaths {
    let scratch = Scratch::new(tag);
    let config = scratch.join("karstd.toml");
    let state = scratch.join("state");
    let socket = scratch.join("control.sock");
    karst_embed::enroll(&invitation(server, pins, relay_ca, tag), &config, &state).expect("enroll");
    NodePaths {
        scratch,
        config,
        state,
        socket,
    }
}

/// This node's ML-DSA control-plane identity public key — the roster's
/// `identity_pk`, not a Noise session key. `bins/karstd/tests/aquifer.rs`'s
/// `node_public` derives the same value from a known seed; here it is read
/// back from the file `enroll_node` just created, since an embedding
/// caller's identity is randomly generated at enrollment time, not chosen.
fn identity_public_key(paths: &NodePaths) -> Vec<u8> {
    let identity = karstd::control::Identity::load(&paths.state.join("identity.key"))
        .expect("load the identity enroll_node just created");
    identity.public_key().clone()
}

/// Finish starting a node `enroll_node` already provisioned, in
/// `network_mode = "userspace"`.
fn start_node(paths: NodePaths, listen_port: u16) -> (Scratch, karst_embed::MeshNode) {
    make_userspace(&paths.config, &paths.state, listen_port);
    let node =
        karst_embed::MeshNode::start(&paths.config, &paths.socket).expect("start embedded node");
    (paths.scratch, node)
}

/// Poll a node's own overlay address until the control plane has assigned
/// one — `StatusJson::addresses`, empty until the first netmap sync lands.
fn wait_for_overlay_address(node: &karst_embed::MeshNode, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let status = node.status_json().expect("status_json");
        let parsed: serde_json::Value = serde_json::from_str(&status).expect("status is JSON");
        if let Some(address) = parsed["addresses"].as_array().and_then(|a| a.first()) {
            let address = address.as_str().expect("address is a string").to_owned();
            // `addresses` carries a CIDR ("100.64.0.1/32"); callers connect
            // to the bare address.
            return address.split('/').next().expect("non-empty").to_owned();
        }
        assert!(
            Instant::now() < deadline,
            "node never received an overlay address; last status: {status}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Poll a node's own view of its one peer until the datapath reports it
/// `established` — direct or via relay, either is fine.
///
/// **Not optional before the first `connect_tcp`.** `connect_tcp` only sets
/// up a local `smoltcp` socket; it has no idea whether a session with the
/// peer exists yet, and neither does `smoltcp`. A SYN sent before one does
/// is silently dropped at the engine layer (`tx_dropped_no_session`) with no
/// signal back to `smoltcp`, which then backs off its own retransmissions on
/// a clock with no relation to when the session actually comes up — found
/// directly, not guessed: a status check mid-test showed `established:
/// true, transport: "direct"` on both nodes while the TCP handshake this
/// test had already attempted was still stuck, because that first SYN went
/// out (and was dropped) long before the session existed. Waiting here is
/// what a real embedding caller gets for free from `MeshNode::connect_tcp`'s
/// own retry inside a real protocol that expects the mesh to already be up;
/// this test's `enroll`-then-immediately-`start`-then-immediately-`connect`
/// sequence compresses time in a way nothing stops a caller from doing too,
/// so this wait is the honest fix, not a workaround only this test needs.
fn wait_for_peer_established(node: &karst_embed::MeshNode, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let status = node.status_json().expect("status_json");
        let parsed: serde_json::Value = serde_json::from_str(&status).expect("status is JSON");
        if parsed["peers"]
            .as_array()
            .and_then(|peers| peers.first())
            .and_then(|peer| peer["established"].as_bool())
            == Some(true)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "peer never reached established; last status: {status}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// `22`, not an arbitrary port — this fixture's own hardcoded policy
/// document only grants `["*:22", "10.99.0.0/24:22"]`
/// (`server/management/internals/karst/testserver/netmap.go`'s
/// `buildNetmapServer`, the same restriction `bins/karstd/tests/aquifer.rs`'s
/// own real TCP exchange (`exchange_tcp_under_the_acl`) already works
/// around the identical way). **Found the hard way**: with port 7777, both
/// nodes registered, synced, and reached a fully `established` direct
/// session — real progress, confirmed in `status_json` — and then every TCP
/// byte this test tried to send simply vanished with `acl_denied_out`
/// climbing on every retry, which is egress policy enforcement doing
/// exactly its job against a port this fixture never grants, not a defect
/// in the mesh, the relay, or `karst-embed` itself.
const PORT: u16 = 22;

/// GitHub issue #214's own acceptance criterion: a node built from
/// `crates/karst-embed` becomes a reachable mesh peer, with no `karstd`
/// process anywhere, and real bytes cross a TCP connection between two of
/// them.
#[test]
#[ignore = "builds and runs the Go control server"]
fn two_embedded_nodes_exchange_tcp_with_no_karstd_process() {
    // The embedded engine thread's own `tracing::*!` calls otherwise go
    // nowhere, the same gap `crates/karst-ffi::engine`'s module doc names
    // for the identical reason (no subscriber installed by default outside
    // a full `karstd` process) — installing one here is this test's own
    // diagnostic, not something a real embedding application needs to do.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
        .with_test_writer()
        .try_init();

    let relay_dir = Scratch::new("relay");
    let relay_setup = RelaySetup::prepare(&relay_dir.0, 18443);
    let (server, pins) = start_server(&relay_setup);

    let paths_a = enroll_node(&server, &pins, &relay_setup.cert_pem, "node-a");
    let paths_b = enroll_node(&server, &pins, &relay_setup.cert_pem, "node-b");
    let pk_a = identity_public_key(&paths_a);
    let pk_b = identity_public_key(&paths_b);
    // Only spawned now that both real identities are known, so the roster
    // it starts with is already the one it needs — no hot-reload polling to
    // replicate from `aquifer.rs` for what is otherwise a one-shot setup.
    let _relay = relay_setup.spawn(&[pk_a, pk_b]);

    let (_scratch_a, node_a) = start_node(paths_a, 51820);
    let (_scratch_b, node_b) = start_node(paths_b, 51821);

    let address_b = wait_for_overlay_address(&node_b, Duration::from_secs(30));
    wait_for_overlay_address(&node_a, Duration::from_secs(30));

    // See `wait_for_peer_established`'s own doc comment: this is not
    // optional ceremony, it is what keeps the TCP handshake below from
    // racing session establishment.
    wait_for_peer_established(&node_a, Duration::from_secs(150));
    wait_for_peer_established(&node_b, Duration::from_secs(150));

    let mut listener = node_b.listen_tcp(PORT).expect("listen on node b");
    let accepted = std::thread::scope(|scope| {
        let server_side = scope.spawn(move || {
            let (mut stream, _peer) = listener.accept().expect("accept on node b");
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).expect("read on node b");
            assert_eq!(&buf, b"hello", "node b did not receive what node a sent");
            stream.write_all(b"world").expect("write on node b");
            true
        });

        let address: std::net::IpAddr = address_b.parse().expect("valid overlay address");
        let deadline = Instant::now() + Duration::from_secs(180);
        let mut stream_a = loop {
            match node_a.connect_tcp(address, PORT) {
                Ok(stream) => break stream,
                Err(error) => {
                    assert!(
                        Instant::now() < deadline,
                        "node a never connected to node b: {error}"
                    );
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        };
        stream_a.write_all(b"hello").expect("write on node a");
        let mut buf = [0u8; 5];
        stream_a.read_exact(&mut buf).expect("read on node a");
        assert_eq!(&buf, b"world", "node a did not receive node b's reply");

        server_side.join().expect("accept thread")
    });
    assert!(accepted);

    node_a.stop();
    node_b.stop();
}
