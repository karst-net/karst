// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! A node against a real coordination server.
//!
//! `crates/karst-control-client/tests/interop.rs` proves the two
//! implementations complete a handshake and exchange envelopes. This goes the
//! rest of the way: a node registers, fetches a netmap, and turns it into a
//! datapath configuration it could route from.
//!
//! The server is the real Go code — `node.Store`, the PSK deriver, the ACL
//! compiler, `NetmapHandler`, the version hash — with the fork's account
//! manager stood in for, because that layer has its own tests and needs a SQL
//! fixture to build.
//!
//! `#[ignore]`d by default because it needs a Go toolchain. Run with:
//!
//! ```sh
//! cargo test -p karstd --test control -- --ignored
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use karst_bedrock::{encode_log, genesis_body, node_sign_body, Builder, Op, Signature};
use karst_control_client::transport::Signer as _;
use karst_crypto::sign::{AuthorityKey, RootKey, ROOT_SEED};
use karstd::config::{encode_hex, ControlSection, LocalSettings};
use karstd::control::{Client, Identity};
use karstd::netmap::Outcome;

struct TestServer {
    child: Child,
    address: String,
    kem_pin: String,
    verify_pin: String,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Build and start the Go server with `peers` peers already enrolled.
fn start_server(peers: usize) -> TestServer {
    start_server_with(peers, None)
}

/// As [`start_server`], optionally seeding Bedrock.
///
/// `bedrock` is `N[:mode]`: countersign the first N preloaded peers and
/// advertise `mode`. The enrolling node is always countersigned, standing in
/// for an admin who signed promptly — without that, every enforcing test would
/// fail on the node's own coverage rather than on the peer it is about.
fn start_server_with(peers: usize, bedrock: Option<&str>) -> TestServer {
    let mut args = vec!["--netmap".to_owned(), peers.to_string()];
    if let Some(handles) = bedrock {
        args.push("--bedrock".to_owned());
        args.push(handles.to_owned());
    }
    start_server_args(&args)
}

/// Start the real control fixture with an explicit Bedrock log. Unlike
/// [`start_server_with`]'s historical `--bedrock` shortcut, this path gives
/// the server only already-signed wire bytes: it cannot manufacture coverage
/// while a node is enrolling.
fn start_server_with_log(peers: usize, log: &Path) -> TestServer {
    start_server_args(&[
        "--netmap".to_owned(),
        peers.to_string(),
        "--bedrock-log".to_owned(),
        log.to_string_lossy().into_owned(),
        "--bedrock-mode".to_owned(),
        "enforcing".to_owned(),
    ])
}

fn start_server_args(args: &[String]) -> TestServer {
    let repo = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let bin = format!("{repo}/target/karst-testserver");

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

    let mut child = Command::new(&bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the test server");

    let stdout = child.stdout.take().expect("stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read the server's pins");
    let v: serde_json::Value = serde_json::from_str(&line).unwrap_or_else(|err| {
        let stderr = child
            .stderr
            .as_mut()
            .and_then(|pipe| {
                let mut text = String::new();
                std::io::Read::read_to_string(pipe, &mut text).ok()?;
                Some(text)
            })
            .unwrap_or_default();
        panic!("pins are not JSON: {err}; server stderr: {stderr}");
    });

    TestServer {
        child,
        address: v["address"].as_str().expect("address").to_string(),
        kem_pin: v["static_kem"].as_str().expect("static_kem").to_string(),
        verify_pin: v["verify_key"].as_str().expect("verify_key").to_string(),
    }
}

fn write_identity_seed(path: &Path, seed: u8) {
    std::fs::write(path, encode_hex(&[seed; 32])).expect("identity seed");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("identity mode");
}

/// Build the exact compact log a server receives after a root bootstrap and an
/// authority's offline node-sign response. The server under test only decodes
/// and distributes these bytes; Rust produced every signature.
fn offline_ceremony_for(
    identity_seed: u8,
    static_keys: &karst_noise::handshake::StaticKeys,
) -> Vec<u8> {
    let root = RootKey::from_seed(&[0xA1; ROOT_SEED]).expect("root");
    let authority = AuthorityKey::from_seed(&[0xB2; 32]).expect("authority");
    let identity = Identity::from_seed(&[identity_seed; 32]);
    let identity_public = identity.public_key();

    let mut builder = Builder::new();
    let (genesis, input) = builder.prepare(
        1_000,
        Op::Genesis,
        genesis_body(
            "fixture.karst.",
            &[root.public_key()],
            1,
            &[authority.public_key()],
            1,
            &[],
        ),
    );
    builder
        .commit(
            genesis,
            vec![Signature {
                signer_index: 0,
                sig: root.sign(&input).expect("root signs genesis"),
            }],
        )
        .expect("commit genesis");

    let (node_sign, input) = builder.prepare(
        1_001,
        Op::NodeSign,
        node_sign_body(
            &identity.handle(),
            &identity_public,
            &static_keys.kem_pk.to_bytes(),
            static_keys.dh_pk.as_bytes(),
            0,
            0,
        ),
    );
    builder
        .commit(
            node_sign,
            vec![Signature {
                signer_index: 0,
                sig: authority.sign(&input).expect("authority signs node"),
            }],
        )
        .expect("commit node-sign");

    encode_log(&builder.into_entries())
}

/// A temporary directory that removes itself.
///
/// Fixtures here used to create one per process and never remove it, which
/// accumulated thousands of directories in `/tmp` across repeated runs.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("karst-scratch-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn section(server: &TestServer, dir: &Path, cache: Option<&str>) -> ControlSection {
    section_with_floor(server, dir, cache, None)
}

/// As [`section`], with a local Bedrock floor the server cannot lower.
fn section_with_floor(
    server: &TestServer,
    dir: &Path,
    cache: Option<&str>,
    floor: Option<&str>,
) -> ControlSection {
    ControlSection {
        bedrock_mode: floor.map(ToOwned::to_owned),
        control_minimum_version: None,
        relay_ca_file: None,
        server: format!("http://{}", server.address),
        server_kem_pin: server.kem_pin.clone(),
        server_verify_pin: server.verify_pin.clone(),
        identity_key_file: dir.join("identity.key"),
        setup_key: Some("fixture".to_owned()),
        cache_file: cache.map(|c| dir.join(c)),
    }
}

fn keys(seed: u8) -> Arc<karst_noise::handshake::StaticKeys> {
    Arc::new(karst_noise::handshake::StaticKeys::from_seed(
        &[seed; 64],
        &[seed; 32],
    ))
}

fn local(seed: u8) -> LocalSettings {
    LocalSettings {
        relay_ca_file: None,
        exit_node_state_file: None,
        keys: keys(seed),
        listen: "0.0.0.0:51820".parse().expect("addr"),
        port_mapping: true,
        interface: "karst0".to_owned(),
        network_mode: karstd::config::NetworkMode::Tun,
        dns: karstd::config::DnsSettings::default(),
        userspace_socks5_listen: None,
        userspace_publish: Vec::new(),
        nat64: None,
        metrics_listen: None,
    }
}

/// **The exit criterion, end to end.** A node that has never been manually
/// configured registers, receives a netmap, and ends up with a routable
/// configuration naming peers it was never told about.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn a_node_registers_and_receives_a_routable_netmap() {
    let server = start_server(2);
    let dir = Scratch::new("register");
    let mut client =
        Client::new(&section(&server, dir.path(), None), dir.path(), &keys(0x31)).expect("client");

    let outcome = client.sync().await.expect("register and fetch");
    assert!(
        matches!(outcome, Outcome::Replaced { peers: 2 }),
        "expected a full netmap with the two preloaded peers, got {outcome:?}"
    );

    let config = client
        .to_config(local(0x31))
        .expect("a netmap must configure a datapath");

    assert_eq!(config.peers.len(), 2);
    assert_eq!(config.psk_epoch, 7, "the epoch comes from the server");
    assert_eq!(
        config.relays.len(),
        1,
        "the relay registry was not retained"
    );
    let relay = config.relays.first().expect("the fixture relay");
    assert_eq!(relay.address, "127.0.0.1:443");
    assert_eq!(relay.region, "test");
    assert_eq!(relay.identity_key.len(), 2592);
    for peer in &config.peers {
        assert!(
            !peer.psk_is_fallback,
            "peer {} arrived without a PSK, so its session would be lattice-only",
            peer.name
        );
        assert!(!peer.allowed_ips.is_empty());
    }

    // The node's own address must carry the on-link prefix, or no peer is
    // reachable over the interface.
    let addr = config.addresses.first().expect("an address");
    assert_eq!(addr.prefix_len, 16, "the account's /16, not a bare /32");
    for peer in &config.peers {
        for range in &peer.allowed_ips {
            assert!(
                addr.network().contains(range.base()),
                "peer range {range} is not on-link with {addr}"
            );
        }
    }

    // And every peer's address routes to it.
    for (index, peer) in config.peers.iter().enumerate() {
        let range = peer.allowed_ips.first().expect("a range");
        assert_eq!(
            config.routes.route(range.base()),
            Some(index),
            "peer {} does not own the address it was given",
            peer.name
        );
    }
}

/// The server's compiled ACL reaches the datapath. The fixture's policy permits
/// port 22 and nothing else, so the filter must enforce exactly that.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn the_servers_policy_arrives_and_is_enforced() {
    let server = start_server(1);
    let dir = Scratch::new("policy");
    let mut client =
        Client::new(&section(&server, dir.path(), None), dir.path(), &keys(0x32)).expect("client");
    client.sync().await.expect("sync");
    let config = client.to_config(local(0x32)).expect("config");

    assert!(
        config.filter.is_enforcing(),
        "a server-managed node always enforces"
    );

    let tcp = |port: u16| {
        let mut p = vec![0u8; 24];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&24u16.to_be_bytes());
        p[9] = 6;
        p[22..24].copy_from_slice(&port.to_be_bytes());
        p
    };

    assert!(
        config.filter.ingress(0, &tcp(22)).permitted(),
        "the policy permits 22"
    );
    assert!(
        !config.filter.ingress(0, &tcp(8080)).permitted(),
        "and nothing else — default deny is what the server compiled"
    );
}

/// **A second fetch must be cheap.** The node sends the version it holds, the
/// server recognizes it, and no peer entry crosses the wire. That is the whole
/// point of the content-hash version, and it is the property that silently
/// breaks if the two implementations disagree about how to compute it.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn an_unchanged_netmap_is_answered_without_resending_it() {
    let server = start_server(2);
    let dir = Scratch::new("unchanged");
    let mut client =
        Client::new(&section(&server, dir.path(), None), dir.path(), &keys(0x33)).expect("client");

    client.sync().await.expect("first fetch");
    let version = client.netmap().version;
    assert_ne!(version, 0, "a fetched netmap must have a version");

    let again = client.sync().await.expect("second fetch");
    assert_eq!(
        again,
        Outcome::Unchanged,
        "the server re-sent a netmap the node already held"
    );
    assert_eq!(client.netmap().version, version);
    assert_eq!(client.netmap().peers().len(), 2, "and dropped nobody");
}

/// The node checks the server's arithmetic on every fetch. If this passes, the
/// Rust and Go version functions agree over a netmap neither test constructed —
/// which is the thing the vectors pin and this confirms in the field.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn the_assembled_netmap_reproduces_the_servers_version() {
    let server = start_server(3);
    let dir = Scratch::new("version");
    let mut client =
        Client::new(&section(&server, dir.path(), None), dir.path(), &keys(0x34)).expect("client");
    client.sync().await.expect("fetch");

    assert_eq!(
        client.netmap().content_version(),
        client.netmap().version,
        "the node's view does not hash to what the server called it"
    );
}

/// A node comes up on its cache when the server is gone — and the PSKs survive
/// the round trip, or every peer would silently become lattice-only after a
/// restart.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn a_cached_netmap_survives_the_server_going_away() {
    let dir = Scratch::new("cache");
    let version;
    let handle;
    {
        let server = start_server(2);
        let mut client = Client::new(
            &section(&server, dir.path(), Some("netmap.bin")),
            dir.path(),
            &keys(0x35),
        )
        .expect("client");
        client.sync().await.expect("sync");
        client.save_cache().expect("save");
        version = client.netmap().version;
        handle = client.netmap().node_id.clone();
        // The server is killed here, when `server` drops.
    }

    // A fresh client with the same identity file and no reachable server.
    let dead = ControlSection {
        bedrock_mode: None,
        control_minimum_version: None,
        relay_ca_file: None,
        server: "http://127.0.0.1:1".to_owned(),
        server_kem_pin: encode_hex(&[0x01; 1184]),
        server_verify_pin: encode_hex(&[0x02; 2592]),
        identity_key_file: dir.join("identity.key"),
        setup_key: None,
        cache_file: Some(dir.join("netmap.bin")),
    };
    let mut offline = Client::new(&dead, dir.path(), &keys(0x35)).expect("client");
    let loaded = offline
        .load_cache()
        .expect("a cache exists")
        .expect("it must open");
    assert_eq!(loaded, Outcome::Replaced { peers: 2 });
    assert_eq!(offline.netmap().version, version);
    assert_eq!(offline.netmap().node_id, handle);

    // And it is still a usable configuration, PSKs included.
    let config = offline.to_config(local(0x35)).expect("config from cache");
    assert_eq!(config.peers.len(), 2);
    for peer in &config.peers {
        assert!(
            !peer.psk_is_fallback,
            "the PSK for {} did not survive the cache",
            peer.name
        );
    }
}

// ── Bedrock, over the wire ──────────────────────────────────────────────────

/// The node fetches the Bedrock log and verifies it from genesis — plan items
/// 10.7 and 10.8, `bedrock-v1.md` §5 layers 1 and 2.
///
/// The chain is signed by keys generated inside the fixture, which this node
/// has never seen. It verifies anyway, because verification starts at genesis
/// and the genesis names its own roots — which is the entire point of the
/// design and the thing a test with pinned keys would fail to exercise.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn a_node_fetches_and_verifies_the_bedrock_log() {
    let server = start_server_with(2, Some("2"));
    let dir = Scratch::new("bedrock");
    let mut client =
        Client::new(&section(&server, dir.path(), None), dir.path(), &keys(0x41)).expect("client");

    client.sync().await.expect("register and fetch");

    let state = client
        .bedrock_state()
        .expect("the node did not verify a bedrock log");

    // Genesis, the two preloaded peers, and this node — countersigned as it
    // enrolled, which is why the chain is four entries and not three.
    assert_eq!(state.head_seq, 4, "unexpected chain length");
    assert_eq!(state.head.len(), 64, "the head is not a SHA-512 hash");
    assert_eq!(state.zone, "fixture.karst.");
    assert_eq!(state.q, 1);
    assert!(!state.disabled);

    // The coverage the log established. Handles are derived from identity
    // keys, never chosen, so this asserts the count and that this node is
    // among them rather than pinning names the fixture does not get to pick.
    assert_eq!(state.covered.len(), 3);
    let self_handle = String::from_utf8_lossy(&client.netmap().node_id).into_owned();
    assert!(
        state.covered.contains_key(&self_handle),
        "the enrolling node was not countersigned"
    );
}

/// The head in the netmap and the head from the fetch must agree.
///
/// If they could disagree, a server could advance the log while reporting an
/// old head — or the reverse — and a node would have no way to tell which of
/// the two it should be enforcing against.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn the_netmap_head_matches_the_fetched_log() {
    let server = start_server_with(1, Some("1"));
    let dir = Scratch::new("bedrock-head");
    let mut client =
        Client::new(&section(&server, dir.path(), None), dir.path(), &keys(0x42)).expect("client");

    client.sync().await.expect("register and fetch");

    let state = client.bedrock_state().expect("a verified log");
    let head = client.netmap().bedrock_head.clone();
    assert!(
        head.is_present(),
        "the netmap carried no Bedrock head, so the version hash covers nothing"
    );
    assert_eq!(head.seq, state.head_seq, "netmap and fetched head disagree");
    assert_eq!(head.hash, state.head, "netmap and fetched head disagree");
}

/// A server with no Bedrock log is a normal server, not a broken one.
///
/// Most accounts never turn Bedrock on, so this is the common path: no head in
/// the netmap, nothing to fetch, and a node that comes up regardless.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn a_server_without_bedrock_is_not_an_error() {
    let server = start_server(1);
    let dir = Scratch::new("bedrock-absent");
    let mut client =
        Client::new(&section(&server, dir.path(), None), dir.path(), &keys(0x43)).expect("client");

    client.sync().await.expect("register and fetch");

    assert!(client.bedrock_state().is_none());
    assert!(!client.netmap().bedrock_head.is_present());
    client
        .to_config(local(0x43))
        .expect("a node must come up without Bedrock");
}

/// The verified log survives a restart, so a node that boots with the server
/// unreachable enforces the policy it last verified rather than none.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn the_verified_log_is_persisted_and_re_verified_on_load() {
    let server = start_server_with(2, Some("2"));
    let dir = Scratch::new("bedrock-cache");

    let mut client = Client::new(
        &section(&server, dir.path(), Some("netmap.cache")),
        dir.path(),
        &keys(0x44),
    )
    .expect("client");
    client.sync().await.expect("register and fetch");
    let head = client.bedrock_state().expect("a verified log").head.clone();

    // A second node, same state directory, no network call at all.
    let mut restarted = Client::new(
        &section(&server, dir.path(), Some("netmap.cache")),
        dir.path(),
        &keys(0x44),
    )
    .expect("client");
    restarted
        .load_bedrock()
        .expect("a log was written")
        .expect("the stored log must verify");

    assert_eq!(
        restarted.bedrock_state().expect("state").head,
        head,
        "the restored log is not the one that was verified"
    );
}

// ── enforcement ─────────────────────────────────────────────────────────────

/// A completed offline ceremony reaches the client as an actual Bedrock log,
/// not as the testserver's historical auto-countersigning fixture. The covered
/// client is admitted while the unrelated enrolled peer is absent from its
/// datapath configuration under enforcing mode.
///
/// This is the client-facing half of the Bedrock vertical slice: Rust creates
/// the signed compact log, the Go control server decodes and publishes it, and
/// the Rust node verifies it before deciding which real netmap peers may reach
/// the datapath.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn a_real_offline_ceremony_admits_only_covered_aquifer_members() {
    let dir = Scratch::new("bedrock-real-ceremony-enforcement");
    let identity_seed = 0x5A;
    let static_keys = keys(identity_seed);
    write_identity_seed(&dir.join("identity.key"), identity_seed);

    let log = dir.join("ceremony.bedrock");
    std::fs::write(&log, offline_ceremony_for(identity_seed, &static_keys))
        .expect("write ceremony");

    // The preloaded peer enrolls normally, but is deliberately absent from the
    // offline authority response. It therefore reaches the netmap but not the
    // datapath; the test would fail if the testserver re-signed it on our
    // behalf.
    let server = start_server_with_log(1, &log);
    let mut client = Client::new(
        &section(&server, dir.path(), None),
        dir.path(),
        &static_keys,
    )
    .expect("client");

    client
        .sync()
        .await
        .expect("register, fetch, and verify ceremony");
    assert!(
        client.bedrock_covers_self(4_000_000_000),
        "the actual offline authority response did not cover the enrolling client"
    );
    assert_eq!(
        client.netmap().peers().len(),
        1,
        "fixture lost the uncovered peer"
    );

    let config = client
        .to_config(local(identity_seed))
        .expect("covered client starts");
    assert!(
        config.peers.is_empty(),
        "the uncovered peer crossed the enforcing Bedrock boundary"
    );
    assert!(
        config
            .skipped
            .iter()
            .any(|peer| peer.reason.contains("bedrock: not countersigned")),
        "the client's rejection was not recorded as a Bedrock exclusion: {:?}",
        config.skipped
    );
}

/// **The fail-closed path.** Two peers, one countersigned, enforcement on: the
/// uncovered one is not in the datapath configuration at all.
///
/// Not "is refused when dialled" — *absent*. A peer that is not in the
/// configuration cannot be handshaked with, so enforcement holds by
/// construction rather than by a check in the session path that could be
/// forgotten or reordered.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn an_uncovered_peer_is_dropped_from_the_datapath() {
    let server = start_server_with(2, Some("1:enforcing"));
    let dir = Scratch::new("enforce");
    let mut client =
        Client::new(&section(&server, dir.path(), None), dir.path(), &keys(0x51)).expect("client");
    client.sync().await.expect("register and fetch");

    assert_eq!(
        client.netmap().peers().len(),
        2,
        "the netmap itself should still carry both peers"
    );

    let config = client.to_config(local(0x51)).expect("config");
    assert_eq!(
        config.peers.len(),
        1,
        "the uncovered peer reached the datapath"
    );
    let skipped = config
        .skipped
        .iter()
        .find(|s| s.reason.starts_with("bedrock:"))
        .expect("the exclusion was not reported");
    assert!(
        skipped.reason.contains("not countersigned"),
        "unhelpful exclusion reason: {}",
        skipped.reason
    );
}

/// Advisory reports exactly what enforcing would drop, and drops nothing.
///
/// This is the mode that makes the feature deployable: an operator sees the
/// list before anybody is cut off. If advisory and enforcing could disagree
/// about who is uncovered, the preview would be worthless.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn advisory_reports_what_enforcing_would_drop() {
    let server = start_server_with(2, Some("1:advisory"));
    let dir = Scratch::new("advisory");
    let mut client =
        Client::new(&section(&server, dir.path(), None), dir.path(), &keys(0x52)).expect("client");
    client.sync().await.expect("register and fetch");

    let now = 4_000_000_000;
    let exclusions = client.bedrock_exclusions(now);
    assert_eq!(exclusions.len(), 1, "advisory did not report the exclusion");

    // And nothing was dropped.
    let config = client.to_config_at(local(0x52), now).expect("config");
    assert_eq!(
        config.peers.len(),
        2,
        "advisory mode dropped a peer; it must only report"
    );
}

/// With Bedrock off, nothing is excluded even though a peer is uncovered.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn off_excludes_nothing() {
    let server = start_server_with(2, Some("1:off"));
    let dir = Scratch::new("bedrock-off");
    let mut client =
        Client::new(&section(&server, dir.path(), None), dir.path(), &keys(0x53)).expect("client");
    client.sync().await.expect("register and fetch");

    assert!(client.bedrock_exclusions(4_000_000_000).is_empty());
    let config = client.to_config(local(0x53)).expect("config");
    assert_eq!(config.peers.len(), 2);
}

/// **A local floor the server cannot lower.**
///
/// The server advertises `off`; the node was configured `enforcing`. The node
/// enforces. Without this rule the mode would be a bypass: Bedrock exists
/// because the coordination server may be compromised, and a server that could
/// select `off` would switch the mechanism off by saying so.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn a_local_floor_survives_a_server_that_says_off() {
    let server = start_server_with(2, Some("1:off"));
    let dir = Scratch::new("floor");
    let mut client = Client::new(
        &section_with_floor(&server, dir.path(), None, Some("enforcing")),
        dir.path(),
        &keys(0x54),
    )
    .expect("client");
    client.sync().await.expect("register and fetch");

    assert!(
        !client.netmap().bedrock_head.mode_is_enforcing(),
        "the fixture should be advertising off for this test to mean anything"
    );

    let config = client.to_config(local(0x54)).expect("config");
    assert_eq!(
        config.peers.len(),
        1,
        "the server talked this node out of enforcing"
    );
}

/// A node whose own key is uncovered refuses to bring the interface up.
///
/// Its peers would refuse it under enforcement, so coming up would produce a
/// daemon that reports healthy and reaches nothing. The error names the cause.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn a_node_whose_own_key_is_uncovered_refuses_to_start() {
    // No Bedrock log at all, but a local floor of `enforcing`. Nothing is
    // covered, this node included.
    let server = start_server(1);
    let dir = Scratch::new("self-uncovered");
    let mut client = Client::new(
        &section_with_floor(&server, dir.path(), None, Some("enforcing")),
        dir.path(),
        &keys(0x55),
    )
    .expect("client");
    client.sync().await.expect("register and fetch");

    let err = client
        .to_config(local(0x55))
        .expect_err("an uncovered node brought its interface up");
    let text = format!("{err}");
    assert!(
        text.contains("not countersigned"),
        "the refusal does not say why: {text}"
    );
}

/// **The disclosure gate.** A node the log does not cover is refused a netmap
/// under enforcement, so it never learns the network's shape or its PSKs.
///
/// The node-side filter is what carries the security property, and it is
/// unaffected by this: the server may be compromised, so nothing it does is
/// trusted. This is the other half — a non-compromised server declining to hand
/// out every peer's keys, addresses and per-pair PSK to whoever presented a
/// setup key, when every peer would refuse that node anyway.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn an_uncovered_node_is_refused_a_netmap_under_enforcement() {
    let server = start_server_with(2, Some("2:enforcing:nocover"));
    let dir = Scratch::new("gate");
    let mut client =
        Client::new(&section(&server, dir.path(), None), dir.path(), &keys(0x61)).expect("client");

    let err = client
        .sync()
        .await
        .expect_err("an uncovered node was served a netmap");
    let text = format!("{err}");
    assert!(
        text.contains("countersigned"),
        "the refusal does not say why: {text}"
    );

    // And nothing about the network leaked with the refusal.
    assert_eq!(
        client.netmap().peers().len(),
        0,
        "peers reached a node that was refused"
    );
}

/// The same server serves a node it has countersigned. Together with the test
/// above this pins the gate to coverage and not to enforcement being on.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn a_covered_node_is_served_under_the_same_enforcement() {
    let server = start_server_with(2, Some("2:enforcing"));
    let dir = Scratch::new("gate-covered");
    let mut client =
        Client::new(&section(&server, dir.path(), None), dir.path(), &keys(0x62)).expect("client");

    client.sync().await.expect("a covered node was refused");
    assert_eq!(client.netmap().peers().len(), 2);
}

// ── the control-suite floor ─────────────────────────────────────────────────

/// **A floor this build cannot satisfy refuses at startup, not at the
/// handshake** — ADR-0015 item 4.
///
/// A node configured for control version 2 can never connect: the CNSA profile
/// is reserved and not implemented. Saying so when the daemon starts, naming
/// the suite, is the useful moment — the alternative is a node that comes up
/// looking healthy and fails every handshake for a reason nothing states.
///
/// It is also the correct direction. The floor means "nothing weaker than
/// this", so a build that cannot reach it must refuse rather than fall back to
/// the suite it happens to implement.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn a_floor_this_build_cannot_reach_is_refused_at_startup() {
    let server = start_server(1);
    let dir = Scratch::new("suite-floor");

    let mut section = section(&server, dir.path(), None);
    section.control_minimum_version = Some(2);

    let err = Client::new(&section, dir.path(), &keys(0x71))
        .expect_err("a node with an unreachable floor started anyway");
    let text = format!("{err}");
    assert!(
        text.contains("not implemented") && text.contains("version 2"),
        "the refusal does not name the suite: {text}"
    );
}

/// An unknown floor is refused too, and distinguishably.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn an_unknown_floor_is_refused_distinguishably() {
    let server = start_server(1);
    let dir = Scratch::new("suite-unknown");

    let mut section = section(&server, dir.path(), None);
    section.control_minimum_version = Some(99);

    let err = Client::new(&section, dir.path(), &keys(0x73))
        .expect_err("a node with an unknown floor started anyway");
    assert!(
        format!("{err}").contains("unknown"),
        "an unknown version was not distinguished from an unimplemented one: {err}"
    );
}

/// And the default floor accepts the suite this build speaks, so the check
/// above is testing the floor rather than a server that was broken anyway.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn the_default_floor_accepts_the_shipping_suite() {
    let server = start_server(1);
    let dir = Scratch::new("suite-default");
    let mut client =
        Client::new(&section(&server, dir.path(), None), dir.path(), &keys(0x72)).expect("client");
    client.sync().await.expect("the shipping suite was refused");
}
