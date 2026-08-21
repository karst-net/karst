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
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use karstd::config::{encode_hex, ControlSection, LocalSettings};
use karstd::control::Client;
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
        .args(["--netmap", &peers.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the test server");

    let stdout = child.stdout.take().expect("stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read the server's pins");
    let v: serde_json::Value = serde_json::from_str(&line).expect("pins are not JSON");

    TestServer {
        child,
        address: v["address"].as_str().expect("address").to_string(),
        kem_pin: v["static_kem"].as_str().expect("static_kem").to_string(),
        verify_pin: v["verify_key"].as_str().expect("verify_key").to_string(),
    }
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
    ControlSection {
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
        keys: keys(seed),
        listen: "0.0.0.0:51820".parse().expect("addr"),
        port_mapping: true,
        interface: "karst0".to_owned(),
        network_mode: karstd::config::NetworkMode::Tun,
        userspace_socks5_listen: None,
        userspace_publish: Vec::new(),
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
    assert_eq!(relay.identity_key.len(), 1952);
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
/// server recognises it, and no peer entry crosses the wire. That is the whole
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
        relay_ca_file: None,
        server: "http://127.0.0.1:1".to_owned(),
        server_kem_pin: encode_hex(&[0x01; 1184]),
        server_verify_pin: encode_hex(&[0x02; 1952]),
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
