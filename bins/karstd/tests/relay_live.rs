// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The node's relay client against a **real relay, on a real socket.**
//!
//! Everything below this had tests and none of them opened a socket. The Ponor
//! codec is exercised by `karst-relay-proto`; the node-side session by unit
//! tests with a stub signature scheme; the relay's own listener by
//! `karst-relay/tests/listener.rs` with a hand-rolled client. What nothing
//! covered is the pair — `karstd`'s client talking to `karst-relay`'s server —
//! and that is where a mismatched identifier, a wrong TLS name or a context
//! string that differs by one byte would live.
//!
//! A stub agrees with the code that calls it by construction. Two independent
//! implementations do not, which is the entire reason this file exists.
//!
//! Not privileged: everything runs on loopback in one process.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use base64ct::{Base64, Encoding as _};
use karst_relay::config::Config as RelayConfig;
use karst_relay::roster::FileRoster;
use karst_relay::server::{serve_on, Ctx};
use karst_relay::sign::Identity as RelayIdentity;
use karst_relay::tls as relay_tls;
use karstd::control::{Identity, RelayVerifier};
use karstd::netmap::Relay;
use tokio::net::TcpListener;

/// A temporary directory that removes itself.
struct TempDir(std::path::PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(tag: &str) -> TempDir {
    let p = std::env::temp_dir().join(format!("karst-relaylive-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("mkdir");
    TempDir(p)
}

/// A node's control identity. The same key signs the Ponor handshake, under a
/// different context string — see `control.rs`.
fn node(seed: u8) -> Arc<Identity> {
    Arc::new(Identity::from_seed(&[seed; 32]))
}

fn public_of(id: &Identity) -> Vec<u8> {
    <Identity as karst_control_client::transport::Signer>::public_key(id)
}

struct Running {
    relay: Relay,
    ca_path: std::path::PathBuf,
    _dir: TempDir,
}

/// Start a relay on an ephemeral loopback port, admitting `nodes`.
async fn start_relay(tag: &str, nodes: &[&Identity]) -> Running {
    let dir = temp_dir(tag);

    // Self-signed, which §4.2 makes fine and finding 16 made *possible*: the
    // node trusts it through `relay_ca_file`, and the relay's actual identity
    // is the ML-DSA-65 key pinned below.
    let cert = rcgen::generate_simple_self_signed(vec!["relay.test".to_owned()])
        .expect("self-signed certificate");
    let cert_path = dir.0.join("relay.crt");
    let key_path = dir.0.join("relay.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).expect("write key");

    let mut roster_text = String::new();
    for id in nodes {
        use std::fmt::Write as _;
        let _ = write!(
            roster_text,
            "[[client]]\nidentity_pk = \"{}\"\naquifer = \"t1\"\n\n",
            Base64::encode_string(&public_of(id))
        );
    }
    let roster_path = dir.0.join("roster.toml");
    std::fs::write(&roster_path, roster_text).expect("write roster");

    let cfg = RelayConfig::parse(&format!(
        "listen = \"127.0.0.1:0\"\n\
         identity_key = \"{}\"\n\
         roster = \"{}\"\n\
         tls_cert = \"{}\"\n\
         tls_key = \"{}\"\n",
        dir.0.join("relay.key").display(),
        roster_path.display(),
        cert_path.display(),
        key_path.display()
    ))
    .expect("relay config parses");
    cfg.validate().expect("relay config is valid");

    let identity = Arc::new(RelayIdentity::load_or_create(&cfg.identity_key).expect("identity"));
    let roster = Arc::new(FileRoster::load(&cfg.roster).expect("roster"));
    let tls_config = relay_tls::server_config(&cfg.tls_cert, &cfg.tls_key).expect("relay tls");

    let listener = TcpListener::bind(cfg.listen).await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let ctx = Ctx::new(&cfg, Arc::clone(&identity), roster, tls_config);
    tokio::spawn(async move {
        let _ = serve_on(listener, ctx).await;
    });

    // The registry entry a netmap would carry. `relay_id` is derived from the
    // key rather than stored beside it (§5.1, §5.2), and `netmap::Relay`
    // re-derives and checks it when a real netmap is decoded.
    let identity_key = identity.public_key().to_vec();
    let relay = Relay {
        address: addr.to_string(),
        tls_server_name: "relay.test".to_owned(),
        relay_id: karst_relay::sign::relay_id(&identity_key),
        identity_key,
        region: "test".to_owned(),
    };

    Running {
        relay,
        ca_path: cert_path,
        _dir: dir,
    }
}

/// Connect one node to the relay, all the way through the Ponor handshake.
async fn connect(
    running: &Running,
    id: &Arc<Identity>,
) -> Result<karstd::relay::Connection, karstd::relay::ConnectError> {
    let tls = karstd::relay_tls::client_config(Some(&running.ca_path)).expect("client tls");
    let session = karstd::relay::Session::from_control_handle(
        id.handle().as_bytes(),
        &running.relay,
        [0x5A; 32],
    )
    .expect("the node's own handle decodes");
    karstd::relay::Connection::connect(session, &**id, &RelayVerifier, tls, &running.relay).await
}

/// **The identifier both ends must agree on.**
///
/// The node converts its control-plane handle to a Ponor id; the relay derives
/// one from the public key in its roster. Nothing forces those to be the same
/// function — they live in different crates and were written months apart — and
/// if they disagreed every admission would fail with a roster miss, which §10.1
/// deliberately makes indistinguishable from an unknown node.
#[test]
fn a_control_handle_and_a_relay_node_id_are_the_same_value() {
    let id = node(0x11);
    let from_handle = karst_control_client::handle_bytes(&id.handle()).expect("handle decodes");
    let from_key = karst_relay::sign::node_id(&public_of(&id));
    assert_eq!(
        from_handle, from_key,
        "the control plane and the relay derive different ids from one key"
    );
}

/// The whole node-side stack on a socket: TLS with a self-signed CA, the HTTP
/// upgrade, and the Ponor handshake with real ML-DSA-65 on both sides.
#[tokio::test]
async fn a_node_completes_a_ponor_handshake_with_a_real_relay() {
    let a = node(0x11);
    let running = start_relay("handshake", &[&a]).await;

    // `connect` loops until the session is established or the stream fails, so
    // **the `Ok` is the assertion**: it means the relay's ML-DSA-65 signature
    // over the transcript verified against the key pinned in `Relay`.
    //
    // An earlier version of this comment credited `split`'s established check
    // instead. That check is defensive and unreachable through `connect` —
    // removing it changes nothing here — and saying otherwise would have
    // described a guarantee this test does not provide.
    let connection = connect(&running, &a).await.expect("handshake");
    assert!(connection.split().is_some());
}

/// A substituted registry entry is refused, however good the certificate is —
/// which is §4.2's whole argument, that TLS does not authenticate the relay.
///
/// **Where it is refused is worth being precise about.** This fails on the
/// `relay_id` comparison in the client's hello handling, not on the signature:
/// disabling the signature check leaves this test passing. That is not a gap,
/// it is §5.1 and §5.2 working — `relay_id` is *derived* from the key rather
/// than stored beside it, so an entry naming a different key necessarily names
/// a different id and there is no way to construct one that passes the id check
/// and fails the signature.
///
/// The signature defends the complementary case, a relay claiming an id it
/// cannot sign for, which needs a malicious relay to construct;
/// `spec/models/ponor-norelayid.pv` and `karst-relay/tests/end_to_end.rs` cover
/// it. This test does not, and an earlier version of this comment implied it
/// did.
#[tokio::test]
async fn a_substituted_relay_registry_entry_is_refused() {
    let a = node(0x11);
    let mut running = start_relay("wrongpin", &[&a]).await;

    // Same host, same certificate, same address — only the pinned identity is
    // somebody else's. `relay_id` is re-derived so the entry stays internally
    // consistent, which is what a substituted registry row would look like.
    let impostor = vec![0x7E; 1952];
    running.relay.relay_id = karst_relay::sign::relay_id(&impostor);
    running.relay.identity_key = impostor;

    assert!(
        connect(&running, &a).await.is_err(),
        "a relay presenting a different identity key was accepted"
    );
}

/// Two admitted nodes, and a datagram that crosses between them.
///
/// This is what the PHREATIC relay path rides on. `relay_path.rs` proves the
/// two engines choose the relay and handle what arrives; this proves the bytes
/// actually get there.
#[tokio::test]
async fn a_packet_crosses_between_two_admitted_nodes() {
    let a = node(0x11);
    let b = node(0x22);
    let running = start_relay("packet", &[&a, &b]).await;

    let a_conn = connect(&running, &a).await.expect("a connects");
    let b_conn = connect(&running, &b).await.expect("b connects");
    let (mut a_tx, _a_rx) = a_conn.split().expect("a established");
    let (_b_tx, mut b_rx) = b_conn.split().expect("b established");

    let b_id = karst_control_client::handle_bytes(&b.handle()).expect("b's handle");
    let payload = b"a sealed PHREATIC datagram, as far as the relay knows";
    a_tx.send_packet(b_id, payload).await.expect("send");
    a_tx.flush().await.expect("flush");

    let events = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        b_rx.receive(&*b, &RelayVerifier),
    )
    .await
    .expect("b received nothing before the timeout")
    .expect("b's stream failed");

    let a_id = karst_control_client::handle_bytes(&a.handle()).expect("a's handle");
    assert_eq!(
        events,
        vec![karstd::relay::Event::Packet {
            source_id: a_id,
            payload: payload.to_vec(),
        }],
        "the relay did not forward the packet, or stamped the wrong source"
    );
}

/// §9.1's measurement, end to end: a real ping on an established connection, a
/// real relay answering it, and the probe table turning the pair into a number.
///
/// The two halves are proven separately elsewhere — `karst-relay`'s listener
/// suite answers a `Ping`, and `home.rs` matches tokens — and neither one shows
/// that `karstd` sends a frame this relay recognises. A token echoed back under
/// a different length or a `Pong` the client did not parse would leave the
/// selector receiving nothing at all, which looks exactly like a relay that is
/// merely slow: the home relay would never be re-elected and nothing would say
/// why.
#[tokio::test]
async fn a_relay_answers_a_latency_probe_and_the_round_trip_is_measured() {
    let a = node(0x11);
    let running = start_relay("latency", &[&a]).await;

    let (mut tx, mut rx) = connect(&running, &a)
        .await
        .expect("a connects")
        .split()
        .expect("established");

    // Keyed by the relay it is sent to, as the daemon holds it: with
    // alternatives being measured there is more than one connection in flight,
    // and a round trip belongs to the relay that answered it.
    let mut probes = karstd::home::Probes::default();
    let relay_id = running.relay.relay_id;
    let token = [0xA7; karstd::relay::PING_TOKEN_LEN];
    let sent_at = 1_000;
    assert!(probes.sent(relay_id, token, sent_at));
    tx.ping(token).await.expect("ping");
    tx.flush().await.expect("flush");

    let events = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rx.receive(&*a, &RelayVerifier),
    )
    .await
    .expect("the relay did not answer the ping before the timeout")
    .expect("the stream failed");

    assert_eq!(
        events,
        vec![karstd::relay::Event::Pong { token }],
        "the relay answered with something other than this node's token"
    );
    let karstd::relay::Event::Pong { token } = events[0] else {
        unreachable!()
    };
    assert_eq!(
        probes.resolve(relay_id, token, sent_at + 7),
        Some(7),
        "the answered token did not resolve to the round trip"
    );
    assert_eq!(probes.in_flight(relay_id), 0);
}

/// A node the relay has no roster entry for is refused.
///
/// §5.3 makes this structural rather than a mode: `ClientAuth` carries no
/// public key, so a relay with no entry cannot verify the signature at all.
/// The node must fail closed rather than proceed unauthenticated.
#[tokio::test]
async fn an_unlisted_node_is_refused() {
    let listed = node(0x11);
    let stranger = node(0x33);
    let running = start_relay("unlisted", &[&listed]).await;

    assert!(
        connect(&running, &stranger).await.is_err(),
        "a node absent from the roster was admitted"
    );
    // And the relay is still serving, so the refusal was of that node rather
    // than a listener that fell over.
    assert!(connect(&running, &listed).await.is_ok());
}

/// **The certificate is validated even though it does not authenticate the
/// relay** (§4.2). Without the CA the connection must fail at TLS, before any
/// Ponor frame — which is also the check that `relay_ca_file` is what makes the
/// other tests here pass, rather than something else being permissive.
#[tokio::test]
async fn without_the_configured_ca_the_tls_hop_is_refused() {
    let a = node(0x11);
    let running = start_relay("nocert", &[&a]).await;

    let tls = karstd::relay_tls::client_config(None).expect("system roots only");
    let session = karstd::relay::Session::from_control_handle(
        a.handle().as_bytes(),
        &running.relay,
        [0x5A; 32],
    )
    .expect("handle decodes");
    let result =
        karstd::relay::Connection::connect(session, &*a, &RelayVerifier, tls, &running.relay).await;
    // **The failure mode is asserted, not just the failure.** A negative test
    // that only checks `is_err()` passes for a wrong port, a dead listener or a
    // typo in the address — every one of which would also make the positive
    // tests above fail, but not at the moment somebody breaks the CA handling.
    let Err(e) = result else {
        panic!("a self-signed relay certificate was accepted without its CA");
    };
    let rendered = format!("{e:?}");
    assert!(
        rendered.contains("UnknownIssuer"),
        "refused, but not for want of a trust anchor: {rendered}"
    );
}

/// **A peer this relay cannot reach comes back as an event, not as a
/// disconnection**, which is what §9.1's second rule is built on.
///
/// Before this the client had no case for `PeerGone` at all: the frame fell
/// through to the packet path, produced `OutOfOrder`, and the receive loop
/// treated it as a broken stream. Addressing a peer that is offline or homed
/// elsewhere is an ordinary event on a relay — and it happens *first*, since a
/// node cannot know where a peer is until it tries — so the cost of getting
/// this wrong was the connection to every other peer, torn down and rebuilt
/// with backoff each time.
///
/// Against a real relay because the two ends decide this independently: the
/// relay picks the reason byte from its own roster (§5.4 deliberately gives
/// "unknown" and "in another aquifer" the same one), and the client has to
/// parse the frame it actually sends.
#[tokio::test]
async fn a_relay_reports_a_peer_it_cannot_reach_without_dropping_the_connection() {
    let a = node(0x11);
    let stranger = node(0x33);
    // Only `a` is admitted, so `stranger` is a destination this relay will not
    // deliver to — the case a node hits when a peer is homed somewhere else.
    let running = start_relay("gone", &[&a]).await;

    let (mut tx, mut rx) = connect(&running, &a)
        .await
        .expect("a connects")
        .split()
        .expect("established");

    let stranger_id =
        karst_control_client::handle_bytes(&stranger.handle()).expect("the stranger's handle");
    tx.send_packet(stranger_id, b"nobody is going to get this")
        .await
        .expect("send");
    tx.flush().await.expect("flush");

    let events = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rx.receive(&*a, &RelayVerifier),
    )
    .await
    .expect("the relay said nothing about an undeliverable destination")
    .expect("the client treated PeerGone as a broken stream");

    let karstd::relay::Event::Gone { peer_id, .. } = events.first().expect("one event") else {
        panic!("expected a Gone event, got {events:?}");
    };
    assert_eq!(
        *peer_id, stranger_id,
        "the relay named a different peer from the one addressed"
    );

    // **The connection is still usable**, which is the half that matters: this
    // is the same connection every other peer's traffic is on.
    let a_id = karst_control_client::handle_bytes(&a.handle()).expect("a's handle");
    tx.send_packet(a_id, b"still here").await.expect("send");
    tx.flush().await.expect("flush");
}
