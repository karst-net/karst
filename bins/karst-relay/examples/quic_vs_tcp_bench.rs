// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! ADR-0020's performance comparison: QUIC vs TCP+TLS as the Ponor relay
//! transport, over loopback in one process.
//!
//! Measures two things for each transport, against the same relay and the
//! same two client identities:
//!
//! 1. **Handshake latency** — wall-clock time from opening the socket to the
//!    Ponor handshake completing (`RelayAuth` verified), over N trials.
//! 2. **Forwarding throughput** — wall-clock time to relay K
//!    maximum-size `SendPacket`/`RecvPacket` frames from one admitted client
//!    to another, back to back on one already-established connection.
//!
//! **Scope.** This is a clean-loopback measurement: it shows the fixed cost
//! of each transport's handshake and framing, not the loss-recovery
//! difference ADR-0020 is actually motivated by — that needs induced loss
//! (e.g. `tc qdisc add dev lo root netem loss <pct>`), which this harness
//! deliberately does not apply itself, since it would affect every process
//! using loopback on the host it runs on, not just this benchmark. An
//! operator who wants that comparison should run this binary once with such
//! a qdisc applied to a dedicated network namespace and once without, and
//! diff the throughput numbers — the harness itself does not change.
//!
//! Run with `cargo run --release --example quic_vs_tcp_bench -p karst-relay`.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_precision_loss
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64ct::{Base64, Encoding as _};
use karst_relay::config::Config;
use karst_relay::roster::FileRoster;
use karst_relay::server::{serve_on, Ctx};
use karst_relay::sign::{node_id, Identity, PonorVerifier, SEED_LEN};
use karst_relay::tls;
use karst_relay_proto::consts::ID_LEN;
use karst_relay_proto::{frame::decode, ClientHandshake, Frame, Role};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const HANDSHAKE_TRIALS: usize = 200;
const FORWARD_FRAMES: usize = 2_000;
const PAYLOAD: [u8; 1336] = [0xab; 1336];

fn identity(seed: u8) -> Identity {
    Identity::from_seed(&[seed; SEED_LEN])
}

fn nid(id: &Identity) -> [u8; ID_LEN] {
    node_id(id.public_key())
}

struct Harness {
    dir: std::path::PathBuf,
    addr: std::net::SocketAddr,
    quic_addr: std::net::SocketAddr,
    ca_path: std::path::PathBuf,
    relay: Arc<Identity>,
}

async fn start(alice: &Identity, bob: &Identity) -> Harness {
    let dir = std::env::temp_dir().join(format!("karst-quic-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");

    let cert = rcgen::generate_simple_self_signed(vec!["relay.bench".to_owned()]).expect("cert");
    let cert_path = dir.join("relay.crt");
    let key_path = dir.join("relay.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).expect("write key");
    let ca_path = dir.join("ca.pem");
    std::fs::write(&ca_path, cert.cert.pem()).expect("write ca");

    let roster_text = format!(
        "[[client]]\nidentity_pk = \"{}\"\naquifer = \"bench\"\n\n\
         [[client]]\nidentity_pk = \"{}\"\naquifer = \"bench\"\n",
        Base64::encode_string(alice.public_key()),
        Base64::encode_string(bob.public_key()),
    );
    let roster_path = dir.join("roster.toml");
    std::fs::write(&roster_path, roster_text).expect("write roster");

    let cfg = Config::parse(&format!(
        "listen = \"127.0.0.1:0\"\nidentity_key = \"{}\"\nroster = \"{}\"\n\
         tls_cert = \"{}\"\ntls_key = \"{}\"\nquic = true\n",
        dir.join("relay.key").display(),
        roster_path.display(),
        cert_path.display(),
        key_path.display(),
    ))
    .expect("config");
    cfg.validate().expect("valid");

    let identity = Arc::new(Identity::load_or_create(&cfg.identity_key).expect("identity"));
    let roster = Arc::new(FileRoster::load(&cfg.roster).expect("roster"));
    let tls_config = tls::server_config(&cfg.tls_cert, &cfg.tls_key).expect("tls");
    let listener = TcpListener::bind(cfg.listen).await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let ctx = Ctx::new(&cfg, Arc::clone(&identity), roster, Arc::clone(&tls_config));

    let quic_cfg = karst_relay::quic::server_config(&tls_config).expect("quic tls");
    let endpoint = karst_relay::quic::bind(cfg.listen, quic_cfg).expect("bind quic");
    let quic_addr = endpoint.local_addr().expect("quic addr");
    tokio::spawn(karst_relay::quic::serve_on(endpoint, Arc::clone(&ctx)));
    tokio::spawn(async move {
        let _ = serve_on(listener, ctx).await;
    });

    Harness {
        dir,
        addr,
        quic_addr,
        ca_path,
        relay: identity,
    }
}

/// One TCP+TLS handshake, start to finish, returning how long it took.
async fn tcp_handshake(h: &Harness, node: &Identity) -> Duration {
    let start = Instant::now();
    let mut roots = rustls::RootCertStore::empty();
    let ca: rustls_pki_types::CertificateDer<'static> =
        rustls_pki_types::pem::PemObject::from_pem_file(&h.ca_path).expect("ca");
    roots.add(ca).expect("trust");
    let provider = tls::provider().expect("provider");
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(h.addr).await.expect("tcp");
    let name = rustls::pki_types::ServerName::try_from("relay.bench").expect("name");
    let mut tls = connector.connect(name, tcp).await.expect("tls");
    tls.write_all(
        b"GET /ponor HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: ponor\r\nPonor-Version: 1\r\n\r\n",
    )
    .await
    .expect("upgrade");
    let mut buf = Vec::new();
    let head = loop {
        let mut chunk = [0u8; 512];
        let n = tls.read(&mut chunk).await.expect("read");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    buf.drain(..head);
    let mut client = ClientHandshake::new(
        Role::Client,
        nid(node),
        h.relay.relay_id(),
        h.relay.public_key().to_vec(),
        rand_nonce(),
    );
    let hello = next_frame(&mut tls, &mut buf).await;
    let (hello, _) = decode(&hello).expect("decodes").expect("complete");
    let auth = client.on_relay_hello(&hello, node).expect("sign");
    tls.write_all(&auth).await.expect("write");
    let reply = next_frame(&mut tls, &mut buf).await;
    let (reply, _) = decode(&reply).expect("decodes").expect("complete");
    client
        .on_relay_auth(&reply, &PonorVerifier)
        .expect("verify");
    assert!(client.may_send());
    start.elapsed()
}

async fn next_frame(
    tls: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    buf: &mut Vec<u8>,
) -> Vec<u8> {
    loop {
        if let Some((_, used)) = decode(buf).expect("decodes") {
            return buf.drain(..used).collect();
        }
        let mut chunk = [0u8; 512];
        let n = tls.read(&mut chunk).await.expect("read");
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn rand_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).expect("entropy");
    nonce
}

fn percentiles(mut samples: Vec<Duration>) -> (Duration, Duration, Duration, Duration) {
    samples.sort_unstable();
    let n = samples.len();
    let p95 = samples[(n * 95 / 100).min(n - 1)];
    (samples[0], samples[n / 2], p95, samples[n - 1])
}

#[tokio::main]
async fn main() {
    let alice = identity(0x01);
    let bob = identity(0x02);
    let h = start(&alice, &bob).await;
    println!("relay: tcp={} quic={}", h.addr, h.quic_addr);

    // --- Handshake latency ---
    let mut tcp_times = Vec::with_capacity(HANDSHAKE_TRIALS);
    for _ in 0..HANDSHAKE_TRIALS {
        tcp_times.push(tcp_handshake(&h, &alice).await);
    }
    let (min, med, p95, max) = percentiles(tcp_times);
    println!(
        "tcp+tls handshake  (n={HANDSHAKE_TRIALS}): min={min:?} median={med:?} p95={p95:?} max={max:?}"
    );

    let tls_cfg = tls::client_config(&h.ca_path).expect("client tls");
    let quic_cfg = karst_relay::quic::client_config(&tls_cfg).expect("quic client");
    let mut quic_times = Vec::with_capacity(HANDSHAKE_TRIALS);
    for _ in 0..HANDSHAKE_TRIALS {
        let start = Instant::now();
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("client");
        endpoint.set_default_client_config(quic_cfg.clone());
        let connection = endpoint
            .connect(h.quic_addr, "relay.bench")
            .expect("connect")
            .await
            .expect("handshake");
        let (send, recv) = connection.accept_bi().await.expect("accept_bi");
        let mut stream = tokio::io::join(recv, send);
        let mut client = ClientHandshake::new(
            Role::Client,
            nid(&alice),
            h.relay.relay_id(),
            h.relay.public_key().to_vec(),
            rand_nonce(),
        );
        let mut buf = Vec::new();
        let hello = quic_next_frame(&mut stream, &mut buf).await;
        let (hello, _) = decode(&hello).expect("decodes").expect("complete");
        let auth = client.on_relay_hello(&hello, &alice).expect("sign");
        stream.write_all(&auth).await.expect("write");
        let reply = quic_next_frame(&mut stream, &mut buf).await;
        let (reply, _) = decode(&reply).expect("decodes").expect("complete");
        client
            .on_relay_auth(&reply, &PonorVerifier)
            .expect("verify");
        assert!(client.may_send());
        quic_times.push(start.elapsed());
    }
    let (min, med, p95, max) = percentiles(quic_times);
    println!(
        "quic handshake     (n={HANDSHAKE_TRIALS}): min={min:?} median={med:?} p95={p95:?} max={max:?}"
    );

    // --- Forwarding throughput ---
    let tcp_elapsed = tcp_forward_bench(&h, &alice, &bob).await;
    println!(
        "tcp+tls forwarding {FORWARD_FRAMES} max-size frames: {tcp_elapsed:?} ({:.0} frames/s)",
        FORWARD_FRAMES as f64 / tcp_elapsed.as_secs_f64()
    );
    let quic_elapsed = quic_forward_bench(&h, &alice, &bob, &quic_cfg).await;
    println!(
        "quic forwarding    {FORWARD_FRAMES} max-size frames: {quic_elapsed:?} ({:.0} frames/s)",
        FORWARD_FRAMES as f64 / quic_elapsed.as_secs_f64()
    );

    let _ = std::fs::remove_dir_all(&h.dir);
}

async fn tcp_forward_bench(h: &Harness, alice: &Identity, bob: &Identity) -> Duration {
    async fn connect_and_handshake(
        h: &Harness,
        node: &Identity,
    ) -> (
        tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        Vec<u8>,
    ) {
        let mut roots = rustls::RootCertStore::empty();
        let ca: rustls_pki_types::CertificateDer<'static> =
            rustls_pki_types::pem::PemObject::from_pem_file(&h.ca_path).expect("ca");
        roots.add(ca).expect("trust");
        let provider = tls::provider().expect("provider");
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls13")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
        let tcp = tokio::net::TcpStream::connect(h.addr).await.expect("tcp");
        let name = rustls::pki_types::ServerName::try_from("relay.bench").expect("name");
        let mut tls = connector.connect(name, tcp).await.expect("tls");
        tls.write_all(
            b"GET /ponor HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: ponor\r\nPonor-Version: 1\r\n\r\n",
        )
        .await
        .expect("upgrade");
        let mut buf = Vec::new();
        let head = loop {
            let mut chunk = [0u8; 512];
            let n = tls.read(&mut chunk).await.expect("read");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        buf.drain(..head);
        let mut client = ClientHandshake::new(
            Role::Client,
            nid(node),
            h.relay.relay_id(),
            h.relay.public_key().to_vec(),
            rand_nonce(),
        );
        let hello = next_frame(&mut tls, &mut buf).await;
        let (hello, _) = decode(&hello).expect("decodes").expect("complete");
        let auth = client.on_relay_hello(&hello, node).expect("sign");
        tls.write_all(&auth).await.expect("write");
        let reply = next_frame(&mut tls, &mut buf).await;
        let (reply, _) = decode(&reply).expect("decodes").expect("complete");
        client
            .on_relay_auth(&reply, &PonorVerifier)
            .expect("verify");
        (tls, buf)
    }

    let (mut a, _) = connect_and_handshake(h, alice).await;
    let (mut b, mut b_buf) = connect_and_handshake(h, bob).await;

    let start = Instant::now();
    for _ in 0..FORWARD_FRAMES {
        a.write_all(
            &Frame::SendPacket {
                dst_id: nid(bob),
                payload: &PAYLOAD,
            }
            .to_vec(),
        )
        .await
        .expect("send");
        let got = next_frame(&mut b, &mut b_buf).await;
        let (frame, _) = decode(&got).expect("decodes").expect("complete");
        assert!(matches!(frame, Frame::RecvPacket { .. }));
    }
    start.elapsed()
}

async fn quic_next_frame(stream: &mut karst_relay::quic::BiStream, buf: &mut Vec<u8>) -> Vec<u8> {
    loop {
        if let Some((_, used)) = decode(buf).expect("decodes") {
            return buf.drain(..used).collect();
        }
        let mut chunk = [0u8; 2048];
        let n = stream.read(&mut chunk).await.expect("read");
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn quic_forward_bench(
    h: &Harness,
    alice: &Identity,
    bob: &Identity,
    quic_cfg: &quinn::ClientConfig,
) -> Duration {
    async fn connect_and_handshake(
        h: &Harness,
        node: &Identity,
        quic_cfg: &quinn::ClientConfig,
    ) -> (karst_relay::quic::BiStream, Vec<u8>) {
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("client");
        endpoint.set_default_client_config(quic_cfg.clone());
        let connection = endpoint
            .connect(h.quic_addr, "relay.bench")
            .expect("connect")
            .await
            .expect("handshake");
        let (send, recv) = connection.accept_bi().await.expect("accept_bi");
        let mut stream = tokio::io::join(recv, send);
        let mut client = ClientHandshake::new(
            Role::Client,
            nid(node),
            h.relay.relay_id(),
            h.relay.public_key().to_vec(),
            rand_nonce(),
        );
        let mut buf = Vec::new();
        let hello = quic_next_frame(&mut stream, &mut buf).await;
        let (hello, _) = decode(&hello).expect("decodes").expect("complete");
        let auth = client.on_relay_hello(&hello, node).expect("sign");
        stream.write_all(&auth).await.expect("write");
        let reply = quic_next_frame(&mut stream, &mut buf).await;
        let (reply, _) = decode(&reply).expect("decodes").expect("complete");
        client
            .on_relay_auth(&reply, &PonorVerifier)
            .expect("verify");
        (stream, buf)
    }

    let (mut a, _) = connect_and_handshake(h, alice, quic_cfg).await;
    let (mut b, mut b_buf) = connect_and_handshake(h, bob, quic_cfg).await;

    let start = Instant::now();
    for _ in 0..FORWARD_FRAMES {
        a.write_all(
            &Frame::SendPacket {
                dst_id: nid(bob),
                payload: &PAYLOAD,
            }
            .to_vec(),
        )
        .await
        .expect("send");
        let got = quic_next_frame(&mut b, &mut b_buf).await;
        let (frame, _) = decode(&got).expect("decodes").expect("complete");
        assert!(matches!(frame, Frame::RecvPacket { .. }));
    }
    start.elapsed()
}
