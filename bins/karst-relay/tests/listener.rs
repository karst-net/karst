// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The relay over a real socket: TLS, the HTTP upgrade, the Ponor handshake
//! and a forwarded packet.
//!
//! `end_to_end.rs` drives the same components with the sockets removed. This
//! file exists because the things that go wrong *at* the socket are a
//! different set: bytes that arrive split across reads, frames that arrive
//! coalesced with the HTTP head, a 101 written before the peer is listening
//! for one. None of those are visible without a socket.
//!
//! It also asserts the property spec §4.1 makes a MUST and that nothing else
//! can check: that the connection actually negotiated `X25519MLKEM768`.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use base64ct::{Base64, Encoding as _};
use karst_relay::config::Config;
use karst_relay::roster::FileRoster;
use karst_relay::server::{serve_on, Ctx};
use karst_relay::sign::{node_id, Identity, PonorVerifier, SEED_LEN};
use karst_relay::tls;
use karst_relay_proto::consts::ID_LEN;
use karst_relay_proto::{frame::decode, ClientHandshake, Frame, Role};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;

const UPGRADE: &str = "GET /ponor HTTP/1.1\r\n\
     Host: relay.test\r\n\
     Connection: Upgrade\r\n\
     Upgrade: ponor\r\n\
     Ponor-Version: 1\r\n\r\n";

struct Harness {
    addr: std::net::SocketAddr,
    ca: rustls::pki_types::CertificateDer<'static>,
    relay: Arc<Identity>,
    _dir: TempDir,
}

/// A temporary directory that removes itself.
struct TempDir(std::path::PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(tag: &str) -> TempDir {
    let p = std::env::temp_dir().join(format!(
        "karst-relay-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("mkdir");
    TempDir(p)
}

/// Start a relay on an ephemeral port with the given nodes admitted.
async fn start(tag: &str, nodes: &[(&Identity, &str)]) -> Harness {
    let dir = temp_dir(tag);

    // A self-signed certificate. §4.2 is the reason this is fine: relay
    // identity is an ML-DSA-65 signature over a registry key, and the
    // certificate is only what makes the connection behave like HTTPS.
    let cert = rcgen::generate_simple_self_signed(vec!["relay.test".to_owned()])
        .expect("self-signed certificate");
    let cert_path = dir.0.join("relay.crt");
    let key_path = dir.0.join("relay.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).expect("write key");

    let mut roster_text = String::new();
    for (id, aquifer) in nodes {
        use std::fmt::Write as _;
        let _ = write!(
            roster_text,
            "[[client]]\nidentity_pk = \"{}\"\naquifer = \"{aquifer}\"\n\n",
            Base64::encode_string(id.public_key())
        );
    }
    let roster_path = dir.0.join("roster.toml");
    std::fs::write(&roster_path, roster_text).expect("write roster");

    let cfg = Config::parse(&format!(
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
    .expect("config parses");
    cfg.validate().expect("config is valid");

    let identity = Arc::new(Identity::load_or_create(&cfg.identity_key).expect("identity"));
    let roster = Arc::new(FileRoster::load(&cfg.roster).expect("roster"));
    let tls_config = tls::server_config(&cfg.tls_cert, &cfg.tls_key).expect("tls");

    let listener = TcpListener::bind(cfg.listen).await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let ctx = Ctx::new(&cfg, Arc::clone(&identity), roster, tls_config);

    tokio::spawn(async move {
        let _ = serve_on(listener, ctx).await;
    });

    Harness {
        addr,
        ca: cert.cert.der().clone(),
        relay: identity,
        _dir: dir,
    }
}

/// A client connection, past TLS and past the HTTP upgrade.
struct Conn {
    tls: TlsStream<TcpStream>,
    buf: Vec<u8>,
}

impl Conn {
    async fn read_more(&mut self) {
        let mut chunk = [0u8; 4096];
        let n = self
            .tls
            .read(&mut chunk)
            .await
            .expect("read from the relay");
        assert_ne!(n, 0, "the relay closed the connection");
        self.buf.extend_from_slice(&chunk[..n]);
    }

    /// Read one whole frame, however it happens to be segmented.
    async fn frame(&mut self) -> Vec<u8> {
        loop {
            if let Some((_, used)) = decode(&self.buf).expect("decodable") {
                return self.buf.drain(..used).collect();
            }
            self.read_more().await;
        }
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.tls.write_all(bytes).await.expect("write");
    }
}

/// TLS-connect, upgrade, and return the connection with the negotiated group.
async fn connect(h: &Harness) -> (Conn, Option<rustls::NamedGroup>) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(h.ca.clone()).expect("trust the test CA");

    let provider = tls::provider().expect("provider");
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .with_root_certificates(roots)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(h.addr).await.expect("connect");
    let name = rustls::pki_types::ServerName::try_from("relay.test").expect("name");
    let mut tls = connector.connect(name, tcp).await.expect("tls handshake");

    let group = tls
        .get_ref()
        .1
        .negotiated_key_exchange_group()
        .map(rustls::crypto::SupportedKxGroup::name);

    tls.write_all(UPGRADE.as_bytes()).await.expect("upgrade");

    // Read exactly the 101 and no more, so any Ponor bytes that arrived with
    // it stay in the buffer where the frame reader will find them.
    let mut buf = Vec::new();
    let head = loop {
        let mut chunk = [0u8; 512];
        let n = tls.read(&mut chunk).await.expect("read 101");
        assert_ne!(n, 0, "relay closed before answering the upgrade");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let status = String::from_utf8_lossy(&buf[..head]).to_string();
    assert!(status.starts_with("HTTP/1.1 101 "), "{status}");
    buf.drain(..head);

    (Conn { tls, buf }, group)
}

/// Complete the Ponor handshake as `node`.
async fn handshake(h: &Harness, conn: &mut Conn, node: &Identity) {
    let mut client = ClientHandshake::new(
        Role::Client,
        node_id(node.public_key()),
        h.relay.relay_id(),
        h.relay.public_key().to_vec(),
        [0x5a; 32],
    );

    let hello_bytes = conn.frame().await;
    let (hello, _) = decode(&hello_bytes).expect("decodes").expect("complete");
    let auth = client
        .on_relay_hello(&hello, node)
        .expect("client signs the hello");
    conn.send(&auth).await;

    let reply_bytes = conn.frame().await;
    let (reply, _) = decode(&reply_bytes).expect("decodes").expect("complete");
    client
        .on_relay_auth(&reply, &PonorVerifier)
        .expect("relay authenticates");
    assert!(client.may_send(), "handshake did not establish");
}

fn identity(seed: u8) -> Identity {
    Identity::from_seed(&[seed; SEED_LEN])
}

fn nid(id: &Identity) -> [u8; ID_LEN] {
    node_id(id.public_key())
}

#[tokio::test]
async fn a_packet_crosses_the_relay_over_a_real_socket() {
    let alice = identity(0x21);
    let bob = identity(0x22);
    let h = start("fwd", &[(&alice, "acme"), (&bob, "acme")]).await;

    let (mut a, group) = connect(&h).await;
    // §4.1's MUST, observed on the connection rather than in the
    // configuration. This is the only place it can be checked.
    assert_eq!(
        group,
        Some(rustls::NamedGroup::X25519MLKEM768),
        "the relay negotiated a classical key exchange"
    );
    handshake(&h, &mut a, &alice).await;

    let (mut b, _) = connect(&h).await;
    handshake(&h, &mut b, &bob).await;

    let payload = [0xcd; 1336];
    a.send(
        &Frame::SendPacket {
            dst_id: nid(&bob),
            payload: &payload,
        }
        .to_vec(),
    )
    .await;

    let got = b.frame().await;
    let (frame, _) = decode(&got).expect("decodes").expect("complete");
    assert_eq!(
        frame,
        Frame::RecvPacket {
            src_id: nid(&alice),
            payload: &payload,
        }
    );
}

#[tokio::test]
async fn a_ping_is_answered() {
    let alice = identity(0x21);
    let h = start("ping", &[(&alice, "acme")]).await;
    let (mut a, _) = connect(&h).await;
    handshake(&h, &mut a, &alice).await;

    let token = [1, 2, 3, 4, 5, 6, 7, 8];
    a.send(&Frame::Ping(&token).to_vec()).await;
    let got = a.frame().await;
    let (frame, _) = decode(&got).expect("decodes").expect("complete");
    assert_eq!(frame, Frame::Pong(&token));
}

#[tokio::test]
async fn an_offline_peer_produces_peer_gone() {
    let alice = identity(0x21);
    let bob = identity(0x22);
    // Bob is rostered but never connects.
    let h = start("gone", &[(&alice, "acme"), (&bob, "acme")]).await;
    let (mut a, _) = connect(&h).await;
    handshake(&h, &mut a, &alice).await;

    let payload = [1u8; 32];
    a.send(
        &Frame::SendPacket {
            dst_id: nid(&bob),
            payload: &payload,
        }
        .to_vec(),
    )
    .await;

    let got = a.frame().await;
    let (frame, _) = decode(&got).expect("decodes").expect("complete");
    assert_eq!(
        frame,
        Frame::PeerGone {
            peer_id: nid(&bob),
            reason: karst_relay_proto::Reason::NotHere,
        }
    );
}

#[tokio::test]
async fn an_unrostered_node_is_closed_without_a_reason() {
    // §10: uniform rejection. The relay closes; it does not send a Close
    // frame, and it does not say whether the id was unknown or the signature
    // wrong, because either answer is a membership oracle.
    let alice = identity(0x21);
    let stranger = identity(0x99);
    let h = start("stranger", &[(&alice, "acme")]).await;

    let (mut c, _) = connect(&h).await;
    let mut client = ClientHandshake::new(
        Role::Client,
        nid(&stranger),
        h.relay.relay_id(),
        h.relay.public_key().to_vec(),
        [7; 32],
    );
    let hello_bytes = c.frame().await;
    let (hello, _) = decode(&hello_bytes).expect("decodes").expect("complete");
    let auth = client.on_relay_hello(&hello, &stranger).expect("signs");
    c.send(&auth).await;

    // The relay closes. Nothing is written first.
    let mut chunk = [0u8; 256];
    let n = c.tls.read(&mut chunk).await.unwrap_or(0);
    assert_eq!(n, 0, "the relay said something: {:?}", &chunk[..n]);
}

#[tokio::test]
async fn a_plain_get_is_refused_without_becoming_a_ponor_connection() {
    // A health checker or a scanner hitting the path must get an HTTP answer,
    // not a binary protocol.
    let alice = identity(0x21);
    let h = start("plain", &[(&alice, "acme")]).await;

    let mut roots = rustls::RootCertStore::empty();
    roots.add(h.ca.clone()).expect("trust");
    let provider = tls::provider().expect("provider");
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(h.addr).await.expect("connect");
    let name = rustls::pki_types::ServerName::try_from("relay.test").expect("name");
    let mut tls = connector.connect(name, tcp).await.expect("tls");

    tls.write_all(b"GET /ponor HTTP/1.1\r\nHost: relay.test\r\n\r\n")
        .await
        .expect("write");
    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp).await;
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 400 "), "{text}");
}

#[tokio::test]
async fn a_request_for_another_path_is_a_404() {
    let alice = identity(0x21);
    let h = start("path", &[(&alice, "acme")]).await;

    let mut roots = rustls::RootCertStore::empty();
    roots.add(h.ca.clone()).expect("trust");
    let provider = tls::provider().expect("provider");
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(h.addr).await.expect("connect");
    let name = rustls::pki_types::ServerName::try_from("relay.test").expect("name");
    let mut tls = connector.connect(name, tcp).await.expect("tls");

    tls.write_all(b"GET /metrics HTTP/1.1\r\nHost: relay.test\r\nConnection: Upgrade\r\nUpgrade: ponor\r\n\r\n")
        .await
        .expect("write");
    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp).await;
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 404 "), "{text}");
}

#[tokio::test]
async fn a_reconnecting_node_replaces_its_old_connection() {
    // §7.6, over real sockets: the old connection is closed and the new one
    // receives the traffic. Refusing the new one instead would black-hole a
    // node whose old TCP connection is a half-open zombie.
    let alice = identity(0x21);
    let bob = identity(0x22);
    let h = start("replace", &[(&alice, "acme"), (&bob, "acme")]).await;

    let (mut a1, _) = connect(&h).await;
    handshake(&h, &mut a1, &alice).await;

    let (mut a2, _) = connect(&h).await;
    handshake(&h, &mut a2, &alice).await;

    // The first connection is told why and then closed.
    let closed = a1.frame().await;
    let (frame, _) = decode(&closed).expect("decodes").expect("complete");
    assert_eq!(
        frame,
        Frame::Close(karst_relay_proto::Reason::Replaced),
        "the replaced connection was not told"
    );

    // Traffic for Alice now reaches the second connection.
    let (mut b, _) = connect(&h).await;
    handshake(&h, &mut b, &bob).await;
    let payload = [9u8; 16];
    b.send(
        &Frame::SendPacket {
            dst_id: nid(&alice),
            payload: &payload,
        }
        .to_vec(),
    )
    .await;

    let got = a2.frame().await;
    let (frame, _) = decode(&got).expect("decodes").expect("complete");
    assert_eq!(
        frame,
        Frame::RecvPacket {
            src_id: nid(&bob),
            payload: &payload,
        }
    );
}

#[tokio::test]
async fn a_frame_split_across_reads_is_reassembled() {
    // The failure a socket-free test cannot see: TCP is a byte stream and a
    // 1372-byte frame does not arrive atomically just because it was written
    // that way.
    let alice = identity(0x21);
    let bob = identity(0x22);
    let h = start("split", &[(&alice, "acme"), (&bob, "acme")]).await;

    let (mut a, _) = connect(&h).await;
    handshake(&h, &mut a, &alice).await;
    let (mut b, _) = connect(&h).await;
    handshake(&h, &mut b, &bob).await;

    let payload = [0x77; 1336];
    let bytes = Frame::SendPacket {
        dst_id: nid(&bob),
        payload: &payload,
    }
    .to_vec();

    // One byte, a pause, then the rest.
    a.send(&bytes[..1]).await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    a.send(&bytes[1..7]).await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    a.send(&bytes[7..]).await;

    let got = b.frame().await;
    let (frame, _) = decode(&got).expect("decodes").expect("complete");
    assert_eq!(
        frame,
        Frame::RecvPacket {
            src_id: nid(&alice),
            payload: &payload,
        }
    );
}

#[tokio::test]
async fn two_frames_in_one_write_are_both_delivered() {
    let alice = identity(0x21);
    let bob = identity(0x22);
    let h = start("coalesced", &[(&alice, "acme"), (&bob, "acme")]).await;

    let (mut a, _) = connect(&h).await;
    handshake(&h, &mut a, &alice).await;
    let (mut b, _) = connect(&h).await;
    handshake(&h, &mut b, &bob).await;

    let mut both = Vec::new();
    for n in 0u8..2 {
        let payload = [n; 64];
        both.extend_from_slice(
            &Frame::SendPacket {
                dst_id: nid(&bob),
                payload: &payload,
            }
            .to_vec(),
        );
    }
    a.send(&both).await;

    for n in 0u8..2 {
        let got = b.frame().await;
        let (frame, _) = decode(&got).expect("decodes").expect("complete");
        match frame {
            Frame::RecvPacket { payload, .. } => assert_eq!(payload, &[n; 64]),
            other => panic!("expected RecvPacket, got {other:?}"),
        }
    }
}
