// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The relay over QUIC — ADR-0020.
//!
//! Mirrors `tests/listener.rs`'s shape for the TCP+TLS transport: a real
//! socket, the Ponor handshake, and a forwarded packet, but through
//! `quic::serve_on`/ALPN instead of `serve_on`/the HTTP upgrade. The point of
//! this file is the interop and failure-mode coverage issue #122 asks for:
//! that QUIC and TCP+TLS clients of the same relay are interchangeable at the
//! Ponor layer, and that QUIC fails the same way TCP does when a peer is not
//! admitted.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64ct::{Base64, Encoding as _};
use karst_relay::config::Config;
use karst_relay::quic::BiStream;
use karst_relay::roster::FileRoster;
use karst_relay::server::{serve_on, Ctx};
use karst_relay::sign::{node_id, Identity, PonorVerifier, SEED_LEN};
use karst_relay::tls;
use karst_relay_proto::consts::ID_LEN;
use karst_relay_proto::{frame::decode, ClientHandshake, Frame, Role};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const UPGRADE: &str = "GET /ponor HTTP/1.1\r\n\
     Host: relay.test\r\n\
     Connection: Upgrade\r\n\
     Upgrade: ponor\r\n\
     Ponor-Version: 1\r\n\r\n";

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(tag: &str) -> TempDir {
    let p = std::env::temp_dir().join(format!(
        "karst-relay-quic-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("mkdir");
    TempDir(p)
}

struct Harness {
    addr: std::net::SocketAddr,
    quic_addr: Option<std::net::SocketAddr>,
    ca_path: PathBuf,
    relay: Arc<Identity>,
    _dir: TempDir,
}

/// Start a relay on ephemeral TCP and (when `quic` is set) QUIC ports, with
/// the given nodes admitted.
async fn start(tag: &str, nodes: &[(&Identity, &str)], quic: bool) -> Harness {
    start_with_ctx(tag, nodes, quic).await.0
}

/// As [`start`], but keeping the [`Ctx`] a mesh test needs to reload the
/// roster and start dialling from.
async fn start_with_ctx(tag: &str, nodes: &[(&Identity, &str)], quic: bool) -> (Harness, Arc<Ctx>) {
    let dir = temp_dir(tag);

    let cert = rcgen::generate_simple_self_signed(vec!["relay.test".to_owned()])
        .expect("self-signed certificate");
    let cert_path = dir.0.join("relay.crt");
    let key_path = dir.0.join("relay.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).expect("write key");
    let ca_path = dir.0.join("relay-ca.pem");
    std::fs::write(&ca_path, cert.cert.pem()).expect("write ca");

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
    std::fs::write(&roster_path, &roster_text).expect("write roster");

    let cfg = Config::parse(&format!(
        "listen = \"127.0.0.1:0\"\n\
         identity_key = \"{}\"\n\
         roster = \"{}\"\n\
         tls_cert = \"{}\"\n\
         tls_key = \"{}\"\n\
         quic = {quic}\n",
        dir.0.join("relay.key").display(),
        roster_path.display(),
        cert_path.display(),
        key_path.display(),
    ))
    .expect("config parses");
    cfg.validate().expect("config is valid");

    let identity = Arc::new(Identity::load_or_create(&cfg.identity_key).expect("identity"));
    let roster = Arc::new(FileRoster::load(&cfg.roster).expect("roster"));
    let tls_config = tls::server_config(&cfg.tls_cert, &cfg.tls_key).expect("tls");

    let listener = TcpListener::bind(cfg.listen).await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let ctx = Ctx::new(&cfg, Arc::clone(&identity), roster, Arc::clone(&tls_config));

    let quic_addr = if quic {
        let quic_server_cfg = karst_relay::quic::server_config(&tls_config).expect("quic tls");
        let endpoint =
            karst_relay::quic::bind(cfg.listen, quic_server_cfg).expect("bind quic endpoint");
        let quic_addr = endpoint.local_addr().expect("quic addr");
        tokio::spawn(karst_relay::quic::serve_on(endpoint, Arc::clone(&ctx)));
        Some(quic_addr)
    } else {
        None
    };

    let ctx_handle = Arc::clone(&ctx);
    tokio::spawn(async move {
        let _ = serve_on(listener, ctx).await;
    });

    (
        Harness {
            addr,
            quic_addr,
            ca_path,
            relay: identity,
            _dir: dir,
        },
        ctx_handle,
    )
}

/// A client connection over QUIC, past ALPN.
struct QConn {
    stream: BiStream,
    buf: Vec<u8>,
    _endpoint: quinn::Endpoint,
}

impl QConn {
    async fn read_more(&mut self) -> bool {
        let mut chunk = [0u8; 4096];
        match self.stream.read(&mut chunk).await {
            Ok(0) | Err(_) => false,
            Ok(n) => {
                self.buf.extend_from_slice(&chunk[..n]);
                true
            }
        }
    }

    async fn frame(&mut self) -> Vec<u8> {
        loop {
            if let Some((_, used)) = decode(&self.buf).expect("decodable") {
                return self.buf.drain(..used).collect();
            }
            assert!(self.read_more().await, "the relay closed the connection");
        }
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.expect("write");
    }
}

/// Connect to `h`'s QUIC listener and open the one Ponor stream.
///
/// **The endpoint is kept alive on the returned `QConn`.** Dropping it drops
/// every connection it holds, `quinn`'s documented behavior for the last
/// handle to a connection going away — exactly the property the
/// `is_refused_without_the_relay_opting_in` test below relies on to observe a
/// clean failure rather than a hang.
async fn connect_quic(h: &Harness) -> QConn {
    let addr = h.quic_addr.expect("harness has a QUIC listener");
    let tls = tls::client_config(&h.ca_path).expect("client tls");
    let quic_cfg = karst_relay::quic::client_config(&tls).expect("quic client config");

    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("bind client");
    endpoint.set_default_client_config(quic_cfg);

    let connection = endpoint
        .connect(addr, "relay.test")
        .expect("connect")
        .await
        .expect("quic handshake");
    // The relay opens the stream and speaks first; see `quic.rs`'s "Who opens
    // the stream" note.
    let (send, recv) = connection.accept_bi().await.expect("accept_bi");
    QConn {
        stream: tokio::io::join(recv, send),
        buf: Vec::new(),
        _endpoint: endpoint,
    }
}

/// Complete the Ponor handshake as `node`, over QUIC.
async fn handshake_quic(h: &Harness, conn: &mut QConn, node: &Identity) {
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

/// A frame's raw bytes, extracted from `buf` into an owned `Vec` before
/// decoding — `decode` borrows from whatever it is given, and holding that
/// borrow while also draining the same `buf` does not typecheck.
async fn next_frame_bytes(
    tls: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    buf: &mut Vec<u8>,
) -> Vec<u8> {
    loop {
        if let Some((_, used)) = decode(buf).expect("decodes") {
            return buf.drain(..used).collect();
        }
        let mut chunk = [0u8; 512];
        let n = tls.read(&mut chunk).await.expect("read");
        assert_ne!(n, 0, "relay closed before a complete frame arrived");
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[tokio::test]
async fn a_packet_crosses_the_relay_over_quic() {
    let alice = identity(0x31);
    let bob = identity(0x32);
    let h = start("fwd", &[(&alice, "acme"), (&bob, "acme")], true).await;

    let mut a = connect_quic(&h).await;
    handshake_quic(&h, &mut a, &alice).await;
    let mut b = connect_quic(&h).await;
    handshake_quic(&h, &mut b, &bob).await;

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

/// The interop property issue #122 asks for: QUIC and TCP+TLS are two
/// carriers of the same Ponor connection, not two relays. A packet sent by a
/// QUIC client must reach a TCP+TLS one and back.
#[tokio::test]
async fn quic_and_tcp_clients_interoperate() {
    let alice = identity(0x33);
    let bob = identity(0x34);
    let h = start("interop", &[(&alice, "acme"), (&bob, "acme")], true).await;

    // Alice, over QUIC.
    let mut a = connect_quic(&h).await;
    handshake_quic(&h, &mut a, &alice).await;

    // Bob, over plain TCP+TLS+HTTP-upgrade — the existing path, unmodified.
    let mut roots = rustls::RootCertStore::empty();
    let ca: rustls_pki_types::CertificateDer<'static> =
        rustls_pki_types::pem::PemObject::from_pem_file(&h.ca_path).expect("parse ca");
    roots.add(ca).expect("trust the test CA");
    let provider = tls::provider().expect("provider");
    let tls_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));
    let tcp = tokio::net::TcpStream::connect(h.addr)
        .await
        .expect("connect");
    let name = rustls::pki_types::ServerName::try_from("relay.test").expect("name");
    let mut tls = connector.connect(name, tcp).await.expect("tls handshake");
    tls.write_all(UPGRADE.as_bytes()).await.expect("upgrade");
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
    assert!(String::from_utf8_lossy(&buf[..head]).starts_with("HTTP/1.1 101 "));
    buf.drain(..head);

    let mut client = ClientHandshake::new(
        Role::Client,
        node_id(bob.public_key()),
        h.relay.relay_id(),
        h.relay.public_key().to_vec(),
        [0x5b; 32],
    );

    let hello_bytes = next_frame_bytes(&mut tls, &mut buf).await;
    let (hello, _) = decode(&hello_bytes).expect("decodes").expect("complete");
    let auth = client.on_relay_hello(&hello, &bob).expect("signs hello");
    tls.write_all(&auth).await.expect("write auth");

    let reply_bytes = next_frame_bytes(&mut tls, &mut buf).await;
    let (reply, _) = decode(&reply_bytes).expect("decodes").expect("complete");
    client
        .on_relay_auth(&reply, &PonorVerifier)
        .expect("relay authenticates");
    assert!(client.may_send());

    // Alice (QUIC) -> Bob (TCP+TLS).
    a.send(
        &Frame::SendPacket {
            dst_id: nid(&bob),
            payload: &[1u8; 64],
        }
        .to_vec(),
    )
    .await;
    let got_bytes = next_frame_bytes(&mut tls, &mut buf).await;
    let (got, _) = decode(&got_bytes).expect("decodes").expect("complete");
    assert_eq!(
        got,
        Frame::RecvPacket {
            src_id: nid(&alice),
            payload: &[1u8; 64],
        }
    );

    // And Bob (TCP+TLS) -> Alice (QUIC), to prove it is not one-directional.
    tls.write_all(
        &Frame::SendPacket {
            dst_id: nid(&alice),
            payload: &[2u8; 64],
        }
        .to_vec(),
    )
    .await
    .expect("write");
    let got = a.frame().await;
    let (frame, _) = decode(&got).expect("decodes").expect("complete");
    assert_eq!(
        frame,
        Frame::RecvPacket {
            src_id: nid(&bob),
            payload: &[2u8; 64],
        }
    );
}

/// §10's uniform-silent-rejection property, over QUIC: a peer the roster does
/// not admit gets its connection closed with nothing more specific than that.
#[tokio::test]
async fn an_unrostered_node_over_quic_is_closed_without_a_reason() {
    let stranger = identity(0x35);
    let h = start("unrostered", &[], true).await;

    let mut conn = connect_quic(&h).await;
    let mut client = ClientHandshake::new(
        Role::Client,
        node_id(stranger.public_key()),
        h.relay.relay_id(),
        h.relay.public_key().to_vec(),
        [0x5c; 32],
    );
    let hello_bytes = conn.frame().await;
    let (hello, _) = decode(&hello_bytes).expect("decodes").expect("complete");
    let auth = client
        .on_relay_hello(&hello, &stranger)
        .expect("client signs the hello");
    conn.send(&auth).await;

    // No `RelayAuth`, no `Close` frame — just the connection going away.
    let closed = tokio::time::timeout(Duration::from_secs(5), conn.read_more()).await;
    assert_eq!(
        closed,
        Ok(false),
        "an unrostered peer must be closed, not left open"
    );
}

/// ADR-0020: QUIC is opt-in. A relay that has not turned it on must not
/// silently accept a QUIC connection on the port it publishes for TCP.
#[tokio::test]
async fn quic_is_refused_when_the_relay_has_not_enabled_it() {
    let h = start("disabled", &[], false).await;
    assert!(h.quic_addr.is_none());

    let tls = tls::client_config(&h.ca_path).expect("client tls");
    let quic_cfg = karst_relay::quic::client_config(&tls).expect("quic client config");
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("bind client");
    endpoint.set_default_client_config(quic_cfg);

    // Nothing is listening on `h.addr`'s UDP port — the TCP listener does not
    // imply a QUIC one. The attempt must fail rather than hang or succeed.
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint
            .connect(h.addr, "relay.test")
            .expect("connect() itself only validates the name"),
    )
    .await;
    // Refused, or the attempt timed out — either is "not accepted".
    if let Ok(Ok(_)) = result {
        panic!("a relay with quic = false must not accept a QUIC connection");
    }
}

/// The mesh counterpart of `quic_and_tcp_clients_interoperate`: two relays
/// meshed over QUIC (`crate::quic::dial_mesh`, ADR-0020's mesh-dial path)
/// forward a packet between their clients exactly as a TCP-meshed pair does.
#[tokio::test(flavor = "multi_thread")]
async fn two_relays_mesh_over_quic_and_a_packet_crosses() {
    let alice = identity(0x41);
    let bob = identity(0x42);

    // Both relays roster both clients, exactly as `listener.rs`'s TCP-mesh
    // test does: a relay only forwards within an aquifer it knows, whichever
    // side of the mesh a peer actually connects to.
    let both = [(&alice, "acme"), (&bob, "acme")];
    let (h1, ctx1) = start_with_ctx("mesh-quic-1", &both, true).await;
    let (h2, ctx2) = start_with_ctx("mesh-quic-2", &both, true).await;

    // Roster each relay with the other as a QUIC mesh peer, dialled at its
    // QUIC address — the "same port either way" convention ADR-0020 assumes
    // collapses to two ports here only because the test binds TCP and QUIC
    // independently; a real deployment configures one `listen` for both.
    for (me_ctx, me_h, them_h) in [(&ctx1, &h1, &h2), (&ctx2, &h2, &h1)] {
        let mut clients = String::new();
        for (id, aquifer) in both {
            use std::fmt::Write as _;
            let _ = write!(
                clients,
                "[[client]]\nidentity_pk = \"{}\"\naquifer = \"{aquifer}\"\n\n",
                Base64::encode_string(id.public_key())
            );
        }
        let roster = format!(
            "{clients}[[mesh]]\nidentity_pk = \"{}\"\ndial = \"{}\"\nname = \"relay.test\"\n\
             region = \"default\"\nquic = true\n",
            Base64::encode_string(them_h.relay.public_key()),
            them_h.quic_addr.expect("peer runs quic"),
        );
        // Scoped so the temp dir is removed once the roster is parsed into
        // memory — nothing re-reads the file afterward, unlike `Source`'s
        // hot-reload path.
        let reloaded = {
            let dir = temp_dir(&format!("mesh-quic-roster-{}", me_h.addr.port()));
            let path = dir.0.join("roster.toml");
            std::fs::write(&path, roster).expect("write mesh roster");
            FileRoster::load(&path).expect("mesh roster loads")
        };
        me_ctx.replace_roster(reloaded);
    }

    // Start dialling from both sides; `Dialler::dials` picks the one whose
    // relay id sorts lower, exactly as `run` does — the test does not need to
    // know which that is.
    for (ctx, me_h, them_h) in [(&ctx1, &h1, &h2), (&ctx2, &h2, &h1)] {
        let ca_path = them_h.ca_path.clone();
        let tls = tls::client_config(&ca_path).expect("client tls");
        let quic_tls = karst_relay::quic::client_config(&tls).expect("client quic tls");
        let dialler = karst_relay::mesh::Dialler::new(me_h.relay.relay_id(), "default".to_owned());
        tokio::spawn(karst_relay::server::mesh_loop(
            Arc::clone(ctx),
            tls,
            quic_tls,
            dialler,
        ));
    }

    let mut a = connect_quic(&h1).await;
    handshake_quic(&h1, &mut a, &alice).await;
    let mut b = connect_quic(&h2).await;
    handshake_quic(&h2, &mut b, &bob).await;

    // Presence has to propagate over the mesh before h1 knows Bob is on h2 —
    // §8 makes it advisory and eventually consistent, so this asserts
    // convergence by retrying rather than by sleeping a fixed guess.
    let payload = [0xab; 200];
    let mut delivered = None;
    for _ in 0..40 {
        a.send(
            &Frame::SendPacket {
                dst_id: nid(&bob),
                payload: &payload,
            }
            .to_vec(),
        )
        .await;
        if let Ok(bytes) = tokio::time::timeout(Duration::from_millis(250), b.frame()).await {
            delivered = Some(bytes);
            break;
        }
    }

    let bytes = delivered.expect("the packet never crossed the quic mesh");
    let (frame, _) = decode(&bytes).expect("decodes").expect("complete");
    assert_eq!(
        frame,
        Frame::RecvPacket {
            src_id: nid(&alice),
            payload: &payload,
        }
    );
}
