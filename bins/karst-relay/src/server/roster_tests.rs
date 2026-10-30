// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Exercise the production roster watcher and admission boundary over real TLS
//! sockets. Only the private loop timing changes; no operator can shorten it.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use super::{roster_loop_with_timing, serve_until, Ctx};
use crate::{config::Config, roster::Source as RosterSource, sign::Identity};
use base64ct::{Base64, Encoding as _};
use karst_relay_proto::{frame::decode, ClientHandshake, Role};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::client::TlsStream;

struct TempDir(std::path::PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn frame(stream: &mut TlsStream<TcpStream>) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0];
        stream.read_exact(&mut byte).await.expect("read frame");
        bytes.extend_from_slice(&byte);
        if decode(&bytes).expect("valid frame").is_some() {
            return bytes;
        }
    }
}

async fn authenticate(
    address: SocketAddr,
    tls: Arc<rustls::ClientConfig>,
    relay: &Identity,
    node: &Identity,
    admitted: bool,
) -> TlsStream<TcpStream> {
    let tcp = TcpStream::connect(address).await.expect("connect");
    let mut stream = tokio_rustls::TlsConnector::from(tls)
        .connect("relay.test".try_into().expect("server name"), tcp)
        .await
        .expect("TLS");
    stream
        .write_all(b"GET /ponor HTTP/1.1\r\nHost: relay.test\r\nConnection: Upgrade\r\nUpgrade: ponor\r\nPonor-Version: 1\r\n\r\n")
        .await
        .expect("upgrade");
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).await.expect("HTTP response");
        head.extend_from_slice(&byte);
    }
    assert!(head.starts_with(b"HTTP/1.1 101 "));
    let mut client = ClientHandshake::new(
        Role::Client,
        crate::sign::node_id(node.public_key()),
        relay.relay_id(),
        relay.public_key().to_vec(),
        [7; 32],
    );
    let hello = frame(&mut stream).await;
    let (hello, _) = decode(&hello).unwrap().unwrap();
    let auth = client.on_relay_hello(&hello, node).expect("sign");
    stream.write_all(&auth).await.expect("authenticate");
    if admitted {
        let reply = frame(&mut stream).await;
        let (reply, _) = decode(&reply).unwrap().unwrap();
        client
            .on_relay_auth(&reply, &crate::sign::PonorVerifier)
            .expect("relay authenticates");
        assert!(client.may_send());
    } else {
        let mut byte = [0];
        assert_eq!(
            stream.read(&mut byte).await.unwrap_or(0),
            0,
            "silent denial"
        );
    }
    stream
}

async fn wait_for_membership(ctx: &Ctx, count: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while ctx.roster().client_count() != count {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("watcher updated admission");
}

#[tokio::test]
async fn roster_lease_expiry_refuses_admission_and_refresh_restores_it() {
    // GitHub issue #468: this exercise's own real work (a 3-second mandatory
    // lease wait, real TLS handshakes, 20ms-granularity file-watch polling)
    // left too little margin against ordinary CI scheduling contention under
    // the previous 20-second budget -- observed finishing at ~23.3-23.4s on
    // the runs that timed out, consistently just over, not wildly unbounded.
    // This is a safety-margin bump only: the lease duration and poll interval
    // this test actually verifies, below, are unchanged -- "no operator can
    // shorten it" still holds.
    tokio::time::timeout(Duration::from_secs(45), Box::pin(exercise_roster_lease()))
        .await
        .expect("lease regression completed");
}

async fn exercise_roster_lease() {
    let dir = TempDir(std::env::temp_dir().join(format!(
        "karst-lease-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    )));
    std::fs::create_dir_all(&dir.0).expect("temp directory");
    let cert = rcgen::generate_simple_self_signed(vec!["relay.test".to_owned()]).unwrap();
    let ca = dir.0.join("relay.crt");
    let key = dir.0.join("relay.pem");
    std::fs::write(&ca, cert.cert.pem()).unwrap();
    std::fs::write(&key, cert.signing_key.serialize_pem()).unwrap();
    let node = Identity::from_seed(&[0x21; crate::sign::SEED_LEN]);
    let path = dir.0.join("roster.toml");
    let roster = format!(
        "[[client]]\nidentity_pk = \"{}\"\naquifer = \"acme\"\n",
        Base64::encode_string(node.public_key())
    );
    std::fs::write(&path, &roster).unwrap();
    let cfg = Config::parse(&format!(
        "listen = \"127.0.0.1:0\"\nidentity_key = \"{}\"\nroster = \"{}\"\ntls_cert = \"{}\"\ntls_key = \"{}\"\n",
        dir.0.join("relay.key").display(), path.display(), ca.display(), key.display()
    )).unwrap();
    let relay = Arc::new(Identity::load_or_create(&cfg.identity_key).unwrap());
    let (source, first) = RosterSource::open(&path).unwrap();
    let ctx = Ctx::new(
        &cfg,
        Arc::clone(&relay),
        Arc::new(first),
        crate::tls::server_config(&ca, &key).unwrap(),
    );
    let listener = TcpListener::bind(cfg.listen).await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_until(
        listener,
        Arc::clone(&ctx),
        std::future::pending(),
    ));
    let watcher = tokio::spawn(roster_loop_with_timing(
        source,
        Arc::clone(&ctx),
        Duration::from_secs(3),
        Duration::from_millis(20),
    ));
    let client_tls = crate::tls::client_config(&ca).unwrap();
    let mut existing = authenticate(address, Arc::clone(&client_tls), &relay, &node, true).await;

    // Stop publishing: successful reads of an unchanged file must not
    // renew its lease. Expiry also revokes the already admitted socket.
    wait_for_membership(&ctx, 0).await;
    let closed = frame(&mut existing).await;
    assert_eq!(
        decode(&closed).unwrap().unwrap().0,
        karst_relay_proto::Frame::Close(karst_relay_proto::Reason::NotAdmitted)
    );
    let mut byte = [0];
    assert_eq!(existing.read(&mut byte).await.unwrap_or(0), 0);
    let _ = authenticate(address, Arc::clone(&client_tls), &relay, &node, false).await;

    // An invalid write is activity, but must not renew or reopen admission.
    std::fs::write(&path, "not valid TOML [").unwrap();
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(ctx.roster().client_count(), 0);
    let _ = authenticate(address, Arc::clone(&client_tls), &relay, &node, false).await;

    // Resume the writer with exactly the original membership. Atomic
    // replacement and a new mtime prove liveness without changing members.
    let replacement = dir.0.join("next.toml");
    std::fs::write(&replacement, &roster).unwrap();
    std::fs::File::open(&replacement)
        .unwrap()
        .set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::SystemTime::now() + Duration::from_secs(1)),
        )
        .unwrap();
    std::fs::rename(&replacement, &path).unwrap();
    wait_for_membership(&ctx, 1).await;
    let _ = authenticate(address, client_tls, &relay, &node, true).await;
    watcher.abort();
    server.abort();
}
