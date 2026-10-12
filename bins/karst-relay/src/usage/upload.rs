// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Best-effort, acknowledgment-gated upload of immutable usage spool batches.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use super::{spool::BatchId, SpoolCommand};
use crate::sign::{usage_upload_signing_input, Identity, USAGE_UPLOAD_PATH};

const RETRY_DELAY: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) async fn run(
    url: String,
    identity: Arc<Identity>,
    commands: tokio::sync::mpsc::Sender<SpoolCommand>,
    mut cancel: tokio::sync::watch::Receiver<bool>,
) {
    let Some((host, port)) = parse_origin(&url) else {
        eprintln!("karst-relay: usage upload: invalid HTTPS origin");
        return;
    };
    let tls = match crate::tls::webpki_client_config() {
        Ok(tls) => tls,
        Err(e) => {
            eprintln!("karst-relay: usage upload: {e}");
            return;
        }
    };
    loop {
        if *cancel.borrow() {
            return;
        }
        match pending(&commands).await {
            Ok(ids) => {
                for id in ids {
                    if *cancel.borrow() {
                        return;
                    }
                    if let Err(e) = upload_one(&host, port, &tls, &identity, &commands, id).await {
                        eprintln!("karst-relay: usage upload: {e}");
                        break;
                    }
                }
            }
            Err(e) => eprintln!("karst-relay: usage upload: spool: {e}"),
        }
        tokio::select! {
            () = tokio::time::sleep(RETRY_DELAY) => {},
            changed = cancel.changed() => if changed.is_err() || *cancel.borrow() { return; },
        }
    }
}

async fn pending(
    commands: &tokio::sync::mpsc::Sender<SpoolCommand>,
) -> std::io::Result<Vec<BatchId>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    commands
        .send(SpoolCommand::Pending(tx))
        .await
        .map_err(|_| closed())?;
    rx.await.map_err(|_| closed())?
}

async fn read(
    commands: &tokio::sync::mpsc::Sender<SpoolCommand>,
    id: BatchId,
) -> std::io::Result<Vec<u8>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    commands
        .send(SpoolCommand::Read(id, tx))
        .await
        .map_err(|_| closed())?;
    rx.await.map_err(|_| closed())?
}

async fn acknowledge(
    commands: &tokio::sync::mpsc::Sender<SpoolCommand>,
    id: BatchId,
    digest: [u8; 32],
) -> std::io::Result<()> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    commands
        .send(SpoolCommand::Ack(id, digest, tx))
        .await
        .map_err(|_| closed())?;
    rx.await.map_err(|_| closed())?
}

async fn upload_one(
    host: &str,
    port: u16,
    tls: &Arc<rustls::ClientConfig>,
    identity: &Identity,
    commands: &tokio::sync::mpsc::Sender<SpoolCommand>,
    id: BatchId,
) -> Result<(), String> {
    let body = read(commands, id).await.map_err(|e| e.to_string())?;
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        let stream = TcpStream::connect((host, port)).await.map_err(|e| format!("connect: {e}"))?;
        let server_name = rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|e| format!("server name: {e}"))?;
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(tls));
        let mut stream = connector.connect(server_name, stream).await.map_err(|e| format!("tls: {e}"))?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| format!("clock: {e}"))?.as_micros();
        let timestamp = u64::try_from(timestamp).map_err(|_| "clock exceeds supported range".to_owned())?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| "request nonce entropy unavailable".to_owned())?;
        let transcript = usage_upload_signing_input(timestamp, &nonce, &body);
        let signature = identity.sign_usage_upload(&transcript).map_err(|e| format!("sign: {e}"))?;
        let relay_id = Base64UrlUnpadded::encode_string(&identity.relay_id());
        let nonce_hex = nonce.iter().fold(String::with_capacity(64), |mut out, byte| { use std::fmt::Write as _; let _ = write!(out, "{byte:02x}"); out });
        let authorization = format!("KarstUsage {relay_id}.{timestamp}.{nonce_hex}.{}", Base64::encode_string(&signature));
        let authority_host = if host.contains(':') { format!("[{host}]") } else { host.to_owned() };
        let host_header = if port == 443 { authority_host } else { format!("{authority_host}:{port}") };
        let request = format!("POST {USAGE_UPLOAD_PATH} HTTP/1.1\r\nHost: {host_header}\r\nAuthorization: {authorization}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        stream.write_all(request.as_bytes()).await.map_err(|e| format!("write: {e}"))?;
        stream.write_all(&body).await.map_err(|e| format!("write body: {e}"))?;
        stream.flush().await.map_err(|e| format!("flush: {e}"))?;
        let mut response = tokio::io::BufReader::new(stream);
        let mut status = Vec::new();
        (&mut response).take(512).read_until(b'\n', &mut status).await.map_err(|e| format!("read status: {e}"))?;
        if !status.ends_with(b"\r\n") {
            return Err("server returned an invalid status line".to_owned());
        }
        let status = String::from_utf8_lossy(&status);
        if !durable_ack_status(&status) {
            return Err(format!("server did not durably acknowledge batch: {}", status.trim()));
        }
        Ok::<(), String>(())
    }).await.map_err(|_| "request timed out".to_owned())??;
    let digest: [u8; 32] = Sha256::digest(&body).into();
    acknowledge(commands, id, digest)
        .await
        .map_err(|e| format!("ack spool: {e}"))
}

fn parse_origin(url: &str) -> Option<(String, u16)> {
    crate::config::parse_https_origin(url).map(|(host, port)| (host.to_owned(), port))
}

fn closed() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "usage spool task stopped")
}

fn durable_ack_status(status: &str) -> bool {
    status.starts_with("HTTP/1.1 204 ") || status.starts_with("HTTP/1.0 204 ")
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]

    use super::*;
    use rustls::pki_types::pem::PemObject as _;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn origin_requires_https_authority_only() {
        assert_eq!(
            parse_origin("https://control.example:8443"),
            Some(("control.example".into(), 8443))
        );
        assert_eq!(
            parse_origin("https://control.example"),
            Some(("control.example".into(), 443))
        );
        for invalid in [
            "http://control.example",
            "https://user@control.example",
            "https://control.example/path",
            "https://control.example?x",
        ] {
            assert!(parse_origin(invalid).is_none(), "accepted {invalid}");
        }
    }

    #[test]
    fn only_http_204_is_a_durable_acknowledgment() {
        assert!(durable_ack_status("HTTP/1.1 204 No Content\r\n"));
        for status in [
            "HTTP/1.1 200 OK\r\n",
            "HTTP/1.1 202 Accepted\r\n",
            "HTTP/1.1 409 Conflict\r\n",
            "garbage",
        ] {
            assert!(!durable_ack_status(status), "accepted {status:?}");
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn retry_reuses_batch_bytes_refreshes_auth_and_only_204_acks() {
        let cert =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).expect("certificate");
        let server_tls =
            rustls::ServerConfig::builder_with_provider(crate::tls::provider().expect("provider"))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS 1.3")
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.cert.der().clone()],
                    rustls::pki_types::PrivateKeyDer::from_pem_slice(
                        cert.signing_key.serialize_pem().as_bytes(),
                    )
                    .expect("private key"),
                )
                .expect("server TLS config");
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(cert.cert.der().clone())
            .expect("trusted test certificate");
        let client_tls = Arc::new(
            rustls::ClientConfig::builder_with_provider(crate::tls::provider().expect("provider"))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS 1.3")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let port = listener.local_addr().expect("address").port();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for status in ["500 Retry", "204 No Content"] {
                let (tcp, _) = listener.accept().await.expect("accept");
                let tls = acceptor.accept(tcp).await.expect("TLS accept");
                let mut stream = tokio::io::BufReader::new(tls);
                let mut headers = Vec::new();
                let mut content_length = 0usize;
                loop {
                    let mut line = Vec::new();
                    stream
                        .read_until(b'\n', &mut line)
                        .await
                        .expect("read header");
                    if line == b"\r\n" {
                        break;
                    }
                    if line.to_ascii_lowercase().starts_with(b"content-length:") {
                        content_length = std::str::from_utf8(&line)
                            .expect("header UTF-8")
                            .split(':')
                            .nth(1)
                            .expect("value")
                            .trim()
                            .parse()
                            .expect("content length");
                    }
                    headers.extend_from_slice(&line);
                }
                let mut body = vec![0; content_length];
                stream.read_exact(&mut body).await.expect("read body");
                requests.push((headers, body));
                stream
                    .get_mut()
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .expect("write response");
            }
            requests
        });

        let body = b"signed immutable KRUS batch".to_vec();
        let id = BatchId {
            epoch: [7; 16],
            sequence: 3,
        };
        let acked = Arc::new(AtomicBool::new(false));
        let acked_by_commands = Arc::clone(&acked);
        let (commands, mut command_rx) = tokio::sync::mpsc::channel(4);
        let command_task = tokio::spawn(async move {
            while let Some(command) = command_rx.recv().await {
                match command {
                    SpoolCommand::Read(got_id, reply) => {
                        assert_eq!(got_id, id);
                        let _ = reply.send(Ok(body.clone()));
                    }
                    SpoolCommand::Ack(got_id, _, reply) => {
                        assert_eq!(got_id, id);
                        acked_by_commands.store(true, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    SpoolCommand::Pending(reply) => {
                        let _ = reply.send(Ok(vec![id]));
                    }
                }
            }
        });
        let identity = Identity::from_seed(&[0x42; crate::sign::SEED_LEN]);
        let client_tls = Arc::new(client_tls);

        assert!(
            upload_one("127.0.0.1", port, &client_tls, &identity, &commands, id)
                .await
                .is_err()
        );
        assert!(
            !acked.load(Ordering::SeqCst),
            "a non-204 response deleted the batch"
        );
        upload_one("127.0.0.1", port, &client_tls, &identity, &commands, id)
            .await
            .expect("204 acknowledges");
        assert!(acked.load(Ordering::SeqCst));

        let requests = server.await.expect("server task");
        let auth = |headers: &[u8]| {
            String::from_utf8_lossy(headers)
                .lines()
                .find(|line| line.starts_with("Authorization:"))
                .expect("authorization")
                .to_owned()
        };
        assert_ne!(
            auth(&requests[0].0),
            auth(&requests[1].0),
            "retry reused request authentication"
        );
        assert_eq!(
            requests[0].1, requests[1].1,
            "retry changed immutable batch bytes"
        );
        command_task.abort();
    }
}
