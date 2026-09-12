// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Push this relay's own health/throughput telemetry to the control plane —
//! ADR-0021.
//!
//! **Push, not pull, and hand-rolled HTTPS**, for the reasons the ADR gives:
//! a relay can already reach the control plane outbound, the reverse is a
//! materially stronger assumption for a self-hosted deployment, and a JSON
//! body over one POST does not earn a client-library dependency any more
//! than the metrics endpoint's response or `server.rs`'s own mesh dial do.
//!
//! **Best-effort.** A failed report is logged and retried next tick, never
//! fatal — matching every other periodic loop in this crate (`roster_loop`,
//! `reflect_loop`).
//!
//! **Aggregate only**, matching `metrics.rs`'s own disclosure posture: this
//! reports totals, never a per-node field.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::config::Telemetry as TelemetryConfig;
use crate::server::Ctx;

/// How long a whole report — connect, TLS, request, response — may take
/// before this tick gives up. Generous relative to a single request because
/// a stalled DNS lookup or a slow TLS handshake is exactly the failure mode
/// this bounds, not the ordinary case.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Push one report every `interval_secs`, until the process ends.
pub async fn telemetry_loop(cfg: TelemetryConfig, ctx: Arc<Ctx>) {
    let tls = match crate::tls::webpki_client_config() {
        Ok(tls) => tls,
        Err(e) => {
            eprintln!("karst-relay: telemetry: {e}; not reporting telemetry this run");
            return;
        }
    };
    let mut tick = tokio::time::interval(Duration::from_secs(cfg.interval_secs));
    loop {
        tick.tick().await;
        match tokio::time::timeout(REQUEST_TIMEOUT, report_once(&cfg, &tls, &ctx)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => eprintln!("karst-relay: telemetry: {e}"),
            Err(_) => eprintln!("karst-relay: telemetry: timed out"),
        }
    }
}

async fn report_once(
    cfg: &TelemetryConfig,
    tls: &Arc<rustls::ClientConfig>,
    ctx: &Arc<Ctx>,
) -> Result<(), String> {
    let (host, port) = parse_authority(&cfg.control_url)?;
    let relay_id = ctx.identity.relay_id();
    let snapshot = ctx.snapshot();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_secs();

    let local_clients = snapshot.local_clients as u64;
    let mesh_peers = snapshot.mesh_peers as u64;
    let remote_clients = snapshot.remote_clients as u64;
    let bytes_total = snapshot
        .totals
        .bytes_in
        .saturating_add(snapshot.totals.bytes_out);
    let uptime_secs = snapshot.uptime_secs;

    let msg = signing_input(
        &relay_id,
        timestamp,
        local_clients,
        mesh_peers,
        remote_clients,
        bytes_total,
        uptime_secs,
    );

    let signature = ctx
        .identity
        .sign_telemetry(&msg)
        .map_err(|e| format!("sign: {e}"))?;

    let relay_id_b64 = Base64UrlUnpadded::encode_string(&relay_id);
    let signature_b64 = Base64::encode_string(&signature);

    let body = format!(
        "{{\"relay_id\":\"{relay_id_b64}\",\"timestamp\":{timestamp},\
         \"local_clients\":{local_clients},\"mesh_peers\":{mesh_peers},\
         \"remote_clients\":{remote_clients},\"bytes_total\":{bytes_total},\
         \"uptime_secs\":{uptime_secs},\"signature\":\"{signature_b64}\"}}"
    );

    let path = format!("/karst/v1/relays/{relay_id_b64}/telemetry");
    post(&host, port, tls, &path, &body).await
}

/// Connect, send one HTTPS POST, and check the status line — nothing more.
/// The response body carries nothing this relay acts on; ADR-0021's report
/// is fire-and-forget.
async fn post(
    host: &str,
    port: u16,
    tls: &Arc<rustls::ClientConfig>,
    path: &str,
    body: &str,
) -> Result<(), String> {
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|e| format!("server name: {e}"))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(tls));
    let mut stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| format!("tls: {e}"))?;

    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;

    let mut buf = [0u8; 512];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| format!("read: {e}"))?;
    let response = String::from_utf8_lossy(buf.get(..n).unwrap_or_default());
    let status = response.lines().next().unwrap_or_default();
    if status.starts_with("HTTP/1.1 2") || status.starts_with("HTTP/1.0 2") {
        Ok(())
    } else {
        Err(format!("control plane rejected the report: {status}"))
    }
}

/// ADR-0021's exact 80-byte signed message: `relay_id` followed by six
/// big-endian `u64` fields. Never the JSON body — JSON has no canonical
/// encoding, and a signature must cover bytes both sides construct
/// identically without agreeing on field order or whitespace.
///
/// Pure and deterministic, unlike the signature over it: this is what
/// `spec/vectors/relay-telemetry-v1.json` pins against
/// `relaytelemetry.signingInput` on the Go side, the same way
/// `karst-control-v1.json` pins `channel.SigningInput` rather than a
/// signature — ML-DSA-87 is hedged, so a signature is never reproducible
/// vector material, but the bytes it signs over always are.
#[must_use]
pub fn signing_input(
    relay_id: &[u8; 32],
    timestamp: u64,
    local_clients: u64,
    mesh_peers: u64,
    remote_clients: u64,
    bytes_total: u64,
    uptime_secs: u64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(80);
    msg.extend_from_slice(relay_id);
    msg.extend_from_slice(&timestamp.to_be_bytes());
    msg.extend_from_slice(&local_clients.to_be_bytes());
    msg.extend_from_slice(&mesh_peers.to_be_bytes());
    msg.extend_from_slice(&remote_clients.to_be_bytes());
    msg.extend_from_slice(&bytes_total.to_be_bytes());
    msg.extend_from_slice(&uptime_secs.to_be_bytes());
    msg
}

/// Split a `https://host[:port]` control-plane URL into what
/// [`TcpStream::connect`] and TLS SNI each need.
fn parse_authority(control_url: &str) -> Result<(String, u16), String> {
    let authority = control_url
        .strip_prefix("https://")
        .ok_or_else(|| format!("control_url {control_url:?} must start with https://"))?
        .split('/')
        .next()
        .unwrap_or_default();
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse()
                .map_err(|_| format!("control_url {control_url:?} has an invalid port"))?;
            Ok((host.to_owned(), port))
        }
        None => Ok((authority.to_owned(), 443)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_control_url_with_no_port_defaults_to_443() {
        assert_eq!(
            parse_authority("https://control.example.com").expect("parses"),
            ("control.example.com".to_owned(), 443)
        );
    }

    #[test]
    fn a_control_url_with_a_port_uses_it() {
        assert_eq!(
            parse_authority("https://control.example.com:8443").expect("parses"),
            ("control.example.com".to_owned(), 8443)
        );
    }

    #[test]
    fn a_non_https_control_url_is_refused() {
        assert!(parse_authority("http://control.example.com").is_err());
    }

    #[test]
    fn a_trailing_path_is_ignored() {
        // config::Config::validate does not forbid one; parsing tolerates it
        // rather than posting to a mangled authority.
        assert_eq!(
            parse_authority("https://control.example.com/anything").expect("parses"),
            ("control.example.com".to_owned(), 443)
        );
    }
}
