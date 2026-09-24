// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Opt-in client-side distributed trace export — GitHub issue #170.
//!
//! `plans/phase-6/08-observability.md` §3.3 deferred this on purpose: a
//! client-side exporter needs a second transport, a second collector
//! endpoint, and a real answer to "may `karstd` ever originate outbound
//! telemetry traffic at all" — not something that workstream's budget
//! covered. Disposition recorded via GitHub issue #131: pursue it, scoped.
//!
//! # What this is not
//!
//! **Not a second exporter stack.** `opentelemetry-otlp`'s bundled HTTP
//! clients (`reqwest-*`, `hyper-client`) are deliberately left off in
//! `Cargo.toml` — [`Client`] below is a hand-rolled
//! [`opentelemetry_http::HttpClient`] built on the same blocking rustls
//! primitives `relay_tls.rs`/`dot.rs` already use, so this feature adds one
//! TLS stack and one HTTP/1.1 request writer to the binary, not a second of
//! each.
//!
//! **Not authenticated the way the control channel is.** TLS here is a
//! conventional trust-store hop — ordinary `WebPKI` chain validation against
//! `server_name` — not the pinned, post-quantum-hybrid posture ADR-0011
//! gives the control channel. There is no second, protocol-level check
//! behind this one: the certificate *is* the trust boundary, because this is
//! telemetry to an operator-chosen sidecar (their own collector, possibly
//! inside their own air-gapped deployment), not a channel PHREATIC itself
//! depends on. See [`crate::config::TracingCollector`]'s doc comment for the
//! full reasoning §170 asked for.
//!
//! # Failure behavior
//!
//! Built on [`opentelemetry_sdk`]'s [`opentelemetry_sdk::trace::BatchSpanProcessor`],
//! which already gives the two properties an opt-in, best-effort telemetry
//! path needs: spans queue in a bounded channel and a full queue *drops* the
//! new span rather than blocking the caller, and the exporter's own HTTP
//! call runs on the processor's dedicated background thread — never on the
//! datapath, never on the control-refresh thread that calls
//! [`crate::control::Client::sync`]. An unreachable collector costs dropped
//! spans, never tunnel operation.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_http::{Bytes, HttpClient, HttpError, Request, Response};
use opentelemetry_otlp::{Protocol, SpanExporter, WithExportConfig as _, WithHttpConfig as _};
use opentelemetry_sdk::trace::SdkTracerProvider;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, StreamOwned};
use sha2::{Digest as _, Sha256};
use tracing_subscriber::{Layer, Registry};

use crate::config::TracingCollector;

/// A [`Layer`] this daemon may or may not have yet, dynamically swappable —
/// `None` (the no-op case, present from process start) until [`install`]
/// replaces it, if it ever does. Boxed and object-safe rather than generic
/// over a concrete tracer type, because [`main`](../../main.rs)'s subscriber
/// is built before a configuration — and therefore before it is known
/// whether trace export is even on — has been read.
pub type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync>;

/// The handle [`crate::main`]'s `init_tracing` hands back, so [`install`] can
/// replace the no-op slot once `[tracing] collector` is known.
pub type ReloadHandle = tracing_subscriber::reload::Handle<Option<BoxedLayer>, Registry>;

/// How long one HTTP request to the collector may take before this node gives
/// up on it — generous, since this runs on the batch processor's own
/// background thread and never blocks anything else, but still bounded per
/// [`opentelemetry_sdk::trace::SpanExporter::export`]'s own contract that an
/// exporter must not block indefinitely.
const TIMEOUT: Duration = Duration::from_secs(10);

/// An installed exporter, held for the daemon's lifetime so it can be flushed
/// on shutdown.
#[derive(Debug)]
pub struct Handle {
    provider: SdkTracerProvider,
}

impl Handle {
    /// Flush and stop the batch processor's background thread. Best-effort:
    /// a collector that is down when this runs simply loses whatever spans
    /// were still queued, the same as any other export failure.
    pub fn shutdown(&self) {
        if let Err(error) = self.provider.shutdown() {
            tracing::warn!(%error, "trace export: shutdown did not flush cleanly");
        }
    }
}

/// Build the OTLP/HTTP exporter, wire it into a fresh [`SdkTracerProvider`],
/// and swap it into `reload` in place of the no-op layer `init_tracing`
/// installed at startup.
///
/// # Errors
/// The collector's TLS configuration could not be built (no usable system
/// trust roots), or the exporter itself refused the configuration.
pub fn install(collector: &TracingCollector, reload: &ReloadHandle) -> Result<Handle, String> {
    let client = Client::new(
        collector.address,
        collector.server_name.clone(),
        collector.pin,
    )?;
    let endpoint = format!(
        "https://{}:{}/v1/traces",
        collector.server_name,
        collector.address.port()
    );
    let exporter = SpanExporter::builder()
        .with_http()
        .with_http_client(client)
        .with_endpoint(endpoint)
        .with_protocol(Protocol::HttpBinary)
        .build()
        .map_err(|error| format!("trace export: {error}"))?;

    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name("karstd")
        .build();
    let provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();

    let tracer = provider.tracer("karstd");
    let layer: BoxedLayer = Box::new(tracing_opentelemetry::layer().with_tracer(tracer));
    reload
        .reload(Some(layer))
        .map_err(|error| format!("trace export: {error}"))?;

    Ok(Handle { provider })
}

/// TLS 1.3 to the collector: ordinary `WebPKI` chain validation against the
/// system trust store when `pin` is `None`, or a bare SPKI-pin check when
/// it is set — the same pair of postures
/// `crates/karst-dns/src/forward/tls.rs` gives `DoT`'s own unpinned/pinned
/// paths, for the same reason: a self-hosted collector with no public CA
/// certificate is exactly the case pinning exists for, and requiring chain
/// validation to *also* pass would make it unusable for that case. See the
/// module doc's "What this is not" section for why *neither* of these is
/// the control channel's pinned/PQ-hybrid posture.
fn tls_config(pin: Option<[u8; 32]>) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| format!("trace export: {error}"))?;
    if let Some(pin) = pin {
        return Ok(Arc::new(
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedVerifier { pin, provider }))
                .with_no_client_auth(),
        ));
    }
    let loaded = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    let (added, _invalid) = roots.add_parsable_certificates(loaded.certs);
    if added == 0 {
        return Err("trace export: the host has no usable certificate authority roots".to_owned());
    }
    Ok(Arc::new(
        builder.with_root_certificates(roots).with_no_client_auth(),
    ))
}

/// Verifies a collector's certificate by SPKI pin alone, not by CA chain or
/// hostname — see [`tls_config`]. Identical in shape to
/// `crates/karst-dns/src/forward/tls.rs`'s `PinnedVerifier`, reimplemented
/// here because that one is private to `karst-dns`.
#[derive(Debug)]
struct PinnedVerifier {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let hash = spki_sha256(end_entity)?;
        if hash == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "trace export: collector certificate does not match the configured pin".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// SHA-256 of a leaf certificate's DER-encoded `SubjectPublicKeyInfo` — the
/// same pin construction `crates/karst-dns/src/forward/tls.rs::spki_sha256`
/// uses (curl `--pinnedpubkey`, historical HPKP).
fn spki_sha256(cert: &CertificateDer<'_>) -> Result<[u8; 32], rustls::Error> {
    use x509_cert::der::{Decode as _, Encode as _};
    let parsed = x509_cert::Certificate::from_der(cert.as_ref()).map_err(|error| {
        rustls::Error::General(format!(
            "trace export: malformed collector certificate: {error}"
        ))
    })?;
    let spki = parsed
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|error| {
            rustls::Error::General(format!("trace export: could not re-encode SPKI: {error}"))
        })?;
    Ok(Sha256::digest(spki).into())
}

/// A minimal, one-shot-connection-per-call [`HttpClient`]: opens a fresh
/// TLS connection, sends exactly one request, reads exactly one response,
/// and closes. Batches are infrequent enough (one per
/// [`opentelemetry_sdk::trace::BatchConfig`] export interval, by default
/// every few seconds at most) that connection reuse would add real
/// complexity — a live connection to track, reconnect, and expire — for a
/// path this codebase's other one-shot TLS callers (`dot.rs`) show is not
/// needed to be correct.
///
/// `address` and `server_name` are kept separate rather than dialing
/// whatever `server_name` resolves to — the same split
/// [`crate::config::DotUpstreamSection`] already makes, and for the same
/// reason: an operator's collector may sit at an address no DNS record names
/// (a bare IP, a split-horizon name, a NAT64-rewritten literal), and the
/// certificate name it presents is a separate fact from where it is reached.
#[derive(Debug)]
struct Client {
    address: SocketAddr,
    server_name: String,
    tls: Arc<ClientConfig>,
}

impl Client {
    fn new(
        address: SocketAddr,
        server_name: String,
        pin: Option<[u8; 32]>,
    ) -> Result<Self, String> {
        Ok(Self {
            address,
            server_name,
            tls: tls_config(pin)?,
        })
    }
}

#[async_trait::async_trait]
impl HttpClient for Client {
    /// Fully synchronous underneath the `async fn`: the SDK's batch
    /// processor drives this with `futures_executor::block_on` on its own
    /// dedicated background thread (not a Tokio runtime), so there is
    /// nothing here for an `.await` to usefully yield to — see the module
    /// doc's "Failure behavior" section.
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let name = ServerName::try_from(self.server_name.clone()).map_err(|_| {
            format!(
                "trace export: {:?} is not a usable TLS server name",
                self.server_name
            )
        })?;
        let conn = ClientConnection::new(Arc::clone(&self.tls), name)?;
        let sock = TcpStream::connect(self.address)?;
        sock.set_read_timeout(Some(TIMEOUT))?;
        sock.set_write_timeout(Some(TIMEOUT))?;
        let mut tls = StreamOwned { conn, sock };
        // Complete the handshake — including certificate verification —
        // before a single byte of telemetry is written, the same discipline
        // `dot.rs::query_one` uses for the query it sends.
        tls.conn.complete_io(&mut tls.sock)?;

        let path = request
            .uri()
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);
        write!(
            tls,
            "{} {path} HTTP/1.1\r\nHost: {}\r\n",
            request.method(),
            self.server_name,
        )?;
        for (name, value) in request.headers() {
            // `Host`/`Content-Length`/`Connection` are this function's own
            // to set, from the connection and body it actually has rather
            // than whatever the exporter's generic `Request` carried.
            if matches!(name.as_str(), "host" | "content-length" | "connection") {
                continue;
            }
            tls.write_all(name.as_str().as_bytes())?;
            tls.write_all(b": ")?;
            tls.write_all(value.as_bytes())?;
            tls.write_all(b"\r\n")?;
        }
        write!(
            tls,
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            request.body().len()
        )?;
        tls.write_all(request.body())?;
        tls.flush()?;

        let mut raw = Vec::new();
        match tls.read_to_end(&mut raw) {
            Ok(_) => {}
            // rustls's own manual names this exact situation: a peer that
            // closes the TCP connection once its response is fully sent,
            // without the TLS `close_notify` alert a fully spec-compliant
            // shutdown would send first. The plaintext already decoded
            // before that abrupt close is the complete response regardless
            // — discarding it over a missing alert would treat an ordinary,
            // widely-seen server behavior as a transport failure.
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => {}
            Err(error) => return Err(error.into()),
        }
        parse_response(&raw)
    }
}

/// Parse a minimal HTTP/1.1 response: status line, headers (discarded — the
/// exporter above never reads them), body. `Connection: close` on the
/// request means a compliant collector closes the connection once the
/// response is sent, so reading to EOF is enough — the same
/// read-to-completion-then-parse shape `dot.rs`'s framed reads use, at the
/// HTTP layer instead of the DNS-message layer.
fn parse_response(raw: &[u8]) -> Result<Response<Bytes>, HttpError> {
    let separator = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("trace export: collector response has no header/body separator")?;
    let (head, rest) = raw.split_at(separator);
    let body = rest.get(4..).unwrap_or_default();
    let status_line = head
        .split(|&b| b == b'\n')
        .next()
        .ok_or("trace export: collector sent an empty response")?;
    let status_line = std::str::from_utf8(status_line)
        .map_err(|_| "trace export: collector's status line is not valid UTF-8")?;
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("trace export: collector's status line has no status code")?
        .parse()
        .map_err(|_| "trace export: collector's status code did not parse")?;
    Ok(Response::builder()
        .status(code)
        .body(Bytes::copy_from_slice(body))?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::net::TcpListener;

    /// A loopback OTLP/HTTP collector: real TLS, terminated by a background
    /// thread, answering exactly one request with a fixed status and body —
    /// enough to prove [`Client::send_bytes`] speaks HTTP/1.1 correctly over
    /// TLS without standing up a real `OTel` Collector.
    struct FakeCollector {
        address: SocketAddr,
        spki_pin: [u8; 32],
    }

    fn start_fake_collector(name: &str, status: u16, body: &'static [u8]) -> FakeCollector {
        let cert = rcgen::generate_simple_self_signed(vec![name.to_owned()]).expect("cert");
        let key = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let leaf = CertificateDer::from(cert.cert.der().to_vec());
        let spki_pin = spki_sha256(&leaf).expect("hash fixture cert");
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf], key)
            .expect("server config");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        std::thread::spawn(move || {
            let Ok((sock, _)) = listener.accept() else {
                return;
            };
            let conn = rustls::ServerConnection::new(Arc::new(server_config)).expect("server conn");
            let mut tls = StreamOwned { conn, sock };
            // Drain the full request (headers + `Content-Length` body)
            // before responding. The client's writes land as more than one
            // TLS record, so a single `read()` can return before later
            // records arrive; closing the socket with those bytes still
            // sitting unread in the kernel receive buffer is exactly what
            // makes the OS answer with a RST instead of a graceful FIN —
            // surfacing to the client as `ConnectionReset` rather than a
            // clean EOF. See GitHub issue #187.
            read_full_request(&mut tls);
            let _ = write!(
                tls,
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = tls.write_all(body);
        });
        FakeCollector { address, spki_pin }
    }

    /// Read from `tls` until the full HTTP/1.1 request — headers plus the
    /// body its `Content-Length` header promises — has arrived, rather than
    /// trusting a single `read()` call to have collected it all in one go.
    fn read_full_request(tls: &mut StreamOwned<rustls::ServerConnection, TcpStream>) {
        let mut buf = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            if remaining_body_bytes(&buf) == Some(0) {
                return;
            }
            match tls.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(chunk.get(..n).unwrap_or_default()),
            }
        }
    }

    /// `None` until `buf` holds the header/body separator; `Some(0)` once it
    /// also holds as many body bytes as `Content-Length` promised.
    fn remaining_body_bytes(buf: &[u8]) -> Option<usize> {
        let separator = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
        let head = std::str::from_utf8(buf.get(..separator)?).ok()?;
        let content_length = head
            .split("\r\n")
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let body_len = buf.len() - (separator + 4);
        Some(content_length.saturating_sub(body_len))
    }

    fn request() -> Request<Bytes> {
        Request::post("https://otel.test/v1/traces")
            .header("content-type", "application/x-protobuf")
            .body(Bytes::from_static(b"payload"))
            .expect("request")
    }

    /// The pinned path succeeds against a self-signed fixture — the case
    /// unpinned `WebPKI` validation can never pass locally, and the reason
    /// `[tracing] collector_pin_hex` exists at all (see [`tls_config`]'s
    /// doc comment).
    #[test]
    fn a_matching_pin_succeeds_against_a_self_signed_collector() {
        let collector = start_fake_collector("otel.test", 200, b"ok");
        let client = Client::new(
            collector.address,
            "otel.test".to_owned(),
            Some(collector.spki_pin),
        )
        .expect("client");
        let response =
            futures_executor::block_on(client.send_bytes(request())).expect("send_bytes");
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), &Bytes::from_static(b"ok"));
    }

    #[test]
    fn a_non_2xx_status_is_reported_not_treated_as_a_transport_error() {
        let collector = start_fake_collector("otel.test", 503, b"unavailable");
        let client = Client::new(
            collector.address,
            "otel.test".to_owned(),
            Some(collector.spki_pin),
        )
        .expect("client");
        let response =
            futures_executor::block_on(client.send_bytes(request())).expect("send_bytes");
        assert_eq!(response.status(), 503);
    }

    #[test]
    fn a_pin_mismatch_is_rejected_before_the_request_is_sent() {
        let collector = start_fake_collector("otel.test", 200, b"ok");
        let wrong_pin = [0_u8; 32];
        let client = Client::new(collector.address, "otel.test".to_owned(), Some(wrong_pin))
            .expect("client");
        let error =
            futures_executor::block_on(client.send_bytes(request())).expect_err("pin mismatch");
        assert!(error.to_string().contains("pin"));
    }

    /// Unpinned (`pin: None`) means ordinary `WebPKI` chain validation, so a
    /// self-signed fixture — the only kind these tests can stand up without
    /// reaching a real, publicly trusted host — is rejected. This is the
    /// same failure mode `dot.rs::an_unpinned_self_signed_resolver_is_rejected`
    /// asserts for the identical reason: it is what proves the unpinned path
    /// is real validation and not an accept-anything fallback; that same
    /// property makes a *success* test for this path impossible to write
    /// locally, which is exactly why the pinned tests above exist.
    #[test]
    fn an_unpinned_self_signed_collector_is_rejected() {
        let collector = start_fake_collector("otel.test", 200, b"ok");
        let client = Client::new(collector.address, "otel.test".to_owned(), None).expect("client");
        assert!(futures_executor::block_on(client.send_bytes(request())).is_err());
    }
}
