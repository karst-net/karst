// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Detect this relay's own location via cloud instance metadata — ADR-0048.
//!
//! **Still a declared fact, not an inference.** This asks the relay's own
//! cloud platform "where am I" — the provider's own record of where it
//! placed the instance — rather than resolving `address` through a `GeoIP`
//! database, which ADR-0046 already rejected as involuntary inference.
//!
//! **AWS only, today.** [`detect`] is a plain dispatcher, not a trait —
//! there is no second provider implementation yet to design an abstraction
//! against. A GCP or Azure prober, if one is ever written, becomes another
//! arm in [`detect`]'s body.
//!
//! **Opt-in, off by default** (`[telemetry] detect_location`, see
//! `config.rs`). A relay that hasn't been told to probe never reaches
//! `169.254.169.254` at all.

use crate::config::Telemetry as TelemetryConfig;

/// A relay's self-detected position. Never constructed from a guess — see
/// `aws_imds::region_to_location`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DetectedLocation {
    pub lat: f64,
    pub lon: f64,
}

/// Tries each known cloud metadata source in turn. Today: AWS only. Returns
/// `None` on anything other than a clean, recognized detection — a relay
/// not running on a known cloud, a disabled config, a timeout, or an
/// unrecognized region all look the same to a caller: nothing to report.
pub async fn detect(cfg: &TelemetryConfig) -> Option<DetectedLocation> {
    if !cfg.detect_location {
        return None;
    }
    aws_imds::probe().await
}

mod aws_imds {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpStream;

    use super::DetectedLocation;

    /// The well-known link-local address every supported cloud's instance
    /// metadata service listens on. Not routable off the instance itself —
    /// there is no DNS lookup, no TLS, nothing this relay reaches outside
    /// its own host/hypervisor boundary.
    const METADATA_HOST: &str = "169.254.169.254";
    const METADATA_PORT: u16 = 80;

    /// Bounds the whole token-fetch-then-region-fetch exchange. A relay not
    /// running on AWS typically gets a fast connection refusal here, but
    /// this bounds the slower failure modes (a stalled connect, a metadata
    /// service that accepts but never answers) so startup never waits long
    /// on a probe that was never going to succeed.
    const PROBE_BUDGET: Duration = Duration::from_secs(1);

    /// Major, well-known AWS regions only. An unrecognized region code
    /// falls through to `None` in [`region_to_location`] rather than
    /// guessing — see ADR-0048's named "Reconsider if" for this table's own
    /// staleness. Approximate datacenter-area centroids, not exact
    /// addresses — precision well beyond "which metro area" was never the
    /// point.
    const AWS_REGION_CENTROIDS: &[(&str, f64, f64)] = &[
        ("us-east-1", 39.0438, -77.4874),       // N. Virginia
        ("us-east-2", 39.9612, -82.9988),       // Ohio
        ("us-west-1", 37.3382, -121.8863),      // N. California
        ("us-west-2", 45.8399, -119.7006),      // Oregon
        ("ca-central-1", 45.5017, -73.5673),    // Montreal
        ("eu-west-1", 53.3498, -6.2603),        // Ireland
        ("eu-west-2", 51.5074, -0.1278),        // London
        ("eu-west-3", 48.8566, 2.3522),         // Paris
        ("eu-central-1", 50.1109, 8.6821),      // Frankfurt
        ("eu-north-1", 59.3293, 18.0686),       // Stockholm
        ("ap-southeast-1", 1.3521, 103.8198),   // Singapore
        ("ap-southeast-2", -33.8688, 151.2093), // Sydney
        ("ap-northeast-1", 35.6762, 139.6503),  // Tokyo
        ("ap-northeast-2", 37.5665, 126.9780),  // Seoul
        ("ap-south-1", 19.0760, 72.8777),       // Mumbai
        ("sa-east-1", -23.5505, -46.6333),      // Sao Paulo
    ];

    pub(super) async fn probe() -> Option<DetectedLocation> {
        probe_at(METADATA_HOST, METADATA_PORT).await
    }

    /// The real logic, parameterized so tests can point it at a local mock
    /// listener instead of the real link-local address.
    async fn probe_at(host: &str, port: u16) -> Option<DetectedLocation> {
        tokio::time::timeout(PROBE_BUDGET, async {
            let token = fetch_token(host, port).await?;
            let region = fetch_region(host, port, &token).await?;
            region_to_location(region.trim())
        })
        .await
        .ok()
        .flatten()
    }

    /// `IMDSv2`'s session-token step: a PUT with a TTL header, body is the
    /// token to present on every subsequent metadata request.
    async fn fetch_token(host: &str, port: u16) -> Option<String> {
        let request = format!(
            "PUT /latest/api/token HTTP/1.1\r\n\
             Host: {host}\r\n\
             X-aws-ec2-metadata-token-ttl-seconds: 21600\r\n\
             Connection: close\r\n\r\n"
        );
        exchange(host, port, &request).await
    }

    async fn fetch_region(host: &str, port: u16, token: &str) -> Option<String> {
        let request = format!(
            "GET /latest/meta-data/placement/region HTTP/1.1\r\n\
             Host: {host}\r\n\
             X-aws-ec2-metadata-token: {token}\r\n\
             Connection: close\r\n\r\n"
        );
        exchange(host, port, &request).await
    }

    /// Connect, send one plain-HTTP request, and return the response body
    /// if the status line is 2xx. **No TLS** — IMDS is plain HTTP by
    /// design, unlike `telemetry.rs::post()`'s control-plane POST, which
    /// this matches only in request-construction/status-line-parsing
    /// style, not by calling it.
    async fn exchange(host: &str, port: u16, request: &str) -> Option<String> {
        let mut stream = TcpStream::connect((host, port)).await.ok()?;
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await.ok()?;
        let response = String::from_utf8_lossy(buf.get(..n)?);
        let mut parts = response.split("\r\n\r\n");
        let status_line = parts.next()?.lines().next()?;
        if !(status_line.starts_with("HTTP/1.1 2") || status_line.starts_with("HTTP/1.0 2")) {
            return None;
        }
        Some(parts.next().unwrap_or_default().to_owned())
    }

    fn region_to_location(region: &str) -> Option<DetectedLocation> {
        AWS_REGION_CENTROIDS
            .iter()
            .find(|(code, _, _)| *code == region)
            .map(|(_, lat, lon)| DetectedLocation {
                lat: *lat,
                lon: *lon,
            })
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::unwrap_used, clippy::expect_used)]

        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::TcpListener;

        use super::*;

        const FAKE_TOKEN: &str = "fake-imds-token";

        /// Accepts connections one at a time and answers each with a
        /// canned response chosen by the request's path — the same shape
        /// a real `IMDSv2` token-then-region exchange produces, without a
        /// real AWS instance to test against.
        async fn serve_once(listener: TcpListener, region_body: &'static str) {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut buf = [0u8; 512];
                let n = stream.read(&mut buf).await.expect("read request");
                let request = String::from_utf8_lossy(buf.get(..n).unwrap_or_default());
                let body = if request.starts_with("PUT /latest/api/token") {
                    FAKE_TOKEN
                } else {
                    region_body
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write response");
            }
        }

        #[tokio::test]
        async fn a_recognized_region_resolves_to_its_centroid() {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local addr");
            tokio::spawn(serve_once(listener, "us-west-2"));

            let got = probe_at(&addr.ip().to_string(), addr.port()).await;

            assert_eq!(
                got,
                Some(DetectedLocation {
                    lat: 45.8399,
                    lon: -119.7006
                })
            );
        }

        #[tokio::test]
        async fn an_unrecognized_region_is_none_not_a_guess() {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local addr");
            tokio::spawn(serve_once(listener, "mars-central-1"));

            let got = probe_at(&addr.ip().to_string(), addr.port()).await;

            assert_eq!(got, None);
        }

        #[tokio::test]
        async fn a_refused_connection_is_none_promptly() {
            // Nothing is listening on this port -- the connection is
            // refused immediately, not timed out, on a loopback address.
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local addr");
            drop(listener); // free the port, guaranteeing nothing answers it

            let started = std::time::Instant::now();
            let got = probe_at(&addr.ip().to_string(), addr.port()).await;

            assert_eq!(got, None);
            assert!(
                started.elapsed() < PROBE_BUDGET,
                "a refused connection should fail well under the probe budget"
            );
        }
    }
}
