// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! ADR-0045 §4b: opt-in, per-region anchor RTT probing.
//!
//! The planner's §4a histogram can say "something near me is underserved,"
//! never *which direction*. This closes that gap the same way §4a closes
//! its own: the client never reports where it is, only the measured
//! TCP-handshake RTT to a small set of fixed, provider-operated endpoints —
//! "anchors" — one per allowlisted `(provider, region)` pair. The server
//! folds each report into a histogram keyed by the anchor, discarding this
//! node's identity once aggregated (`regionallow.Store.RecordAnchorRTT`).
//!
//! **The dispatcher stays ADR-0048's shape** — a plain function per
//! provider, not a trait (see `cloud_location.rs`) — with each arm
//! formatting its own hostname from a region code. A region whose anchor
//! does not resolve, or a provider this dispatcher does not yet cover, is
//! simply unmeasured, never an error.
//!
//! **Opt-in, off by default** (`[probe] anchor_probe`, see `config.rs`). A
//! node that has not enabled this never resolves a single provider
//! hostname — the same ADR-0039 air-gap guarantee `detect_location` gives
//! the relay side.
//!
//! **Runs on its own dedicated OS thread**, not the async netmap-refresh
//! loop: probing every allowlisted region can take seconds in the worst
//! case (one [`PROBE_BUDGET`] per anchor, serially), and that must never
//! delay the push-reactive netmap refresh a live reconfiguration depends
//! on. [`run`] is spawned the way `run.rs`'s other dedicated workers are —
//! see its own `scope.spawn` call sites — and hands its results to the
//! refresh loop through a shared, mutex-guarded queue rather than holding
//! any part of `control::Client` itself, which the refresh loop owns
//! exclusively for the daemon's lifetime.

use std::net::{TcpStream, ToSocketAddrs as _};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use karst_control_client::transport::pb;

use crate::netmap::AllowedRegions;
use crate::run::Shutdown;

/// Bounds one anchor's TCP-handshake attempt — resolve-then-connect. The
/// same bound `cloud_location.rs`'s own instance-metadata probe uses, for
/// the same reason: a cheap, fast failure (most anchors, most of the time)
/// must not be held hostage by the slow ones (a filtered port, a stalled
/// connect).
const PROBE_BUDGET: Duration = Duration::from_secs(1);

/// How often a full pass over the allowlist runs.
///
/// Far longer than `control::REFRESH` (60s): what this measures — distance
/// to a fixed, provider-operated endpoint — changes on the timescale of
/// Internet routing, not on the timescale of a netmap poll, and a fleet of
/// nodes hitting AWS/Azure/GCP endpoints every minute forever is exactly
/// the "real but opt-in" third-party dependency the ADR's own risk section
/// asks this to stay light about.
const PROBE_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// The largest single sleep between cooperative shutdown checks — matches
/// `portmap.rs::run`'s own chunked-wait convention, so a shutdown request
/// is noticed within a quarter second rather than at the end of a
/// 15-minute sleep.
const SLEEP_CHUNK: Duration = Duration::from_millis(250);

const PROBE_PORT: u16 = 443;

/// This provider's anchor hostname for `region`, or `None` for a provider
/// this dispatcher does not (yet) cover — see the module doc comment.
fn anchor_hostname(provider: &str, region: &str) -> Option<String> {
    match provider {
        // AWS GovCloud regions (`us-gov-west-1`, `us-gov-east-1`) resolve
        // their regional S3 endpoint under the same `amazonaws.com` DNS
        // namespace commercial AWS does; only the region code differs, so
        // one arm covers both partitions.
        "aws" | "aws-gov-cloud" => Some(format!("s3.{region}.amazonaws.com")),
        // Azure Government's own top-level domain (`usgovcloudapi.net`)
        // has not been verified to offer an equivalent Live Metrics
        // regional ingestion endpoint — unlike the four patterns ADR-0045
        // §4b's own table verified against the real service, so this is
        // left unmeasured rather than guessed at.
        "azure" => Some(azure_anchor(region)),
        "gcp" => Some(format!("storage.{region}.rep.googleapis.com")),
        _ => None,
    }
}

/// Azure Monitor's Live Metrics ingestion endpoint, regional for every
/// public region except `westcentralus` — which has no regional endpoint
/// of its own and falls back to the Cognitive Services anchor instead
/// (ADR-0045 §4b's table).
fn azure_anchor(region: &str) -> String {
    if region == "westcentralus" {
        azure_anchor_fallback(region)
    } else {
        format!("{region}.livediagnostics.monitor.azure.com")
    }
}

fn azure_anchor_fallback(region: &str) -> String {
    format!("{region}.api.cognitive.microsoft.com")
}

/// Resolve and time one TCP handshake to `host:443`. `None` covers every
/// failure mode alike — unresolvable, refused, filtered, timed out — since
/// none of them distinguishes "this anchor moved" from "this anchor was
/// never going to answer," and the ADR's own text treats all of them as
/// "simply unmeasured."
///
/// DNS resolution itself is not separately bounded beyond the OS resolver's
/// own behavior, unlike the connect below — acceptable here, unlike in
/// `cloud_location.rs` (which resolves nothing), because this runs on its
/// own dedicated thread: a slow lookup for one anchor delays only this
/// probe pass, never the netmap refresh loop or anything else the daemon
/// does.
fn probe(host: &str) -> Option<Duration> {
    let addr = (host, PROBE_PORT).to_socket_addrs().ok()?.next()?;
    let started = Instant::now();
    TcpStream::connect_timeout(&addr, PROBE_BUDGET).ok()?;
    Some(started.elapsed())
}

#[allow(clippy::cast_possible_truncation)]
fn rtt_ms(rtt: Duration) -> u32 {
    u32::try_from(rtt.as_millis()).unwrap_or(u32::MAX)
}

/// Sleep up to `duration`, checking `shutdown` every [`SLEEP_CHUNK`] so a
/// stop request is noticed promptly rather than at the end of one long
/// sleep — `portmap.rs::run`'s own convention.
fn sleep_cooperatively(duration: Duration, shutdown: &Shutdown) {
    let deadline = Instant::now() + duration;
    while !shutdown.requested() {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return;
        };
        std::thread::sleep(remaining.min(SLEEP_CHUNK));
    }
}

/// Run until `shutdown`. Reads the live allowlist from `allowed_regions`
/// (projected by the netmap-refresh loop after each successful sync) and
/// queues measured RTTs into `anchor_rtt_out`, which that same loop drains
/// and hands to
/// [`control::Client::set_anchor_rtt_observations`](crate::control::Client::set_anchor_rtt_observations)
/// right before its next request — the same "observation queued here, sent
/// on the next request" shape `sessions`/`home_relay` already use, bridged
/// across threads because, unlike those two, this daemon's only `Client`
/// value is owned exclusively by the refresh loop's own thread for the
/// whole run.
///
/// A pass's results **replace** whatever `anchor_rtt_out` held, rather than
/// accumulating: this is "the last locally measured anchor RTTs," not a
/// growing log, and a region that dropped out of the allowlist (or whose
/// anchor stopped answering) between passes must not have its last known
/// value quietly re-sent forever.
pub fn run(
    allowed_regions: &Mutex<AllowedRegions>,
    anchor_rtt_out: &Mutex<Vec<pb::KarstAnchorRtt>>,
    shutdown: &Shutdown,
) {
    while !shutdown.requested() {
        let targets: Vec<(String, String)> = allowed_regions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(provider, region)| (provider.to_owned(), region.to_owned()))
            .collect();

        let mut measured = Vec::with_capacity(targets.len());
        for (provider, region) in &targets {
            if shutdown.requested() {
                return;
            }
            if let Some(host) = anchor_hostname(provider, region) {
                if let Some(rtt) = probe(&host) {
                    measured.push(pb::KarstAnchorRtt {
                        provider: provider.clone(),
                        region: region.clone(),
                        rtt_ms: rtt_ms(rtt),
                    });
                }
            }
        }
        *anchor_rtt_out
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = measured;

        sleep_cooperatively(PROBE_INTERVAL, shutdown);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::net::TcpListener;

    use super::*;

    #[test]
    fn aws_anchor_hostnames_follow_the_regional_s3_pattern() {
        assert_eq!(
            anchor_hostname("aws", "us-east-1"),
            Some("s3.us-east-1.amazonaws.com".to_owned())
        );
    }

    #[test]
    fn aws_gov_cloud_shares_aws_s3_anchor_pattern() {
        assert_eq!(
            anchor_hostname("aws-gov-cloud", "us-gov-west-1"),
            Some("s3.us-gov-west-1.amazonaws.com".to_owned())
        );
    }

    #[test]
    fn azure_anchor_hostnames_follow_the_live_metrics_pattern() {
        assert_eq!(
            anchor_hostname("azure", "eastus"),
            Some("eastus.livediagnostics.monitor.azure.com".to_owned())
        );
    }

    #[test]
    fn azure_west_central_us_falls_back_to_the_cognitive_services_anchor() {
        assert_eq!(
            anchor_hostname("azure", "westcentralus"),
            Some("westcentralus.api.cognitive.microsoft.com".to_owned())
        );
    }

    #[test]
    fn azure_gov_cloud_is_unmeasured_until_a_verified_anchor_exists() {
        assert_eq!(anchor_hostname("azure-gov-cloud", "usgovvirginia"), None);
    }

    #[test]
    fn gcp_anchor_hostnames_follow_the_regional_storage_pattern() {
        assert_eq!(
            anchor_hostname("gcp", "us-central1"),
            Some("storage.us-central1.rep.googleapis.com".to_owned())
        );
    }

    #[test]
    fn an_unrecognized_provider_is_unmeasured() {
        assert_eq!(anchor_hostname("oracle", "us-ashburn-1"), None);
    }

    #[test]
    fn a_refused_connection_is_none_promptly() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        drop(listener); // free the port, guaranteeing nothing answers it

        let started = Instant::now();
        let got = probe_at(addr.ip(), addr.port());

        assert_eq!(got, None);
        assert!(
            started.elapsed() < PROBE_BUDGET,
            "a refused connection should fail well under the probe budget"
        );
    }

    #[test]
    fn a_reachable_listener_on_an_arbitrary_port_returns_a_bounded_rtt() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        std::thread::spawn(move || {
            let _ = listener.accept();
        });

        let got = probe_at(addr.ip(), addr.port());
        assert!(got.is_some(), "a reachable listener should yield an RTT");
    }

    /// `probe` parameterized on port, mirroring `cloud_location.rs`'s own
    /// `probe_at` split between the real entry point (fixed port 443) and
    /// a test seam that can point at a local listener's ephemeral port.
    fn probe_at(ip: std::net::IpAddr, port: u16) -> Option<Duration> {
        let addr = std::net::SocketAddr::new(ip, port);
        let started = Instant::now();
        TcpStream::connect_timeout(&addr, PROBE_BUDGET).ok()?;
        Some(started.elapsed())
    }

    #[test]
    fn rtt_ms_rounds_down_to_whole_milliseconds() {
        assert_eq!(rtt_ms(Duration::from_micros(1_999)), 1);
        assert_eq!(rtt_ms(Duration::from_millis(42)), 42);
    }

    #[test]
    fn a_shutdown_mid_pass_stops_probing_promptly() {
        let allowed = Mutex::new(AllowedRegions::default());
        let out = Mutex::new(Vec::new());
        let shutdown = Shutdown::default();
        shutdown.request();

        let started = Instant::now();
        run(&allowed, &out, &shutdown);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
