// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The opt-in `[metrics] listen` HTTP surface for `karst-scaler advise` —
//! ADR-0045 §7 Phase 1 PR 4 ("Phase 1b starts here").
//!
//! Simpler than `karstd`'s own `metrics_http` (`bins/karstd/src/metrics_http.rs`,
//! which this mirrors in shape — loopback-only `TcpListener`, non-blocking
//! accept + shutdown poll): there is no IPC hop to a separate control
//! process here, because `advise_loop::run` and this listener already live
//! in the same process. Every scrape renders the latest in-process
//! [`Snapshot`] (behind a `Mutex`, updated once per tick) directly, as
//! either Prometheus text (`GET /metrics`) or JSON (`GET /recommendations`)
//! — the same data, two encodings, so a human curling `/recommendations`
//! and a scraper reading `/metrics` can never disagree about what the last
//! tick actually recommended. `/recommendations` is also what resolves PR
//! 5's browser-reachability question: `karst-control` proxies a
//! server-to-server GET here rather than the browser dialing this loopback
//! listener directly.
//!
//! **Loopback-only, enforced at config load, not here**: see
//! `advise_config::AdviseConfig::parse` — by the time `serve` is called,
//! `listen` has already been refused if it was anything else.
//!
//! Before the first tick completes, [`Snapshot`] is `None` and both routes
//! answer `503 Service Unavailable` rather than an empty or fabricated
//! body — a scraper reading "zero pools" on startup would otherwise be
//! indistinguishable from a deployment with genuinely zero configured
//! pools.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use karst_scaler::advise::Recommendation;

/// How long a poll-for-shutdown iteration waits before checking again —
/// mirrors `karstd::metrics_http`'s own constant.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// One tick's recommendation, paired with what [`Recommendation`] itself
/// does not carry: the wall-clock time of the tick, and each pool's
/// *configured* node count (`pool.min_nodes`) — static cost-model data
/// `advise::Recommendation` has no reason to repeat on every tick, but that
/// `/metrics`'s `karst_scaler_configured_nodes` and the console page (PR 5)
/// both need alongside it.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct Snapshot {
    pub tick_unix: i64,
    pub recommendation: Recommendation,
    pub configured_nodes: HashMap<String, u32>,
}

/// Shared between `advise_loop`'s tick loop (writer) and this module's
/// request handler (reader) — a plain `Mutex`, not a channel: the only
/// operation either side needs is "replace with the latest" / "read the
/// latest," never a queue of every tick that was ever produced.
pub(crate) type SharedSnapshot = Arc<Mutex<Option<Snapshot>>>;

/// A cooperative stop signal for [`serve`]'s accept loop — this process has
/// no other shutdown mechanism today (`advise_loop::run`'s own loop runs
/// until killed), so this exists only so this module's own tests can bring
/// the listener down cleanly rather than leaking a thread per test.
#[derive(Debug, Default)]
pub(crate) struct Shutdown(AtomicBool);

impl Shutdown {
    /// Only this module's own tests ever call this — `advise_loop::run`'s
    /// production listener is deliberately fire-and-forget (see its own
    /// comment on why), so a plain, non-test build never calls it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn request(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn requested(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Serve `GET /metrics` and `GET /recommendations` on `listen` until
/// `shutdown` is requested.
///
/// # Errors
/// Binding the listener failed. A per-connection I/O error is logged (via
/// `eprintln!` — this binary has no tracing subscriber, matching the rest of
/// `advise_loop`'s own logging) and does not stop the listener.
pub(crate) fn serve(
    listen: SocketAddr,
    snapshot: &SharedSnapshot,
    shutdown: &Shutdown,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    listener.set_nonblocking(true)?;
    while !shutdown.requested() {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                if let Err(error) = handle(stream, snapshot) {
                    eprintln!("karst-scaler advise: metrics HTTP request failed: {error}");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => std::thread::sleep(POLL_INTERVAL),
        }
    }
    Ok(())
}

fn handle(mut stream: TcpStream, snapshot: &SharedSnapshot) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 || header == "\r\n" || header == "\n" {
            break;
        }
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    if method != "GET" {
        return respond(&mut stream, "404 Not Found", "text/plain", "not found\n");
    }

    // The lock is held only long enough to clone the snapshot — a
    // concurrent tick-loop write blocks for a clone, never for a full
    // request/response round trip.
    let current = snapshot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();

    match (path, current) {
        ("/metrics", Some(snap)) => respond(
            &mut stream,
            "200 OK",
            "text/plain; version=0.0.4",
            &render_prometheus(&snap),
        ),
        ("/recommendations", Some(snap)) => {
            let body = serde_json::to_string(&snap)
                .unwrap_or_else(|_| "{\"error\":\"could not encode recommendation\"}".to_owned());
            respond(&mut stream, "200 OK", "application/json", &body)
        }
        ("/metrics" | "/recommendations", None) => respond(
            &mut stream,
            "503 Service Unavailable",
            "text/plain",
            "karst-scaler advise: no tick has completed yet\n",
        ),
        _ => respond(&mut stream, "404 Not Found", "text/plain", "not found\n"),
    }
}

/// Render `snap` as Prometheus text exposition format — metric names and
/// labels per `docs/observability.md`'s new `karst-scaler` table.
fn render_prometheus(snap: &Snapshot) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();

    out.push_str("# HELP karst_scaler_recommended_nodes The Advisor's desired node count for this pool this tick.\n");
    out.push_str("# TYPE karst_scaler_recommended_nodes gauge\n");
    for pool in &snap.recommendation.pools {
        let _ = writeln!(
            out,
            "karst_scaler_recommended_nodes{{pool=\"{}\"}} {}",
            escape(&pool.pool_id),
            pool.desired_nodes
        );
    }

    out.push_str("# HELP karst_scaler_configured_nodes The pool's own configured floor (pool.min_nodes) — \"configured baseline,\" not an introspected live count. See docs/observability.md.\n");
    out.push_str("# TYPE karst_scaler_configured_nodes gauge\n");
    for pool in &snap.recommendation.pools {
        let configured = snap
            .configured_nodes
            .get(&pool.pool_id)
            .copied()
            .unwrap_or(0);
        let _ = writeln!(
            out,
            "karst_scaler_configured_nodes{{pool=\"{}\"}} {configured}",
            escape(&pool.pool_id),
        );
    }

    out.push_str("# HELP karst_scaler_cost_delta_usd Recommended allocation's cost for the rest of the period, minus the configured floor's — positive means the Advisor recommends spending more.\n");
    out.push_str("# TYPE karst_scaler_cost_delta_usd gauge\n");
    for pool in &snap.recommendation.pools {
        let _ = writeln!(
            out,
            "karst_scaler_cost_delta_usd{{pool=\"{}\"}} {}",
            escape(&pool.pool_id),
            pool.cost_delta
        );
    }

    out.push_str("# HELP karst_scaler_binding_constraint 1 for the hard constraint that is binding this pool's recommendation; see the `constraint` label.\n");
    out.push_str("# TYPE karst_scaler_binding_constraint gauge\n");
    for pool in &snap.recommendation.pools {
        let constraint = constraint_label(pool.binding_constraint);
        let _ = writeln!(
            out,
            "karst_scaler_binding_constraint{{pool=\"{}\",constraint=\"{constraint}\"}} 1",
            escape(&pool.pool_id),
        );
    }

    out.push_str("# HELP karst_scaler_baseline_cost_usd Sum of every pool's naive-greedy-baseline cost this tick — the solver's own correctness floor, not \"the bill\". See docs/observability.md.\n");
    out.push_str("# TYPE karst_scaler_baseline_cost_usd gauge\n");
    let _ = writeln!(
        out,
        "karst_scaler_baseline_cost_usd {}",
        snap.recommendation.baseline_cost
    );

    out.push_str(
        "# HELP karst_scaler_last_tick_timestamp_seconds Unix time of the last completed tick.\n",
    );
    out.push_str("# TYPE karst_scaler_last_tick_timestamp_seconds gauge\n");
    let _ = writeln!(
        out,
        "karst_scaler_last_tick_timestamp_seconds {}",
        snap.tick_unix
    );

    out
}

/// Reuses `Constraint`'s own `Serialize` impl (`serde(rename_all =
/// "snake_case")`) rather than a second hand-written mapping here — see
/// that derive's doc comment for why one spelling is the point.
fn constraint_label(constraint: karst_scaler::advise::Constraint) -> String {
    match serde_json::to_value(constraint) {
        Ok(serde_json::Value::String(s)) => s,
        _ => "none".to_owned(),
    }
}

/// Prometheus label values escape `\`, `"`, and newline — this crate never
/// produces a pool ID containing any of them today (`cost_model.rs`'s own
/// TOML-key-derived pool IDs), but a label-value escaper that assumes its
/// input is already safe is the kind of assumption that stops being true
/// without anyone noticing.
fn escape(label: &str) -> String {
    label
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn respond(
    stream: &mut impl Write,
    status: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
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
    use karst_scaler::advise::{Constraint, PoolRecommendation};
    use std::io::Read;

    fn sample_snapshot() -> Snapshot {
        Snapshot {
            tick_unix: 1_700_000_000,
            recommendation: Recommendation {
                pools: vec![PoolRecommendation {
                    pool_id: "aws-use1".to_owned(),
                    desired_nodes: 5,
                    cost_delta: 340.5,
                    binding_constraint: Constraint::Headroom,
                }],
                total_cost_delta: -10.0,
                baseline_cost: 500.0,
            },
            configured_nodes: HashMap::from([("aws-use1".to_owned(), 2)]),
        }
    }

    #[test]
    fn prometheus_text_carries_every_named_series() {
        let text = render_prometheus(&sample_snapshot());
        assert!(text.contains("karst_scaler_recommended_nodes{pool=\"aws-use1\"} 5"));
        assert!(text.contains("karst_scaler_configured_nodes{pool=\"aws-use1\"} 2"));
        assert!(text.contains("karst_scaler_cost_delta_usd{pool=\"aws-use1\"} 340.5"));
        assert!(text.contains(
            "karst_scaler_binding_constraint{pool=\"aws-use1\",constraint=\"headroom\"} 1"
        ));
        assert!(text.contains("karst_scaler_baseline_cost_usd 500"));
        assert!(text.contains("karst_scaler_last_tick_timestamp_seconds 1700000000"));
    }

    #[test]
    fn a_pool_id_needing_escape_does_not_break_the_label() {
        let mut snap = sample_snapshot();
        snap.recommendation.pools[0].pool_id = "weird\"pool".to_owned();
        let text = render_prometheus(&snap);
        assert!(text.contains("pool=\"weird\\\"pool\""), "{text}");
    }

    fn get(bound: SocketAddr, path: &str) -> String {
        let mut got = String::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match TcpStream::connect(bound) {
                Ok(mut stream) => {
                    stream
                        .write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                        .expect("write request");
                    stream.read_to_string(&mut got).expect("read response");
                    return got;
                }
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("connect: {e}"),
            }
        }
    }

    #[test]
    fn before_the_first_tick_both_routes_answer_503_not_an_empty_body() {
        let http_addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let probe = TcpListener::bind(http_addr).expect("bind http");
        let bound = probe.local_addr().expect("local addr");
        drop(probe);

        let snapshot: SharedSnapshot = Arc::new(Mutex::new(None));
        let shutdown = Shutdown::default();

        std::thread::scope(|scope| {
            let http_thread = scope.spawn(|| serve(bound, &snapshot, &shutdown));
            let got = get(bound, "/metrics");
            shutdown.request();
            http_thread.join().expect("http thread").expect("serve");
            assert!(got.starts_with("HTTP/1.1 503"), "got {got:?}");
        });
    }

    #[test]
    fn after_a_tick_metrics_and_recommendations_both_serve_it() {
        let http_addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let probe = TcpListener::bind(http_addr).expect("bind http");
        let bound = probe.local_addr().expect("local addr");
        drop(probe);

        let snapshot: SharedSnapshot = Arc::new(Mutex::new(Some(sample_snapshot())));
        let shutdown = Shutdown::default();

        std::thread::scope(|scope| {
            let http_thread = scope.spawn(|| serve(bound, &snapshot, &shutdown));

            let metrics = get(bound, "/metrics");
            assert!(metrics.contains("200 OK"), "{metrics}");
            assert!(metrics.contains("karst_scaler_recommended_nodes"));

            let recs = get(bound, "/recommendations");
            assert!(recs.contains("200 OK"), "{recs}");
            assert!(recs.contains("\"pool_id\":\"aws-use1\""), "{recs}");
            assert!(recs.contains("\"configured_nodes\""), "{recs}");

            let missing = get(bound, "/nonsense");
            assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");

            shutdown.request();
            http_thread.join().expect("http thread").expect("serve");
        });
    }
}
