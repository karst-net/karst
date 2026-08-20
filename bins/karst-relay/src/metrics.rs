// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Prometheus exposition for the relay.
//!
//! **Hand-rolled, like `http.rs` beside it, and for the same reason.** The
//! text format is six lines of rules — a `# HELP`, a `# TYPE`, and
//! `name value` — and a client library would bring a registry, a macro layer
//! and a transitive dependency tree to render them. `cargo deny` reviews every
//! one of those, and this crate is a network-facing daemon where the argument
//! for a small dependency surface is strongest.
//!
//! # What is deliberately not here
//!
//! No per-node labels. A relay in a public pool carries thousands of nodes, and
//! a label per node turns a scrape into a cardinality bomb — but the more
//! important reason is disclosure: `ponor-v1.md` §11 bounds what a relay
//! operator learns, and a metrics endpoint that named every node by id would
//! publish the tailnet's membership to anything that could reach it. Totals
//! carry the operational signal without carrying the roster.

use core::fmt::Write as _;

use crate::hub::ConnStats;

/// A point-in-time view of the relay, ready to render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// Nodes connected to this relay right now.
    pub local_clients: usize,
    /// Meshed relays connected right now.
    pub mesh_peers: usize,
    /// Nodes this relay believes are on a meshed peer — §8.
    pub remote_clients: usize,
    /// Everything carried since start, live and departed connections alike.
    pub totals: ConnStats,
    /// Seconds since the process started.
    pub uptime_secs: u64,
}

/// Render the Prometheus text exposition format.
///
/// Counters are named `_total` per the convention, gauges are not, and every
/// metric carries a `# HELP` — an unhelped metric is one the next operator has
/// to read this source to understand.
#[must_use]
pub fn render(s: &Snapshot) -> String {
    let mut out = String::with_capacity(1024);
    let t = &s.totals;

    for (name, help, value) in [
        (
            "karst_relay_clients",
            "Nodes currently connected to this relay.",
            s.local_clients as u64,
        ),
        (
            "karst_relay_mesh_peers",
            "Meshed relays currently connected.",
            s.mesh_peers as u64,
        ),
        (
            "karst_relay_remote_clients",
            "Nodes believed to be connected to a meshed peer.",
            s.remote_clients as u64,
        ),
        (
            "karst_relay_uptime_seconds",
            "Seconds since this relay started.",
            s.uptime_secs,
        ),
    ] {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} gauge");
        let _ = writeln!(out, "{name} {value}");
    }

    for (name, help, value) in [
        (
            "karst_relay_frames_in_total",
            "Frames accepted from connections.",
            t.frames_in,
        ),
        (
            "karst_relay_bytes_in_total",
            "Bytes accepted from connections, frame headers included.",
            t.bytes_in,
        ),
        (
            "karst_relay_frames_out_total",
            "Frames queued towards connections.",
            t.frames_out,
        ),
        (
            "karst_relay_bytes_out_total",
            "Bytes queued towards connections.",
            t.bytes_out,
        ),
        (
            "karst_relay_dropped_rate_total",
            "Frames refused by the per-connection rate limiter.",
            t.dropped_rate,
        ),
        (
            "karst_relay_dropped_queue_total",
            "Frames discarded because a destination's write queue was full.",
            t.dropped_queue,
        ),
        (
            "karst_relay_undeliverable_total",
            "Frames for a destination this relay does not hold.",
            t.undeliverable,
        ),
    ] {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} counter");
        let _ = writeln!(out, "{name} {value}");
    }

    out
}

/// A complete HTTP response carrying the exposition.
///
/// `Connection: close` and an explicit `Content-Length`: this endpoint answers
/// one request per connection and does not implement keep-alive, so saying so
/// is what keeps a scraper from waiting on a socket that will never speak
/// again.
#[must_use]
pub fn http_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    )
}

/// The refusal for anything that is not a `GET` of the metrics path.
#[must_use]
pub fn http_not_found() -> String {
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
}

/// Whether a request line asks for the metrics.
///
/// Deliberately strict: `GET /metrics` and nothing else. A relay's metrics
/// listener is not a web server, and every path it answers is a path somebody
/// has to reason about.
#[must_use]
pub fn wants_metrics(request_line: &str) -> bool {
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(path)) = (parts.next(), parts.next()) else {
        return false;
    };
    method == "GET" && (path == "/metrics" || path == "/metrics/")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn snapshot() -> Snapshot {
        Snapshot {
            local_clients: 3,
            mesh_peers: 1,
            remote_clients: 7,
            totals: ConnStats {
                frames_in: 100,
                bytes_in: 4096,
                frames_out: 98,
                bytes_out: 4000,
                dropped_rate: 1,
                dropped_queue: 2,
                undeliverable: 3,
            },
            uptime_secs: 42,
        }
    }

    #[test]
    fn every_metric_carries_help_and_type() {
        // An unhelped metric is one the next operator has to read this source
        // to understand, which is the failure this format exists to prevent.
        let text = render(&snapshot());
        let names: Vec<&str> = text
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_whitespace().next())
            .collect();
        assert!(!names.is_empty());
        for name in names {
            assert!(
                text.contains(&format!("# HELP {name} ")),
                "{name} has no HELP"
            );
            assert!(
                text.contains(&format!("# TYPE {name} ")),
                "{name} has no TYPE"
            );
        }
    }

    #[test]
    fn counters_are_named_total_and_gauges_are_not() {
        // The convention is load-bearing: a scraper derives rates from `_total`
        // and a gauge that ends in `_total` is silently differentiated.
        let text = render(&snapshot());
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let mut parts = rest.split_whitespace();
                let (Some(name), Some(kind)) = (parts.next(), parts.next()) else {
                    panic!("malformed TYPE line: {line}");
                };
                match kind {
                    "counter" => assert!(name.ends_with("_total"), "counter {name}"),
                    "gauge" => assert!(!name.ends_with("_total"), "gauge {name}"),
                    other => panic!("unexpected metric type {other}"),
                }
            }
        }
    }

    #[test]
    fn the_values_are_the_snapshots() {
        let text = render(&snapshot());
        assert!(text.contains("\nkarst_relay_clients 3\n"));
        assert!(text.contains("\nkarst_relay_frames_in_total 100\n"));
        assert!(text.contains("\nkarst_relay_undeliverable_total 3\n"));
        assert!(text.contains("\nkarst_relay_uptime_seconds 42\n"));
    }

    #[test]
    fn no_metric_names_a_node() {
        // `ponor-v1.md` §11 bounds what a relay operator learns. An endpoint
        // labelled by node id would publish the tailnet's membership to
        // anything that could reach it, which is a disclosure rather than a
        // cardinality problem — though it is that too.
        let text = render(&snapshot());
        assert!(
            !text.contains('{'),
            "a label appeared; this endpoint must carry no per-node dimension"
        );
    }

    #[test]
    fn the_response_declares_its_length_and_closes() {
        let body = render(&snapshot());
        let response = http_response(&body);
        assert!(response.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(response.contains("Connection: close\r\n"));
        assert!(response.ends_with(&body));
    }

    #[test]
    fn only_a_get_of_metrics_is_answered() {
        assert!(wants_metrics("GET /metrics HTTP/1.1"));
        assert!(wants_metrics("GET /metrics/ HTTP/1.1"));
        assert!(!wants_metrics("GET / HTTP/1.1"));
        assert!(!wants_metrics("POST /metrics HTTP/1.1"));
        assert!(!wants_metrics("GET /metrics/../roster HTTP/1.1"));
        assert!(!wants_metrics(""));
        assert!(!wants_metrics("GET"));
    }
}
