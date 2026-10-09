// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The `karst-scaler advise` subcommand's own loop — ADR-0045 §7 Phase 1:
//! "the planner and constraint set... running continuously." This is the
//! one place in the crate with a network dependency; see `Cargo.toml`'s own
//! comment on why `advise` is the deliberate exception to Phase 0's
//! "no network stack" posture, and [`karst_scaler::advise`]'s module doc for
//! the solver this loop drives.
//!
//! Bin-target-only (not part of the `karst_scaler` library — see
//! `[[bin]]`/`[lib]` in `Cargo.toml`): this keeps the library itself free of
//! a network dependency even though the binary built from the same crate
//! now has one.
//!
//! ## Two placeholders named, not hidden
//!
//! - **Which meter bills for a node.** [`karst_scaler::advise::PoolState`]
//!   takes `node_meter` per pool; this loop hardcodes `"instance_hours"`
//!   for every pool, matching the name ADR-0045 §2's own examples and every
//!   existing cost-model fixture in this crate use for exactly that meter.
//!   A pool whose operator named it something else gets no recommendation
//!   from this loop today — a per-pool config knob is follow-up work, not
//!   silently assumed solved.
//! - **Turning a §4a RTT histogram into a node count.** Neither ADR-0045
//!   nor any later PR in its own Phase 1 plan specifies this mapping —
//!   [`karst_scaler::advise`] deliberately takes `demand_nodes` as an
//!   already-resolved input so its own solver logic does not have to guess
//!   at one. [`demand_nodes_by_region`] below is a deliberately crude stand-
//!   in (every RTT bucket observation counts as the same "one session," a
//!   fixed sessions-per-node constant converts a session count to a node
//!   count), good enough to make the loop end-to-end runnable and its
//!   output sanity-checkable, not a claim that it is the right formula. A
//!   real one needs a relay's actual measured per-node session or bandwidth
//!   capacity, which no existing signal in this tree provides yet.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use karst_scaler::advise::{self, PoolState, Problem};
use karst_scaler::cost_model::Document;
use karst_scaler::position::Position;
use karst_scaler::simulate::{hours_remaining_in_period, period_key};

/// See [`demand_nodes_by_region`]'s own doc comment.
const PLACEHOLDER_SESSIONS_PER_NODE: f64 = 100.0;

/// See the module doc's "two placeholders" section.
const NODE_METER: &str = "instance_hours";

pub(crate) struct Config {
    pub cost_model_path: String,
    /// The control server's own API base, e.g. `https://control.example.test/api`
    /// -- `/karst/v1/demand/regions` and `/karst/v1/demand/anchors` are
    /// appended to this directly.
    pub control_api_base: String,
    /// A `UserRoleAdvisor`-scoped PAT -- see ADR-0045 §7 Phase 1's own PR 1
    /// (`relayreg.Store.DemandByRegion`'s doc comment) for why a dedicated
    /// role exists for exactly this read.
    pub pat: String,
    pub poll_interval: Duration,
}

#[derive(Debug, Deserialize)]
struct RegionDemandRow {
    region: String,
    #[serde(rename = "account_id")]
    _account_id: String,
    rtt_under_20ms: i64,
    rtt_20_to_50ms: i64,
    rtt_50_to_100ms: i64,
    rtt_over_100ms: i64,
}

#[derive(Debug, Deserialize)]
struct AnchorHistogramRow {
    provider: String,
    region: String,
    bucket: String,
    count: i64,
}

/// Runs the poll loop forever, logging each tick and continuing past a
/// single tick's failure (a transient control-server or network hiccup
/// should not kill a long-lived advisory process — there is nothing here
/// urgent enough to justify exiting over one missed tick).
///
/// # Errors
/// Only for setup: the cost-model file failing to load or validate.
pub(crate) fn run(config: &Config) -> Result<(), String> {
    let doc = Document::load(Path::new(&config.cost_model_path))
        .map_err(|e| format!("reading {}: {e}", config.cost_model_path))?;
    doc.validate().map_err(|e| e.to_string())?;

    let agent = build_agent()?;
    let mut positions: HashMap<String, Position> = HashMap::new();

    loop {
        match tick(&doc, &mut positions, config, &agent) {
            Ok(()) => {}
            Err(e) => eprintln!("karst-scaler advise: tick failed: {e}"),
        }
        std::thread::sleep(config.poll_interval);
    }
}

/// An `Agent` with root certs loaded from the OS's own store via
/// `rustls-native-certs` — see `Cargo.toml`'s own comment for why this
/// loop does not use ureq's bundled root-certificate options.
fn build_agent() -> Result<ureq::Agent, String> {
    let loaded = rustls_native_certs::load_native_certs();
    if loaded.certs.is_empty() {
        return Err("the host has no usable certificate authority roots".to_owned());
    }
    let roots: ureq::tls::RootCerts = loaded
        .certs
        .into_iter()
        .map(|der| ureq::tls::Certificate::from_der(der.as_ref()).to_owned())
        .collect::<Vec<_>>()
        .into();
    let tls_config = ureq::tls::TlsConfig::builder().root_certs(roots).build();
    let config = ureq::Agent::config_builder().tls_config(tls_config).build();
    Ok(ureq::Agent::new_with_config(config))
}

fn tick(
    doc: &Document,
    positions: &mut HashMap<String, Position>,
    config: &Config,
    agent: &ureq::Agent,
) -> Result<(), String> {
    let now = now_unix()?;
    let period = period_key(now);
    let remaining_period_hours = hours_remaining_in_period(now);

    let regions: Vec<RegionDemandRow> = fetch(agent, config, "/karst/v1/demand/regions")?;
    let anchors: Vec<AnchorHistogramRow> = fetch(agent, config, "/karst/v1/demand/anchors")?;
    let demand_by_region = demand_nodes_by_region(&regions);

    // Nothing is ever observed into these positions today: Phase 1 has no
    // live feed of real per-node usage (that needs either Phase 2's driver
    // interface or a separate usage-reporting pipeline this phase does not
    // build), so each pool's month-to-date total stays at zero and
    // `advise`'s pricing is always relative to a zero baseline. The
    // bookkeeping stays in place -- a real usage feed, once one exists,
    // plugs in here by observing into the same positions -- rather than
    // being built and then thrown away.
    for pool_id in doc.pools.keys() {
        positions
            .entry(pool_id.clone())
            .or_insert_with(|| Position::new(period));
    }

    let mut states = Vec::with_capacity(doc.pools.len());
    for (pool_id, pool) in &doc.pools {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let demand_nodes = demand_by_region.get(&pool.region).copied().unwrap_or(0.0) as u32;
        // Inserted above for every pool_id in doc.pools, so this cannot
        // actually miss -- `unwrap_or_else(|| unreachable!())` rather than
        // `.expect(...)` to satisfy this crate's workspace-wide
        // `clippy::expect_used` deny, matching existing precedent
        // (`crates/karst-proto/src/dos.rs`) for a Result/Option API whose
        // failure case genuinely cannot occur here.
        let position = positions.get(pool_id).unwrap_or_else(|| unreachable!());
        states.push(PoolState {
            pool_id,
            pool,
            position,
            demand_nodes,
            node_meter: NODE_METER,
        });
    }

    let problem = Problem {
        pools: &states,
        headroom: 0.2,
        budget_cap: None,
        remaining_period_hours,
    };
    let recommendation = advise::advise(&problem).map_err(|e| e.to_string())?;

    println!(
        "tick_unix={now} pools={} total_cost_delta={:.2} baseline_cost={:.2}",
        recommendation.pools.len(),
        recommendation.total_cost_delta,
        recommendation.baseline_cost
    );
    for pool in &recommendation.pools {
        println!(
            "  pool={} desired_nodes={} cost_delta={:+.2} binding={:?}",
            pool.pool_id, pool.desired_nodes, pool.cost_delta, pool.binding_constraint
        );
    }
    let anchor_total: i64 = anchors.iter().map(|a| a.count).sum();
    println!(
        "  anchors: {} rows, {anchor_total} total observations (candidate-region promotion not implemented)",
        anchors.len()
    );
    for anchor in &anchors {
        println!(
            "    {}/{} {}={}",
            anchor.provider, anchor.region, anchor.bucket, anchor.count
        );
    }

    Ok(())
}

/// See the module doc's "two placeholders" section.
fn demand_nodes_by_region(rows: &[RegionDemandRow]) -> HashMap<String, f64> {
    let mut sessions: HashMap<String, i64> = HashMap::new();
    for row in rows {
        let total =
            row.rtt_under_20ms + row.rtt_20_to_50ms + row.rtt_50_to_100ms + row.rtt_over_100ms;
        *sessions.entry(row.region.clone()).or_insert(0) += total;
    }
    sessions
        .into_iter()
        .map(|(region, total)| {
            #[allow(clippy::cast_precision_loss)]
            let total = total as f64;
            (
                region,
                (total / PLACEHOLDER_SESSIONS_PER_NODE).ceil().max(0.0),
            )
        })
        .collect()
}

fn fetch<T: serde::de::DeserializeOwned>(
    agent: &ureq::Agent,
    config: &Config,
    path: &str,
) -> Result<T, String> {
    let url = format!("{}{path}", config.control_api_base);
    agent
        .get(&url)
        .header("Authorization", &format!("Bearer {}", config.pat))
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?
        .body_mut()
        .read_json::<T>()
        .map_err(|e| format!("GET {url}: decoding response: {e}"))
}

fn now_unix() -> Result<i64, String> {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock: {e}"))?;
    Ok(i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX))
}
