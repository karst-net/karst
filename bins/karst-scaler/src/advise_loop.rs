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
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use karst_scaler::advise::{self, PoolState, Problem};
use karst_scaler::cost_model::Document;
use karst_scaler::position::Position;
use karst_scaler::simulate::{hours_remaining_in_period, period_key};

use crate::metrics_http::{self, SharedSnapshot, Snapshot};

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
    /// The opt-in `[metrics] listen` address -- ADR-0045 §7 Phase 1 PR 4.
    /// `None` (the default) starts no listener at all; already refused at
    /// config-load time if configured non-loopback -- see
    /// `advise_config::AdviseConfig::parse`.
    pub metrics_listen: Option<SocketAddr>,
}

#[derive(Debug, Deserialize)]
struct RegionDemandRow {
    region: String,
    account_id: String,
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

    // `None` unless `[metrics] listen` is configured -- no listener binds,
    // and `tick` below skips building a `Snapshot` nobody can ever read,
    // the same default-off posture `karstd`'s own `[metrics]` section has.
    let snapshot: Option<SharedSnapshot> = config.metrics_listen.map(|listen| {
        let snapshot: SharedSnapshot = Arc::new(Mutex::new(None));
        let shared = Arc::clone(&snapshot);
        // Detached, not joined: this process has no shutdown path of its
        // own today (this `loop` below runs until killed), so there is
        // nothing for this thread to be joined against -- see
        // `metrics_http::Shutdown`'s own doc comment.
        std::thread::spawn(move || {
            let shutdown = metrics_http::Shutdown::default();
            if let Err(e) = metrics_http::serve(listen, &shared, &shutdown) {
                eprintln!("karst-scaler advise: metrics listener on {listen} failed: {e}");
            }
        });
        snapshot
    });

    loop {
        match tick(&doc, &mut positions, config, &agent, snapshot.as_ref()) {
            Ok(()) => {}
            Err(e) => eprintln!("karst-scaler advise: tick failed: {e}"),
        }
        std::thread::sleep(config.poll_interval);
    }
}

/// An `Agent` with root certs loaded from the OS's own store via
/// `rustls-native-certs` — see `Cargo.toml`'s own comment for why this
/// loop does not use ureq's bundled root-certificate options.
///
/// `pub(crate)`: `drive_loop` (ADR-0045 §7 Phase 2) builds the same kind of
/// `Agent` for the same reason and should not have to duplicate this.
pub(crate) fn build_agent() -> Result<ureq::Agent, String> {
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

/// Fetches this tick's region-demand signal and runs [`advise::advise`]
/// against it. Factored out of [`tick`] so `drive_loop` (ADR-0045 §7
/// Phase 2) reuses exactly the same solver call this subcommand already
/// runs, rather than a second copy of it — `drive` differs from `advise`
/// only in what happens *after* a recommendation exists.
///
/// `pub(crate)`: used by `drive_loop`, a sibling module in this same binary
/// crate, not part of the `karst_scaler` library.
pub(crate) fn tick_recommendation(
    doc: &Document,
    positions: &mut HashMap<String, Position>,
    config: &Config,
    agent: &ureq::Agent,
) -> Result<(i64, advise::Recommendation, Vec<UnplaceableDemand>), String> {
    let now = now_unix()?;
    let period = period_key(now);
    let remaining_period_hours = hours_remaining_in_period(now);

    let regions: Vec<RegionDemandRow> = fetch(agent, config, "/karst/v1/demand/regions")?;
    let (demand_by_pool, unplaceable) = attribute_demand(doc, &regions);

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
        let demand_nodes = demand_by_pool.get(pool_id).copied().unwrap_or(0);
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
    Ok((now, recommendation, unplaceable))
}

fn tick(
    doc: &Document,
    positions: &mut HashMap<String, Position>,
    config: &Config,
    agent: &ureq::Agent,
    snapshot: Option<&SharedSnapshot>,
) -> Result<(), String> {
    let (now, recommendation, unplaceable) = tick_recommendation(doc, positions, config, agent)?;
    let anchors: Vec<AnchorHistogramRow> = fetch(agent, config, "/karst/v1/demand/anchors")?;

    if let Some(shared) = snapshot {
        let configured_nodes = doc
            .pools
            .iter()
            .map(|(pool_id, pool)| (pool_id.clone(), pool.min_nodes))
            .collect();
        let new_snapshot = Snapshot {
            tick_unix: now,
            recommendation: recommendation.clone(),
            configured_nodes,
            unplaceable_demand: unplaceable.clone(),
        };
        *shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(new_snapshot);
    }

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
    if !unplaceable.is_empty() {
        println!(
            "  residency: {} account/region pairs could not be placed on any pool \
             (ADR-0045 §3 -- no pool satisfies their residency requirement)",
            unplaceable.len()
        );
        for u in &unplaceable {
            println!(
                "    account={} region={} nodes={}",
                u.account_id, u.region, u.nodes
            );
        }
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

/// One account's demand that matched zero pools eligible to serve it —
/// ADR-0045 §3's Residency constraint, §3's own "not a candidate, not a
/// penalized candidate" framing: this demand is never silently folded
/// into some other, ineligible pool's count. See [`attribute_demand`].
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct UnplaceableDemand {
    pub region: String,
    pub account_id: String,
    pub nodes: u32,
}

/// Aggregates `rows` by `(region, account_id)`, then attributes each
/// pair's demand to every pool in `doc.pools` whose region matches *and*
/// whose [`crate::cost_model::Pool::residency_tags`] satisfy that
/// account's own requirement (`doc.account_residency` — absent or empty
/// means no requirement, eligible everywhere) — ADR-0045 §3's Residency
/// constraint. A pair matching zero eligible pools in its own region is
/// never silently dropped into the regional total; it comes back
/// separately as [`UnplaceableDemand`].
///
/// When no account has a residency requirement at all, every pool in a
/// region receives that region's full combined demand, exactly as
/// before this constraint existed — including the pre-existing, already
/// documented simplification that two pools sharing one region both see
/// its full demand rather than splitting it; this change narrows what
/// counts toward a pool, it does not newly arbitrate between several
/// equally-eligible ones. See the module doc's "two placeholders"
/// section for the sessions -> nodes formula this reuses unchanged.
fn attribute_demand(
    doc: &Document,
    rows: &[RegionDemandRow],
) -> (HashMap<String, u32>, Vec<UnplaceableDemand>) {
    let mut sessions_by_region_account: HashMap<(String, String), i64> = HashMap::new();
    for row in rows {
        let total =
            row.rtt_under_20ms + row.rtt_20_to_50ms + row.rtt_50_to_100ms + row.rtt_over_100ms;
        *sessions_by_region_account
            .entry((row.region.clone(), row.account_id.clone()))
            .or_insert(0) += total;
    }

    let mut sessions_by_pool: HashMap<String, i64> = HashMap::new();
    let mut unplaceable = Vec::new();

    for ((region, account_id), total_sessions) in sessions_by_region_account {
        let required = doc
            .account_residency
            .get(&account_id)
            .map_or(&[][..], Vec::as_slice);
        let eligible_pool_ids: Vec<&str> = doc
            .pools
            .iter()
            .filter(|(_, pool)| pool.region == region && pool.satisfies_residency(required))
            .map(|(pool_id, _)| pool_id.as_str())
            .collect();

        if eligible_pool_ids.is_empty() {
            unplaceable.push(UnplaceableDemand {
                region,
                account_id,
                nodes: sessions_to_nodes(total_sessions),
            });
            continue;
        }

        for pool_id in eligible_pool_ids {
            *sessions_by_pool.entry(pool_id.to_owned()).or_insert(0) += total_sessions;
        }
    }

    let demand_nodes = sessions_by_pool
        .into_iter()
        .map(|(pool_id, total)| (pool_id, sessions_to_nodes(total)))
        .collect();
    (demand_nodes, unplaceable)
}

/// See the module doc's "two placeholders" section — the crude
/// sessions-per-node stand-in, unchanged by residency attribution.
fn sessions_to_nodes(total_sessions: i64) -> u32 {
    #[allow(clippy::cast_precision_loss)]
    let total = total_sessions as f64;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let nodes = (total / PLACEHOLDER_SESSIONS_PER_NODE).ceil().max(0.0) as u32;
    nodes
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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use karst_scaler::cost_model::{CostModel, Pool, Provider};

    fn pool(region: &str, residency_tags: &[&str]) -> Pool {
        Pool {
            provider: Provider::Onprem,
            region: region.to_owned(),
            cost_model: CostModel::default(),
            min_nodes: 0,
            nodes_max: None,
            residency_tags: residency_tags.iter().map(|t| (*t).to_owned()).collect(),
        }
    }

    fn row(region: &str, account_id: &str, sessions: i64) -> RegionDemandRow {
        // All of one account's sessions in one RTT bucket -- attribution
        // only cares about the per-(region, account) total.
        RegionDemandRow {
            region: region.to_owned(),
            account_id: account_id.to_owned(),
            rtt_under_20ms: sessions,
            rtt_20_to_50ms: 0,
            rtt_50_to_100ms: 0,
            rtt_over_100ms: 0,
        }
    }

    #[test]
    fn an_account_with_no_residency_requirement_is_counted_in_every_pool_sharing_its_region() {
        // The pre-existing, already-documented simplification: two pools
        // in one region both see the region's full demand. This must
        // hold unchanged when nothing has a residency requirement at
        // all -- the regression case.
        let mut doc = Document::default();
        doc.pools.insert("a".to_owned(), pool("eu-west-1", &[]));
        doc.pools.insert("b".to_owned(), pool("eu-west-1", &[]));
        let rows = [row("eu-west-1", "acct-1", 500)];

        let (demand, unplaceable) = attribute_demand(&doc, &rows);

        assert!(unplaceable.is_empty());
        assert_eq!(demand.get("a").copied(), Some(5));
        assert_eq!(demand.get("b").copied(), Some(5));
    }

    #[test]
    fn an_ineligible_accounts_demand_is_excluded_from_a_mismatched_pool() {
        let mut doc = Document::default();
        doc.pools
            .insert("eu-pool".to_owned(), pool("eu-west-1", &["eu"]));
        doc.pools
            .insert("plain-pool".to_owned(), pool("eu-west-1", &[]));
        doc.account_residency
            .insert("acct-eu".to_owned(), vec!["eu".to_owned()]);
        let rows = [row("eu-west-1", "acct-eu", 500)];

        let (demand, unplaceable) = attribute_demand(&doc, &rows);

        assert!(unplaceable.is_empty());
        assert_eq!(demand.get("eu-pool").copied(), Some(5));
        // Not eligible for acct-eu's demand -- its own tags don't satisfy
        // the account's requirement, so it gets none of it.
        assert_eq!(demand.get("plain-pool").copied(), None);
    }

    #[test]
    fn demand_with_no_eligible_pool_anywhere_is_unplaceable_not_dropped_into_another_pool() {
        let mut doc = Document::default();
        doc.pools
            .insert("plain-pool".to_owned(), pool("eu-west-1", &[]));
        doc.account_residency
            .insert("acct-eu".to_owned(), vec!["eu".to_owned()]);
        let rows = [row("eu-west-1", "acct-eu", 500)];

        let (demand, unplaceable) = attribute_demand(&doc, &rows);

        assert_eq!(demand.get("plain-pool").copied(), None);
        assert_eq!(unplaceable.len(), 1);
        let only = unplaceable.first().expect("one unplaceable entry");
        assert_eq!(only.region, "eu-west-1");
        assert_eq!(only.account_id, "acct-eu");
        assert_eq!(only.nodes, 5);
    }

    #[test]
    fn an_account_absent_from_account_residency_has_no_restriction() {
        let mut doc = Document::default();
        doc.pools.insert("a".to_owned(), pool("eu-west-1", &["eu"]));
        // A different account does have a requirement, but acct-open
        // (this test's account) has no entry at all.
        doc.account_residency
            .insert("acct-strict".to_owned(), vec!["us".to_owned()]);
        let rows = [row("eu-west-1", "acct-open", 300)];

        let (demand, unplaceable) = attribute_demand(&doc, &rows);

        assert!(unplaceable.is_empty());
        assert_eq!(demand.get("a").copied(), Some(3));
    }

    #[test]
    fn demand_in_a_different_region_never_reaches_a_pool_elsewhere() {
        let mut doc = Document::default();
        doc.pools.insert("eu".to_owned(), pool("eu-west-1", &[]));
        doc.pools.insert("us".to_owned(), pool("us-east-1", &[]));
        let rows = [row("eu-west-1", "acct-1", 500)];

        let (demand, unplaceable) = attribute_demand(&doc, &rows);

        assert!(unplaceable.is_empty());
        assert_eq!(demand.get("eu").copied(), Some(5));
        assert_eq!(demand.get("us").copied(), None);
    }
}
