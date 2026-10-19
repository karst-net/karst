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
use karst_scaler::cost_model::{Document, PoolKind};
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
) -> Result<TickOutcome, String> {
    let now = now_unix()?;
    let period = period_key(now);
    let remaining_period_hours = hours_remaining_in_period(now);

    let regions: Vec<RegionDemandRow> = fetch(agent, config, "/karst/v1/demand/regions")?;
    let (demand_by_pool, unplaceable_demand) = attribute_demand(doc, &regions);
    let p95_by_region = region_p95_rtt_ms(&regions);

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
    Ok(TickOutcome {
        tick_unix: now,
        recommendation,
        unplaceable_demand,
        region_p95_rtt_ms: p95_by_region,
    })
}

/// One tick's full result — grouped into a struct, not a growing tuple,
/// now that it carries two independent signals ([`UnplaceableDemand`]'s
/// own Residency check, this module's own Latency estimate) alongside
/// the sizing [`advise::Recommendation`] itself.
pub(crate) struct TickOutcome {
    pub tick_unix: i64,
    pub recommendation: advise::Recommendation,
    pub unplaceable_demand: Vec<UnplaceableDemand>,
    /// ADR-0045 §3's Latency constraint: this tick's estimated p95 RTT
    /// per region, by region — see [`region_p95_rtt_ms`]. Compared
    /// against [`Document::latency_thresholds`] by callers, not stored
    /// pre-compared, the same "expose the raw signal" posture
    /// `metrics_http`'s own Prometheus gauges take.
    pub region_p95_rtt_ms: HashMap<String, f64>,
}

fn tick(
    doc: &Document,
    positions: &mut HashMap<String, Position>,
    config: &Config,
    agent: &ureq::Agent,
    snapshot: Option<&SharedSnapshot>,
) -> Result<(), String> {
    let outcome = tick_recommendation(doc, positions, config, agent)?;
    let anchors: Vec<AnchorHistogramRow> = fetch(agent, config, "/karst/v1/demand/anchors")?;

    if let Some(shared) = snapshot {
        let configured_nodes = doc
            .pools
            .iter()
            .map(|(pool_id, pool)| (pool_id.clone(), pool.min_nodes))
            .collect();
        let new_snapshot = Snapshot {
            tick_unix: outcome.tick_unix,
            recommendation: outcome.recommendation.clone(),
            configured_nodes,
            unplaceable_demand: outcome.unplaceable_demand.clone(),
            region_p95_rtt_ms: outcome.region_p95_rtt_ms.clone(),
            latency_thresholds_ms: doc.latency_thresholds.clone(),
        };
        *shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(new_snapshot);
    }

    println!(
        "tick_unix={} pools={} total_cost_delta={:.2} baseline_cost={:.2}",
        outcome.tick_unix,
        outcome.recommendation.pools.len(),
        outcome.recommendation.total_cost_delta,
        outcome.recommendation.baseline_cost
    );
    for pool in &outcome.recommendation.pools {
        println!(
            "  pool={} desired_nodes={} cost_delta={:+.2} binding={:?}",
            pool.pool_id, pool.desired_nodes, pool.cost_delta, pool.binding_constraint
        );
    }
    if !outcome.unplaceable_demand.is_empty() {
        println!(
            "  residency: {} account/region pairs could not be placed on any pool \
             (ADR-0045 §3 -- no pool satisfies their residency requirement)",
            outcome.unplaceable_demand.len()
        );
        for u in &outcome.unplaceable_demand {
            println!(
                "    account={} region={} nodes={}",
                u.account_id, u.region, u.nodes
            );
        }
    }
    print_latency_breaches(doc, &outcome.region_p95_rtt_ms);
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
/// pair's demand to every `Relay`-kind pool in `doc.pools` whose region
/// matches *and* whose [`crate::cost_model::Pool::residency_tags`] satisfy
/// that account's own requirement (`doc.account_residency` — absent or
/// empty means no requirement, eligible everywhere) — ADR-0045 §3's
/// Residency constraint. A pair matching zero eligible pools in its own
/// region is never silently dropped into the regional total; it comes back
/// separately as [`UnplaceableDemand`].
///
/// `rows` (`/karst/v1/demand/regions`) is relay session telemetry only —
/// no equivalent signal exists for any other [`karst_scaler::cost_model::PoolKind`]
/// yet (ADR-0045 §7b) — so a `Turn`-kind pool is never an eligible
/// destination here, even when its region and residency tags would
/// otherwise match. It is sized by its own `min_nodes`/`nodes_max` alone
/// (`advise::advise`'s `effective_floor` with `demand_nodes` fixed at 0)
/// until a TURN-specific demand signal exists. A region with only
/// `Turn`-kind pools therefore reports its relay demand as unplaceable,
/// the same as a region with no pool at all — correct, not a gap: nothing
/// there can serve it.
///
/// When no account has a residency requirement at all, every eligible pool
/// in a region receives that region's full combined demand, exactly as
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
            .filter(|(_, pool)| {
                pool.kind == PoolKind::Relay
                    && pool.region == region
                    && pool.satisfies_residency(required)
            })
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

/// The four RTT bucket boundaries, in order -- `rtt_under_20ms`'s own
/// upper bound, then `rtt_20_to_50ms`'s, then `rtt_50_to_100ms`'s. The
/// open-ended last bucket (`rtt_over_100ms`) has no upper bound at all;
/// see [`region_p95_rtt_ms`] for how that case is represented.
const RTT_BUCKET_BOUNDS_MS: [f64; 3] = [20.0, 50.0, 100.0];

/// ADR-0045 §3's Latency constraint: this tick's estimated p95 RTT, by
/// region, summed across every account (latency is a property of
/// "clients in region R" collectively, unlike [`attribute_demand`]'s own
/// per-account Residency attribution). A region with zero sessions this
/// tick is omitted entirely from the result -- no signal, not a zero.
///
/// Estimated the same way `calculateP95FromHistogram` already does in
/// `server/management/server/telemetry/account_aggregator.go`: walk the
/// buckets in ascending order, report the first one whose cumulative
/// count reaches `ceil(total * 0.95)`'s own upper bound. The open-ended
/// last bucket has no upper bound to report -- [`f64::INFINITY`] instead
/// of fabricating a number the histogram cannot actually support, which
/// also makes "is this a breach" a plain `>` comparison with no special
/// case at the call site.
fn region_p95_rtt_ms(rows: &[RegionDemandRow]) -> HashMap<String, f64> {
    let mut buckets: HashMap<String, [i64; 4]> = HashMap::new();
    for row in rows {
        let entry = buckets.entry(row.region.clone()).or_insert([0; 4]);
        entry[0] += row.rtt_under_20ms;
        entry[1] += row.rtt_20_to_50ms;
        entry[2] += row.rtt_50_to_100ms;
        entry[3] += row.rtt_over_100ms;
    }

    buckets
        .into_iter()
        .filter_map(|(region, counts)| {
            let total: i64 = counts.iter().sum();
            if total <= 0 {
                return None;
            }
            #[allow(clippy::cast_precision_loss)]
            let target = (total as f64 * 0.95).ceil();
            let mut cumulative: i64 = 0;
            for (i, count) in counts.iter().enumerate() {
                cumulative += count;
                #[allow(clippy::cast_precision_loss)]
                if cumulative as f64 >= target {
                    let p95 = RTT_BUCKET_BOUNDS_MS
                        .get(i)
                        .copied()
                        .unwrap_or(f64::INFINITY);
                    return Some((region, p95));
                }
            }
            // Unreachable while `total > 0`: the loop above always
            // reaches `cumulative == total >= target` by its last
            // iteration. `f64::INFINITY` is still the honest answer if
            // it somehow did not.
            Some((region, f64::INFINITY))
        })
        .collect()
}

/// Every region in `p95_by_region` whose estimate exceeds
/// `doc.latency_thresholds`'s own entry for it, if any — `(region,
/// estimated_p95_ms, threshold_ms)`, sorted by region for deterministic
/// output. A region with no configured threshold, or whose estimate is
/// within it, is absent.
fn latency_breaches<'a>(
    doc: &Document,
    p95_by_region: &'a HashMap<String, f64>,
) -> Vec<(&'a str, f64, f64)> {
    let mut breaches: Vec<(&str, f64, f64)> = p95_by_region
        .iter()
        .filter_map(|(region, p95)| {
            let threshold = *doc.latency_thresholds.get(region)?;
            (*p95 > threshold).then_some((region.as_str(), *p95, threshold))
        })
        .collect();
    breaches.sort_by(|a, b| a.0.cmp(b.0));
    breaches
}

/// Prints a breach line for each of [`latency_breaches`] — shared by
/// `advise_loop::tick` and `drive_loop::tick` so both tick loops surface
/// the same signal the same way, matching the Residency constraint's
/// own unplaceable-demand print block.
pub(crate) fn print_latency_breaches(doc: &Document, p95_by_region: &HashMap<String, f64>) {
    let breaches = latency_breaches(doc, p95_by_region);
    if breaches.is_empty() {
        return;
    }
    println!(
        "  latency: {} region(s) exceed their configured p95 RTT threshold \
         (ADR-0045 §3)",
        breaches.len()
    );
    for (region, p95, threshold) in breaches {
        println!("    region={region} p95_ms={p95} threshold_ms={threshold}");
    }
}

/// `pub(crate)`: `drive_loop` (ADR-0045 §7 Phase 2, issue #382) fetches its
/// own scaling-mode setting over this same control-API/PAT pair and should
/// not have to duplicate this.
pub(crate) fn fetch<T: serde::de::DeserializeOwned>(
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
    use karst_scaler::cost_model::{CostModel, Pool, PoolKind, Provider};

    fn pool(region: &str, residency_tags: &[&str]) -> Pool {
        pool_with_kind(region, residency_tags, PoolKind::Relay)
    }

    fn pool_with_kind(region: &str, residency_tags: &[&str], kind: PoolKind) -> Pool {
        Pool {
            provider: Provider::Onprem,
            region: region.to_owned(),
            cost_model: CostModel::default(),
            kind,
            min_nodes: 0,
            nodes_max: None,
            residency_tags: residency_tags.iter().map(|t| (*t).to_owned()).collect(),
            spot: None,
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
    fn a_turn_kind_pool_never_receives_relay_demand_even_when_region_and_residency_match() {
        let mut doc = Document::default();
        doc.pools.insert(
            "turn-pool".to_owned(),
            pool_with_kind("eu-west-1", &[], PoolKind::Turn),
        );
        let rows = [row("eu-west-1", "acct-1", 500)];

        let (demand, unplaceable) = attribute_demand(&doc, &rows);

        assert_eq!(demand.get("turn-pool").copied(), None);
        // No relay-kind pool exists anywhere in the region either, so this
        // demand is unplaceable -- not silently handed to the TURN pool.
        assert_eq!(unplaceable.len(), 1);
    }

    #[test]
    fn a_relay_pool_still_gets_demand_a_co_located_turn_pool_does_not() {
        let mut doc = Document::default();
        doc.pools
            .insert("relay-pool".to_owned(), pool("eu-west-1", &[]));
        doc.pools.insert(
            "turn-pool".to_owned(),
            pool_with_kind("eu-west-1", &[], PoolKind::Turn),
        );
        let rows = [row("eu-west-1", "acct-1", 500)];

        let (demand, unplaceable) = attribute_demand(&doc, &rows);

        assert!(unplaceable.is_empty());
        assert_eq!(demand.get("relay-pool").copied(), Some(5));
        assert_eq!(demand.get("turn-pool").copied(), None);
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

    #[test]
    fn a_region_with_almost_all_sessions_under_20ms_estimates_the_first_bucket() {
        // total=100, target=ceil(100*0.95)=95; cumulative after bucket 0
        // alone (96) already reaches it, so bucket 0's own upper bound
        // (20ms) is reported without needing bucket 1 at all.
        let rows = [
            row("eu-west-1", "acct-1", 96),
            RegionDemandRow {
                region: "eu-west-1".to_owned(),
                account_id: "acct-2".to_owned(),
                rtt_under_20ms: 0,
                rtt_20_to_50ms: 4,
                rtt_50_to_100ms: 0,
                rtt_over_100ms: 0,
            },
        ];

        let p95 = region_p95_rtt_ms(&rows);
        assert_eq!(p95.get("eu-west-1").copied(), Some(20.0));
    }

    #[test]
    fn a_region_whose_95th_percentile_just_crosses_into_the_second_bucket() {
        // Same 94/6 split, but all in one row's own buckets -- the 95th
        // percentile (ceil(100*0.95)=95) is only reached once bucket 1's
        // own 6 is added to bucket 0's 94 (cumulative 100), so bucket 1's
        // upper bound (50ms) is reported, not bucket 0's.
        let rows = [RegionDemandRow {
            region: "eu-west-1".to_owned(),
            account_id: "acct-1".to_owned(),
            rtt_under_20ms: 94,
            rtt_20_to_50ms: 6,
            rtt_50_to_100ms: 0,
            rtt_over_100ms: 0,
        }];

        let p95 = region_p95_rtt_ms(&rows);
        assert_eq!(p95.get("eu-west-1").copied(), Some(50.0));
    }

    #[test]
    fn a_region_whose_95th_percentile_falls_in_the_open_ended_bucket_is_infinite() {
        let rows = [RegionDemandRow {
            region: "eu-west-1".to_owned(),
            account_id: "acct-1".to_owned(),
            rtt_under_20ms: 0,
            rtt_20_to_50ms: 0,
            rtt_50_to_100ms: 0,
            rtt_over_100ms: 50,
        }];

        let p95 = region_p95_rtt_ms(&rows);
        assert_eq!(p95.get("eu-west-1").copied(), Some(f64::INFINITY));
    }

    #[test]
    fn a_region_with_zero_sessions_this_tick_is_omitted_not_zero() {
        let rows = [RegionDemandRow {
            region: "eu-west-1".to_owned(),
            account_id: "acct-1".to_owned(),
            rtt_under_20ms: 0,
            rtt_20_to_50ms: 0,
            rtt_50_to_100ms: 0,
            rtt_over_100ms: 0,
        }];

        let p95 = region_p95_rtt_ms(&rows);
        assert_eq!(p95.get("eu-west-1"), None);
    }

    #[test]
    fn region_p95_sums_every_account_in_the_region_together() {
        // Unlike attribute_demand, latency has no per-account dimension
        // -- two accounts' sessions in the same region combine into one
        // estimate.
        let rows = [
            row("eu-west-1", "acct-1", 50),
            row("eu-west-1", "acct-2", 50),
        ];
        let p95 = region_p95_rtt_ms(&rows);
        assert_eq!(p95.get("eu-west-1").copied(), Some(20.0));
    }

    #[test]
    fn latency_breaches_reports_only_regions_exceeding_their_own_threshold() {
        let mut doc = Document::default();
        doc.latency_thresholds.insert("eu-west-1".to_owned(), 50.0);
        doc.latency_thresholds.insert("us-east-1".to_owned(), 200.0);
        let p95_by_region = HashMap::from([
            ("eu-west-1".to_owned(), 120.0),  // exceeds its 50ms threshold
            ("us-east-1".to_owned(), 80.0),   // within its 200ms threshold
            ("ap-south-1".to_owned(), 999.0), // no threshold configured at all
        ]);

        let breaches = latency_breaches(&doc, &p95_by_region);

        assert_eq!(breaches, vec![("eu-west-1", 120.0, 50.0)]);
    }
}
