// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The offline simulator itself — ADR-0045 §7 Phase 0: "an offline tool
//! that replays recorded relay telemetry against a cost model and reports
//! spend per pool, per meter, per edge."
//!
//! **Batch, not incremental.** A live planner (Phase 1+) must track
//! month-to-date position as usage arrives, because it has to decide *now*
//! with only the past available. A Phase 0 replay already has the whole
//! period's usage in hand, so it sums each (pool, metric, period) group
//! once and prices the total — simpler, and for [`cost_model::Mode::Graduated`]
//! bands, exactly as path-independent as doing it incrementally would be.
//! [`cost_model::Mode::Volume`] bands are *not* path-independent in general
//! (the whole quantity reprices at the tier the *total* reaches), which is
//! precisely why this simulator sums first rather than pretending an
//! incremental running total would give the same answer a live planner's
//! month-to-date state will.
//!
//! **Ordering of free allowance, commitment, and bands.** ADR-0045 §2 does
//! not pin an order for these three to compose in; this applies them free
//! allowance first, then commitment, then the schedule's own bands on
//! whatever is left — the order that makes each one strictly only cheaper
//! than the last, never interacting in a way that depends on which ran
//! first.

use std::collections::BTreeMap;

use crate::cost_model::{Document, EdgeClass, Mode, Pool, PriceSchedule};
use crate::usage::{Metric, Record};

/// Errors simulating recorded usage against a cost model.
#[derive(Debug)]
pub enum Error {
    /// Named the pool, metric, and reason.
    Invalid(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

/// A hashable, orderable stand-in for [`Metric`] — [`Metric::Meter`] holds a
/// `String` the schedule lookup already validated against the pool, so this
/// exists only so usage can be grouped in a `BTreeMap`, not to re-validate
/// anything.
///
/// `pub(crate)`, not private: [`crate::position`] groups a running total the
/// same way this module groups a batch, and reuses this key rather than
/// defining its own.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum MetricKey {
    Meter(String),
    // A fixed discriminant ahead of the variant's own ordering keeps meters
    // and edges from interleaving when a pool's report is printed.
    Edge(EdgeClass),
}

impl From<&Metric> for MetricKey {
    fn from(m: &Metric) -> Self {
        match m {
            Metric::Meter(id) => Self::Meter(id.clone()),
            Metric::Edge(class) => Self::Edge(*class),
        }
    }
}

impl std::fmt::Display for MetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Meter(id) => write!(f, "meter {id}"),
            Self::Edge(class) => write!(f, "edge {class}"),
        }
    }
}

/// One pool's simulated spend.
#[derive(Debug, Default, Clone)]
pub struct PoolReport {
    pub meters: BTreeMap<String, f64>,
    pub edges: BTreeMap<EdgeClass, f64>,
    /// Commitment charges, counted once per period they apply to —
    /// ADR-0045 §2: "the commitment's own cost counted whether or not it is
    /// used."
    pub commitments: f64,
    pub total: f64,
    /// ADR-0045 Open Question #6, resolved for **internal reporting only**:
    /// each aquifer's share of `total`, computed per (metric, period)
    /// bucket as that aquifer's share of the bucket's *original* quantity
    /// (before any commitment consumption), applied to whatever that
    /// bucket actually cost — the pool's real blended, post-tier rate,
    /// never a hypothetical rate each aquifer would face alone. A
    /// commitment's flat charge is allocated the same way, by the
    /// committed meter's aquifer shares in that period, because commitment
    /// consumption has no real per-aquifer ordering to allocate by instead.
    ///
    /// Quantity with no aquifer tag is **excluded here, not guessed at** —
    /// it is still counted in `total` and `meters`/`edges`, so
    /// `by_aquifer.values().sum()` is less than `total` whenever any usage
    /// in this pool was unattributed, by exactly that usage's share of
    /// cost. A pool with no aquifer-tagged usage at all leaves this empty.
    ///
    /// **Not a chargeback computation.** A pool shared by several aquifers
    /// usually prices *cheaper* blended than any one aquifer would alone —
    /// this field passes that shared discount through to every
    /// contributor equally. A customer-facing bill must not do that
    /// silently; see `docs/adr/0045-cost-aware-geographic-scaling-across-providers.md`
    /// Open Question #6.
    pub by_aquifer: BTreeMap<String, f64>,
}

/// Split `cost` — whatever this (pool, metric, period) bucket actually
/// priced to — across the aquifers that contributed to it, in proportion to
/// each one's share of the bucket's original quantity. A no-op if the
/// bucket has no aquifer-tagged usage at all.
fn allocate_by_aquifer(
    pool_report: &mut PoolReport,
    aquifer_usage: &BTreeMap<(String, MetricKey, i64), BTreeMap<String, f64>>,
    original_usage: &BTreeMap<(String, MetricKey, i64), f64>,
    key: &(String, MetricKey, i64),
    cost: f64,
) {
    let Some(per_aquifer) = aquifer_usage.get(key) else {
        return;
    };
    let Some(&total_quantity) = original_usage.get(key) else {
        return;
    };
    if total_quantity <= 0.0 {
        return;
    }
    for (aquifer, &quantity) in per_aquifer {
        *pool_report.by_aquifer.entry(aquifer.clone()).or_insert(0.0) +=
            cost * quantity / total_quantity;
    }
}

/// The whole simulated run.
#[derive(Debug, Default, Clone)]
pub struct Report {
    pub pools: BTreeMap<String, PoolReport>,
}

impl Report {
    #[must_use]
    pub fn grand_total(&self) -> f64 {
        self.pools.values().map(|p| p.total).sum()
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (pool_id, report) in &self.pools {
            writeln!(f, "pool {pool_id}:")?;
            for (meter, cost) in &report.meters {
                writeln!(f, "  meter {meter}: {cost:.2}")?;
            }
            for (class, cost) in &report.edges {
                writeln!(f, "  edge  {class}: {cost:.2}")?;
            }
            if report.commitments > 0.0 {
                writeln!(f, "  commitments: {:.2}", report.commitments)?;
            }
            writeln!(f, "  total: {:.2}", report.total)?;
            if !report.by_aquifer.is_empty() {
                writeln!(f, "  by aquifer (internal reporting only, not a bill):")?;
                for (aquifer, cost) in &report.by_aquifer {
                    writeln!(f, "    {aquifer}: {cost:.2}")?;
                }
            }
        }
        write!(f, "grand total: {:.2}", self.grand_total())
    }
}

/// Replay `records` against `doc`'s cost models.
///
/// # Errors
/// [`Error::Invalid`] if a record names a pool or metric the cost model has
/// no price schedule for, or if a period's usage exceeds what a bounded
/// schedule can price — named rather than silently clamped or
/// extrapolated, the same posture [`crate::cost_model::Document::validate`]
/// takes for the schedule itself.
pub fn simulate(doc: &Document, records: &[Record]) -> Result<Report, Error> {
    // Pass 1: round each record to its schedule's minimum increment, then
    // sum into (pool, metric, period) buckets. The increment is applied per
    // record, before summation, because it is a property of each discrete
    // billed event (one instance-hour, one allocation) — summing first and
    // rounding the total would answer a different question.
    let mut usage: BTreeMap<(String, MetricKey, i64), f64> = BTreeMap::new();
    // Each bucket's quantity broken down by aquifer — a record with no
    // aquifer tag contributes to `usage` above but not here, which is what
    // makes it excluded from `by_aquifer` rather than misattributed.
    let mut aquifer_usage: BTreeMap<(String, MetricKey, i64), BTreeMap<String, f64>> =
        BTreeMap::new();
    // Every period that produced *any* usage for a pool, in pool order —
    // the set a commitment's "charged every period" is evaluated against.
    // Phase 0 has no independent notion of a period a pool existed for but
    // reported nothing; see the module doc for why that is a named
    // simplification rather than an oversight.
    let mut pool_periods: BTreeMap<String, Vec<i64>> = BTreeMap::new();

    for record in records {
        let pool = doc.pools.get(&record.pool).ok_or_else(|| {
            Error::Invalid(format!(
                "usage names pool {:?}, which the cost model does not define",
                record.pool
            ))
        })?;
        let schedule = schedule_for(pool, &record.metric).ok_or_else(|| {
            Error::Invalid(format!(
                "pool {:?} has no price schedule for {}",
                record.pool,
                MetricKey::from(&record.metric)
            ))
        })?;
        let rounded = round_up(record.quantity, schedule.minimum_increment);
        let period = period_key(record.timestamp);
        let key = (record.pool.clone(), MetricKey::from(&record.metric), period);
        *usage.entry(key.clone()).or_insert(0.0) += rounded;
        if let Some(aquifer) = &record.aquifer {
            *aquifer_usage
                .entry(key)
                .or_default()
                .entry(aquifer.clone())
                .or_insert(0.0) += rounded;
        }

        let periods = pool_periods.entry(record.pool.clone()).or_default();
        if !periods.contains(&period) {
            periods.push(period);
        }
    }

    // A snapshot of each bucket's full quantity before pass 2 consumes
    // some of it against commitments — `allocate_by_aquifer` always
    // allocates by a bucket's *original* share, not by what happened to be
    // left over after a commitment ate part of it, because commitment
    // consumption has no per-aquifer ordering to attribute that choice to.
    let original_usage = usage.clone();

    let mut report = Report::default();

    // Pass 2: commitments, charged once per (pool, period) regardless of
    // whether their meter had usage that period, and consumed against that
    // meter's usage in that period when it did.
    for (pool_id, periods) in &pool_periods {
        // Looked up again rather than carried from pass 1: `usage`'s keys
        // already proved every referenced pool exists, so this cannot fail,
        // but the lookup is cheap at Phase 0's scale (tens of pools) and
        // keeps every path through this function naming its own error
        // rather than relying on that proof holding across a refactor.
        let pool = doc.pools.get(pool_id).ok_or_else(|| {
            Error::Invalid(format!(
                "usage names pool {pool_id:?}, which the cost model does not define"
            ))
        })?;
        let pool_report = report.pools.entry(pool_id.clone()).or_default();
        for commitment in &pool.cost_model.commitments {
            for _ in periods {
                pool_report.commitments += commitment.price;
            }
            for &period in periods {
                let key = (
                    pool_id.clone(),
                    MetricKey::Meter(commitment.meter.clone()),
                    period,
                );
                allocate_by_aquifer(
                    pool_report,
                    &aquifer_usage,
                    &original_usage,
                    &key,
                    commitment.price,
                );
                if let Some(remaining) = usage.get_mut(&key) {
                    *remaining = (*remaining - commitment.quantity).max(0.0);
                }
            }
        }
        pool_report.total += pool_report.commitments;
    }

    // Pass 3: price what the commitments left behind.
    for ((pool_id, metric, period), quantity) in usage {
        let pool = doc.pools.get(&pool_id).ok_or_else(|| {
            Error::Invalid(format!(
                "usage names pool {pool_id:?}, which the cost model does not define"
            ))
        })?;
        let schedule = schedule_for_key(pool, &metric).ok_or_else(|| {
            Error::Invalid(format!(
                "pool {pool_id:?} has no price schedule for {metric}"
            ))
        })?;
        let cost = price_quantity(schedule, quantity)
            .map_err(|e| Error::Invalid(format!("pool {pool_id:?}, {metric}: {e}")))?;
        let pool_report = report.pools.entry(pool_id.clone()).or_default();
        let key = (pool_id, metric.clone(), period);
        allocate_by_aquifer(pool_report, &aquifer_usage, &original_usage, &key, cost);
        match metric {
            MetricKey::Meter(id) => *pool_report.meters.entry(id).or_insert(0.0) += cost,
            MetricKey::Edge(class) => *pool_report.edges.entry(class).or_insert(0.0) += cost,
        }
        pool_report.total += cost;
    }

    Ok(report)
}

/// One pool's spot/preemptible evaluation — ADR-0045 Open Question #4
/// (issue #339). Populated only for a pool that declares
/// [`crate::cost_model::Pool::spot`]; a pool with none is absent from
/// [`SpotReport::pools`] entirely, not zeroed.
#[derive(Debug, Default, Clone)]
pub struct PoolSpotReport {
    pub meter: String,
    /// Average concurrent nodes this meter billed for, time-weighted
    /// across every period this pool reported usage in (summed node-hours
    /// / summed hours of those periods).
    pub avg_total_nodes: f64,
    /// The slice of `avg_total_nodes` strictly above `min_nodes` — never
    /// the N+1 floor itself, matching issue #339's own scope.
    pub avg_headroom_nodes: f64,
    /// `avg_headroom_nodes / avg_total_nodes`, or `0.0` if this pool
    /// reported no usage for this meter at all.
    pub headroom_fraction: f64,
    /// The on-demand marginal cost of running `avg_headroom_nodes` on
    /// this meter's schedule, summed over every period —
    /// `price(total) - price(total - headroom)` per period, which
    /// (unlike pricing the headroom quantity alone) stays correct under
    /// [`crate::cost_model::Mode::Volume`]'s whole-quantity repricing too.
    pub on_demand_cost: f64,
    /// `on_demand_cost * price_ratio`.
    pub spot_cost: f64,
    /// `on_demand_cost - spot_cost`. Ignores free allowances and
    /// commitments already consumed by the floor's own usage — a
    /// documented simplification (see [`evaluate_spot`]'s own doc), not
    /// an oversight.
    pub savings: f64,
    /// Expected forced re-homes implied by the reclaim model, summed over
    /// every period: independent single-node reclaims plus the node
    /// count lost in every expected correlated event.
    pub expected_reclaims: f64,
    /// Of `expected_reclaims`, how many came from a correlated
    /// (pool-wide, simultaneous) event rather than an independent
    /// single-node one — the number Open Question #4's "overstates real
    /// redundancy" concern is actually about: not the total count, but
    /// how much of it arrives in one simultaneous batch instead of
    /// spread out.
    pub expected_correlated_reclaims: f64,
}

/// The whole spot/preemptible evaluation run — see [`evaluate_spot`].
#[derive(Debug, Default, Clone)]
pub struct SpotReport {
    pub pools: BTreeMap<String, PoolSpotReport>,
}

impl SpotReport {
    #[must_use]
    pub fn total_savings(&self) -> f64 {
        self.pools.values().map(|p| p.savings).sum()
    }
}

impl std::fmt::Display for SpotReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.pools.is_empty() {
            return writeln!(f, "no pool declares a [pools.*.spot] model");
        }
        for (pool_id, r) in &self.pools {
            writeln!(f, "pool {pool_id} (spot meter {}):", r.meter)?;
            writeln!(
                f,
                "  avg nodes: {:.2} total, {:.2} headroom ({:.1}% of pool)",
                r.avg_total_nodes,
                r.avg_headroom_nodes,
                r.headroom_fraction * 100.0
            )?;
            writeln!(
                f,
                "  cost of headroom: {:.2} on-demand, {:.2} spot, {:.2} savings",
                r.on_demand_cost, r.spot_cost, r.savings
            )?;
            writeln!(
                f,
                "  expected re-homes: {:.2} ({:.2} from correlated/multi-node events)",
                r.expected_reclaims, r.expected_correlated_reclaims
            )?;
        }
        write!(
            f,
            "total savings across every spot-modeled pool: {:.2}",
            self.total_savings()
        )
    }
}

/// Evaluate ADR-0045 Open Question #4 for every pool that declares a
/// [`crate::cost_model::SpotModel`] — issue #339's own scope: a data-only
/// estimate of what running headroom on spot/preemptible capacity would
/// save and what it would cost in forced re-homes, so that gate can
/// actually be checked instead of assumed. No driver changes, and no
/// effect on [`simulate`]'s own report: this is a separate, independent
/// read of the same usage.
///
/// # Headroom
/// For each period a pool reported this meter's usage in, headroom is
/// whatever node-hours that period's total exceeds `min_nodes * hours in
/// that period` — the N+1 floor itself is never considered for spot,
/// matching the issue's own scope ("strictly above its N+1 floor, never
/// the floor itself").
///
/// # What this ignores
/// Free allowances and commitments already consumed by the floor's own
/// usage are not separated out here — `on_demand_cost` is the marginal
/// cost of the headroom slice against the schedule's bands alone, which
/// slightly overstates savings whenever a commitment or free allowance
/// would otherwise have covered part of that headroom. Named here as a
/// first-approximation simplification, not an oversight: issue #339 asks
/// for an estimate to decide whether driver work is worth scoping, not a
/// bill.
///
/// # Reclaim model
/// Deliberately an analytic expectation, not a Monte Carlo replay: for
/// each period, `avg_spot_nodes = headroom_hours / hours_in_period`, and
/// - independent reclaims = `avg_spot_nodes * reclaim_rate_per_hour *
///   (1 - correlation) * hours_in_period`
/// - correlated events = `reclaim_rate_per_hour * correlation *
///   hours_in_period`, each one taking `avg_spot_nodes` nodes at once
///
/// `correlation` does not change the expected *count* of nodes reclaimed
/// (both terms still sum to `avg_spot_nodes * reclaim_rate_per_hour *
/// hours_in_period` at either edge of `correlation`) — only how much of
/// that count arrives in one simultaneous event instead of spread out,
/// which is precisely Open Question #4's "overstates real redundancy"
/// concern, not a claim that spot capacity causes more total churn.
///
/// # Errors
/// [`Error::Invalid`] if usage exceeds what a bounded schedule can price
/// — the same condition [`simulate`] itself reports.
pub fn evaluate_spot(doc: &Document, records: &[Record]) -> Result<SpotReport, Error> {
    let mut report = SpotReport::default();
    for (pool_id, pool) in &doc.pools {
        let Some(spot) = &pool.spot else { continue };
        // `cost_model::Document::validate` already proved this exists;
        // looked up again rather than carried along, matching `simulate`
        // itself (see its pass 2's own comment) so this path names its
        // own error rather than relying on that proof holding across a
        // refactor.
        let schedule = pool.cost_model.meters.get(&spot.meter).ok_or_else(|| {
            Error::Invalid(format!(
                "pool {pool_id:?}: spot.meter {:?} has no price schedule",
                spot.meter
            ))
        })?;

        let mut by_period: BTreeMap<i64, f64> = BTreeMap::new();
        for record in records {
            if record.pool != *pool_id || record.metric != Metric::Meter(spot.meter.clone()) {
                continue;
            }
            let rounded = round_up(record.quantity, schedule.minimum_increment);
            *by_period.entry(period_key(record.timestamp)).or_insert(0.0) += rounded;
        }

        let mut pool_report = PoolSpotReport {
            meter: spot.meter.clone(),
            ..PoolSpotReport::default()
        };
        let mut total_node_hours = 0.0_f64;
        let mut headroom_node_hours = 0.0_f64;
        let mut total_hours = 0.0_f64;

        for (period, quantity) in by_period {
            let hours = hours_in_calendar_month(period);
            let floor_hours = f64::from(pool.min_nodes) * hours;
            let headroom_hours = (quantity - floor_hours).max(0.0);

            total_node_hours += quantity;
            headroom_node_hours += headroom_hours;
            total_hours += hours;

            if headroom_hours <= 0.0 {
                continue;
            }

            let full_cost = price_quantity(schedule, quantity)
                .map_err(|e| Error::Invalid(format!("pool {pool_id:?}, {}: {e}", spot.meter)))?;
            let floor_cost = price_quantity(schedule, quantity - headroom_hours)
                .map_err(|e| Error::Invalid(format!("pool {pool_id:?}, {}: {e}", spot.meter)))?;
            pool_report.on_demand_cost += (full_cost - floor_cost).max(0.0);

            let avg_spot_nodes = headroom_hours / hours;
            let independent =
                avg_spot_nodes * spot.reclaim_rate_per_hour * (1.0 - spot.correlation) * hours;
            let correlated_events = spot.reclaim_rate_per_hour * spot.correlation * hours;
            let correlated = correlated_events * avg_spot_nodes;
            pool_report.expected_reclaims += independent + correlated;
            pool_report.expected_correlated_reclaims += correlated;
        }

        pool_report.spot_cost = pool_report.on_demand_cost * spot.price_ratio;
        pool_report.savings = pool_report.on_demand_cost - pool_report.spot_cost;
        pool_report.avg_total_nodes = if total_hours > 0.0 {
            total_node_hours / total_hours
        } else {
            0.0
        };
        pool_report.avg_headroom_nodes = if total_hours > 0.0 {
            headroom_node_hours / total_hours
        } else {
            0.0
        };
        pool_report.headroom_fraction = if pool_report.avg_total_nodes > 0.0 {
            pool_report.avg_headroom_nodes / pool_report.avg_total_nodes
        } else {
            0.0
        };

        report.pools.insert(pool_id.clone(), pool_report);
    }
    Ok(report)
}

/// Total hours in the calendar month `period` (as produced by
/// [`period_key`]) — the denominator [`evaluate_spot`] uses to turn a
/// period's summed node-hours into an average concurrent node count.
fn hours_in_calendar_month(period: i64) -> f64 {
    let year = period.div_euclid(12);
    let month = period.rem_euclid(12) + 1;
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    let start = days_from_civil(year, month, 1);
    let end = days_from_civil(next_year, next_month, 1);
    #[allow(clippy::cast_precision_loss)] // whole-process-lifetime magnitudes only
    let hours = ((end - start) * 86_400) as f64 / 3600.0;
    hours
}

fn schedule_for<'a>(pool: &'a Pool, metric: &Metric) -> Option<&'a PriceSchedule> {
    match metric {
        Metric::Meter(id) => pool.cost_model.meters.get(id),
        Metric::Edge(class) => pool.cost_model.edges.get(class),
    }
}

fn schedule_for_key<'a>(pool: &'a Pool, key: &MetricKey) -> Option<&'a PriceSchedule> {
    match key {
        MetricKey::Meter(id) => pool.cost_model.meters.get(id),
        MetricKey::Edge(class) => pool.cost_model.edges.get(class),
    }
}

/// A calendar-month bucket for `timestamp` (UTC, seconds since epoch) —
/// Phase 0's only supported period (ADR-0045 §2 also allows "the provider's
/// actual cycle anchor," left for whichever later phase first has an
/// operator who needs it). Encoded as `year * 12 + (month - 1)` so adjacent
/// months are adjacent integers and nothing but ordering is ever asked of
/// the result.
///
/// `pub`, not `pub(crate)`, for the same cross-crate reason as
/// [`hours_remaining_in_period`]: the Phase 1 `advise` CLI (the `[[bin]]`
/// target, a separate crate from this library) uses the same period key a
/// [`crate::position::Position`] rolls over on, so a tick's observations
/// and a position's own notion of "has the period changed" never drift
/// apart into two different calendars.
#[must_use]
pub fn period_key(timestamp: i64) -> i64 {
    let days = timestamp.div_euclid(86_400);
    let (year, month, _day) = civil_from_days(days);
    year * 12 + i64::from(month - 1)
}

/// Hours remaining from `now` (UTC, seconds since epoch) until the start of
/// the next calendar month — the Phase 1 `advise` CLI's own conversion from
/// a candidate node count into a quantity of whatever meter bills per node
/// per hour (see `crate::advise`'s module doc). `pub`, not `pub(crate)`:
/// the bin target that needs this is a separate crate from this library
/// (Cargo's `[[bin]]`/`[lib]` split), so only a fully public item is
/// reachable from it — unlike `round_up`/`price_quantity`/`MetricKey`,
/// which `crate::position` reaches from inside this same library crate.
#[must_use]
pub fn hours_remaining_in_period(now: i64) -> f64 {
    let days = now.div_euclid(86_400);
    let (year, month, _day) = civil_from_days(days);
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, i64::from(month) + 1)
    };
    let next_month_start = days_from_civil(next_year, next_month, 1) * 86_400;
    let seconds_remaining = (next_month_start - now).max(0);
    #[allow(clippy::cast_precision_loss)] // whole-process-lifetime magnitudes only
    let hours = seconds_remaining as f64 / 3600.0;
    hours
}

/// The inverse of [`civil_from_days`] — days since the Unix epoch for the
/// first moment of (`year`, `month`, `day`), same algorithm family (Howard
/// Hinnant's `chrono`-compatible civil calendar).
#[allow(clippy::many_single_char_names)]
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Rounds `quantity` up to the nearest multiple of `increment`, or returns
/// it unchanged if there is none — ADR-0045 §2's "minimum billing
/// increments... set the *cost of churn*."
///
/// `pub(crate)`: [`crate::position`] rounds its own running totals with
/// this, rather than a second copy of the same one-line rule.
pub(crate) fn round_up(quantity: f64, increment: Option<f64>) -> f64 {
    match increment {
        Some(inc) if inc > 0.0 => (quantity / inc).ceil() * inc,
        _ => quantity,
    }
}

/// Prices `quantity` (already net of free allowance and any commitment —
/// callers apply those first) against `schedule`.
///
/// # Errors
/// A string naming the schedule's capacity if `quantity` exceeds what a
/// schedule with a bounded last band can price — [`crate::cost_model`]
/// allows an operator to write a capped schedule deliberately; this is
/// what happens when usage then exceeds the cap, surfaced rather than
/// silently clamped or extrapolated past the operator's own boundary.
///
/// `pub(crate)`: [`crate::position`] prices its own running totals against
/// the same bands, rather than a second copy of the pricing math.
pub(crate) fn price_quantity(schedule: &PriceSchedule, quantity: f64) -> Result<f64, String> {
    let billable = (quantity - schedule.free_allowance).max(0.0);
    match schedule.mode {
        Mode::Graduated => {
            let mut remaining = billable;
            let mut lower = 0.0_f64;
            let mut cost = 0.0_f64;
            for band in &schedule.bands {
                let width = band
                    .up_to
                    .map_or(remaining, |up_to| (up_to - lower).max(0.0));
                let take = remaining.min(width);
                cost += take * band.unit_price;
                remaining -= take;
                if let Some(up_to) = band.up_to {
                    lower = up_to;
                }
                if remaining <= 0.0 {
                    break;
                }
            }
            if remaining > 0.0 {
                return Err(format!(
                    "quantity {billable} exceeds this schedule's priced capacity of {lower}"
                ));
            }
            Ok(cost)
        }
        Mode::Volume => {
            let mut lower = 0.0_f64;
            for band in &schedule.bands {
                match band.up_to {
                    Some(up_to) if billable <= up_to => return Ok(billable * band.unit_price),
                    Some(up_to) => lower = up_to,
                    None => return Ok(billable * band.unit_price),
                }
            }
            Err(format!(
                "quantity {billable} exceeds this schedule's priced capacity of {lower}"
            ))
        }
    }
}

/// Civil (year, month, day) from a day count since the Unix epoch —
/// Howard Hinnant's `chrono`-compatible algorithm, exact for the proleptic
/// Gregorian calendar. The same algorithm `bins/karst-bedrock`'s `utc()`
/// uses for its timestamp rendering; duplicated rather than shared because
/// that one lives in a bin crate with no library an offline cost tool
/// should depend on for twenty lines of date math.
#[allow(clippy::many_single_char_names)] // the algorithm's own variable names
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::float_cmp
    )]

    use super::*;
    use crate::cost_model::Document;
    use crate::usage;

    fn doc(toml: &str) -> Document {
        let d = Document::parse(toml).expect("parses");
        d.validate().expect("validates");
        d
    }

    #[test]
    fn a_flat_graduated_schedule_charges_unit_price_times_quantity() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ unit_price = 0.1 }]
"#);
        let records = usage::parse("1,p,meter,egress_gb,100.0").expect("parses");
        let report = simulate(&d, &records).expect("simulates");
        assert_eq!(report.pools["p"].meters["egress_gb"], 10.0);
        assert_eq!(report.grand_total(), 10.0);
    }

    #[test]
    fn graduated_bands_price_each_slice_separately() {
        // First 10 at 0.0, next 90 at 0.1 — a classic free-tier-then-rate.
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ up_to = 10.0, unit_price = 0.0 }, { unit_price = 0.1 }]
"#);
        let records = usage::parse("1,p,meter,egress_gb,100.0").expect("parses");
        let report = simulate(&d, &records).expect("simulates");
        // 10 free + 90 * 0.1 = 9.0
        assert_eq!(report.pools["p"].meters["egress_gb"], 9.0);
    }

    #[test]
    fn volume_pricing_reprices_the_whole_quantity_at_the_tier_reached() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "volume"
bands = [{ up_to = 100.0, unit_price = 0.2 }, { unit_price = 0.1 }]
"#);
        // 100 at the lower tier: whole 100 billed at 0.2, not 0.1.
        let records = usage::parse("1,p,meter,egress_gb,100.0").expect("parses");
        let report = simulate(&d, &records).expect("simulates");
        assert_eq!(report.pools["p"].meters["egress_gb"], 20.0);

        // 101 crosses into the next tier: the *whole* 101 reprices at 0.1,
        // which is cheaper than the 100 would have been at 0.2 — the
        // non-convexity ADR-0045 §4 calls out as why greedy placement is
        // wrong for volume pricing.
        let records = usage::parse("1,p,meter,egress_gb,101.0").expect("parses");
        let report = simulate(&d, &records).expect("simulates");
        assert!(
            (report.pools["p"].meters["egress_gb"] - 10.1).abs() < 1e-9,
            "{}",
            report.pools["p"].meters["egress_gb"]
        );
    }

    #[test]
    fn free_allowance_is_subtracted_before_bands_apply() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ unit_price = 0.1 }]
free_allowance = 10.0
"#);
        let records = usage::parse("1,p,meter,egress_gb,30.0").expect("parses");
        let report = simulate(&d, &records).expect("simulates");
        assert_eq!(report.pools["p"].meters["egress_gb"], 2.0);
    }

    #[test]
    fn a_commitment_is_charged_once_per_period_even_with_no_usage() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "us-east-1"
[pools.p.cost_model.meters.instance_hours]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
[[pools.p.cost_model.commitments]]
meter = "instance_hours"
quantity = 100.0
price = 5.0
"#);
        // A zero-quantity record still opens the period for pool `p` without
        // itself costing anything, so the commitment's own flat price is
        // the only thing this test is actually checking.
        let records = usage::parse("1,p,meter,instance_hours,0.0").expect("parses");
        let report = simulate(&d, &records).expect("simulates");
        assert_eq!(report.pools["p"].commitments, 5.0);
        assert_eq!(report.pools["p"].total, 5.0);
    }

    #[test]
    fn a_commitment_is_consumed_before_the_schedule() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "us-east-1"
[pools.p.cost_model.meters.instance_hours]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
[[pools.p.cost_model.commitments]]
meter = "instance_hours"
quantity = 100.0
price = 5.0
"#);
        let records = usage::parse("1,p,meter,instance_hours,80.0").expect("parses");
        let report = simulate(&d, &records).expect("simulates");
        // 80 <= the 100-hour commitment, so nothing reaches the band —
        // only the commitment's own flat price is charged, and the meter
        // reports zero rather than being left out of the report entirely
        // (it was still used, just fully covered by the commitment).
        assert_eq!(report.pools["p"].total, 5.0);
        assert_eq!(report.pools["p"].meters["instance_hours"], 0.0);

        let records = usage::parse("1,p,meter,instance_hours,120.0").expect("parses");
        let report = simulate(&d, &records).expect("simulates");
        // 20 hours spill past the 100-hour commitment at 1.0/hr, plus the
        // commitment's flat 5.0.
        assert_eq!(report.pools["p"].meters["instance_hours"], 20.0);
        assert_eq!(report.pools["p"].total, 25.0);
    }

    #[test]
    fn a_pool_with_no_aquifer_tagged_usage_has_an_empty_by_aquifer_map() {
        // ADR-0045 Open Question #6: a pool nobody tagged is the overwhelming
        // common case (a single-tenant pool), and must behave exactly as it
        // did before this field existed.
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ unit_price = 0.1 }]
"#);
        let records = usage::parse("1,p,meter,egress_gb,100.0").expect("parses");
        let report = simulate(&d, &records).expect("simulates");
        assert!(report.pools["p"].by_aquifer.is_empty());
        assert_eq!(report.pools["p"].total, 10.0);
    }

    #[test]
    fn aquifer_tagged_usage_splits_a_volume_pools_blended_cost_proportionally() {
        // Volume pricing reprices the *whole* quantity at the tier the total
        // reaches (the non-convexity `volume_pricing_reprices_the_whole_quantity_at_the_tier_reached`
        // already covers) -- the case this test exists for. 60 GB alone
        // would price at the 0.2 tier (12.0); 40 GB alone would too (8.0);
        // combined, 100 GB crosses the 50 GB boundary into the 0.1 tier and
        // blended-prices at 10.0 total -- cheaper per GB than either
        // aquifer would face alone. Each aquifer's by_aquifer share must
        // reflect that shared discount, not a hypothetical standalone price.
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "volume"
bands = [{ up_to = 50.0, unit_price = 0.2 }, { unit_price = 0.1 }]
"#);
        let text = "1,p,meter,egress_gb,60.0,acme\n1,p,meter,egress_gb,40.0,beta\n";
        let records = usage::parse(text).expect("parses");
        let report = simulate(&d, &records).expect("simulates");
        assert_eq!(report.pools["p"].meters["egress_gb"], 10.0);
        assert!((report.pools["p"].by_aquifer["acme"] - 6.0).abs() < 1e-9);
        assert!((report.pools["p"].by_aquifer["beta"] - 4.0).abs() < 1e-9);
        assert!(
            (report.pools["p"].by_aquifer.values().sum::<f64>() - report.pools["p"].total).abs()
                < 1e-9
        );
    }

    #[test]
    fn untagged_usage_is_excluded_from_by_aquifer_but_still_counted_in_total() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ unit_price = 0.1 }]
"#);
        // 80 GB tagged to acme, 20 GB left unattributed, same bucket.
        let text = "1,p,meter,egress_gb,80.0,acme\n1,p,meter,egress_gb,20.0\n";
        let records = usage::parse(text).expect("parses");
        let report = simulate(&d, &records).expect("simulates");
        assert_eq!(report.pools["p"].total, 10.0);
        // acme's share is 80/100 of the bucket's cost, not 100% of it.
        assert!((report.pools["p"].by_aquifer["acme"] - 8.0).abs() < 1e-9);
        assert_eq!(report.pools["p"].by_aquifer.len(), 1);
    }

    #[test]
    fn a_commitments_flat_charge_is_allocated_by_the_committed_meters_aquifer_shares() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "us-east-1"
[pools.p.cost_model.meters.instance_hours]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
[[pools.p.cost_model.commitments]]
meter = "instance_hours"
quantity = 100.0
price = 5.0
"#);
        // acme used 60 of the 100 committed hours, beta 40 -- a 60/40 split.
        let text = "1,p,meter,instance_hours,60.0,acme\n1,p,meter,instance_hours,40.0,beta\n";
        let records = usage::parse(text).expect("parses");
        let report = simulate(&d, &records).expect("simulates");
        assert_eq!(report.pools["p"].total, 5.0);
        assert!((report.pools["p"].by_aquifer["acme"] - 3.0).abs() < 1e-9);
        assert!((report.pools["p"].by_aquifer["beta"] - 2.0).abs() < 1e-9);
    }

    #[test]
    fn edge_usage_is_reported_separately_from_meter_usage() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "us-east-1"
[pools.p.cost_model.edges.cross-region]
mode = "graduated"
bands = [{ unit_price = 0.02 }]
"#);
        let records = usage::parse("1,p,edge,cross-region,50.0").expect("parses");
        let report = simulate(&d, &records).expect("simulates");
        assert_eq!(report.pools["p"].edges[&EdgeClass::CrossRegion], 1.0);
        assert!(report.pools["p"].meters.is_empty());
    }

    #[test]
    fn usage_in_different_calendar_months_is_priced_in_separate_periods() {
        // A free allowance of 10 applies *per period*. Two records of 10 in
        // two different months should both land fully in the free band;
        // summed into one period they would not.
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ unit_price = 0.1 }]
free_allowance = 10.0
"#);
        // 2026-01-15T00:00:00Z and 2026-02-15T00:00:00Z.
        let jan = 1_768_435_200_i64;
        let feb = 1_771_113_600_i64;
        let text = format!("{jan},p,meter,egress_gb,10.0\n{feb},p,meter,egress_gb,10.0\n");
        let records = usage::parse(&text).expect("parses");
        let report = simulate(&d, &records).expect("simulates");
        assert_eq!(report.pools["p"].meters["egress_gb"], 0.0);
    }

    #[test]
    fn usage_for_an_undeclared_pool_is_an_error() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ unit_price = 0.1 }]
"#);
        let records = usage::parse("1,ghost,meter,egress_gb,1.0").expect("parses");
        let err = simulate(&d, &records).expect_err("undeclared pool");
        assert!(format!("{err}").contains("ghost"), "{err}");
    }

    #[test]
    fn usage_for_an_unpriced_meter_is_an_error_not_a_silent_zero() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ unit_price = 0.1 }]
"#);
        let records = usage::parse("1,p,meter,instance_hours,1.0").expect("parses");
        let err = simulate(&d, &records).expect_err("unpriced meter");
        assert!(format!("{err}").contains("instance_hours"), "{err}");
    }

    #[test]
    fn usage_exceeding_a_capped_schedule_is_an_error_not_an_extrapolation() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ up_to = 10.0, unit_price = 0.1 }]
"#);
        let records = usage::parse("1,p,meter,egress_gb,11.0").expect("parses");
        let err = simulate(&d, &records).expect_err("over capacity");
        assert!(format!("{err}").contains("exceeds"), "{err}");
    }

    #[test]
    fn minimum_increment_rounds_each_record_up_before_summing() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "us-east-1"
[pools.p.cost_model.meters.instance_hours]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
minimum_increment = 1.0
"#);
        // Two half-hour boots in the same period round up to two full hours,
        // not one — the "cost of churn" ADR-0045 §2 names minimum
        // increments for.
        let text = "1,p,meter,instance_hours,0.5\n2,p,meter,instance_hours,0.5\n";
        let records = usage::parse(text).expect("parses");
        let report = simulate(&d, &records).expect("simulates");
        assert_eq!(report.pools["p"].meters["instance_hours"], 2.0);
    }

    fn spot_doc(min_nodes: u32, price_ratio: f64, reclaim_rate: f64, correlation: f64) -> Document {
        let text = format!(
            r#"
[pools.p]
provider = "onprem"
region = "x"
min_nodes = {min_nodes}
[pools.p.cost_model.meters.instance_hours]
mode = "graduated"
bands = [{{ unit_price = 1.0 }}]
[pools.p.spot]
meter = "instance_hours"
price_ratio = {price_ratio}
reclaim_rate_per_hour = {reclaim_rate}
correlation = {correlation}
"#
        );
        doc(&text)
    }

    #[test]
    fn a_pool_with_no_spot_model_is_absent_from_the_report() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.instance_hours]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
"#);
        let records = usage::parse("1,p,meter,instance_hours,100.0").expect("parses");
        let report = evaluate_spot(&d, &records).expect("evaluates");
        assert!(report.pools.is_empty());
    }

    #[test]
    fn headroom_cost_and_savings_match_hand_computed_numbers() {
        // January 2026: 744 hours. 5 avg nodes (3720 node-hours), min_nodes
        // 2 (1488 node-hours floor) -> 3 avg nodes of headroom (2232
        // node-hours), at $1/hr flat: on-demand cost of headroom is 2232.0.
        let d = spot_doc(2, 0.3, 0.01, 0.0);
        let jan = 1_768_435_200_i64; // 2026-01-15T00:00:00Z
        let records =
            usage::parse(&format!("{jan},p,meter,instance_hours,3720.0")).expect("parses");
        let report = evaluate_spot(&d, &records).expect("evaluates");
        let p = &report.pools["p"];
        assert!(
            (p.avg_total_nodes - 5.0).abs() < 1e-9,
            "{}",
            p.avg_total_nodes
        );
        assert!(
            (p.avg_headroom_nodes - 3.0).abs() < 1e-9,
            "{}",
            p.avg_headroom_nodes
        );
        assert!(
            (p.headroom_fraction - 0.6).abs() < 1e-9,
            "{}",
            p.headroom_fraction
        );
        assert!(
            (p.on_demand_cost - 2232.0).abs() < 1e-6,
            "{}",
            p.on_demand_cost
        );
        assert!((p.spot_cost - 669.6).abs() < 1e-6, "{}", p.spot_cost);
        assert!((p.savings - 1562.4).abs() < 1e-6, "{}", p.savings);
    }

    #[test]
    fn correlation_redistributes_reclaims_without_changing_their_total() {
        let jan = 1_768_435_200_i64;
        let records =
            usage::parse(&format!("{jan},p,meter,instance_hours,3720.0")).expect("parses");

        let independent = spot_doc(2, 0.3, 0.01, 0.0);
        let r = evaluate_spot(&independent, &records).expect("evaluates");
        let p = &r.pools["p"];
        assert!(
            (p.expected_reclaims - 22.32).abs() < 1e-6,
            "{}",
            p.expected_reclaims
        );
        assert_eq!(p.expected_correlated_reclaims, 0.0);

        let correlated = spot_doc(2, 0.3, 0.01, 1.0);
        let r = evaluate_spot(&correlated, &records).expect("evaluates");
        let p = &r.pools["p"];
        // Same expected total reclaim count as the fully independent case
        // -- correlation only changes how clustered they are, never the
        // count, matching evaluate_spot's own doc comment.
        assert!(
            (p.expected_reclaims - 22.32).abs() < 1e-6,
            "{}",
            p.expected_reclaims
        );
        assert!(
            (p.expected_correlated_reclaims - 22.32).abs() < 1e-6,
            "{}",
            p.expected_correlated_reclaims
        );
    }

    #[test]
    fn usage_entirely_below_the_floor_has_no_headroom_cost_or_churn() {
        // 2 avg nodes against a min_nodes floor of 2 -- no headroom at all.
        let d = spot_doc(2, 0.3, 0.01, 0.0);
        let jan = 1_768_435_200_i64;
        let records =
            usage::parse(&format!("{jan},p,meter,instance_hours,1488.0")).expect("parses");
        let report = evaluate_spot(&d, &records).expect("evaluates");
        let p = &report.pools["p"];
        assert!((p.avg_total_nodes - 2.0).abs() < 1e-9);
        assert_eq!(p.avg_headroom_nodes, 0.0);
        assert_eq!(p.on_demand_cost, 0.0);
        assert_eq!(p.savings, 0.0);
        assert_eq!(p.expected_reclaims, 0.0);
    }

    #[test]
    fn multiple_periods_are_combined_time_weighted() {
        // January (744h) at 5 avg nodes, February (672h, 2026 is not a leap
        // year) at 3 avg nodes -- combined average must weight by each
        // period's own hours, not average the two node counts unweighted.
        let jan = 1_768_435_200_i64;
        let feb = 1_771_113_600_i64;
        let d = spot_doc(0, 0.3, 0.01, 0.0);
        let text = format!(
            "{jan},p,meter,instance_hours,{}\n{feb},p,meter,instance_hours,{}\n",
            5.0 * 744.0,
            3.0 * 672.0
        );
        let records = usage::parse(&text).expect("parses");
        let report = evaluate_spot(&d, &records).expect("evaluates");
        let p = &report.pools["p"];
        let expected = (5.0 * 744.0 + 3.0 * 672.0) / (744.0 + 672.0);
        assert!(
            (p.avg_total_nodes - expected).abs() < 1e-9,
            "{}",
            p.avg_total_nodes
        );
    }

    #[test]
    fn hours_in_calendar_month_matches_known_months() {
        assert!((hours_in_calendar_month(period_key(0)) - 744.0).abs() < 1e-9); // Jan 1970
        assert!(
            (hours_in_calendar_month(period_key(31 * 86_400)) - 672.0).abs() < 1e-9 // Feb 1970
        );
    }

    #[test]
    fn period_key_matches_known_calendar_months() {
        assert_eq!(period_key(0), period_key(86_399)); // 1970-01-01, both days
        assert_ne!(period_key(0), period_key(31 * 86_400)); // into February
    }

    #[test]
    fn hours_remaining_in_period_counts_down_to_the_next_calendar_month() {
        // 2026-01-15T00:00:00Z -- 17 days left in January (16 remaining in
        // January itself, plus the day that rolls into February).
        let jan_15 = 1_768_435_200_i64;
        assert!((hours_remaining_in_period(jan_15) - 408.0).abs() < 1e-9);

        // One hour before February: 3,600 seconds remaining.
        let jan_31_23 = jan_15 + 16 * 86_400 + 23 * 3_600;
        assert!((hours_remaining_in_period(jan_31_23) - 1.0).abs() < 1e-9);

        // December rolls into the next calendar year, not a parse error or
        // a negative count.
        let dec_15_2026 = jan_15 + 334 * 86_400; // 2026-12-15T00:00:00Z
        assert!((hours_remaining_in_period(dec_15_2026) - 408.0).abs() < 1e-9);
    }
}
