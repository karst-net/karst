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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum MetricKey {
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
        *usage.entry(key).or_insert(0.0) += rounded;

        let periods = pool_periods.entry(record.pool.clone()).or_default();
        if !periods.contains(&period) {
            periods.push(period);
        }
    }

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
                if let Some(remaining) = usage.get_mut(&key) {
                    *remaining = (*remaining - commitment.quantity).max(0.0);
                }
            }
        }
        pool_report.total += pool_report.commitments;
    }

    // Pass 3: price what the commitments left behind.
    for ((pool_id, metric, _period), quantity) in usage {
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
        let pool_report = report.pools.entry(pool_id).or_default();
        match metric {
            MetricKey::Meter(id) => *pool_report.meters.entry(id).or_insert(0.0) += cost,
            MetricKey::Edge(class) => *pool_report.edges.entry(class).or_insert(0.0) += cost,
        }
        pool_report.total += cost;
    }

    Ok(report)
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
fn period_key(timestamp: i64) -> i64 {
    let days = timestamp.div_euclid(86_400);
    let (year, month, _day) = civil_from_days(days);
    year * 12 + i64::from(month - 1)
}

/// Rounds `quantity` up to the nearest multiple of `increment`, or returns
/// it unchanged if there is none — ADR-0045 §2's "minimum billing
/// increments... set the *cost of churn*."
fn round_up(quantity: f64, increment: Option<f64>) -> f64 {
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
fn price_quantity(schedule: &PriceSchedule, quantity: f64) -> Result<f64, String> {
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
provider = "aws"
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
provider = "aws"
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
    fn edge_usage_is_reported_separately_from_meter_usage() {
        let d = doc(r#"
[pools.p]
provider = "aws"
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
provider = "aws"
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

    #[test]
    fn period_key_matches_known_calendar_months() {
        assert_eq!(period_key(0), period_key(86_399)); // 1970-01-01, both days
        assert_ne!(period_key(0), period_key(31 * 86_400)); // into February
    }
}
