// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Incremental, month-to-date cost tracking — ADR-0045 §7 Phase 1.
//! [`crate::simulate`]'s own module doc names the gap this fills: "A live
//! planner (Phase 1+) must track month-to-date position as usage arrives,"
//! because it has to decide *now* with only the past available, unlike a
//! batch replay that already has the whole period's usage in hand.
//!
//! [`Position`] is that running state for one pool: a total per metric
//! (meter or edge class) for whichever period it is currently tracking.
//! [`Position::estimated_cost`] is `simulate`'s per-pool total, computed
//! from a running sum instead of a batch; [`Position::marginal_cost`] is the
//! genuinely new piece of math a batch replay never has to ask: "what would
//! the *next* unit of this meter cost, from here."
//!
//! **Rounding is approximated, not replayed.** `simulate` rounds each
//! individual usage *record* up to a schedule's `minimum_increment` before
//! summing, because the increment prices a discrete billed event (one
//! instance-hour, one allocation). A [`Position`] does not retain individual
//! records — only a running total per metric — so it cannot reproduce that
//! per-record rounding exactly: it rounds the *accumulated* total once, each
//! time [`Position::estimated_cost`] or [`Position::marginal_cost`] is
//! asked for a number, rather than rounding each observation as it arrives.
//! When `minimum_increment` is set and usage arrives in many small
//! observations, this will generally sum to a smaller billed quantity than
//! `simulate`'s per-record rounding does — a [`Position`] never *overcounts*
//! relative to `simulate` on the same records, only potentially undercounts
//! the "cost of churn" `minimum_increment` is meant to capture. Exact
//! agreement with `simulate` therefore only holds for schedules with no
//! `minimum_increment` at all, which the equivalence test below is scoped
//! to.
//!
//! **Why `Mode::Graduated` agrees with `simulate` and `Mode::Volume` is not
//! guaranteed to, for `marginal_cost`.** Both modes price a *total*, and a
//! running sum is still the same total regardless of how it was
//! accumulated, so [`Position::estimated_cost`] agrees with `simulate` for
//! either mode (modulo the rounding note above). What is path-order-
//! sensitive is the sum of individual `marginal_cost` calls along the way:
//! for [`crate::cost_model::Mode::Graduated`], each band prices its own
//! slice independently, so the marginal cost of crossing from quantity A to
//! quantity B is the same regardless of how many observations it took to
//! get there. For [`crate::cost_model::Mode::Volume`], the *whole* quantity
//! reprices at whichever tier the total reaches, so the marginal cost of
//! the same final step can differ depending on where a tier boundary falls
//! relative to the observations — a real, correct consequence of Volume's
//! own non-convexity (ADR-0045 §4's reason greedy placement is wrong for
//! it), not a bug in `marginal_cost` itself.

use std::collections::BTreeMap;

use crate::cost_model::{CostModel, PriceSchedule};
use crate::simulate::{price_quantity, round_up, MetricKey};
use crate::usage::Metric;

/// Errors pricing a [`Position`].
#[derive(Debug)]
pub enum Error {
    /// Named the metric and reason — see [`crate::simulate::Error`], which
    /// this mirrors; a [`Position`] belongs to one pool already known to
    /// its caller, so there is no pool id to name here.
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

/// One pool's incremental, month-to-date cost position — see the module doc.
#[derive(Debug, Clone)]
pub struct Position {
    period: i64,
    totals: BTreeMap<MetricKey, f64>,
}

impl Position {
    /// A fresh position for `period` (the same period-key spelling
    /// [`crate::simulate`]'s own period function produces — `year * 12 +
    /// (month - 1)`, though this module takes the key as given and attaches
    /// no calendar meaning to it), with no usage recorded yet.
    #[must_use]
    pub const fn new(period: i64) -> Self {
        Self {
            period,
            totals: BTreeMap::new(),
        }
    }

    /// The period this position is currently tracking.
    #[must_use]
    pub const fn period(&self) -> i64 {
        self.period
    }

    /// Records `quantity` of `metric` as observed at `period`.
    ///
    /// If `period` is later than the position's current period, the
    /// position rolls over to a fresh, zeroed position for that period
    /// first, discarding whatever it had tracked — a live Advisor asks "what
    /// is this month's spend," not "what was every month's," so there is
    /// nothing to carry forward once a period has closed. A `period` that
    /// is not later (the common case: usage for the period already being
    /// tracked) is simply added in; this module does not reject a `period`
    /// older than the one it holds, since an out-of-order report arriving a
    /// little late is folded into the current totals rather than lost —
    /// cheaper to tolerate than to build a per-period history this struct is
    /// deliberately too small to hold.
    pub fn observe(&mut self, period: i64, metric: &Metric, quantity: f64) {
        if period > self.period {
            *self = Self::new(period);
        }
        *self.totals.entry(MetricKey::from(metric)).or_insert(0.0) += quantity;
    }

    /// This position's total cost so far this period, under `cost_model` —
    /// the running "recommended vs actual" number ADR-0045 §7 Phase 1 needs.
    /// A metric this position has never observed contributes nothing; a
    /// metric it has observed but `cost_model` has no schedule for is an
    /// error, the same posture [`crate::simulate::simulate`] takes.
    ///
    /// # Errors
    /// [`Error::Invalid`] if an observed metric has no price schedule in
    /// `cost_model`, or if its total exceeds what a bounded schedule can
    /// price.
    pub fn estimated_cost(&self, cost_model: &CostModel) -> Result<f64, Error> {
        let mut total = 0.0;
        for (key, quantity) in &self.totals {
            let schedule = schedule_for_key(cost_model, key)
                .ok_or_else(|| Error::Invalid(format!("no price schedule for {key}")))?;
            total += price_quantity(schedule, round_up(*quantity, schedule.minimum_increment))
                .map_err(|e| Error::Invalid(format!("{key}: {e}")))?;
        }
        Ok(total)
    }

    /// The cost of observing `quantity` more of meter `meter`, on top of
    /// whatever this position has already observed for it this period —
    /// `estimated_cost` with `quantity` added, minus `estimated_cost` as it
    /// stands now, computed directly from the one meter's own schedule
    /// rather than by re-pricing every other metric this position holds.
    /// See the module doc for why this is path-order-sensitive for
    /// [`crate::cost_model::Mode::Volume`] and not for
    /// [`crate::cost_model::Mode::Graduated`].
    ///
    /// # Errors
    /// [`Error::Invalid`] if `meter` has no price schedule in `cost_model`,
    /// or if the before or after total exceeds what a bounded schedule can
    /// price.
    pub fn marginal_cost(
        &self,
        cost_model: &CostModel,
        meter: &str,
        quantity: f64,
    ) -> Result<f64, Error> {
        let schedule = cost_model
            .meters
            .get(meter)
            .ok_or_else(|| Error::Invalid(format!("no price schedule for meter {meter:?}")))?;
        let key = MetricKey::Meter(meter.to_owned());
        let current = self.totals.get(&key).copied().unwrap_or(0.0);
        let before = price_quantity(schedule, round_up(current, schedule.minimum_increment))
            .map_err(|e| Error::Invalid(format!("meter {meter:?}: {e}")))?;
        let after = price_quantity(
            schedule,
            round_up(current + quantity, schedule.minimum_increment),
        )
        .map_err(|e| Error::Invalid(format!("meter {meter:?}: {e}")))?;
        Ok(after - before)
    }
}

fn schedule_for_key<'a>(cost_model: &'a CostModel, key: &MetricKey) -> Option<&'a PriceSchedule> {
    match key {
        MetricKey::Meter(id) => cost_model.meters.get(id),
        MetricKey::Edge(class) => cost_model.edges.get(class),
    }
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
    use crate::cost_model::{Document, EdgeClass};
    use crate::simulate;
    use crate::usage::{self, Metric};

    fn doc(toml: &str) -> Document {
        let d = Document::parse(toml).expect("parses");
        d.validate().expect("validates");
        d
    }

    #[test]
    fn a_fresh_position_costs_nothing() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ unit_price = 0.1 }]
"#);
        let position = Position::new(0);
        assert_eq!(
            position
                .estimated_cost(&d.pools["p"].cost_model)
                .expect("prices"),
            0.0
        );
    }

    #[test]
    fn observing_rolls_up_a_running_total() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ unit_price = 0.1 }]
"#);
        let mut position = Position::new(0);
        position.observe(0, &Metric::Meter("egress_gb".to_owned()), 30.0);
        position.observe(0, &Metric::Meter("egress_gb".to_owned()), 70.0);
        assert_eq!(
            position
                .estimated_cost(&d.pools["p"].cost_model)
                .expect("prices"),
            10.0
        );
    }

    #[test]
    fn observing_a_later_period_rolls_over_and_discards_the_previous_total() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ unit_price = 0.1 }]
"#);
        let mut position = Position::new(0);
        position.observe(0, &Metric::Meter("egress_gb".to_owned()), 100.0);
        position.observe(1, &Metric::Meter("egress_gb".to_owned()), 5.0);
        assert_eq!(position.period(), 1);
        assert_eq!(
            position
                .estimated_cost(&d.pools["p"].cost_model)
                .expect("prices"),
            0.5
        );
    }

    #[test]
    fn observing_an_earlier_or_equal_period_is_folded_into_the_current_total() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ unit_price = 0.1 }]
"#);
        let mut position = Position::new(5);
        position.observe(5, &Metric::Meter("egress_gb".to_owned()), 10.0);
        // A late report for an earlier period does not roll back or get
        // dropped -- it folds into the position's current total.
        position.observe(3, &Metric::Meter("egress_gb".to_owned()), 10.0);
        assert_eq!(position.period(), 5);
        assert_eq!(
            position
                .estimated_cost(&d.pools["p"].cost_model)
                .expect("prices"),
            2.0
        );
    }

    #[test]
    fn an_unpriced_metric_is_an_error_not_a_silent_zero() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ unit_price = 0.1 }]
"#);
        let mut position = Position::new(0);
        position.observe(0, &Metric::Meter("instance_hours".to_owned()), 1.0);
        let err = position
            .estimated_cost(&d.pools["p"].cost_model)
            .expect_err("unpriced meter");
        assert!(format!("{err}").contains("instance_hours"), "{err}");
    }

    #[test]
    fn edge_usage_is_priced_the_same_way_as_meter_usage() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.edges.cross-region]
mode = "graduated"
bands = [{ unit_price = 0.02 }]
"#);
        let mut position = Position::new(0);
        position.observe(0, &Metric::Edge(EdgeClass::CrossRegion), 50.0);
        assert_eq!(
            position
                .estimated_cost(&d.pools["p"].cost_model)
                .expect("prices"),
            1.0
        );
    }

    #[test]
    fn marginal_cost_of_a_graduated_schedule_is_the_flat_unit_price() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ up_to = 10.0, unit_price = 0.0 }, { unit_price = 0.1 }]
"#);
        let mut position = Position::new(0);
        position.observe(0, &Metric::Meter("egress_gb".to_owned()), 10.0);
        // The next 5 units land entirely past the free band, at 0.1 each.
        let delta = position
            .marginal_cost(&d.pools["p"].cost_model, "egress_gb", 5.0)
            .expect("prices");
        assert!((delta - 0.5).abs() < 1e-9, "{delta}");
    }

    #[test]
    fn marginal_cost_of_a_volume_schedule_depends_on_the_tier_the_total_reaches() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "volume"
bands = [{ up_to = 100.0, unit_price = 0.2 }, { unit_price = 0.1 }]
"#);
        let mut position = Position::new(0);
        position.observe(0, &Metric::Meter("egress_gb".to_owned()), 99.0);
        // 99 -> 100 stays in the lower tier: one more unit at 0.2.
        let delta = position
            .marginal_cost(&d.pools["p"].cost_model, "egress_gb", 1.0)
            .expect("prices");
        assert!((delta - 0.2).abs() < 1e-9, "{delta}");

        // 100 -> 101 crosses into the next tier: the *whole* 101 reprices at
        // 0.1 (10.1), replacing the 100 already billed at 0.2 (20.0) -- a
        // negative marginal cost for this one unit, which is exactly
        // Volume's non-convexity and not a bug: see the module doc.
        position.observe(0, &Metric::Meter("egress_gb".to_owned()), 1.0);
        let delta = position
            .marginal_cost(&d.pools["p"].cost_model, "egress_gb", 1.0)
            .expect("prices");
        assert!(delta < 0.0, "{delta}");
    }

    #[test]
    fn marginal_cost_of_an_unpriced_meter_is_an_error() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ unit_price = 0.1 }]
"#);
        let position = Position::new(0);
        let err = position
            .marginal_cost(&d.pools["p"].cost_model, "instance_hours", 1.0)
            .expect_err("unpriced meter");
        assert!(format!("{err}").contains("instance_hours"), "{err}");
    }

    /// The equivalence test the plan calls for: observing N records one at a
    /// time produces the same `estimated_cost` as `simulate::simulate` on
    /// the same N records batched, for `Mode::Graduated` with no
    /// `minimum_increment` -- the module doc explains why both of those
    /// conditions matter (Volume's marginal non-convexity does not affect
    /// this *total*-agreement test, but `minimum_increment`'s per-record
    /// rounding genuinely would).
    #[test]
    fn graduated_totals_agree_with_batch_simulate_at_period_end() {
        let d = doc(r#"
[pools.p]
provider = "onprem"
region = "x"
[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ up_to = 10.0, unit_price = 0.0 }, { up_to = 100.0, unit_price = 0.1 }, { unit_price = 0.05 }]
"#);
        let quantities = [3.0, 4.0, 2.0, 50.0, 41.0, 60.0];

        let mut position = Position::new(0);
        for &q in &quantities {
            position.observe(0, &Metric::Meter("egress_gb".to_owned()), q);
        }
        let incremental = position
            .estimated_cost(&d.pools["p"].cost_model)
            .expect("prices");

        let text = quantities.iter().fold(String::new(), |mut acc, q| {
            use std::fmt::Write as _;
            let _ = writeln!(acc, "0,p,meter,egress_gb,{q}");
            acc
        });
        let records = usage::parse(&text).expect("parses");
        let report = simulate::simulate(&d, &records).expect("simulates");

        assert!(
            (incremental - report.pools["p"].total).abs() < 1e-9,
            "incremental = {incremental}, batch = {}",
            report.pools["p"].total
        );
    }
}
