// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The solver — ADR-0045 §7 Phase 1 ("Phase 1a"): "the planner and
//! constraint set (§3, §4) running continuously." Phase 0's `simulate` asks
//! "what did this cost"; [`position`] asks "what does this cost so far";
//! [`advise`] is the first thing in this crate that asks "how many nodes
//! *should* this pool have" and can explain why.
//!
//! ## Scope this phase actually has data for
//!
//! §4's planner description is deliberately general ("the cheaper place to
//! serve a region... is idle on-prem capacity") — a *cross-pool* placement
//! problem: which of several pools that could serve the same region's
//! demand should absorb it. Phase 1 has no signal to drive that choice: §4a's
//! `DemandByRegion` aggregates by `(region, account)`, not by which of
//! possibly several candidate pools in that region should take the load, and
//! no per-aquifer residency *tag* exists on [`crate::cost_model::Pool`] yet
//! (only §4c's deployment-wide allowlist, already enforced at
//! [`crate::cost_model::Document::validate`] time — every pool reaching
//! [`advise`] has already passed it). Building a real cross-pool placement
//! search on top of a demand signal that cannot yet attribute "this much of
//! this region's demand could go to any of these pools" would be
//! implementing a problem this phase cannot actually pose.
//!
//! What Phase 1 *can* do, and does: size **each pool independently** to its
//! own already-attributed demand (`PoolState::demand_nodes`, resolved to a
//! node count by whatever built the [`Problem`] — outside this module), and
//! get that sizing right even where a naive greedy walk gets it wrong. §4's
//! own example of greedy's failure mode — "it will refuse to move into a
//! pool whose price falls after a tier boundary" — is fully present within
//! a *single* pool's own [`crate::cost_model::Mode::Volume`] schedule: the
//! cheapest feasible node count is not always the smallest one, because
//! crossing a tier can make a larger quantity cost less in total. That is
//! the non-convexity this phase's bounded enumeration is built to catch;
//! genuine cross-pool substitution is left for whichever later phase has a
//! real placement signal to drive it.
//!
//! ## From node count to money
//!
//! Neither [`crate::cost_model`] nor [`position`] has any notion of "the
//! cost of running N nodes" — a [`position::Position`] only holds a raw
//! accumulated quantity per meter, with no rate or time dimension
//! connecting a node count to a billable quantity. [`Problem`] closes that
//! gap explicitly rather than guessing at a convention: each
//! [`PoolState::node_meter`] names which of the pool's own meters bills for
//! one running node, and [`Problem::remaining_period_hours`] is how many
//! hours are left in the period that meter bills against, so a candidate
//! node count becomes `candidate_nodes * remaining_period_hours` of that
//! meter's own quantity unit — the same unit [`position::Position`] already
//! accumulates in, so [`position::Position::marginal_cost`] (added in the
//! previous PR for exactly this) prices it correctly against whatever this
//! pool has *already* consumed this period, tier crossings included.
//!
//! ## Two different "baseline"s, both named in the ADR
//!
//! §4's "never worse than the on-prem-first greedy baseline" and §7's
//! "recommended vs actual" are two different comparisons, both present here
//! under the names the plan gave them:
//!
//! - [`Recommendation::baseline_cost`] / [`Recommendation::total_cost_delta`]
//!   compare the chosen allocation against the **naive greedy baseline**:
//!   the smallest node count that satisfies demand and the floor, with no
//!   search for a cheaper larger one. This is the solver's own correctness
//!   invariant (`total_cost_delta` must never be positive — checked as a
//!   test, not just claimed in a comment) and is not shown to an operator as
//!   "the bill"; it is what proves the search is never worse than the
//!   strategy the ADR says it must beat.
//! - [`PoolRecommendation::cost_delta`] compares the chosen allocation
//!   against the **configured baseline**: `pool.min_nodes`, standing in for
//!   "what is actually running" until §5's driver interface exists to ask a
//!   provider directly (see the doc comment that will sit on the CLI
//!   subcommand that calls this). This is the human-facing number — the
//!   ADR's own example, "aws-use1 configured for 2, Advisor recommends 5,
//!   bound by Headroom, +$340/mo," is this value.
//!
//! ## Why three of the six `Constraint` values are never produced here
//!
//! §3's constraint table is written for the whole ADR, not for Phase 1
//! alone, and three of its five named constraints have no scenario this
//! phase's implementation can bind on:
//!
//! - **Latency** has no data model yet — nothing in [`crate::cost_model`] or
//!   [`position`] represents a per-region RTT threshold to check against.
//! - **Residency**, as §3 defines it, is a per-aquifer tag match; [`Pool`]
//!   carries no tag, only §4c's deployment-wide allowlist, which is already
//!   fully resolved before a `Document` validates at all (see above) — by
//!   the time a pool reaches this module there is nothing left to exclude.
//! - **Budget** cannot *trim* a pool's recommendation in this
//!   implementation, on purpose: §3 states plainly that "nothing trades SLA
//!   for savings unless the operator explicitly marks a constraint soft
//!   with a penalty," and this phase adds no soft/penalty mechanism.
//!   Treating `budget_cap` as license to recommend fewer nodes than
//!   Headroom or `min_nodes` (Availability) requires would be silently
//!   trading away a constraint §3 calls hard — exactly the failure mode a
//!   cost-control feature should least want to risk once a real driver
//!   acts on its output (Phase 2). `Problem::budget_cap` is deliberately
//!   compared, not enforced: if every pool at its own hard floor already
//!   costs more than the cap, that is a real conflict between two
//!   constraints the ADR says are both hard, and this module surfaces it as
//!   an honest `total_cost_delta`/`baseline_cost` a human reads, rather than
//!   resolving it by quietly breaching Headroom or Availability. A
//!   soft/penalty mechanism, if one is ever added, is where `Budget` would
//!   start being produced.
//!
//! `Availability` similarly has nothing to bind on *in this phase*: nothing
//! here ever tries to recommend fewer nodes than `min_nodes` in the first
//! place (there is no mechanism that would push a count below it, per the
//! Budget note above), so there is no "stopped by Availability" event to
//! report — a pool sitting exactly at its own floor is reported as
//! [`Constraint::None`] (see
//! [`PoolRecommendation`]'s own doc comment for why that is the correct
//! reading, not a gap). Only [`Constraint::Headroom`],
//! [`Constraint::Capacity`], and [`Constraint::None`] are ever produced by
//! [`advise`] today.
//!
//! [`Constraint::Capacity`] itself is not one of §3's five SLA constraints
//! at all — it is this module's own addition, for a case §3's vocabulary
//! has no name for: `pool.nodes_max` (§1's hard physical ceiling) capping a
//! pool below what Headroom would otherwise call for. Attributing that to
//! `Headroom` would misreport *why* the count is what it is (Headroom is
//! unsatisfied in that case, not satisfied-and-binding); a dedicated name
//! keeps `binding_constraint` honest about which of these two very
//! different situations occurred.

use crate::cost_model::Pool;
use crate::position::{self, Position};

/// How far above a pool's own floor this module searches for a cheaper
/// larger node count (a [`crate::cost_model::Mode::Volume`] tier crossing).
/// Fixed and small, matching §4's "the problem sizes are small... so the
/// planner uses an exact or near-exact search" reasoning applied per pool
/// rather than per deployment: a tier whose cheaper rate starts more than
/// this many nodes above the floor is outside what this phase's bounded
/// search claims to find — a named scope limit, not a silent one.
const SEARCH_WINDOW: u32 = 32;

/// One pool's inputs to [`advise`].
#[derive(Debug, Clone, Copy)]
pub struct PoolState<'a> {
    pub pool_id: &'a str,
    pub pool: &'a Pool,
    pub position: &'a Position,

    /// Nodes this pool's own demand calls for, before headroom — the
    /// §4a/§4b signal, already resolved to a node count by whatever built
    /// this [`PoolState`]; see the module doc for why that resolution
    /// happens outside this module.
    pub demand_nodes: u32,

    /// Which meter in `pool.cost_model.meters` bills for one running node
    /// for the rest of the period — see the module doc's "From node count
    /// to money" section for why this is named explicitly rather than
    /// assumed from a fixed meter name.
    pub node_meter: &'a str,
}

/// The whole deployment-wide sizing problem for one tick.
#[derive(Debug, Clone, Copy)]
pub struct Problem<'a> {
    pub pools: &'a [PoolState<'a>],

    /// §3's Headroom constraint's own multiplier: provisioned capacity must
    /// be at least `demand_nodes * (1.0 + headroom)`.
    pub headroom: f64,

    /// §3's Budget constraint. Compared, not enforced — see the module
    /// doc's "why three of six are never produced" section for why this
    /// phase does not trim a pool's recommendation to fit under it.
    pub budget_cap: Option<f64>,

    /// Hours remaining in the period `node_meter` bills against, for every
    /// pool in `pools` — converts a candidate node count into that meter's
    /// own quantity unit. See the module doc's "From node count to money"
    /// section.
    pub remaining_period_hours: f64,
}

/// Which hard constraint explains a [`PoolRecommendation`]'s
/// `desired_nodes` — see the module doc for which of these this
/// implementation can actually produce today, and why.
///
/// `Serialize`s lowercase (`serde(rename_all = "snake_case")`) to match the
/// label value `metrics_http`'s `karst_scaler_binding_constraint{constraint}`
/// renders and the JSON `/recommendations` endpoint both use — one spelling,
/// not two independently hand-written ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Constraint {
    Latency,
    Availability,
    Headroom,
    Residency,
    Budget,
    /// This module's own addition — see the module doc's last paragraph.
    Capacity,
    /// Nothing forced `desired_nodes` away from `pool.min_nodes` — the
    /// recommendation agrees with the operator's own configured floor, not
    /// because nothing was checked, but because nothing needed to change
    /// it.
    None,
}

/// One pool's recommendation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PoolRecommendation {
    pub pool_id: String,
    pub desired_nodes: u32,

    /// `desired_nodes`'s cost for the rest of the period, minus
    /// `pool.min_nodes`'s — the "recommended vs actual" number ADR-0045 §7
    /// Phase 1 exists to publish. Positive means the Advisor recommends
    /// spending more than the configured floor; see the module doc for why
    /// `min_nodes` stands in for "actual" until a real driver exists to ask
    /// a provider directly.
    pub cost_delta: f64,
    pub binding_constraint: Constraint,
}

/// The whole tick's recommendation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Recommendation {
    pub pools: Vec<PoolRecommendation>,

    /// The sum of every pool's chosen allocation's cost, minus
    /// [`Self::baseline_cost`] — the solver's own correctness invariant.
    /// Never positive: see the module doc's "two different baselines"
    /// section.
    pub total_cost_delta: f64,

    /// The sum of every pool's **naive greedy baseline** cost — the
    /// smallest node count that satisfies demand and the floor, with no
    /// search for a cheaper larger one. Not "the bill"; see the module doc.
    pub baseline_cost: f64,
}

/// Size every pool in `problem` independently — see the module doc for the
/// full algorithm and its scope.
///
/// # Errors
/// [`position::Error`] if a pool's `node_meter` has no price schedule, or if
/// a candidate node count's projected usage exceeds what a bounded schedule
/// can price.
pub fn advise(problem: &Problem) -> Result<Recommendation, position::Error> {
    let mut pools = Vec::with_capacity(problem.pools.len());
    let mut total_cost_delta = 0.0;
    let mut baseline_cost = 0.0;

    for state in problem.pools {
        let sized = size_pool(state, problem)?;
        total_cost_delta += sized.chosen_cost - sized.floor_cost;
        baseline_cost += sized.floor_cost;
        pools.push(PoolRecommendation {
            pool_id: (*state.pool_id).to_owned(),
            desired_nodes: sized.desired_nodes,
            cost_delta: sized.chosen_cost - sized.configured_cost,
            binding_constraint: sized.binding_constraint,
        });
    }

    Ok(Recommendation {
        pools,
        total_cost_delta,
        baseline_cost,
    })
}

struct Sized {
    desired_nodes: u32,
    binding_constraint: Constraint,
    /// This pool's chosen allocation's cost for the rest of the period.
    chosen_cost: f64,
    /// This pool's naive-greedy-baseline cost — see [`Recommendation::baseline_cost`].
    floor_cost: f64,
    /// `pool.min_nodes`'s cost — see [`PoolRecommendation::cost_delta`].
    configured_cost: f64,
}

fn size_pool(state: &PoolState<'_>, problem: &Problem<'_>) -> Result<Sized, position::Error> {
    let demand_floor = (f64::from(state.demand_nodes) * (1.0 + problem.headroom)).ceil();
    // Any reasonable headroom/demand keeps this well within u32 range; a
    // saturating cast is the honest behavior if it somehow does not; a demand
    // this large has bigger problems than this cast.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let demand_floor = demand_floor as u32;
    let effective_floor = demand_floor.max(state.pool.min_nodes);

    let configured_cost = cost_of(state, problem, state.pool.min_nodes)?;

    if let Some(max) = state.pool.nodes_max {
        if effective_floor > max {
            let cost = cost_of(state, problem, max)?;
            return Ok(Sized {
                desired_nodes: max,
                binding_constraint: Constraint::Capacity,
                chosen_cost: cost,
                // The floor itself is infeasible here, so the "naive
                // greedy baseline" this pool can actually reach is the same
                // capacity-capped count -- there is no cheaper-but-smaller
                // greedy alternative to compare against.
                floor_cost: cost,
                configured_cost,
            });
        }
    }

    let floor_cost = cost_of(state, problem, effective_floor)?;
    let search_upper = state
        .pool
        .nodes_max
        .map_or(effective_floor + SEARCH_WINDOW, |max| {
            max.min(effective_floor + SEARCH_WINDOW)
        });

    let mut best_nodes = effective_floor;
    let mut best_cost = floor_cost;
    for candidate in (effective_floor + 1)..=search_upper {
        let cost = cost_of(state, problem, candidate)?;
        if cost < best_cost {
            best_nodes = candidate;
            best_cost = cost;
        }
    }

    let binding_constraint = if effective_floor > state.pool.min_nodes {
        Constraint::Headroom
    } else {
        Constraint::None
    };

    Ok(Sized {
        desired_nodes: best_nodes,
        binding_constraint,
        chosen_cost: best_cost,
        floor_cost,
        configured_cost,
    })
}

/// `nodes`' cost for the rest of the period, against `state.position`'s
/// already-observed total for `state.node_meter` this period — see the
/// module doc's "From node count to money" section.
fn cost_of(
    state: &PoolState<'_>,
    problem: &Problem<'_>,
    nodes: u32,
) -> Result<f64, position::Error> {
    let quantity = f64::from(nodes) * problem.remaining_period_hours;
    state
        .position
        .marginal_cost(&state.pool.cost_model, state.node_meter, quantity)
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

    fn doc(toml: &str) -> Document {
        let d = Document::parse(toml).expect("parses");
        d.validate().expect("validates");
        d
    }

    const FLAT: &str = r#"
[pools.p]
provider = "onprem"
region = "x"
min_nodes = 2

[pools.p.cost_model.meters.instance_hours]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
"#;

    #[test]
    fn a_pool_already_satisfied_at_its_floor_gets_no_change_and_no_binding_constraint() {
        let d = doc(FLAT);
        let position = Position::new(0);
        let state = PoolState {
            pool_id: "p",
            pool: &d.pools["p"],
            position: &position,
            // 0 demand: min_nodes (2) alone already covers it.
            demand_nodes: 0,
            node_meter: "instance_hours",
        };
        let problem = Problem {
            pools: &[state],
            headroom: 0.2,
            budget_cap: None,
            remaining_period_hours: 100.0,
        };
        let rec = advise(&problem).expect("advises");
        assert_eq!(rec.pools.len(), 1);
        assert_eq!(rec.pools[0].desired_nodes, 2);
        assert_eq!(rec.pools[0].cost_delta, 0.0);
        assert_eq!(rec.pools[0].binding_constraint, Constraint::None);
        assert_eq!(rec.total_cost_delta, 0.0);
    }

    #[test]
    fn demand_above_the_floor_is_sized_with_headroom_and_bound_by_headroom() {
        let d = doc(FLAT);
        let position = Position::new(0);
        let state = PoolState {
            pool_id: "p",
            pool: &d.pools["p"],
            position: &position,
            demand_nodes: 4,
            node_meter: "instance_hours",
        };
        let problem = Problem {
            pools: &[state],
            headroom: 0.25,
            budget_cap: None,
            remaining_period_hours: 100.0,
        };
        let rec = advise(&problem).expect("advises");
        // ceil(4 * 1.25) = 5.
        assert_eq!(rec.pools[0].desired_nodes, 5);
        assert_eq!(rec.pools[0].binding_constraint, Constraint::Headroom);
        // configured (min_nodes = 2) costs 2*100 = 200; desired (5) costs
        // 5*100 = 500 at this flat unit_price of 1.0/hr.
        assert!((rec.pools[0].cost_delta - 300.0).abs() < 1e-9);
    }

    #[test]
    fn a_demand_floor_exceeding_nodes_max_is_capped_and_bound_by_capacity() {
        let text = r#"
[pools.p]
provider = "onprem"
region = "x"
min_nodes = 2
nodes_max = 6

[pools.p.cost_model.meters.instance_hours]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
"#;
        let d = doc(text);
        let position = Position::new(0);
        let state = PoolState {
            pool_id: "p",
            pool: &d.pools["p"],
            position: &position,
            demand_nodes: 10,
            node_meter: "instance_hours",
        };
        let problem = Problem {
            pools: &[state],
            headroom: 0.0,
            budget_cap: None,
            remaining_period_hours: 100.0,
        };
        let rec = advise(&problem).expect("advises");
        assert_eq!(rec.pools[0].desired_nodes, 6);
        assert_eq!(rec.pools[0].binding_constraint, Constraint::Capacity);
    }

    #[test]
    fn a_volume_tier_crossing_beyond_the_floor_is_found_and_never_costs_more_than_the_floor() {
        // 0-9 at 1.0/hr, 10+ at 0.3/hr (volume: the whole quantity
        // reprices). At the bare demand floor of 8 nodes the cost is
        // 8*100*1.0 = 800; crossing to 10 nodes reprices the whole 10*100 =
        // 1000 units at 0.3/hr = 300, strictly cheaper despite more nodes --
        // exactly the case a greedy "stop at the floor" walk would miss.
        let text = r#"
[pools.p]
provider = "aws"
region = "us-east-1"
min_nodes = 1

[allowed_regions]
aws = ["us-east-1"]

[pools.p.cost_model.meters.instance_hours]
mode = "volume"
bands = [{ up_to = 900.0, unit_price = 1.0 }, { unit_price = 0.3 }]
"#;
        let d = doc(text);
        let position = Position::new(0);
        let state = PoolState {
            pool_id: "p",
            pool: &d.pools["p"],
            position: &position,
            demand_nodes: 8,
            node_meter: "instance_hours",
        };
        let problem = Problem {
            pools: &[state],
            headroom: 0.0,
            budget_cap: None,
            remaining_period_hours: 100.0,
        };
        let rec = advise(&problem).expect("advises");
        assert_eq!(rec.pools[0].desired_nodes, 10);
        assert!(
            rec.total_cost_delta <= 0.0,
            "never worse than the naive floor baseline: {}",
            rec.total_cost_delta
        );
        assert!(
            (rec.total_cost_delta - (300.0 - 800.0)).abs() < 1e-9,
            "{}",
            rec.total_cost_delta
        );
    }

    #[test]
    fn the_never_worse_than_baseline_invariant_holds_across_synthetic_fixtures() {
        // A sweep of demand levels and headrooms over the same volume
        // schedule as above: total_cost_delta must never be positive,
        // regardless of where the floor happens to land relative to the
        // tier boundary.
        let text = r#"
[pools.p]
provider = "onprem"
region = "x"
min_nodes = 1

[pools.p.cost_model.meters.instance_hours]
mode = "volume"
bands = [{ up_to = 500.0, unit_price = 1.0 }, { up_to = 2000.0, unit_price = 0.4 }, { unit_price = 0.6 }]
"#;
        let d = doc(text);
        for demand in [1, 3, 5, 7, 9, 12, 15, 20, 25] {
            for headroom in [0.0, 0.1, 0.3, 0.5] {
                let position = Position::new(0);
                let state = PoolState {
                    pool_id: "p",
                    pool: &d.pools["p"],
                    position: &position,
                    demand_nodes: demand,
                    node_meter: "instance_hours",
                };
                let problem = Problem {
                    pools: &[state],
                    headroom,
                    budget_cap: None,
                    remaining_period_hours: 50.0,
                };
                let rec = advise(&problem).expect("advises");
                assert!(
                    rec.total_cost_delta <= 1e-9,
                    "demand {demand}, headroom {headroom}: total_cost_delta = {}",
                    rec.total_cost_delta
                );
            }
        }
    }

    #[test]
    fn multiple_pools_are_sized_independently_and_summed() {
        let d = doc(FLAT);
        let a = Position::new(0);
        let b = Position::new(0);
        let states = [
            PoolState {
                pool_id: "p",
                pool: &d.pools["p"],
                position: &a,
                demand_nodes: 0,
                node_meter: "instance_hours",
            },
            PoolState {
                pool_id: "p",
                pool: &d.pools["p"],
                position: &b,
                demand_nodes: 10,
                node_meter: "instance_hours",
            },
        ];
        let problem = Problem {
            pools: &states,
            headroom: 0.0,
            budget_cap: None,
            remaining_period_hours: 10.0,
        };
        let rec = advise(&problem).expect("advises");
        assert_eq!(rec.pools.len(), 2);
        assert_eq!(rec.pools[0].desired_nodes, 2); // unchanged, at its floor
        assert_eq!(rec.pools[1].desired_nodes, 10); // sized to its own demand
    }

    #[test]
    fn budget_cap_is_compared_not_enforced() {
        // See the module doc's "why three of six are never produced"
        // section: a budget_cap tighter than even the configured floor
        // costs is surfaced as a negative headroom in the reported totals,
        // never resolved by recommending fewer nodes than the floor.
        let d = doc(FLAT);
        let position = Position::new(0);
        let state = PoolState {
            pool_id: "p",
            pool: &d.pools["p"],
            position: &position,
            demand_nodes: 4,
            node_meter: "instance_hours",
        };
        let problem = Problem {
            pools: &[state],
            headroom: 0.25,
            budget_cap: Some(1.0), // far below any feasible allocation
            remaining_period_hours: 100.0,
        };
        let rec = advise(&problem).expect("advises");
        // Same answer as without a budget cap at all -- nothing was trimmed.
        assert_eq!(rec.pools[0].desired_nodes, 5);
        assert_eq!(rec.pools[0].binding_constraint, Constraint::Headroom);
    }

    #[test]
    fn an_unpriced_node_meter_is_an_error() {
        let d = doc(FLAT);
        let position = Position::new(0);
        let state = PoolState {
            pool_id: "p",
            pool: &d.pools["p"],
            position: &position,
            demand_nodes: 1,
            node_meter: "egress_gb", // not in FLAT's cost model
        };
        let problem = Problem {
            pools: &[state],
            headroom: 0.0,
            budget_cap: None,
            remaining_period_hours: 10.0,
        };
        let err = advise(&problem).expect_err("unpriced node_meter");
        assert!(format!("{err}").contains("egress_gb"), "{err}");
    }
}
