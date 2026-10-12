// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The `karst-scaler drive` subcommand's own loop — ADR-0045 §7 Phase 2,
//! PR 1: the first piece of "reactive actuation." `advise` (`advise_loop.rs`)
//! computes a [`karst_scaler::advise::Recommendation`] and only prints it;
//! `drive` runs the identical solver call (`advise_loop::tick_recommendation`)
//! and then reconciles each pool's actual instance count against it through
//! a [`Driver`] — `list`s what exists, `create`s a shortfall, or `drain`s
//! and `destroy`s an excess.
//!
//! This loop is itself driver-agnostic: it does not know or care whether
//! `driver` is [`karst_scaler::driver::NoopDriver`] (today's only
//! implementation — no credentials, no cloud dependency) or a later real
//! one. Phase 2's own security boundaries (the budget circuit breaker,
//! the independent region-allowlist re-check — ADR-0045 §6) are later work
//! that wraps whatever `Driver` is passed in here, not something this loop
//! implements itself.

use std::collections::HashMap;
use std::path::Path;

use karst_scaler::cost_model::Document;
use karst_scaler::driver::Driver;
use karst_scaler::position::Position;

use crate::advise_loop::{self, Config};

/// Runs the reconciliation loop forever, logging each tick and continuing
/// past a single tick's failure — matching `advise_loop::run`'s own
/// reasoning: a transient control-server or network hiccup should not kill
/// a long-lived process.
///
/// # Errors
/// Only for setup: the cost-model file failing to load or validate.
pub(crate) fn run(config: &Config, driver: &mut dyn Driver) -> Result<(), String> {
    let doc = Document::load(Path::new(&config.cost_model_path))
        .map_err(|e| format!("reading {}: {e}", config.cost_model_path))?;
    doc.validate().map_err(|e| e.to_string())?;

    let agent = advise_loop::build_agent()?;
    let mut positions: HashMap<String, Position> = HashMap::new();

    loop {
        match tick(&doc, &mut positions, config, &agent, driver) {
            Ok(()) => {}
            Err(e) => eprintln!("karst-scaler drive: tick failed: {e}"),
        }
        std::thread::sleep(config.poll_interval);
    }
}

fn tick(
    doc: &Document,
    positions: &mut HashMap<String, Position>,
    config: &Config,
    agent: &ureq::Agent,
    driver: &mut dyn Driver,
) -> Result<(), String> {
    let outcome = advise_loop::tick_recommendation(doc, positions, config, agent)?;

    println!(
        "tick_unix={} pools={} total_cost_delta={:.2}",
        outcome.tick_unix,
        outcome.recommendation.pools.len(),
        outcome.recommendation.total_cost_delta
    );
    if !outcome.unplaceable_demand.is_empty() {
        println!(
            "  residency: {} account/region pairs could not be placed on any pool \
             (ADR-0045 §3 -- no pool satisfies their residency requirement)",
            outcome.unplaceable_demand.len()
        );
    }
    advise_loop::print_latency_breaches(doc, &outcome.region_p95_rtt_ms);
    for pool in &outcome.recommendation.pools {
        reconcile(driver, &pool.pool_id, pool.desired_nodes)?;
    }

    Ok(())
}

/// Brings `pool_id`'s actual instance count to `desired`: `create`s the
/// shortfall, or `drain`s then `destroys` the excess, **highest-ordinal-
/// first** (see [`ordinal_sort_key`]) — a repeated tick's choice of which
/// instance to remove is deterministic rather than whatever order a
/// driver's own `list` happens to return, and matches the one real driver
/// this matters for: a Kubernetes `StatefulSet` always removes its
/// highest-ordinal pod on scale-down, never an arbitrary one, so a generic
/// "lowest id first" policy here would pick an instance a real driver
/// cannot actually honor.
fn reconcile(driver: &mut dyn Driver, pool_id: &str, desired: u32) -> Result<(), String> {
    let mut current = driver.list(pool_id).map_err(|e| e.to_string())?;
    current.sort_by(|a, b| ordinal_sort_key(&b.id).cmp(&ordinal_sort_key(&a.id)));
    let current_count = u32::try_from(current.len()).unwrap_or(u32::MAX);

    if current_count < desired {
        let created = driver
            .create(pool_id, desired - current_count)
            .map_err(|e| e.to_string())?;
        println!("  pool={pool_id} create={}", created.len());
        return Ok(());
    }

    let excess = current_count - desired;
    let excess = usize::try_from(excess).unwrap_or(usize::MAX);
    for instance in current.iter().take(excess) {
        driver
            .drain(pool_id, &instance.id)
            .map_err(|e| e.to_string())?;
        driver
            .destroy(pool_id, &instance.id)
            .map_err(|e| e.to_string())?;
        println!("  pool={pool_id} destroy={}", instance.id);
    }
    Ok(())
}

/// Sorts `id` by its trailing run of ASCII digits as a number, not as a
/// string — plain string order puts `"relay-10"` before `"relay-2"`
/// (`'1' < '2'`), which is wrong for exactly the ids this module's one
/// real driver produces (Kubernetes `StatefulSet` pod names, `<name>-N`).
/// Falls back to the id's own bytes when there is no trailing digit run
/// (e.g. [`karst_scaler::driver::NoopDriver`]'s own ids still compare
/// correctly against each other either way, since they share one prefix).
fn ordinal_sort_key(id: &str) -> (&str, u64) {
    let digits_start = id.rfind(|c: char| !c.is_ascii_digit()).map_or(0, |i| i + 1);
    if digits_start == id.len() {
        return (id, 0);
    }
    #[allow(clippy::indexing_slicing)] // digits_start is a valid char boundary by construction
    let (prefix, digits) = (&id[..digits_start], &id[digits_start..]);
    (prefix, digits.parse().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use karst_scaler::driver::NoopDriver;

    use super::*;

    #[test]
    fn reconcile_creates_the_shortfall_when_below_desired() {
        let mut driver = NoopDriver::new();
        reconcile(&mut driver, "p", 3).expect("reconciles");
        assert_eq!(driver.list("p").expect("lists").len(), 3);
    }

    #[test]
    fn reconcile_is_a_noop_once_at_the_desired_count() {
        let mut driver = NoopDriver::new();
        reconcile(&mut driver, "p", 2).expect("reconciles");
        reconcile(&mut driver, "p", 2).expect("reconciles");
        assert_eq!(driver.list("p").expect("lists").len(), 2);
    }

    #[test]
    fn reconcile_drains_and_destroys_the_excess() {
        let mut driver = NoopDriver::new();
        reconcile(&mut driver, "p", 5).expect("reconciles");
        reconcile(&mut driver, "p", 2).expect("reconciles");
        assert_eq!(driver.list("p").expect("lists").len(), 2);
    }

    #[test]
    fn reconcile_removes_the_highest_ordinal_instances_first() {
        let mut driver = NoopDriver::new();
        reconcile(&mut driver, "p", 5).expect("reconciles"); // noop-1..noop-5
        reconcile(&mut driver, "p", 2).expect("reconciles");
        let mut remaining: Vec<String> = driver
            .list("p")
            .expect("lists")
            .into_iter()
            .map(|i| i.id)
            .collect();
        remaining.sort();
        assert_eq!(remaining, vec!["noop-1".to_owned(), "noop-2".to_owned()]);
    }

    #[test]
    fn ordinal_sort_key_orders_numerically_not_lexicographically() {
        let mut ids = vec!["relay-10", "relay-2", "relay-1"];
        ids.sort_by_key(|id| ordinal_sort_key(id));
        assert_eq!(ids, vec!["relay-1", "relay-2", "relay-10"]);
    }

    #[test]
    fn ordinal_sort_key_falls_back_to_the_whole_id_with_no_trailing_digits() {
        assert_eq!(ordinal_sort_key("no-digits-here"), ("no-digits-here", 0));
    }

    #[test]
    fn reconcile_never_touches_another_pool() {
        let mut driver = NoopDriver::new();
        reconcile(&mut driver, "a", 2).expect("reconciles");
        reconcile(&mut driver, "b", 1).expect("reconciles");
        reconcile(&mut driver, "a", 0).expect("reconciles");
        assert!(driver.list("a").expect("lists").is_empty());
        assert_eq!(driver.list("b").expect("lists").len(), 1);
    }
}
