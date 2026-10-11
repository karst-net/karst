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
    let (now, recommendation) = advise_loop::tick_recommendation(doc, positions, config, agent)?;

    println!(
        "tick_unix={now} pools={} total_cost_delta={:.2}",
        recommendation.pools.len(),
        recommendation.total_cost_delta
    );
    for pool in &recommendation.pools {
        reconcile(driver, &pool.pool_id, pool.desired_nodes)?;
    }

    Ok(())
}

/// Brings `pool_id`'s actual instance count to `desired`: `create`s the
/// shortfall, or `drain`s then `destroy`s the excess, lowest-id-first so a
/// repeated tick's choice of which instance to remove is deterministic
/// rather than whatever order a driver's own `list` happens to return.
fn reconcile(driver: &mut dyn Driver, pool_id: &str, desired: u32) -> Result<(), String> {
    let mut current = driver.list(pool_id).map_err(|e| e.to_string())?;
    current.sort_by(|a, b| a.id.cmp(&b.id));
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
    fn reconcile_never_touches_another_pool() {
        let mut driver = NoopDriver::new();
        reconcile(&mut driver, "a", 2).expect("reconciles");
        reconcile(&mut driver, "b", 1).expect("reconciles");
        reconcile(&mut driver, "a", 0).expect("reconciles");
        assert!(driver.list("a").expect("lists").is_empty());
        assert_eq!(driver.list("b").expect("lists").len(), 1);
    }
}
