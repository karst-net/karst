// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! ADR-0045 §6's two driver-layer defenses, wrapping any [`Driver`] —
//! Phase 2 PR 2. Both exist because §6 says plainly that neither may live
//! *only* in the planner:
//!
//! - **Budget circuit breaker**: "Hard ceilings on node count per pool and
//!   per period are mandatory configuration, with no 'unlimited' value...
//!   a bug in the planner, corrupt telemetry, or a malicious demand spike
//!   ... must not be able to scale without limit."
//! - **Independent region-allowlist re-check**: "enforced in the driver,
//!   not only in the planner... a bug in the planner or a corrupted
//!   candidate list must not be able to create a resource in a region the
//!   operator excluded."
//!
//! [`BoundedDriver`] loads its own copies of both inputs — the cost-model
//! document's `allowed_regions` and each pool's declared `(provider,
//! region)`, and a separate [`BreakerLimits`] file — independently of
//! whatever [`crate::cost_model::Document`] the planner already validated
//! and holds in memory. That duplication is the point: a corrupted or
//! mutated in-memory planner state cannot carry forward into this check,
//! because this check never shares that memory in the first place.
//!
//! **Why the budget check uses a flat per-node estimate, not
//! [`crate::position`]'s own tiered pricing.** This breaker's whole job is
//! to be a dumb, easily-audited hard stop that still works even if the
//! pricing engine itself is wrong or compromised — replicating
//! [`crate::advise`]'s own tier/volume logic here would make the one
//! component meant to catch a pricing bug depend on that same logic being
//! correct. [`BreakerLimits::cost_per_node_estimate`] only needs to be
//! conservative (high enough to refuse before real spend exceeds the cap,
//! never so low it lets real spend past it) — exactness belongs to the
//! planner's own reported `cost_delta`.
//!
//! **Why node-count and spend state persists to a file, not memory or a
//! database.** A breaker that resets to zero on every process restart is
//! not a breaker — see the module's own `state_path`. A database would
//! hand the scaler process DB credentials, in tension with ADR-0045 §6's
//! "separate trust domain" framing; a file matches this crate's existing
//! file-loaded, no-DB posture ([`crate::cost_model::Document`] itself is
//! one).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::cost_model::{Document, Provider};
use crate::driver::{Driver, DriverError, Instance};
use crate::simulate::period_key;

/// Errors setting up a [`BoundedDriver`] — loading its config, its
/// independent cost-model copy, or its persisted state.
#[derive(Debug)]
pub enum Error {
    CostModel(crate::cost_model::Error),
    Io(std::io::Error),
    Syntax(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CostModel(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Syntax(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

/// One pool's hard ceilings, read from their own file — see the module doc
/// for why this is a separate document from the cost model.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakerLimits {
    pub nodes_max_per_period: u32,
    pub budget_cap_per_period: f64,
    /// See the module doc's "why the budget check uses a flat estimate"
    /// section.
    pub cost_per_node_estimate: f64,
}

/// The whole breaker-limits file: one `[pools.<id>]` table per pool,
/// mirroring [`crate::cost_model::Document`]'s own `[pools.<id>]` shape.
/// A pool with no entry here has no configured ceiling — see
/// [`BoundedDriver::create`], which refuses rather than treating that as
/// unlimited.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakerLimitsDocument {
    #[serde(default)]
    pub pools: HashMap<String, BreakerLimits>,
}

impl BreakerLimitsDocument {
    /// # Errors
    /// [`Error::Syntax`] for malformed TOML, a missing required field, or
    /// an unrecognized one.
    pub fn parse(text: &str) -> Result<Self, Error> {
        toml::from_str(text).map_err(|e| Error::Syntax(format!("breaker limits: {e}")))
    }

    /// # Errors
    /// [`Error::Io`] if the file cannot be read, plus everything
    /// [`Self::parse`] returns.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(Error::Io)?;
        Self::parse(&text)
    }
}

/// This period's cumulative actuation against one pool's limits.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
struct PeriodCounter {
    /// [`period_key`]'s own spelling — `0` (its default) is never a real
    /// period key in practice, so a freshly-inserted counter always looks
    /// stale against the current tick's real period and rolls over on
    /// first use rather than silently starting "already this period."
    period: i64,
    nodes_added: u32,
    spend_committed: f64,
}

/// Every pool's [`PeriodCounter`], persisted as a whole to `state_path` —
/// see the module doc's "why... a file" section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BreakerState {
    #[serde(default)]
    adds_by_pool: HashMap<String, PeriodCounter>,
}

impl BreakerState {
    /// A missing file is a fresh deployment's first tick, not an error —
    /// every counter starts at zero exactly as it would have if this type
    /// had never been serialized yet.
    fn load(path: &Path) -> Result<Self, Error> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                toml::from_str(&text).map_err(|e| Error::Syntax(format!("breaker state: {e}")))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Writes to a sibling temp file and renames over `path` — a crash
    /// mid-write leaves the previous, still-valid state file in place
    /// rather than a half-written one a later load would fail to parse.
    fn save(&self, path: &Path) -> Result<(), Error> {
        let text = toml::to_string_pretty(self)
            .map_err(|e| Error::Syntax(format!("breaker state: {e}")))?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text).map_err(Error::Io)?;
        std::fs::rename(&tmp, path).map_err(Error::Io)
    }
}

/// Wraps any [`Driver`] with ADR-0045 §6's two mandatory driver-layer
/// checks — see the module doc. Every concrete driver (the no-op one
/// today, a real one later) is meant to be reached only through this
/// wrapper once Phase 2 is actually actuating anything, so neither check
/// depends on which driver is underneath.
#[derive(Debug)]
pub struct BoundedDriver<D> {
    inner: D,
    limits: HashMap<String, BreakerLimits>,
    allowed_regions: HashMap<Provider, Vec<String>>,
    /// Each pool's declared `(provider, region)`, from this struct's own
    /// independently-loaded [`Document`] — never the planner's.
    pool_regions: HashMap<String, (Provider, String)>,
    state: BreakerState,
    state_path: PathBuf,
}

impl<D: Driver> BoundedDriver<D> {
    /// Loads its own copy of `cost_model_path` (re-validated independently
    /// of whatever already validated it elsewhere), `limits_path`'s
    /// per-pool ceilings, and `state_path`'s persisted counters (absent on
    /// a fresh deployment).
    ///
    /// # Errors
    /// If any of the three files cannot be read or parsed, or the
    /// cost-model document fails its own validation.
    pub fn new(
        inner: D,
        cost_model_path: &Path,
        limits_path: &Path,
        state_path: &Path,
    ) -> Result<Self, Error> {
        let cost_doc = Document::load(cost_model_path).map_err(Error::CostModel)?;
        cost_doc.validate().map_err(Error::CostModel)?;
        let pool_regions = cost_doc
            .pools
            .iter()
            .map(|(id, pool)| (id.clone(), (pool.provider, pool.region.clone())))
            .collect();

        let limits = BreakerLimitsDocument::load(limits_path)?.pools;
        let state = BreakerState::load(state_path)?;

        Ok(Self {
            inner,
            limits,
            allowed_regions: cost_doc.allowed_regions,
            pool_regions,
            state,
            state_path: state_path.to_owned(),
        })
    }

    /// §4c re-check, independent of the planner's own copy — see the
    /// module doc.
    fn check_region(&self, pool_id: &str) -> Result<(), DriverError> {
        let (provider, region) = self.pool_regions.get(pool_id).ok_or_else(|| {
            DriverError::Other(format!(
                "breaker: pool {pool_id} is not in this driver's own cost-model copy -- refusing to create"
            ))
        })?;
        if !provider.is_region_bound() {
            return Ok(());
        }
        let allowed = self.allowed_regions.get(provider);
        if !allowed.is_some_and(|regions| regions.iter().any(|r| r == region)) {
            return Err(DriverError::Other(format!(
                "breaker: pool {pool_id}'s region {region:?} is not in allowed_regions.{provider} -- refusing to create"
            )));
        }
        Ok(())
    }

    /// §6's circuit breaker: refuses `n` more nodes in `pool_id` if either
    /// ceiling would be exceeded this period, without mutating any state —
    /// callers commit via [`Self::commit`] only after the inner driver's
    /// own `create` actually succeeds.
    fn check_breaker(
        &self,
        pool_id: &str,
        n: u32,
    ) -> Result<(PeriodCounter, BreakerLimits), DriverError> {
        let limits = *self.limits.get(pool_id).ok_or_else(|| {
            DriverError::Other(format!(
                "breaker: pool {pool_id} has no configured breaker limits -- refusing to \
                 create (ADR-0045 §6 allows no \"unlimited\" default)"
            ))
        })?;
        let counter = self.counter_for(pool_id);

        let nodes_added = counter.nodes_added.saturating_add(n);
        if nodes_added > limits.nodes_max_per_period {
            return Err(DriverError::Other(format!(
                "breaker: pool {pool_id} would add {n} node(s) to {} already added this \
                 period, exceeding nodes_max_per_period ({})",
                counter.nodes_added, limits.nodes_max_per_period
            )));
        }

        let spend_committed =
            counter.spend_committed + f64::from(n) * limits.cost_per_node_estimate;
        if spend_committed > limits.budget_cap_per_period {
            return Err(DriverError::Other(format!(
                "breaker: pool {pool_id} would commit an estimated {spend_committed:.2} this \
                 period, exceeding budget_cap_per_period ({:.2})",
                limits.budget_cap_per_period
            )));
        }

        Ok((
            PeriodCounter {
                period: counter.period,
                nodes_added,
                spend_committed,
            },
            limits,
        ))
    }

    /// This pool's counter for the *current* period — rolled over to zero
    /// first if the persisted counter is from an earlier one.
    fn counter_for(&self, pool_id: &str) -> PeriodCounter {
        let now = now_unix();
        let period = period_key(now);
        match self.state.adds_by_pool.get(pool_id) {
            Some(counter) if counter.period == period => *counter,
            _ => PeriodCounter {
                period,
                nodes_added: 0,
                spend_committed: 0.0,
            },
        }
    }

    /// Persists `counter` for `pool_id` and saves the whole state file —
    /// called only after the inner driver's `create` has actually
    /// succeeded, so a refused or failed create never advances state.
    fn commit(&mut self, pool_id: &str, counter: PeriodCounter) -> Result<(), DriverError> {
        self.state.adds_by_pool.insert(pool_id.to_owned(), counter);
        self.state
            .save(&self.state_path)
            .map_err(|e| DriverError::Other(format!("breaker: saving state: {e}")))
    }
}

impl<D: Driver> Driver for BoundedDriver<D> {
    fn list(&self, pool_id: &str) -> Result<Vec<Instance>, DriverError> {
        self.inner.list(pool_id)
    }

    fn create(&mut self, pool_id: &str, n: u32) -> Result<Vec<Instance>, DriverError> {
        self.check_region(pool_id)?;
        let (counter, _limits) = self.check_breaker(pool_id, n)?;
        let created = self.inner.create(pool_id, n)?;
        self.commit(pool_id, counter)?;
        Ok(created)
    }

    fn drain(&mut self, pool_id: &str, id: &str) -> Result<(), DriverError> {
        self.inner.drain(pool_id, id)
    }

    fn destroy(&mut self, pool_id: &str, id: &str) -> Result<(), DriverError> {
        self.inner.destroy(pool_id, id)
    }
}

fn now_unix() -> i64 {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX)
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
    use crate::driver::NoopDriver;

    const COST_MODEL: &str = r#"
[pools.p]
provider = "onprem"
region = "x"
min_nodes = 0

[pools.p.cost_model.meters.instance_hours]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
"#;

    const AWS_COST_MODEL: &str = r#"
[pools.p]
provider = "aws"
region = "us-east-1"
min_nodes = 0

[allowed_regions]
aws = ["us-east-1"]

[pools.p.cost_model.meters.instance_hours]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
"#;

    fn write(dir: &std::path::Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).expect("writes fixture");
        path
    }

    fn bounded(dir: &std::path::Path, cost_model: &str, limits: &str) -> BoundedDriver<NoopDriver> {
        let cost_model_path = write(dir, "cost-model.toml", cost_model);
        let limits_path = write(dir, "limits.toml", limits);
        let state_path = dir.join("state.toml");
        BoundedDriver::new(
            NoopDriver::new(),
            &cost_model_path,
            &limits_path,
            &state_path,
        )
        .expect("builds")
    }

    #[test]
    fn a_create_within_both_ceilings_succeeds_and_is_listed() {
        let dir = tempdir();
        let limits = "[pools.p]\nnodes_max_per_period = 10\nbudget_cap_per_period = 1000.0\ncost_per_node_estimate = 1.0\n";
        let mut d = bounded(dir.path(), COST_MODEL, limits);
        let created = d.create("p", 3).expect("within ceilings");
        assert_eq!(created.len(), 3);
        assert_eq!(d.list("p").expect("lists").len(), 3);
    }

    #[test]
    fn a_pool_with_no_configured_limits_is_refused_not_treated_as_unlimited() {
        let dir = tempdir();
        let d = bounded(dir.path(), COST_MODEL, "");
        let mut d = d;
        let err = d.create("p", 1).expect_err("no limits configured");
        assert!(
            format!("{err}").contains("no configured breaker limits"),
            "{err}"
        );
    }

    #[test]
    fn exceeding_nodes_max_per_period_is_refused() {
        let dir = tempdir();
        let limits = "[pools.p]\nnodes_max_per_period = 2\nbudget_cap_per_period = 1000.0\ncost_per_node_estimate = 1.0\n";
        let mut d = bounded(dir.path(), COST_MODEL, limits);
        let err = d.create("p", 3).expect_err("exceeds nodes_max_per_period");
        assert!(format!("{err}").contains("nodes_max_per_period"), "{err}");
        assert!(
            d.list("p").expect("lists").is_empty(),
            "refused create must not touch the inner driver"
        );
    }

    #[test]
    fn exceeding_budget_cap_per_period_is_refused() {
        let dir = tempdir();
        let limits = "[pools.p]\nnodes_max_per_period = 100\nbudget_cap_per_period = 5.0\ncost_per_node_estimate = 10.0\n";
        let mut d = bounded(dir.path(), COST_MODEL, limits);
        let err = d.create("p", 1).expect_err("exceeds budget_cap_per_period");
        assert!(format!("{err}").contains("budget_cap_per_period"), "{err}");
    }

    #[test]
    fn node_counts_accumulate_within_a_period_and_a_second_call_can_then_be_refused() {
        let dir = tempdir();
        let limits = "[pools.p]\nnodes_max_per_period = 3\nbudget_cap_per_period = 1000.0\ncost_per_node_estimate = 1.0\n";
        let mut d = bounded(dir.path(), COST_MODEL, limits);
        d.create("p", 2).expect("first create within ceiling");
        let err = d.create("p", 2).expect_err("2 + 2 > 3");
        assert!(format!("{err}").contains("nodes_max_per_period"), "{err}");
    }

    #[test]
    fn state_persists_across_a_fresh_boundeddriver_against_the_same_state_file() {
        let dir = tempdir();
        let limits = "[pools.p]\nnodes_max_per_period = 3\nbudget_cap_per_period = 1000.0\ncost_per_node_estimate = 1.0\n";
        let cost_model_path = write(dir.path(), "cost-model.toml", COST_MODEL);
        let limits_path = write(dir.path(), "limits.toml", limits);
        let state_path = dir.path().join("state.toml");

        let mut first = BoundedDriver::new(
            NoopDriver::new(),
            &cost_model_path,
            &limits_path,
            &state_path,
        )
        .expect("builds");
        first.create("p", 2).expect("within ceiling");

        let mut second = BoundedDriver::new(
            NoopDriver::new(),
            &cost_model_path,
            &limits_path,
            &state_path,
        )
        .expect("builds against the same persisted state");
        let err = second
            .create("p", 2)
            .expect_err("2 + 2 > 3, even across processes");
        assert!(format!("{err}").contains("nodes_max_per_period"), "{err}");
    }

    #[test]
    fn a_region_outside_the_allowlist_is_refused_even_though_the_planner_would_have_caught_it_too()
    {
        // AWS_COST_MODEL's own allowed_regions permits us-east-1; simulate
        // a corrupted/stale allowlist reaching only this driver's copy by
        // pointing it at a *different* limits/allowlist file than the one
        // the cost model itself declares -- here, by using a cost model
        // whose own allowed_regions does not list the pool's region.
        let dir = tempdir();
        let bad_cost_model = AWS_COST_MODEL.replace("us-east-1\"]", "eu-west-1\"]");
        let limits = "[pools.p]\nnodes_max_per_period = 10\nbudget_cap_per_period = 1000.0\ncost_per_node_estimate = 1.0\n";
        let cost_model_path = write(dir.path(), "cost-model.toml", &bad_cost_model);
        // The cost model's own validate() would already refuse this
        // Document (region not in its own allowed_regions) -- confirming
        // that, then confirming BoundedDriver::new surfaces the same
        // independent validation rather than skipping it.
        let doc = Document::load(&cost_model_path).expect("parses");
        assert!(
            doc.validate().is_err(),
            "the cost model's own validate() already catches this"
        );

        let limits_path = write(dir.path(), "limits.toml", limits);
        let state_path = dir.path().join("state.toml");
        let err = BoundedDriver::<NoopDriver>::new(
            NoopDriver::new(),
            &cost_model_path,
            &limits_path,
            &state_path,
        )
        .expect_err("BoundedDriver::new re-validates independently too");
        assert!(
            format!("{err}").contains("us-east-1") || format!("{err}").contains("eu-west-1"),
            "{err}"
        );
    }

    #[test]
    fn a_turn_kind_pools_region_is_re_checked_exactly_like_a_relay_pools() {
        // #311's own scope asked this to be confirmed, not assumed:
        // check_region (and BoundedDriver::new's independent re-validation
        // of it, exercised above for a relay-kind pool) reads a pool's
        // `(provider, region)` -- never its `kind` -- so a Turn-kind pool
        // must be refused by exactly the same path. This is the only
        // scope item #311 left that wasn't closed by a prior PR.
        let dir = tempdir();
        let turn_cost_model = AWS_COST_MODEL
            .replace("us-east-1\"]", "eu-west-1\"]")
            .replacen("[pools.p]\n", "[pools.p]\nkind = \"turn\"\n", 1);
        let doc = {
            let path = write(dir.path(), "probe.toml", &turn_cost_model);
            Document::load(&path).expect("parses")
        };
        assert_eq!(
            doc.pools.get("p").expect("pool p").kind,
            crate::cost_model::PoolKind::Turn,
            "fixture actually declares a turn-kind pool"
        );

        let limits = "[pools.p]\nnodes_max_per_period = 10\nbudget_cap_per_period = 1000.0\ncost_per_node_estimate = 1.0\n";
        let cost_model_path = write(dir.path(), "cost-model.toml", &turn_cost_model);
        let limits_path = write(dir.path(), "limits.toml", limits);
        let state_path = dir.path().join("state.toml");
        let err = BoundedDriver::<NoopDriver>::new(
            NoopDriver::new(),
            &cost_model_path,
            &limits_path,
            &state_path,
        )
        .expect_err("a turn-kind pool's region is re-checked the same as a relay-kind pool's");
        assert!(
            format!("{err}").contains("us-east-1") || format!("{err}").contains("eu-west-1"),
            "{err}"
        );
    }

    #[test]
    fn a_refused_create_never_calls_the_inner_driver() {
        let dir = tempdir();
        let limits = "[pools.p]\nnodes_max_per_period = 0\nbudget_cap_per_period = 1000.0\ncost_per_node_estimate = 1.0\n";
        let mut d = bounded(dir.path(), COST_MODEL, limits);
        assert!(d.create("p", 1).is_err());
        assert!(d.list("p").expect("lists").is_empty());
    }

    /// A minimal temp-directory helper — this crate has no `tempfile`
    /// dependency (Phase 0/1's whole point is a short dependency list; see
    /// `Cargo.toml`'s own comment), so tests that need a real filesystem
    /// path make their own scratch directory under `std::env::temp_dir()`
    /// rather than pulling one in for this alone.
    struct TempDir(PathBuf);

    impl TempDir {
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tempdir() -> TempDir {
        let dir = std::env::temp_dir().join(format!(
            "karst-scaler-breaker-test-{}-{}",
            std::process::id(),
            now_unix_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("creates temp dir");
        TempDir(dir)
    }

    fn now_unix_nanos() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos()
    }
}
