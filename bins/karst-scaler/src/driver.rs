// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! ADR-0045 §5: the driver interface a [`crate::advise::Recommendation`] is
//! reconciled against. "The planner never calls a cloud API. It emits
//! desired state to a driver that implements roughly four verbs... against
//! one pool." This module defines that interface and the no-op/"advise"
//! driver §5 names explicitly as one of the drivers worth building —
//! everything else ADR-0045 §7 Phase 2 adds (the budget circuit breaker,
//! the independent region-allowlist re-check, any real cloud/Kubernetes
//! driver) is built on top of [`Driver`], not this module.
//!
//! [`NoopDriver`] is in-memory and pool-scoped: it tracks instances it was
//! asked to create, nothing more. It has no notion of what is actually
//! running anywhere, by design — it exists so `karst-scaler drive`'s own
//! reconciliation loop (`drive_loop.rs`) is runnable and testable end to
//! end before any real driver, with its own credentials, is wired in.

use std::fmt;

/// One instance a [`Driver`] knows about, as it exists right now —
/// [`Driver::list`]'s and [`Driver::create`]'s own return value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    pub id: String,
    pub pool_id: String,
    pub state: InstanceState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceState {
    Running,
    Draining,
}

/// A [`Driver`] operation failed. Deliberately one message-carrying
/// variant today rather than a set of named ones: [`NoopDriver`]'s own
/// failure ("that instance doesn't exist"), `crate::breaker::BoundedDriver`'s
/// refusals, and a real driver's own failure modes (quota, a transient
/// cloud-API error, ...) are not yet a well-enough-understood set to name
/// as distinct variants without guessing which ones callers will actually
/// need to branch on.
#[derive(Debug)]
pub enum DriverError {
    Other(String),
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for DriverError {}

/// ADR-0045 §5's four verbs, against one pool at a time — `pool_id` is
/// always the caller's own, never inferred by a driver from its internal
/// state, so a driver backing more than one pool (e.g. one Kubernetes
/// cluster running several pools' Deployments) never has to guess which
/// pool an instance belongs to.
pub trait Driver {
    /// Every instance this driver currently knows about in `pool_id`,
    /// regardless of state.
    ///
    /// # Errors
    /// If the driver cannot reach whatever backs it (an API call, a file,
    /// ...) to answer the question.
    fn list(&self, pool_id: &str) -> Result<Vec<Instance>, DriverError>;

    /// Create `n` new instances in `pool_id` and return them. A driver that
    /// cannot create exactly `n` (e.g. a quota) returns an error rather
    /// than a partial list — callers must not have to guess whether a
    /// short `Vec` means "this many succeeded" or "the driver's `Vec`
    /// happens to be shorter for some other reason."
    ///
    /// # Errors
    /// If fewer than `n` instances could be created, for any reason.
    fn create(&mut self, pool_id: &str, n: u32) -> Result<Vec<Instance>, DriverError>;

    /// Drain one instance so it stops taking new work. Returns once the
    /// instance has drained or the driver's own bounded wait for that has
    /// elapsed — matching `karst-relay`'s existing `announce_restart`/
    /// `Restarting` broadcast (`bins/karst-relay/src/server.rs`), which
    /// already blocks exactly this way. A caller may call [`Driver::destroy`]
    /// immediately after a successful return; this trait does not require
    /// a caller to poll for drain completion separately.
    ///
    /// # Errors
    /// If `id` is not a known instance of `pool_id`, or the driver could
    /// not reach it to begin draining.
    fn drain(&mut self, pool_id: &str, id: &str) -> Result<(), DriverError>;

    /// Remove one instance for good. Calling this on an instance that was
    /// never drained is a driver's own decision to make (and refuse, if it
    /// wants); this trait does not enforce drain-before-destroy.
    ///
    /// # Errors
    /// If `id` is not a known instance of `pool_id`, or the driver could
    /// not remove it.
    fn destroy(&mut self, pool_id: &str, id: &str) -> Result<(), DriverError>;
}

/// §5's no-op/"advise" driver: records what it was asked to do, in memory,
/// and nothing else. Draining marks an instance [`InstanceState::Draining`]
/// without changing anything else about it (nothing is actually taking
/// traffic to drain); destroying removes it from the in-memory list.
#[derive(Debug, Default)]
pub struct NoopDriver {
    next_id: u64,
    instances: Vec<Instance>,
}

impl NoopDriver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Driver for NoopDriver {
    fn list(&self, pool_id: &str) -> Result<Vec<Instance>, DriverError> {
        Ok(self
            .instances
            .iter()
            .filter(|i| i.pool_id == pool_id)
            .cloned()
            .collect())
    }

    fn create(&mut self, pool_id: &str, n: u32) -> Result<Vec<Instance>, DriverError> {
        let mut created = Vec::new();
        for _ in 0..n {
            self.next_id += 1;
            let instance = Instance {
                id: format!("noop-{}", self.next_id),
                pool_id: pool_id.to_owned(),
                state: InstanceState::Running,
            };
            self.instances.push(instance.clone());
            created.push(instance);
        }
        Ok(created)
    }

    fn drain(&mut self, pool_id: &str, id: &str) -> Result<(), DriverError> {
        let instance = self
            .instances
            .iter_mut()
            .find(|i| i.pool_id == pool_id && i.id == id)
            .ok_or_else(|| {
                DriverError::Other(format!("no such instance {id} in pool {pool_id}"))
            })?;
        instance.state = InstanceState::Draining;
        Ok(())
    }

    fn destroy(&mut self, pool_id: &str, id: &str) -> Result<(), DriverError> {
        let before = self.instances.len();
        self.instances
            .retain(|i| !(i.pool_id == pool_id && i.id == id));
        if self.instances.len() == before {
            return Err(DriverError::Other(format!(
                "no such instance {id} in pool {pool_id}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]

    use super::*;

    #[test]
    fn create_lists_back_exactly_what_it_created() {
        let mut d = NoopDriver::new();
        let created = d.create("p", 3).expect("creates");
        assert_eq!(created.len(), 3);
        let listed = d.list("p").expect("lists");
        assert_eq!(listed, created);
        for instance in &listed {
            assert_eq!(instance.state, InstanceState::Running);
        }
    }

    #[test]
    fn list_is_scoped_to_its_own_pool() {
        let mut d = NoopDriver::new();
        d.create("a", 2).expect("creates");
        d.create("b", 1).expect("creates");
        assert_eq!(d.list("a").expect("lists").len(), 2);
        assert_eq!(d.list("b").expect("lists").len(), 1);
    }

    #[test]
    fn drain_then_destroy_removes_the_instance() {
        let mut d = NoopDriver::new();
        let created = d.create("p", 1).expect("creates");
        let id = created[0].id.clone();
        d.drain("p", &id).expect("drains");
        assert_eq!(
            d.list("p").expect("lists")[0].state,
            InstanceState::Draining
        );
        d.destroy("p", &id).expect("destroys");
        assert!(d.list("p").expect("lists").is_empty());
    }

    #[test]
    fn draining_or_destroying_an_unknown_instance_is_an_error() {
        let mut d = NoopDriver::new();
        assert!(d.drain("p", "nope").is_err());
        assert!(d.destroy("p", "nope").is_err());
    }
}
