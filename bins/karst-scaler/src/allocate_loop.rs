// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The `karst-scaler allocate` subcommand's own loop — ADR-0063, issue
//! #455. A sibling to [`crate::drive_loop`], sharing the same
//! `karst_scaler::driver::Driver` trait but **not merged into it**: a
//! named, capability-specific one-off allocation is not a pool member
//! (ADR-0063's "Alternatives rejected" — forcing one to carry a name, a
//! specific group grant, and capability selection would corrupt the cost
//! model's assumption that every pool member is interchangeable).
//!
//! Each tick polls `POST /karst/v1/relay-allocations/pending` (shaped as
//! a POST, not a GET, for the same reason `relayEnrollTokensCreate`/
//! `relayDeenroll` already are — `types::UserRoleScaler` only ever holds
//! `operations.Create` on `modules.KarstControl`) and drives every
//! returned allocation through exactly the one step its current state
//! needs:
//!
//! - `requested` → call [`karst_scaler::driver::Driver::create`] for one
//!   instance (`list` first, so a crash-and-retry never creates a
//!   second one for the same allocation — the same discipline
//!   `drive_loop::reconcile` already applies at pool scope), then record
//!   the result via `POST .../provisioning`.
//! - `provisioning`/`granting` → look up the instance's own
//!   `tls_server_name` (via `list`, which survives this process
//!   restarting between ticks — see
//!   `karst_scaler_driver::Instance::tls_server_name`'s own doc) and call
//!   `POST .../grant`. A 404 means the relay has not registered yet —
//!   not a failure, just not ready; the server does the actual
//!   `relayservice.Create` call and the `granting`→`ready`/`failed`
//!   transition itself, in-process, so nothing here reports success or
//!   failure after that call beyond "did the HTTP request itself
//!   succeed."
//! - `revoking` → call `POST .../revoke`. The server withdraws the grant
//!   itself, in-process, before transitioning to `deprovisioning`.
//! - `deprovisioning` → `drain` then `destroy` the instance (reversed
//!   order from provisioning: the grant was already withdrawn by the
//!   `revoking` step above, before compute teardown begins — ADR-0063's
//!   own ordering), then record it via `POST .../deprovisioned`.
//!
//! A [`Driver::create`]/`drain`/`destroy` failure is a definitive,
//! locally-known outcome this loop reports through `POST .../failed`
//! itself; a failure calling the control server (network, a transient
//! 5xx) is logged and retried next tick, the same "log and continue"
//! posture [`crate::drive_loop::run`] already has — a missed tick
//! self-heals the next one.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use karst_scaler::driver::Driver;

/// `karst-scaler allocate`'s own config — deliberately not
/// [`crate::advise_loop::Config`]: no cost model, no breaker, and the PAT
/// here is `UserRoleScaler`-scoped, not `UserRoleAdvisor`-scoped.
pub(crate) struct Config {
    pub control_api_base: String,
    pub pat: String,
    pub poll_interval: Duration,
}

/// The one shape every `/karst/v1/relay-allocations/pending` entry is
/// read as — only what this loop's own branching needs. `name`,
/// `infra_connection_id`, `location`, and the capability/group fields
/// the console wrote are not this loop's concern: it drives a state
/// machine forward, it does not re-validate what was already accepted
/// at `POST /relay-allocations` time.
#[derive(Debug, Clone, Deserialize)]
struct Allocation {
    id: String,
    state: String,
    revision: u64,
}

/// Everything this loop needs from the control server, abstracted the
/// same reason `Driver` itself is one: so [`drive_one`]'s branching is
/// unit-testable against a fake, not a real HTTP server.
trait ControlPlane {
    fn pending(&self) -> Result<Vec<Allocation>, String>;
    fn record_provisioning(&self, id: &str, revision: u64, instance_id: &str)
        -> Result<(), String>;
    /// `Ok(true)` means granted, or already past granting — an
    /// idempotent retry; `Ok(false)` means the relay has not registered
    /// yet, per `POST .../grant`'s own 404 contract. Either way the
    /// server has already done whatever state transition is correct;
    /// this return value only tells the loop whether to stop driving
    /// this allocation forward this tick.
    fn grant(&self, id: &str, revision: u64, tls_server_name: &str) -> Result<bool, String>;
    fn revoke(&self, id: &str, revision: u64) -> Result<(), String>;
    fn report_deprovisioned(&self, id: &str, revision: u64) -> Result<(), String>;
    fn report_failed(&self, id: &str, revision: u64, reason: &str) -> Result<(), String>;
}

#[derive(Debug, Serialize)]
struct ProvisioningRequest<'a> {
    expected_revision: u64,
    instance_id: &'a str,
}

#[derive(Debug, Serialize)]
struct GrantRequest<'a> {
    expected_revision: u64,
    tls_server_name: &'a str,
}

#[derive(Debug, Serialize)]
struct RevisionOnlyRequest {
    expected_revision: u64,
}

#[derive(Debug, Serialize)]
struct FailedRequest<'a> {
    expected_revision: u64,
    reason: &'a str,
}

/// The real [`ControlPlane`], over HTTPS with the loop's own
/// `UserRoleScaler`-scoped bearer PAT — same agent-construction
/// convention as [`crate::advise_loop::build_agent`] (reused directly,
/// not duplicated).
struct HttpControlPlane<'a> {
    agent: &'a ureq::Agent,
    config: &'a Config,
}

impl HttpControlPlane<'_> {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.control_api_base)
    }

    fn post_json<B: serde::Serialize>(&self, path: &str, body: &B) -> Result<ureq::Body, String> {
        let url = self.url(path);
        self.agent
            .post(&url)
            .header("Authorization", &format!("Bearer {}", self.config.pat))
            .send_json(body)
            .map(ureq::http::Response::into_body)
            .map_err(|e| format!("POST {url}: {e}"))
    }
}

impl ControlPlane for HttpControlPlane<'_> {
    fn pending(&self) -> Result<Vec<Allocation>, String> {
        let url = self.url("/karst/v1/relay-allocations/pending");
        self.agent
            .post(&url)
            .header("Authorization", &format!("Bearer {}", self.config.pat))
            .send_empty()
            .map_err(|e| format!("POST {url}: {e}"))?
            .body_mut()
            .read_json::<Vec<Allocation>>()
            .map_err(|e| format!("POST {url}: decoding response: {e}"))
    }

    fn record_provisioning(
        &self,
        id: &str,
        revision: u64,
        instance_id: &str,
    ) -> Result<(), String> {
        self.post_json(
            &format!("/karst/v1/relay-allocations/{id}/provisioning"),
            &ProvisioningRequest {
                expected_revision: revision,
                instance_id,
            },
        )
        .map(|_| ())
    }

    fn grant(&self, id: &str, revision: u64, tls_server_name: &str) -> Result<bool, String> {
        let url = self.url(&format!("/karst/v1/relay-allocations/{id}/grant"));
        match self
            .agent
            .post(&url)
            .header("Authorization", &format!("Bearer {}", self.config.pat))
            .send_json(GrantRequest {
                expected_revision: revision,
                tls_server_name,
            }) {
            Ok(_) => Ok(true),
            Err(ureq::Error::StatusCode(404)) => Ok(false),
            Err(e) => Err(format!("POST {url}: {e}")),
        }
    }

    fn revoke(&self, id: &str, revision: u64) -> Result<(), String> {
        self.post_json(
            &format!("/karst/v1/relay-allocations/{id}/revoke"),
            &RevisionOnlyRequest {
                expected_revision: revision,
            },
        )
        .map(|_| ())
    }

    fn report_deprovisioned(&self, id: &str, revision: u64) -> Result<(), String> {
        self.post_json(
            &format!("/karst/v1/relay-allocations/{id}/deprovisioned"),
            &RevisionOnlyRequest {
                expected_revision: revision,
            },
        )
        .map(|_| ())
    }

    fn report_failed(&self, id: &str, revision: u64, reason: &str) -> Result<(), String> {
        self.post_json(
            &format!("/karst/v1/relay-allocations/{id}/failed"),
            &FailedRequest {
                expected_revision: revision,
                reason,
            },
        )
        .map(|_| ())
    }
}

/// Runs the reconciliation loop forever, logging each tick's own failure
/// and continuing past it — matching [`crate::drive_loop::run`]'s own
/// reasoning: a transient control-server or network hiccup should not
/// kill a long-lived process.
pub(crate) fn run(config: &Config, driver: &mut dyn Driver) -> Result<(), String> {
    let agent = crate::advise_loop::build_agent()?;
    loop {
        let control = HttpControlPlane {
            agent: &agent,
            config,
        };
        match tick(&control, driver) {
            Ok(0) => {}
            Ok(n) => println!("karst-scaler allocate: drove {n} allocation(s)"),
            Err(e) => eprintln!("karst-scaler allocate: tick failed: {e}"),
        }
        std::thread::sleep(config.poll_interval);
    }
}

fn tick(control: &dyn ControlPlane, driver: &mut dyn Driver) -> Result<usize, String> {
    let pending = control.pending()?;
    for allocation in &pending {
        if let Err(e) = drive_one(control, driver, allocation) {
            eprintln!("karst-scaler allocate: allocation {}: {e}", allocation.id);
        }
    }
    Ok(pending.len())
}

fn drive_one(
    control: &dyn ControlPlane,
    driver: &mut dyn Driver,
    allocation: &Allocation,
) -> Result<(), String> {
    match allocation.state.as_str() {
        "requested" => provision(control, driver, allocation),
        "provisioning" | "granting" => grant(control, driver, allocation),
        "revoking" => control.revoke(&allocation.id, allocation.revision),
        "deprovisioning" => deprovision(control, driver, allocation),
        other => Err(format!("unrecognized allocation state {other:?}")),
    }
}

/// `list` before `create`: if a previous tick's `create()` succeeded but
/// this loop crashed or the subsequent `record_provisioning` call failed
/// before the server ever saw it, the allocation is still `requested`
/// next tick — without this check, that retry would create a *second*
/// instance for the same allocation. The one real driver this matters
/// for (`AwsDriver`) already tags every instance by `pool_id`, so `list`
/// scoped to this allocation's own id (reused as the `pool_id` argument,
/// per ADR-0063) finds exactly what a previous attempt left behind.
fn provision(
    control: &dyn ControlPlane,
    driver: &mut dyn Driver,
    allocation: &Allocation,
) -> Result<(), String> {
    let existing = driver.list(&allocation.id).map_err(|e| e.to_string())?;
    let instance = match existing.into_iter().next() {
        Some(instance) => instance,
        None => match driver.create(&allocation.id, 1) {
            Ok(created) => created.into_iter().next().ok_or_else(|| {
                format!(
                    "driver reported success but created no instance for allocation {}",
                    allocation.id
                )
            })?,
            Err(e) => {
                let reason = e.to_string();
                report_failure(control, allocation, &reason);
                return Err(format!("create: {reason}"));
            }
        },
    };
    control.record_provisioning(&allocation.id, allocation.revision, &instance.id)
}

/// `list`, not a remembered instance id: this loop's own process may
/// have restarted since `provision` ran, and `tls_server_name` is never
/// echoed back by the server — only `Driver::list`/`create` ever report
/// it (ADR-0063, `karst_scaler_driver::Instance::tls_server_name`'s own
/// doc).
fn grant(
    control: &dyn ControlPlane,
    driver: &mut dyn Driver,
    allocation: &Allocation,
) -> Result<(), String> {
    let instance = driver
        .list(&allocation.id)
        .map_err(|e| e.to_string())?
        .into_iter()
        .next()
        .ok_or_else(|| format!("no instance found for allocation {}", allocation.id))?;
    let tls_server_name = instance.tls_server_name.ok_or_else(|| {
        format!(
            "driver instance {} has no tls_server_name to grant against",
            instance.id
        )
    })?;
    control
        .grant(&allocation.id, allocation.revision, &tls_server_name)
        .map(|_ready| ())
}

/// Reversed from `provision`: the grant was already withdrawn by the
/// `revoking` step (ADR-0063's own ordering) before this ever runs, so
/// draining and destroying here can never leave an access grant pointing
/// at compute the system believes torn down. Idempotent if a previous
/// attempt already destroyed the instance — nothing left to `list`.
fn deprovision(
    control: &dyn ControlPlane,
    driver: &mut dyn Driver,
    allocation: &Allocation,
) -> Result<(), String> {
    let instances = driver.list(&allocation.id).map_err(|e| e.to_string())?;
    for instance in &instances {
        if let Err(e) = driver.drain(&allocation.id, &instance.id) {
            let reason = format!("drain {}: {e}", instance.id);
            report_failure(control, allocation, &reason);
            return Err(reason);
        }
        if let Err(e) = driver.destroy(&allocation.id, &instance.id) {
            let reason = format!("destroy {}: {e}", instance.id);
            report_failure(control, allocation, &reason);
            return Err(reason);
        }
    }
    control.report_deprovisioned(&allocation.id, allocation.revision)
}

/// Best-effort: if reporting the failure itself fails (the control
/// server is unreachable), the original error -- not this one -- is
/// what the caller returns and `tick` logs; the allocation simply stays
/// in its current state and this step retries next tick.
fn report_failure(control: &dyn ControlPlane, allocation: &Allocation, reason: &str) {
    if let Err(report_err) = control.report_failed(&allocation.id, allocation.revision, reason) {
        eprintln!(
            "karst-scaler allocate: allocation {}: failed ({reason}) and reporting that \
             failure also failed: {report_err}",
            allocation.id
        );
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

    use std::cell::RefCell;

    use karst_scaler::driver::{DriverError, Instance, InstanceState, NoopDriver};

    use super::*;

    /// A fake [`ControlPlane`] that records every call it receives and
    /// returns canned, per-test outcomes -- never touches the network.
    struct FakeControlPlane {
        calls: RefCell<Vec<String>>,
        grant_ready: bool,
        fail_revoke: bool,
    }

    impl Default for FakeControlPlane {
        fn default() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                grant_ready: true,
                fail_revoke: false,
            }
        }
    }

    impl ControlPlane for FakeControlPlane {
        fn pending(&self) -> Result<Vec<Allocation>, String> {
            unreachable!("drive_one tests call drive_one directly, not tick")
        }
        fn record_provisioning(
            &self,
            id: &str,
            revision: u64,
            instance_id: &str,
        ) -> Result<(), String> {
            self.calls.borrow_mut().push(format!(
                "record_provisioning({id},{revision},{instance_id})"
            ));
            Ok(())
        }
        fn grant(&self, id: &str, revision: u64, tls_server_name: &str) -> Result<bool, String> {
            self.calls
                .borrow_mut()
                .push(format!("grant({id},{revision},{tls_server_name})"));
            Ok(self.grant_ready)
        }
        fn revoke(&self, id: &str, revision: u64) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("revoke({id},{revision})"));
            if self.fail_revoke {
                return Err("revoke refused".to_owned());
            }
            Ok(())
        }
        fn report_deprovisioned(&self, id: &str, revision: u64) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("report_deprovisioned({id},{revision})"));
            Ok(())
        }
        fn report_failed(&self, id: &str, revision: u64, reason: &str) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("report_failed({id},{revision},{reason})"));
            Ok(())
        }
    }

    /// Unlike [`NoopDriver`], reports a `tls_server_name` from `create`
    /// and recovers it from `list` too -- matching `AwsDriver`/
    /// `K8sDriver`'s real contract, which [`grant`]'s own logic depends
    /// on. Also records `drain`/`destroy` calls so teardown ordering is
    /// assertable.
    #[derive(Default)]
    struct NamedDriver {
        instances: Vec<Instance>,
        drained: Vec<String>,
        destroyed: Vec<String>,
        fail_create: bool,
        fail_destroy: bool,
    }

    impl Driver for NamedDriver {
        fn list(&self, pool_id: &str) -> Result<Vec<Instance>, DriverError> {
            Ok(self
                .instances
                .iter()
                .filter(|i| i.pool_id == pool_id)
                .cloned()
                .collect())
        }
        fn create(&mut self, pool_id: &str, n: u32) -> Result<Vec<Instance>, DriverError> {
            if self.fail_create {
                return Err(DriverError::Other("quota exceeded".to_owned()));
            }
            let mut created = Vec::new();
            for _ in 0..n {
                let instance = Instance {
                    id: format!("{pool_id}-instance"),
                    pool_id: pool_id.to_owned(),
                    state: InstanceState::Running,
                    tls_server_name: Some(format!("{pool_id}.test.karst.internal")),
                };
                self.instances.push(instance.clone());
                created.push(instance);
            }
            Ok(created)
        }
        fn drain(&mut self, _pool_id: &str, id: &str) -> Result<(), DriverError> {
            self.drained.push(id.to_owned());
            Ok(())
        }
        fn destroy(&mut self, pool_id: &str, id: &str) -> Result<(), DriverError> {
            if self.fail_destroy {
                return Err(DriverError::Other("still terminating".to_owned()));
            }
            self.destroyed.push(id.to_owned());
            self.instances
                .retain(|i| !(i.pool_id == pool_id && i.id == id));
            Ok(())
        }
    }

    fn allocation(state: &str) -> Allocation {
        Allocation {
            id: "alloc-1".to_owned(),
            state: state.to_owned(),
            revision: 3,
        }
    }

    #[test]
    fn provision_creates_exactly_one_instance_when_none_exists() {
        let mut driver = NoopDriver::new();
        let control = FakeControlPlane::default();
        drive_one(&control, &mut driver, &allocation("requested")).expect("provisions");
        assert_eq!(driver.list("alloc-1").expect("lists").len(), 1);
        assert_eq!(control.calls.borrow().len(), 1);
        assert!(control.calls.borrow()[0].starts_with("record_provisioning(alloc-1,3,"));
    }

    #[test]
    fn provision_reuses_an_existing_instance_instead_of_creating_a_second_one() {
        let mut driver = NoopDriver::new();
        driver.create("alloc-1", 1).expect("seed");
        driver.create("other-alloc", 1).expect("seed");
        let control = FakeControlPlane::default();
        drive_one(&control, &mut driver, &allocation("requested")).expect("provisions");
        assert_eq!(
            driver.list("alloc-1").expect("lists").len(),
            1,
            "must not create a second instance for the same allocation"
        );
    }

    #[test]
    fn provision_reports_a_driver_create_failure_as_failed_not_a_silent_retry() {
        let mut driver = NamedDriver {
            fail_create: true,
            ..Default::default()
        };
        let control = FakeControlPlane::default();
        let err = drive_one(&control, &mut driver, &allocation("requested"))
            .expect_err("create failure propagates");
        assert!(err.contains("quota exceeded"), "{err}");
        let calls = control.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].starts_with("report_failed(alloc-1,3,"));
        assert!(calls[0].contains("quota exceeded"));
    }

    #[test]
    fn grant_passes_the_driver_reported_tls_server_name() {
        let mut driver = NamedDriver::default();
        driver.create("alloc-1", 1).expect("seed");
        let control = FakeControlPlane::default();
        drive_one(&control, &mut driver, &allocation("provisioning")).expect("grants");
        let calls = control.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], "grant(alloc-1,3,alloc-1.test.karst.internal)");
    }

    #[test]
    fn grant_is_also_reached_from_the_granting_state_for_a_resumed_attempt() {
        let mut driver = NamedDriver::default();
        driver.create("alloc-1", 1).expect("seed");
        let control = FakeControlPlane::default();
        drive_one(&control, &mut driver, &allocation("granting")).expect("grants");
        assert_eq!(control.calls.borrow().len(), 1);
    }

    #[test]
    fn grant_not_registered_yet_is_not_an_error() {
        let mut driver = NamedDriver::default();
        driver.create("alloc-1", 1).expect("seed");
        let control = FakeControlPlane {
            grant_ready: false,
            ..Default::default()
        };
        drive_one(&control, &mut driver, &allocation("provisioning"))
            .expect("a not-yet-registered relay is not a failure");
    }

    #[test]
    fn grant_with_no_instance_is_an_error_not_a_panic() {
        let mut driver = NoopDriver::new(); // nothing created for this pool
        let control = FakeControlPlane::default();
        let err = drive_one(&control, &mut driver, &allocation("provisioning"))
            .expect_err("no instance to grant against");
        assert!(err.contains("alloc-1"), "{err}");
        assert!(control.calls.borrow().is_empty());
    }

    #[test]
    fn revoke_calls_the_control_plane_and_touches_no_compute() {
        let mut driver = NamedDriver::default();
        driver.create("alloc-1", 1).expect("seed");
        let control = FakeControlPlane::default();
        drive_one(&control, &mut driver, &allocation("revoking")).expect("revokes");
        assert_eq!(control.calls.borrow().len(), 1);
        assert_eq!(control.calls.borrow()[0], "revoke(alloc-1,3)");
        assert!(driver.drained.is_empty());
        assert!(driver.destroyed.is_empty());
    }

    #[test]
    fn revoke_failure_propagates_without_reporting_failed() {
        // Unlike a driver failure, an HTTP-layer revoke failure is
        // ambiguous/transient (the server may or may not have acted) --
        // this loop never calls report_failed for it, it just retries
        // next tick.
        let mut driver = NamedDriver::default();
        driver.create("alloc-1", 1).expect("seed");
        let control = FakeControlPlane {
            fail_revoke: true,
            ..Default::default()
        };
        let err = drive_one(&control, &mut driver, &allocation("revoking"))
            .expect_err("revoke failure propagates");
        assert!(err.contains("revoke refused"), "{err}");
        let calls = control.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], "revoke(alloc-1,3)");
    }

    #[test]
    fn deprovision_drains_then_destroys_before_reporting() {
        let mut driver = NamedDriver::default();
        driver.create("alloc-1", 1).expect("seed");
        let control = FakeControlPlane::default();
        drive_one(&control, &mut driver, &allocation("deprovisioning")).expect("deprovisions");
        assert_eq!(driver.drained, vec!["alloc-1-instance".to_owned()]);
        assert_eq!(driver.destroyed, vec!["alloc-1-instance".to_owned()]);
        assert_eq!(driver.list("alloc-1").expect("lists").len(), 0);
        assert_eq!(control.calls.borrow().len(), 1);
        assert_eq!(control.calls.borrow()[0], "report_deprovisioned(alloc-1,3)");
    }

    #[test]
    fn deprovision_is_idempotent_once_nothing_is_left_to_destroy() {
        let mut driver = NoopDriver::new(); // already destroyed by a previous attempt
        let control = FakeControlPlane::default();
        drive_one(&control, &mut driver, &allocation("deprovisioning")).expect("deprovisions");
        assert_eq!(control.calls.borrow().len(), 1);
        assert_eq!(control.calls.borrow()[0], "report_deprovisioned(alloc-1,3)");
    }

    #[test]
    fn deprovision_reports_a_driver_destroy_failure_as_failed() {
        let mut driver = NamedDriver {
            fail_destroy: true,
            ..Default::default()
        };
        driver.create("alloc-1", 1).expect("seed");
        let control = FakeControlPlane::default();
        let err = drive_one(&control, &mut driver, &allocation("deprovisioning"))
            .expect_err("destroy failure propagates");
        assert!(err.contains("still terminating"), "{err}");
        let calls = control.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].starts_with("report_failed(alloc-1,3,"));
    }

    #[test]
    fn an_unrecognized_state_is_an_error_not_a_panic() {
        let mut driver = NoopDriver::new();
        let control = FakeControlPlane::default();
        let err = drive_one(&control, &mut driver, &allocation("ready"))
            .expect_err("ready is terminal for this loop, not pending in the first place");
        assert!(err.contains("ready"), "{err}");
    }
}
