// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! [`K8sTurnDriver`]: the `karst_scaler_driver::Driver` implementation
//! itself. See the crate doc for why this is its own crate rather than a
//! mode of `karst-scaler-k8s`; see `bundle.rs` for the pure naming/
//! bundle-rendering pieces this module calls into.
//!
//! ## `drain`/`destroy`: why the real teardown moves into `drain`
//!
//! `bins/karst-scaler/src/drive_loop.rs::reconcile` calls `drain(id)`
//! immediately followed by `destroy(id)`, synchronously, on the single
//! thread that runs every pool's reconciliation for one tick. The
//! Kubernetes relay driver's own `drain` can block there for its bounded
//! `DRAIN_TIMEOUT` (30s) because that is genuinely how long a pod takes to
//! terminate — a short, real wait.
//!
//! A TURN instance has no equivalent short wait. Once [`drain`] removes
//! this instance's `turncred.Store` row (via `/karst/v1/turn/deenroll`,
//! #320), the instance is *safe to stop advertising* but not yet *safe to
//! kill*: a client with an already-minted credential keeps a live
//! allocation against it until that credential's own `ExpiresAt` passes
//! (turncred's shared-secret design means removing the registry row does
//! not revoke anything coturn-side — see issue #311's own recorded
//! reasoning). Destroying the instance before that window elapses cuts a
//! live allocation off mid-session, exactly what #311 was worried about.
//! That window is the operator's own configured credential TTL
//! ([`K8sTurnDriverConfig::credential_ttl`]) — plausibly hours, not
//! seconds.
//!
//! Blocking `reconcile`'s one thread for hours inside `drain` would stall
//! every other pool's reconciliation and every future tick. So `drain`
//! instead performs the deenroll call synchronously (fast — a single HTTP
//! request) and then spawns a **detached background task** on this
//! driver's own multi-threaded [`tokio::runtime::Runtime`] that sleeps out
//! the TTL and performs the actual `StatefulSet` scale-down itself,
//! independent of whatever the main thread does next. [`destroy`] becomes
//! a no-op: the real work already happened, or was scheduled, inside
//! `drain` — a valid reading of the `Driver` trait's own contract ("a
//! caller may call destroy immediately after a successful [drain]... this
//! trait does not require a caller to poll for drain completion
//! separately"), not a shortcut around it.
//!
//! **This is best-effort, not durable**: the scheduled task lives only in
//! this process's memory. A `karst-scaler drive` restart during the wait
//! window loses the scheduled teardown silently, leaving the instance
//! running (and its `StatefulSet` replica count un-decremented) until an
//! operator notices. Recorded as a known, deliberate limitation of this
//! first implementation, not a gap to silently assume away — a durable,
//! restart-surviving version (persisted per-instance drain timestamps,
//! mirroring `breaker.rs`'s own state-file pattern) is real follow-up
//! work this issue did not take on.
//!
//! [`drain`]: K8sTurnDriver::drain
//! [`destroy`]: K8sTurnDriver::destroy

use std::time::Duration;

use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{Pod, Secret};
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::Client;
use serde_json::json;

use karst_scaler_driver::{Driver, DriverError, Instance, InstanceState};

use crate::bundle::{bundle_secret_name, pod_name, secret_key, turn_uri, EnrollBundle};
use crate::enroll;

/// Errors constructing a [`K8sTurnDriver`] — everything after that
/// surfaces as a [`DriverError`] instead, per the `Driver` trait's own
/// contract.
#[derive(Debug)]
pub enum Error {
    Runtime(std::io::Error),
    Kube(kube::Error),
    Http(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Runtime(e) => write!(f, "building the async runtime: {e}"),
            Self::Kube(e) => write!(f, "connecting to the Kubernetes API: {e}"),
            Self::Http(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

/// What [`K8sTurnDriver::new`] needs.
#[derive(Debug, Clone)]
pub struct K8sTurnDriverConfig {
    pub namespace: String,
    /// The control server's own API base — the same meaning
    /// `advise_config::AdviseConfig::control_api_base` has.
    pub control_api_base: String,
    /// A `UserRoleScaler`-scoped PAT — minting a turn-enroll token and
    /// requesting turn de-enrollment (#320) are the only things it is
    /// good for; `roles.Scaler`'s own `Delete` grant stays `false`.
    pub enroll_pat: String,
    /// Must equal the control server's own `turncred.Minter` TTL — this
    /// driver has no way to read that value from the control server
    /// (nothing exposes it), so the operator is responsible for keeping
    /// the two in sync, the same "two config files, one invariant"
    /// posture `allowed_regions` already has elsewhere in this tree. See
    /// this module's own doc for what this bounds.
    pub credential_ttl: Duration,
}

/// ADR-0045 §7b's `Driver` for a Kubernetes `StatefulSet` of TURN
/// instances — see the crate doc for the overall design and this
/// module's own doc for `drain`/`destroy`'s split.
pub struct K8sTurnDriver {
    rt: tokio::runtime::Runtime,
    client: Client,
    namespace: String,
    control_api_base: String,
    enroll_pat: String,
    http: ureq::Agent,
    credential_ttl: Duration,
}

// `kube::Client` has no `Debug` impl of its own -- this intentionally
// never prints `enroll_pat`, the one field here that's a credential.
impl std::fmt::Debug for K8sTurnDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("K8sTurnDriver")
            .field("namespace", &self.namespace)
            .field("control_api_base", &self.control_api_base)
            .field("credential_ttl", &self.credential_ttl)
            .finish_non_exhaustive()
    }
}

impl K8sTurnDriver {
    /// Connects using the ambient kubeconfig/in-cluster config `kube`
    /// discovers on its own — same posture as `karst_scaler_k8s::K8sDriver::new`;
    /// this driver's own RBAC (a namespace-scoped `Role`, mirroring
    /// `deploy/kubernetes/scaler/rbac.yaml`) is what bounds what the
    /// resulting client can actually do.
    ///
    /// # Errors
    /// [`Error::Runtime`] if the async runtime cannot be built,
    /// [`Error::Kube`] if the client cannot reach or authenticate to the
    /// cluster, [`Error::Http`] if no usable TLS root store is available
    /// for the enroll/deenroll HTTP client.
    pub fn new(config: K8sTurnDriverConfig) -> Result<Self, Error> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(Error::Runtime)?;
        let client = rt.block_on(Client::try_default()).map_err(Error::Kube)?;
        let http = enroll::build_agent().map_err(Error::Http)?;
        Ok(Self {
            rt,
            client,
            namespace: config.namespace,
            control_api_base: config.control_api_base,
            enroll_pat: config.enroll_pat,
            http,
            credential_ttl: config.credential_ttl,
        })
    }

    fn statefulsets(&self) -> Api<StatefulSet> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    fn pods(&self) -> Api<Pod> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    fn secrets(&self) -> Api<Secret> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    /// The pod-label selector a `pool_id`'s own `StatefulSet` declares —
    /// read from the `StatefulSet`'s own spec rather than assumed, the
    /// same reasoning `karst_scaler_k8s::K8sDriver::pod_selector` gives.
    async fn pod_selector(&self, pool_id: &str) -> Result<String, DriverError> {
        let sts = self
            .statefulsets()
            .get(pool_id)
            .await
            .map_err(to_driver_error)?;
        let labels = sts
            .spec
            .and_then(|s| s.selector.match_labels)
            .ok_or_else(|| {
                DriverError::Other(format!(
                    "StatefulSet {pool_id} has no spec.selector.matchLabels"
                ))
            })?;
        Ok(labels
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(","))
    }
}

impl Driver for K8sTurnDriver {
    fn list(&self, pool_id: &str) -> Result<Vec<Instance>, DriverError> {
        self.rt.block_on(async {
            let selector = self.pod_selector(pool_id).await?;
            let lp = ListParams::default().labels(&selector);
            let pods = self.pods().list(&lp).await.map_err(to_driver_error)?;
            Ok(pods
                .into_iter()
                .filter_map(|p| p.metadata.name)
                .map(|id| Instance {
                    id,
                    pool_id: pool_id.to_owned(),
                    state: InstanceState::Running,
                })
                .collect())
        })
    }

    fn create(&mut self, pool_id: &str, n: u32) -> Result<Vec<Instance>, DriverError> {
        self.rt.block_on(async {
            let sts = self
                .statefulsets()
                .get(pool_id)
                .await
                .map_err(to_driver_error)?;
            let current = sts
                .spec
                .as_ref()
                .and_then(|s| s.replicas)
                .unwrap_or(0)
                .max(0);
            #[allow(clippy::cast_sign_loss)]
            let current = current as u32;

            let mut new_keys = serde_json::Map::new();
            let mut created = Vec::with_capacity(n as usize);
            for ordinal in current..current + n {
                let token =
                    enroll::mint_token(&self.http, &self.control_api_base, &self.enroll_pat)
                        .map_err(DriverError::Other)?;
                let name = pod_name(pool_id, ordinal);
                let uri = turn_uri(&name, pool_id, &self.namespace);
                let bundle = EnrollBundle {
                    control_api_base: self.control_api_base.clone(),
                    token,
                    uri,
                };
                new_keys.insert(secret_key(pool_id, ordinal), json!(bundle.to_env()));
                created.push(Instance {
                    id: name,
                    pool_id: pool_id.to_owned(),
                    state: InstanceState::Running,
                });
            }

            let secret_patch = Patch::Merge(json!({ "stringData": new_keys }));
            self.secrets()
                .patch(
                    &bundle_secret_name(pool_id),
                    &PatchParams::default(),
                    &secret_patch,
                )
                .await
                .map_err(to_driver_error)?;

            let sts_patch = Patch::Merge(json!({ "spec": { "replicas": current + n } }));
            self.statefulsets()
                .patch(pool_id, &PatchParams::default(), &sts_patch)
                .await
                .map_err(to_driver_error)?;

            Ok(created)
        })
    }

    fn drain(&mut self, pool_id: &str, id: &str) -> Result<(), DriverError> {
        let uri = turn_uri(id, pool_id, &self.namespace);
        enroll::deenroll(&self.http, &self.control_api_base, &self.enroll_pat, &uri)
            .map_err(DriverError::Other)?;

        // Detached: nothing joins this task, by design -- see the module
        // doc for why the credential-TTL-bounded wait cannot happen on
        // reconcile's own thread. Captures only what the real teardown
        // needs (client, namespace, pool_id, id); the enroll PAT/http
        // agent are not needed again, the deenroll call above already
        // happened.
        let client = self.client.clone();
        let namespace = self.namespace.clone();
        let pool_id_owned = pool_id.to_owned();
        let id_owned = id.to_owned();
        let ttl = self.credential_ttl;
        self.rt.spawn(async move {
            tokio::time::sleep(ttl).await;
            if let Err(e) =
                deferred_scale_down(&client, &namespace, &pool_id_owned, &id_owned).await
            {
                eprintln!(
                    "karst-scaler-turn-k8s: deferred destroy of pool {pool_id_owned} instance \
                     {id_owned} failed: {e}"
                );
            }
        });

        Ok(())
    }

    /// A deliberate no-op — see the module doc. `drain` already removed
    /// the registry row and scheduled (or, in a fast-enough race, already
    /// performed) the actual `StatefulSet` scale-down.
    fn destroy(&mut self, _pool_id: &str, _id: &str) -> Result<(), DriverError> {
        Ok(())
    }
}

/// The real teardown `K8sTurnDriver::destroy` would otherwise do
/// immediately — run later, by `drain`'s own detached task, against
/// whatever the `StatefulSet`'s state actually is *at that time* rather
/// than a value captured when the wait began: another `create`/`drain`
/// cycle may have changed the highest ordinal in the meantime, so this
/// re-fetches and re-checks exactly like `karst_scaler_k8s::K8sDriver::destroy`
/// does, rather than trusting a stale snapshot.
async fn deferred_scale_down(
    client: &Client,
    namespace: &str,
    pool_id: &str,
    id: &str,
) -> Result<(), DriverError> {
    let statefulsets: Api<StatefulSet> = Api::namespaced(client.clone(), namespace);
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);

    let sts = statefulsets.get(pool_id).await.map_err(to_driver_error)?;
    let current = sts
        .spec
        .as_ref()
        .and_then(|s| s.replicas)
        .unwrap_or(0)
        .max(0);
    #[allow(clippy::cast_sign_loss)]
    let current = current as u32;
    if current == 0 {
        return Err(DriverError::Other(format!(
            "pool {pool_id} already has zero replicas"
        )));
    }
    let highest = current - 1;
    let expected_id = pod_name(pool_id, highest);
    if id != expected_id {
        // Another cycle changed the highest ordinal since drain() was
        // called -- refusing rather than silently scaling down a
        // different pod than the one this task was scheduled for. The
        // instance this task was meant to remove may already be gone
        // (removed by a later, ordinary cycle) or may now need its own
        // deferred teardown scheduled again -- either way, not this
        // task's problem to guess at.
        return Err(DriverError::Other(format!(
            "pool {pool_id}: deferred destroy of {id} skipped, current highest ordinal is \
             {expected_id}"
        )));
    }

    let sts_patch = Patch::Merge(json!({ "spec": { "replicas": highest } }));
    statefulsets
        .patch(pool_id, &PatchParams::default(), &sts_patch)
        .await
        .map_err(to_driver_error)?;

    // Best-effort cleanup, same posture as karst_scaler_k8s::K8sDriver::destroy:
    // the bundle key is already single-use (the control server enforces
    // that), so leaving it behind is untidy, not unsafe.
    let cleanup = Patch::Merge(json!({ "stringData": { secret_key(pool_id, highest): null } }));
    let _ = secrets
        .patch(
            &bundle_secret_name(pool_id),
            &PatchParams::default(),
            &cleanup,
        )
        .await;

    Ok(())
}

// By-value, not `&kube::Error`, despite `Display` only needing a
// reference: this is passed directly as a fn pointer to `.map_err(...)`
// at every call site above, which needs `FnOnce(kube::Error) -> _`.
#[allow(clippy::needless_pass_by_value)]
fn to_driver_error(e: kube::Error) -> DriverError {
    DriverError::Other(e.to_string())
}

// No unit tests of `K8sTurnDriver` itself in this module: every one of
// its methods is a thin async wrapper around `kube::Client` calls against
// a real (or test-fixture) Kubernetes API server. `karst_scaler_k8s::driver`
// has none either, for the identical reason its own PR states:
// real-cluster verification was out of reach in the environment that
// built this. `bundle.rs`'s own tests cover every pure naming/rendering
// decision this module depends on, including that `create` and `drain`
// derive a pod's `turn:` URI from the same `turn_uri` function rather
// than two independent string-building call sites that could drift
// apart.
//
// What the test below does check, without needing a Kubernetes API at
// all: the one genuinely new mechanism this driver introduces over
// `karst_scaler_k8s`'s own precedent -- that a task `spawn`ed on a
// multi-threaded `Runtime` really does keep running to completion on its
// own worker thread independent of whatever the thread that spawned it
// does next (here, a `block_on` of its own, mirroring how every other
// `Driver` method call on this driver's main thread would look after
// `drain` returns). `drain`'s entire deferred-teardown design depends on
// this being true; asserting it directly is cheaper than trusting it by
// reading tokio's own documentation.
#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn a_detached_spawned_task_completes_while_the_spawning_thread_does_other_blocking_work() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("multi-thread runtime builds");

        let done = Arc::new(AtomicBool::new(false));
        let done_clone = Arc::clone(&done);
        // Mirrors drain()'s own shape exactly: spawn, then drop the
        // JoinHandle (nothing awaits it), then this thread goes on to do
        // its own unrelated block_on -- the same sequence
        // Driver::drain returning Ok(()) immediately, followed by
        // drive_loop::reconcile's very next call, produces for real.
        rt.spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            done_clone.store(true, Ordering::SeqCst);
        });

        // Unrelated work on the spawning thread, immediately after --
        // the spawned task must not need this thread's cooperation to
        // make progress.
        rt.block_on(async {
            tokio::time::sleep(Duration::from_millis(5)).await;
        });
        assert!(
            !done.load(Ordering::SeqCst),
            "the spawned task finished implausibly fast -- this assertion would be \
             meaningless if it could"
        );

        rt.block_on(async {
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        assert!(
            done.load(Ordering::SeqCst),
            "the detached task never completed -- drain()'s whole deferred-teardown \
             design assumes it would"
        );
    }
}
