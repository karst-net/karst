// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! [`K8sDriver`]: the `karst_scaler_driver::Driver` implementation itself.
//! See the crate doc for the `StatefulSet`/bundle-`Secret` design this
//! implements; see `bundle.rs` for the pure naming/serialization pieces
//! this module calls into.

use std::time::Duration;

use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{Pod, Secret};
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams};
use kube::Client;
use serde_json::json;

use karst_scaler_driver::{Driver, DriverError, Instance, InstanceState};

use crate::bundle::{bundle_secret_name, pod_fqdn, pod_name, secret_key, EnrollBundle};
use crate::enroll;

/// Errors constructing a [`K8sDriver`] — everything after that surfaces as
/// a [`DriverError`] instead, per the `Driver` trait's own contract.
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

/// How long [`K8sDriver::drain`] waits for a pod to actually disappear
/// before giving up — bounded so a stuck pod cannot hang `drive`'s whole
/// reconciliation loop forever. `karst-relay`'s own flush window
/// (`RESTART_FLUSH_MAX`, `bins/karst-relay/src/server.rs`) is 3s; this is
/// deliberately much larger to also cover normal pod-termination overhead
/// (container runtime teardown, kubelet status propagation) that `3s`
/// alone does not account for.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const DRAIN_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// What [`K8sDriver::new`] needs — see the crate doc for why there is no
/// separate "headless service name" field (same name as the pool/
/// `StatefulSet`, by convention) and no per-pool field at all (`pool_id`,
/// passed per `Driver` call, is both the `StatefulSet` name and the
/// headless `Service` name).
#[derive(Debug, Clone)]
pub struct K8sDriverConfig {
    pub namespace: String,
    /// The control server's own API base — the same meaning
    /// `advise_config::AdviseConfig::control_api_base` has.
    pub control_api_base: String,
    /// A `UserRoleScaler`-scoped PAT (ADR-0045 §7 Phase 2 PR 3) — minting
    /// a relay-enroll token is the only thing it is good for.
    pub enroll_pat: String,
}

/// ADR-0045 §7 Phase 2 PR 4's `Driver` for a Kubernetes `StatefulSet`. See
/// the crate doc for the overall design.
pub struct K8sDriver {
    rt: tokio::runtime::Runtime,
    client: Client,
    namespace: String,
    control_api_base: String,
    enroll_pat: String,
    http: ureq::Agent,
}

// `kube::Client` has no `Debug` impl of its own -- this intentionally
// never prints `enroll_pat`, the one field here that's a credential.
impl std::fmt::Debug for K8sDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("K8sDriver")
            .field("namespace", &self.namespace)
            .field("control_api_base", &self.control_api_base)
            .finish_non_exhaustive()
    }
}

impl K8sDriver {
    /// Connects using the ambient kubeconfig/in-cluster config `kube`
    /// discovers on its own (the same default every `kubectl`-adjacent
    /// tool uses) — this driver's own RBAC (a namespace-scoped `Role`; see
    /// the plan's own YAML) is what bounds what the resulting client can
    /// actually do, not anything this constructor chooses.
    ///
    /// # Errors
    /// [`Error::Runtime`] if the async runtime cannot be built,
    /// [`Error::Kube`] if the client cannot reach or authenticate to the
    /// cluster, [`Error::Http`] if no usable TLS root store is available
    /// for the enroll-token HTTP client.
    pub fn new(config: K8sDriverConfig) -> Result<Self, Error> {
        let rt = tokio::runtime::Runtime::new().map_err(Error::Runtime)?;
        let client = rt.block_on(Client::try_default()).map_err(Error::Kube)?;
        let http = enroll::build_agent().map_err(Error::Http)?;
        Ok(Self {
            rt,
            client,
            namespace: config.namespace,
            control_api_base: config.control_api_base,
            enroll_pat: config.enroll_pat,
            http,
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
    /// read from the `StatefulSet`'s own spec rather than assumed, so this
    /// driver imposes no label scheme of its own for an operator to get
    /// exactly right.
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

impl Driver for K8sDriver {
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
                let token = enroll::mint_token(
                    &self.http,
                    &self.control_api_base,
                    &self.enroll_pat,
                    pool_id,
                )
                .map_err(DriverError::Other)?;
                let address = format!("{}:443", pod_fqdn(pool_id, ordinal, &self.namespace));
                let bundle = EnrollBundle {
                    control_api_base: self.control_api_base.clone(),
                    token,
                    tls_server_name: pod_fqdn(pool_id, ordinal, &self.namespace),
                    address,
                };
                let text = bundle
                    .to_toml()
                    .map_err(|e| DriverError::Other(format!("serializing enroll bundle: {e}")))?;
                new_keys.insert(secret_key(pool_id, ordinal), json!(text));
                created.push(Instance {
                    id: pod_name(pool_id, ordinal),
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
        self.rt.block_on(async {
            // A plain delete (default grace period) sends SIGTERM, which
            // `bins/karst-relay/src/server.rs`'s own `shutdown_signal` →
            // `announce_restart` already handles correctly -- no new
            // in-relay RPC needed (confirmed during PR 1's own research).
            self.pods()
                .delete(id, &DeleteParams::default())
                .await
                .map_err(to_driver_error)?;

            let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
            loop {
                match self.pods().get_opt(id).await.map_err(to_driver_error)? {
                    None => return Ok(()),
                    Some(_) if tokio::time::Instant::now() >= deadline => {
                        return Err(DriverError::Other(format!(
                            "pool {pool_id}: pod {id} did not terminate within {DRAIN_TIMEOUT:?}"
                        )));
                    }
                    Some(_) => tokio::time::sleep(DRAIN_POLL_INTERVAL).await,
                }
            }
        })
    }

    fn destroy(&mut self, pool_id: &str, id: &str) -> Result<(), DriverError> {
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
            if current == 0 {
                return Err(DriverError::Other(format!(
                    "pool {pool_id} already has zero replicas"
                )));
            }
            let highest = current - 1;
            let expected_id = pod_name(pool_id, highest);
            if id != expected_id {
                // StatefulSet scale-down always removes the highest
                // ordinal -- see the crate doc. Refusing rather than
                // silently scaling down a different pod than the one
                // asked for.
                return Err(DriverError::Other(format!(
                    "pool {pool_id}: destroy({id}) requested, but a StatefulSet scale-down \
                     would remove {expected_id} (the current highest ordinal) instead"
                )));
            }

            let sts_patch = Patch::Merge(json!({ "spec": { "replicas": highest } }));
            self.statefulsets()
                .patch(pool_id, &PatchParams::default(), &sts_patch)
                .await
                .map_err(to_driver_error)?;

            // Best-effort cleanup: the key is already single-use (the
            // control server enforces that), so leaving it behind is
            // untidy, not unsafe.
            let cleanup =
                Patch::Merge(json!({ "stringData": { secret_key(pool_id, highest): null } }));
            let _ = self
                .secrets()
                .patch(
                    &bundle_secret_name(pool_id),
                    &PatchParams::default(),
                    &cleanup,
                )
                .await;

            Ok(())
        })
    }
}

// By-value, not `&kube::Error`, despite `Display` only needing a
// reference: this is passed directly as a fn pointer to `.map_err(...)`
// at every call site above, which needs `FnOnce(kube::Error) -> _`.
#[allow(clippy::needless_pass_by_value)]
fn to_driver_error(e: kube::Error) -> DriverError {
    DriverError::Other(e.to_string())
}
