// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! [`AwsDriver`]: the `karst_scaler_driver::Driver` implementation itself.
//! See the crate doc for the bundle/tag-based design this implements; see
//! `bundle.rs` for the pure naming/serialization pieces this module calls
//! into.

use std::time::Duration;

use aws_sdk_ec2::error::{DisplayErrorContext, SdkError};
use aws_sdk_ec2::types::{
    Filter, InstanceStateName, InstanceType, ResourceType, Tag, TagSpecification,
};
use base64ct::{Base64, Encoding as _};

use karst_scaler_driver::{Driver, DriverError, Instance, InstanceState};

use crate::bundle::{tls_server_name, EnrollBundle, POOL_TAG_KEY, TLS_SERVER_NAME_TAG_KEY};
use crate::enroll;

/// Errors constructing an [`AwsDriver`] — everything after that surfaces
/// as a [`DriverError`] instead, per the `Driver` trait's own contract.
#[derive(Debug)]
pub enum Error {
    Runtime(std::io::Error),
    Http(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Runtime(e) => write!(f, "building the async runtime: {e}"),
            Self::Http(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

/// How long [`AwsDriver::drain`] waits for an instance to actually reach
/// `stopped` before giving up — bounded so a stuck instance cannot hang
/// `drive`'s whole reconciliation loop forever. Deliberately larger than
/// `karst-scaler-k8s`'s own `DRAIN_TIMEOUT` (30s): stopping an EC2
/// instance tears down a whole guest OS, not just a container, and AWS's
/// own documented stop behavior can take noticeably longer than a pod
/// eviction.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(120);
const DRAIN_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// What [`AwsDriver::new`] needs to launch and manage one pool's worth of
/// EC2 instances. There is no per-pool "which AWS account/VPC" field
/// because this driver, like `K8sDriver`, is scoped to exactly the one
/// account/region/network its own ambient credentials and config reach —
/// an operator running pools across more than one account runs more than
/// one `karst-scaler drive` process, each with its own config.
#[derive(Debug, Clone)]
pub struct AwsDriverConfig {
    /// Passed to `aws-config`'s loader explicitly rather than left to its
    /// own ambient discovery — ADR-0045 §4c's region allowlist makes a
    /// pool's region a load-bearing fact this driver must be told, not
    /// infer from whatever environment it happens to run in.
    pub region: String,
    pub ami_id: String,
    pub instance_type: String,
    pub subnet_id: String,
    pub security_group_ids: Vec<String>,
    /// The control server's own API base — same meaning
    /// `advise_config::AdviseConfig::control_api_base` has.
    pub control_api_base: String,
    /// A `UserRoleScaler`-scoped PAT (ADR-0045 §7 Phase 2 PR 3) — minting
    /// a relay-enroll token is the only thing it is good for.
    pub enroll_pat: String,
}

/// ADR-0045 §5/§7 Phase 3's `Driver` for AWS EC2. See the crate doc for
/// the overall design, and [`AwsDriverConfig`] for what each field below
/// comes from.
pub struct AwsDriver {
    rt: tokio::runtime::Runtime,
    client: aws_sdk_ec2::Client,
    ami_id: String,
    instance_type: String,
    subnet_id: String,
    security_group_ids: Vec<String>,
    control_api_base: String,
    enroll_pat: String,
    http: ureq::Agent,
}

// `aws_sdk_ec2::Client` has no `Debug` impl of its own -- this
// intentionally never prints `enroll_pat`, the one field here that's a
// credential (mirroring `karst_scaler_k8s::K8sDriver`'s own reasoning).
impl std::fmt::Debug for AwsDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsDriver")
            .field("ami_id", &self.ami_id)
            .field("instance_type", &self.instance_type)
            .field("subnet_id", &self.subnet_id)
            .field("control_api_base", &self.control_api_base)
            .finish_non_exhaustive()
    }
}

impl AwsDriver {
    /// Connects using `aws-config`'s own ambient credential chain (env
    /// vars, a shared config/credentials file, or — the real analogue of
    /// `K8sDriver::new`'s ambient kubeconfig — EC2 instance-profile
    /// credentials via IMDS when the scaler itself runs on an EC2
    /// instance). This driver's own IAM policy (see
    /// `deploy/aws/scaler/iam-policy.json`) is what bounds what the
    /// resulting client can actually do, not anything this constructor
    /// chooses.
    ///
    /// # Errors
    /// [`Error::Runtime`] if the async runtime cannot be built,
    /// [`Error::Http`] if no usable TLS root store is available for the
    /// enroll-token HTTP client.
    pub fn new(config: AwsDriverConfig) -> Result<Self, Error> {
        let rt = tokio::runtime::Runtime::new().map_err(Error::Runtime)?;
        let client = rt.block_on(async {
            let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(aws_types::region::Region::new(config.region.clone()))
                .load()
                .await;
            aws_sdk_ec2::Client::new(&sdk_config)
        });
        let http = enroll::build_agent().map_err(Error::Http)?;
        Ok(Self {
            rt,
            client,
            ami_id: config.ami_id,
            instance_type: config.instance_type,
            subnet_id: config.subnet_id,
            security_group_ids: config.security_group_ids,
            control_api_base: config.control_api_base,
            enroll_pat: config.enroll_pat,
            http,
        })
    }

    /// `pool_id`'s own tag filter, plus the "not already gone" state
    /// filter every [`Driver::list`] implementation needs — a terminated
    /// instance is not "an instance this driver knows about," it is one
    /// that no longer exists.
    fn pool_filters(pool_id: &str) -> Vec<Filter> {
        vec![
            Filter::builder()
                .name(format!("tag:{POOL_TAG_KEY}"))
                .values(pool_id)
                .build(),
            Filter::builder()
                .name("instance-state-name")
                .values("pending")
                .values("running")
                .values("stopping")
                .values("stopped")
                .build(),
        ]
    }

    async fn describe_one(&self, id: &str) -> Result<Option<InstanceStateName>, DriverError> {
        let output = self
            .client
            .describe_instances()
            .instance_ids(id)
            .send()
            .await
            .map_err(to_driver_error)?;
        Ok(output
            .reservations()
            .iter()
            .flat_map(aws_sdk_ec2::types::Reservation::instances)
            .find_map(|i| i.state().and_then(aws_sdk_ec2::types::InstanceState::name))
            .cloned())
    }

    /// Reads back `id`'s own [`TLS_SERVER_NAME_TAG_KEY`] tag — issue
    /// #329, `destroy`'s only way to recover the key `relayDeenroll`
    /// needs, since nothing in this driver process remembers it from
    /// `create()` (the `token` it was derived from is long discarded, and
    /// a separate in-memory map would not survive a `karst-scaler drive`
    /// restart the way reading it back from AWS does). `None` means the
    /// tag is missing, not that the call failed — expected for any
    /// instance a pre-#329 driver launched, which never had it.
    async fn describe_tls_server_name(&self, id: &str) -> Result<Option<String>, DriverError> {
        let output = self
            .client
            .describe_instances()
            .instance_ids(id)
            .send()
            .await
            .map_err(to_driver_error)?;
        Ok(output
            .reservations()
            .iter()
            .flat_map(aws_sdk_ec2::types::Reservation::instances)
            .flat_map(aws_sdk_ec2::types::Instance::tags)
            .find(|t| t.key() == Some(TLS_SERVER_NAME_TAG_KEY))
            .and_then(|t| t.value())
            .map(str::to_owned))
    }
}

impl Driver for AwsDriver {
    fn list(&self, pool_id: &str) -> Result<Vec<Instance>, DriverError> {
        self.rt.block_on(async {
            let mut request = self.client.describe_instances();
            for filter in Self::pool_filters(pool_id) {
                request = request.filters(filter);
            }
            let output = request.send().await.map_err(to_driver_error)?;
            Ok(output
                .reservations()
                .iter()
                .flat_map(aws_sdk_ec2::types::Reservation::instances)
                .filter_map(|i| {
                    let id = i.instance_id()?.to_owned();
                    let state = match i.state().and_then(aws_sdk_ec2::types::InstanceState::name) {
                        Some(InstanceStateName::Running | InstanceStateName::Pending) => {
                            InstanceState::Running
                        }
                        _ => InstanceState::Draining,
                    };
                    Some(Instance {
                        id,
                        pool_id: pool_id.to_owned(),
                        state,
                    })
                })
                .collect())
        })
    }

    fn create(&mut self, pool_id: &str, n: u32) -> Result<Vec<Instance>, DriverError> {
        self.rt.block_on(async {
            let mut created = Vec::with_capacity(n as usize);
            for _ in 0..n {
                // One `RunInstances` call per instance, not one batched
                // call for all `n` -- `UserData` is one value per call,
                // and each instance needs its own, distinct enrollment
                // token. See the crate doc.
                let token = enroll::mint_token(
                    &self.http,
                    &self.control_api_base,
                    &self.enroll_pat,
                    pool_id,
                )
                .map_err(DriverError::Other)?;
                let bundle = EnrollBundle {
                    control_api_base: self.control_api_base.clone(),
                    tls_server_name: tls_server_name(pool_id, &token),
                    token,
                    // Unknowable until `RunInstances` returns -- see the
                    // crate doc. `karst-relay enroll` resolves this
                    // itself, via IMDS, once the instance has booted.
                    address: None,
                };
                let text = bundle
                    .to_toml()
                    .map_err(|e| DriverError::Other(format!("serializing enroll bundle: {e}")))?;
                let user_data = Base64::encode_string(text.as_bytes());

                let tag_spec = TagSpecification::builder()
                    .resource_type(ResourceType::Instance)
                    .tags(Tag::builder().key(POOL_TAG_KEY).value(pool_id).build())
                    .tags(
                        Tag::builder()
                            .key(TLS_SERVER_NAME_TAG_KEY)
                            .value(&bundle.tls_server_name)
                            .build(),
                    )
                    .build();

                let mut request = self
                    .client
                    .run_instances()
                    .image_id(&self.ami_id)
                    .instance_type(InstanceType::from(self.instance_type.as_str()))
                    .min_count(1)
                    .max_count(1)
                    .user_data(user_data)
                    .subnet_id(&self.subnet_id)
                    .tag_specifications(tag_spec);
                for security_group_id in &self.security_group_ids {
                    request = request.security_group_ids(security_group_id);
                }

                let output = request.send().await.map_err(to_driver_error)?;
                let launched = output.instances().first().ok_or_else(|| {
                    DriverError::Other(format!("pool {pool_id}: RunInstances returned no instance"))
                })?;
                let id = launched
                    .instance_id()
                    .ok_or_else(|| {
                        DriverError::Other(format!(
                            "pool {pool_id}: RunInstances returned an instance with no id"
                        ))
                    })?
                    .to_owned();
                created.push(Instance {
                    id,
                    pool_id: pool_id.to_owned(),
                    state: InstanceState::Running,
                });
            }
            Ok(created)
        })
    }

    fn drain(&mut self, pool_id: &str, id: &str) -> Result<(), DriverError> {
        self.rt.block_on(async {
            // `StopInstances` sends a normal ACPI shutdown signal to the
            // guest, which a standard Linux init system delivers to
            // `karst-relay` as SIGTERM -- the same
            // `shutdown_signal` -> `announce_restart` path
            // `bins/karst-relay/src/server.rs` already handles. Not
            // independently verified against a real EC2 instance in this
            // environment -- see the crate doc's own caveat.
            self.client
                .stop_instances()
                .instance_ids(id)
                .send()
                .await
                .map_err(to_driver_error)?;

            let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
            loop {
                match self.describe_one(id).await? {
                    Some(InstanceStateName::Stopped | InstanceStateName::Terminated) => {
                        return Ok(())
                    }
                    _ if tokio::time::Instant::now() >= deadline => {
                        return Err(DriverError::Other(format!(
                            "pool {pool_id}: instance {id} did not stop within {DRAIN_TIMEOUT:?}"
                        )));
                    }
                    _ => tokio::time::sleep(DRAIN_POLL_INTERVAL).await,
                }
            }
        })
    }

    fn destroy(&mut self, _pool_id: &str, id: &str) -> Result<(), DriverError> {
        self.rt.block_on(async {
            // Read back this instance's own tls_server_name *before*
            // terminating it -- issue #329. Once terminated, AWS only
            // guarantees describe_instances keeps returning the
            // instance's data for a limited, undocumented window; reading
            // it first while the instance is still fully alive avoids
            // depending on that window at all. A describe failure here
            // leaves the instance untouched: safe to retry, no leak
            // created either way.
            let tls_server_name = self.describe_tls_server_name(id).await?;

            self.client
                .terminate_instances()
                .instance_ids(id)
                .send()
                .await
                .map_err(to_driver_error)?;

            // Removes this instance's own relayreg.Store row. Runs after
            // termination, not before, for the same reason
            // karst_scaler_k8s::driver::K8sDriver::destroy orders its own
            // StatefulSet patch before its deenroll call: a failed
            // deenroll after a successful terminate just reproduces the
            // pre-#319/#329 leak (acceptable, already the status quo);
            // the reverse order risks nothing better and one real way
            // worse (terminating an instance this call never actually
            // reached). A missing tag (an instance a pre-#329 driver
            // launched, before this tag existed) is a known, visible gap
            // this fix only prevents going forward -- not silently
            // treated as success.
            match tls_server_name {
                Some(name) => {
                    enroll::deenroll(&self.http, &self.control_api_base, &self.enroll_pat, &name)
                        .map_err(DriverError::Other)?;
                }
                None => eprintln!(
                    "karst-scaler-aws: instance {id} has no {TLS_SERVER_NAME_TAG_KEY} tag -- \
                     its relayreg.Store row, if any, could not be removed (launched before #329?)"
                ),
            }

            Ok(())
        })
    }
}

// By-value, not `&SdkError<E>`, despite `DisplayErrorContext` only
// needing a reference: this is passed directly as a fn pointer to
// `.map_err(...)` at every call site above, which needs
// `FnOnce(SdkError<E>) -> _` -- same reasoning as
// `karst_scaler_k8s::driver::to_driver_error`.
#[allow(clippy::needless_pass_by_value)]
fn to_driver_error<E>(e: SdkError<E>) -> DriverError
where
    E: std::error::Error + 'static,
{
    DriverError::Other(DisplayErrorContext(e).to_string())
}
