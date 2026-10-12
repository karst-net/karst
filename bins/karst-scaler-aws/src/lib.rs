// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! ADR-0045 §5/§7 Phase 3: the AWS EC2 [`driver::Driver`] implementation —
//! see this crate's own `Cargo.toml` for why it is a separate,
//! feature-gated crate rather than a module of `karst-scaler` itself, and
//! `karst-scaler-k8s`'s crate doc for the sibling driver this one mirrors
//! in structure.
//!
//! ## Why `address` is optional in the bundle, unlike the Kubernetes driver
//!
//! The Kubernetes driver can write a pod's own stable DNS name into its
//! enrollment bundle *before* the pod exists, because a `StatefulSet`
//! ordinal's hostname is fixed by convention. EC2 has no equivalent: an
//! instance's own IP is assigned only once `RunInstances` actually
//! launches it, but the bundle has to be baked into `UserData` at the
//! moment of that same call — the opposite ordering problem. [`create`]
//! therefore writes a bundle with `address: None`, and `karst-relay
//! enroll` resolves its own address after boot via IMDS (extending
//! `bins/karst-relay/src/cloud_location.rs`'s existing probe, the same
//! mechanism ADR-0048 already uses for self-reported location) rather
//! than the driver trying to predict it.
//!
//! `tls_server_name`, by contrast, does *not* need to wait: it is never a
//! real DNS name a client resolves (`bins/karst-relay/src/tls.rs`'s own
//! crate doc — a relay's certificate is never what authenticates it), so
//! [`bundle::tls_server_name`] derives a stable label from the
//! enrollment token, known before the instance does.
//!
//! ## One `RunInstances` call per instance, not one batched call
//!
//! Not a limitation this driver invents: `RunInstances`'s own `UserData`
//! field is one value per call, so giving each new instance its own
//! distinct enrollment token requires `MinCount = 1, MaxCount = 1` per
//! iteration — see [`driver::AwsDriver::create`].
//!
//! ## Tag convention and IAM
//!
//! Every instance this driver creates carries one tag,
//! [`bundle::POOL_TAG_KEY`] = `pool_id` — mirroring the Kubernetes
//! driver's own "`pool_id` is the one identifier, reused everywhere"
//! convention. [`driver::AwsDriver::list`] and
//! [`driver::AwsDriver::destroy`] both filter by it independently of
//! whatever the planner believes exists, the same defense-in-depth
//! posture `karst_scaler::breaker::BoundedDriver` already applies
//! generically. See `deploy/aws/scaler/iam-policy.json` for the reference
//! IAM policy this depends on.
//!
//! [`create`]: driver::AwsDriver::create

pub mod bundle;
mod driver;
mod enroll;

pub use driver::{AwsDriver, AwsDriverConfig, Error};
