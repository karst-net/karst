// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! ADR-0045 §7b (issue #311): the Kubernetes [`driver::Driver`]
//! implementation for TURN gateways — the TURN counterpart of
//! `karst-scaler-k8s`, following the same `StatefulSet`/bundle-`Secret`
//! design that crate's own doc explains (a plain `Deployment`'s
//! interchangeable pods cannot be handed a per-instance enrollment token
//! or address before they exist; a `StatefulSet` gives stable ordinal pod
//! names and, via an operator-provisioned headless `Service` of the same
//! name, stable per-pod DNS).
//!
//! ## Why its own crate, not a mode of `karst-scaler-k8s`
//!
//! The overlap is real (`StatefulSet`/`Secret`/pod-ordinal conventions,
//! `kube::Client` plumbing) but the two drivers enroll and tear down
//! through genuinely different control-server endpoints
//! (`/karst/v1/relays/enroll` vs `/karst/v1/turn/enroll` +
//! `/karst/v1/turn/deenroll`) and on genuinely different timing (a bounded
//! pod-delete wait vs a credential-TTL-bounded deferred teardown — see
//! `driver.rs`'s own doc for why). Merging them into one crate/mode would
//! mean a relay-only build pulling in TURN-only code and vice versa — the
//! same "no feature should cost another feature's dependency weight"
//! posture that already split `k8s`/`aws` into separate optional crates
//! from `karst-scaler` itself.
//!
//! ## What is and is not verified here
//!
//! Real-cluster verification (kind/k3d, an actual coturn instance
//! enrolling itself via `deploy/images/karst-turn-bootstrap.Dockerfile`)
//! was out of reach in the environment that built this — the same posture
//! `karst-scaler-k8s`'s and `karst-scaler-aws`'s own docs already flag for
//! their own real-infrastructure gaps. `bundle.rs`'s own tests cover every
//! pure naming/rendering decision; the bootstrap image's own PR verified
//! the enrollment half end to end against a fake control server.

pub mod bundle;
mod driver;
mod enroll;

pub use driver::{Error, K8sTurnDriver, K8sTurnDriverConfig};
