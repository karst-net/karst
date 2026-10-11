// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! ADR-0045 §7 Phase 2 PR 4: the Kubernetes [`driver::Driver`] implementation
//! — see this crate's own `Cargo.toml` for why it is a separate,
//! feature-gated crate rather than a module of `karst-scaler` itself.
//!
//! ## Why a `StatefulSet`, not a `Deployment`
//!
//! §5's driver interface addresses instances individually (`drain(id)`,
//! `destroy(id)`), and the control server's own registry
//! (`relayreg.Entry`) gives each relay its
//! *own* dialable address. A plain `Deployment`'s pods have random names
//! and one shared pod template — there is no way to hand a specific new
//! pod its own enrollment token or its own address before it exists; every
//! pod in a `Deployment` is interchangeable by construction. A
//! `StatefulSet` gives stable ordinal pod names (`<pool_id>-0`,
//! `<pool_id>-1`, ...) and, with an operator-provisioned headless
//! `Service` of the *same name* as the `StatefulSet` (the convention this
//! driver assumes, so no separate service-name config field exists), stable
//! per-pod DNS: `<pool_id>-<i>.<pool_id>.<namespace>.svc.cluster.local`.
//! That DNS name doubles as the relay's registry address — solving both
//! problems with one primitive.
//!
//! ## Bundle delivery: one `Secret`, one key per ordinal
//!
//! A `StatefulSet`'s pod template is still one shared spec — it cannot
//! reference a *different* `Secret` per ordinal. Instead, [`create`]
//! patches **one** `Secret` (named `bundle_secret_name`), adding one key
//! per new ordinal (`secret_key`, e.g. `"relay-3.toml"`). A `Secret`
//! volume projects every key as a file, so each pod's own init step reads
//! `/etc/karst/enroll/$(hostname).toml` — its own key, found by its own
//! stable hostname, with no per-pod `Secret` objects to create or
//! garbage-collect individually.
//!
//! ## Scale-down removes the highest ordinal — always
//!
//! This is Kubernetes's own `StatefulSet` semantics, not a choice this
//! driver makes: `bins/karst-scaler/src/drive_loop.rs`'s `reconcile` was
//! fixed (ADR-0045 §7 Phase 2 PR 4) to select the highest-ordinal
//! instances as excess for exactly this reason — [`destroy`] refuses a
//! request naming any pod other than the current highest ordinal rather
//! than silently doing something else.
//!
//! [`create`]: driver::K8sDriver::create
//! [`destroy`]: driver::K8sDriver::destroy

pub mod bundle;
mod driver;
mod enroll;

pub use driver::{Error, K8sDriver, K8sDriverConfig};
