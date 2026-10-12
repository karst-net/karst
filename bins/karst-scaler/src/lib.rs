// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! `karst-scaler` — ADR-0045's Phase 0: the declarative cost-model schema
//! (§2) and an offline tool that replays recorded usage against it,
//! reporting spend per pool, per meter, per edge. No actuation, no cloud
//! credentials, no network dependency — see `src/main.rs` for why this
//! phase exists before any of those does.
//!
//! Working name, per ADR-0045: naming follows ADR-0010 and is a placeholder
//! until that is settled.

pub mod advise;
pub mod breaker;
pub mod cost_model;
pub mod position;
pub mod simulate;
pub mod usage;

/// `Driver` lives in its own crate — see `karst_scaler_driver`'s own crate
/// doc for why (breaking a dependency cycle with the optional
/// `karst-scaler-k8s` driver) — re-exported under its original module path
/// so every existing `karst_scaler::driver::...` reference elsewhere in
/// this tree still resolves unchanged.
pub use karst_scaler_driver as driver;
