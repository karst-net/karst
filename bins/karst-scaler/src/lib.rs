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

pub mod cost_model;
pub mod simulate;
pub mod usage;
