// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! Node state machine — the layer that turns the protocol crates into an engine.
//!
//! **Sans-io throughout** (ADR-0003): sockets, clocks and randomness are the
//! caller's. That is what lets the identical code run against a real network and
//! against the deterministic simulation harness in `tests/simulation.rs`, where
//! a failing seed replays exactly (PLAN.md §11).

pub mod session;

pub use session::{Action, CloseReason, Session};
