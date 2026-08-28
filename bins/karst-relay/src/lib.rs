// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! `karst-relay` — the Ponor relay server.
//!
//! Implements `spec/ponor-v1.md`. The protocol itself lives in
//! `karst-relay-proto`; this crate is the server around it.
//!
//! A library beside the binary, for the same reason `karstd` has one: the
//! forwarding core is worth integration-testing, and a `[[bin]]`-only package
//! cannot be imported from `tests/`.

pub mod config;
pub mod http;
pub mod hub;
pub mod limits;
pub mod mesh;
pub mod metrics;
pub mod reflect;
pub mod roster;
pub mod server;
pub mod sign;
pub mod tls;
