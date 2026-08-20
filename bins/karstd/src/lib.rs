// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! `karstd` — the node agent.
//!
//! Joins the two halves built so far: [`karst_tun`] takes packets from the host
//! kernel, [`karst_node`] encrypts them, and [`karst_transport`] puts them on
//! the wire. Everything protocol-shaped lives in the crates; this binary is
//! configuration, routing and an event loop.
//!
//! Phase 2 had no control server, so the roster came from a TOML file
//! ([`config`]). Phase 3 adds the other source: [`netmap`] holds what the
//! coordination server sent, and produces the same peer types, so the datapath
//! below cannot tell where a peer came from.

pub mod config;
pub mod control;
pub mod disco;
pub mod engine;
pub mod filter;
pub mod flow;
pub mod home;
pub mod ipc;
pub mod netmap;
pub mod portmap;
pub mod relay;
pub mod relay_tls;
pub mod routing;
pub mod run;
#[cfg(test)]
mod scratch;
mod socks5;

pub use config::{Config, ConfigError};
pub use engine::Engine;
pub use filter::PacketFilter;
pub use netmap::Netmap;
pub use routing::{AllowedIps, InterfaceAddress, Prefix};

/// Fill a buffer from the operating system's CSPRNG.
///
/// Handshakes need fresh randomness per attempt, and the sans-io crates take it
/// as an argument rather than reaching for it themselves (ADR-0003). This is
/// the one place the daemon asks the OS.
///
/// # Panics
/// If the OS entropy source fails. There is no safe way to continue: every
/// alternative — a counter, a hash of the clock — produces a handshake that
/// looks fine and is not.
#[must_use]
pub fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    #[allow(clippy::panic)]
    if let Err(e) = getrandom::fill(&mut seed) {
        panic!("the OS entropy source failed ({e}); refusing to generate a handshake without it");
    }
    seed
}
