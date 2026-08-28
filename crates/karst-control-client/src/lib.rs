// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod cache;
pub mod channel;
pub mod handle;
pub mod netmap;
pub mod psk;
pub mod suite;
pub mod transport;

pub use channel::{derive_keys, hello_signing_input, init_signing_input, Keys, Record};
pub use handle::{handle, handle_bytes};
pub use netmap::{
    netmap_version, peer_digest, DNSConfigView, DNSRouteView, FilterRuleView, NetmapContent,
    PeerEntry, PeerPsks, PskChoice, RelayView,
};
pub use psk::{pair as psk_pair, Psk};
