// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! `PHREATIC` handshake state machine — `spec/phreatic-v1.md` §7.
//!
//! **Sans-io**: this crate takes bytes and returns bytes. It performs no
//! network access, no clock access and no randomness generation — callers
//! supply seeds and time. That is what makes the handshake deterministically
//! testable and what lets the same code drive both a real socket and a
//! simulated lossy network (ADR-0003, PLAN.md §11).

pub mod handshake;
pub mod symmetric;
pub mod transport;

pub use handshake::{HandshakeError, PeerPublic, StaticKeys, Unconfirmed};
pub use symmetric::{AeadError, SymmetricState, TransportKeys, KEY_LEN, PROTOCOL_LABEL};
pub use transport::{Role, TransportError, TransportSession};
