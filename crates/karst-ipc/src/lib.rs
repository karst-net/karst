// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![cfg(windows)]
// ADR-0003's reasoning — confine `unsafe` to one audited module rather than
// scatter it — applies to this crate too, even though it is not the TUN
// datapath: `sys_windows` carries the sole `allow(unsafe_code)`.
#![deny(unsafe_code)]

//! The Windows named-pipe counterpart to a Unix control socket.
//!
//! `bins/karstd/src/ipc.rs` builds its local admin channel directly on
//! `std::os::unix::net::{UnixListener, UnixStream}`, which has no Windows
//! equivalent. This crate exists only so that module's `#[cfg(windows)]`
//! arm has a [`Listener`]/[`Stream`] pair shaped closely enough to drop in —
//! bind two access levels, accept without blocking, read and write a plain
//! byte stream — rather than needing raw Win32 named-pipe calls (which
//! `bins/karstd` cannot contain: it `#![forbid(unsafe_code)]`) inline there.
//!
//! Windows-only by construction (`#![cfg(windows)]` above empties this crate
//! on every other target), so `karstd`'s `Cargo.toml` depends on it only
//! under `[target.'cfg(target_os = "windows")'.dependencies]` — nothing here
//! is ever compiled, let alone linked, on Linux or macOS.

mod pipe;
mod sys_windows;

pub use pipe::{Listener, Stream};
