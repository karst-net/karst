// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![cfg(windows)]
// ADR-0003's reasoning — confine `unsafe` to one audited module rather than
// scatter it — applies here too: `sys_windows` carries the sole
// `allow(unsafe_code)`.
#![deny(unsafe_code)]

//! The Windows counterpart to `0700`/`0600` POSIX permissions.
//!
//! `bins/karstd/src/exit_node.rs` locks down its state directory and file
//! with `std::os::unix::fs::{PermissionsExt, OpenOptionsExt}`, which has no
//! Windows equivalent — Windows access control is a security descriptor set
//! at creation, not a mode bitmask set after. This crate exists only so
//! that module's `#[cfg(windows)]` arm has [`create_secure_dir`] and
//! [`SecureFile`] to call — raw Win32 security-descriptor and file-creation
//! FFI (which `bins/karstd` cannot contain: it `#![forbid(unsafe_code)]`)
//! lives here instead.
//!
//! [`is_restricted`] is the read side of the same story: a file this
//! process did not create itself (`karstd genkey`'s output, always
//! redirected to disk by an operator, never by `karstd`) needs its ACL
//! checked rather than trusted, the same role Unix's `mode & 0o077 == 0`
//! check plays for `bins/karstd/src/config.rs`'s and
//! `bins/karstd/src/control.rs`'s own secret files.
//!
//! Windows-only by construction (`#![cfg(windows)]` above empties this
//! crate on every other target), so `karstd`'s `Cargo.toml` depends on it
//! only under `[target.'cfg(target_os = "windows")'.dependencies]`.

mod storage;
mod sys_windows;

pub use storage::{create_secure_dir, is_restricted, SecureFile};
