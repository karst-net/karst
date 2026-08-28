// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Host DNS integration primitives.
//!
//! Platform detection belongs to `karstd`; these types make the dangerous
//! operation transactional so every mechanism has the same crash-recovery
//! contract.

mod networkmanager;
mod resolvconf;
mod resolved;

pub use networkmanager::{NetworkManager, NetworkManagerError};
pub use resolvconf::{Controller, ResolvConf, Revert};
pub use resolved::{Resolved, ResolvedError};
