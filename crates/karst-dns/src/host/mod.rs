// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Host DNS integration primitives.
//!
//! Platform detection belongs to `karstd`; these types make the dangerous
//! operation transactional so every mechanism has the same crash-recovery
//! contract.

mod macos;
mod networkmanager;
mod resolvconf;
mod resolved;

pub use macos::{Macos, MacosError, RESOLVER_DIRECTORY, REVERT_STATE};
pub use networkmanager::{NetworkManager, NetworkManagerError};
// Each mechanism names its own paths, so the two `REVERT_STATE` constants are
// disambiguated here rather than in the modules that own them.
pub use resolvconf::{
    Controller, ResolvConf, Revert, LEGACY_REVERT_STATE as LEGACY_RESOLVCONF_REVERT_STATE,
    RESOLV_CONF, REVERT_STATE as RESOLVCONF_REVERT_STATE,
};
pub use resolved::{Resolved, ResolvedError};
