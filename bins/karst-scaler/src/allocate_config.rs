// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! `karst-scaler allocate`'s own config file — ADR-0063/#455's
//! reconciliation loop.
//!
//! Reuses `advise_config`'s `[driver]` table shape ([`DriverSection`])
//! rather than inventing a new one for the same idea, but is its own
//! top-level struct, not a reinterpretation of [`crate::advise_config::AdviseConfig`]:
//! unlike `advise`/`drive`, this loop has no cost model and no pool-keyed
//! budget breaker — a named, capability-specific one-off allocation is
//! not a pool member (ADR-0063's "Alternatives rejected"), so
//! `cost_model_path` and `[breaker]` would be dead weight here, not
//! optional extras.

use std::path::Path;

use serde::Deserialize;

use crate::advise_config::DriverSection;

/// `karst-scaler allocate`'s own config file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AllocateConfig {
    /// The control server's own API base — `/karst/v1/relay-allocations/...`
    /// is appended to this directly, the same convention `AdviseConfig`'s
    /// own field uses.
    pub control_api_base: String,
    /// Path to a file holding a `UserRoleScaler`-scoped PAT (the same
    /// role `drive`'s own `[driver] enroll_pat_file` already uses),
    /// trimmed of surrounding whitespace when read — authenticates every
    /// `/relay-allocations/...` call this loop makes. Read separately
    /// from `driver.enroll_pat_file` below even when an operator points
    /// both at the same file: every config section here manages its own
    /// credential path, matching every other section in this crate.
    pub pat_file: String,
    pub poll_interval_secs: u64,
    /// Required, unlike [`crate::advise_config::AdviseConfig`]'s own
    /// optional field: an allocate loop with no driver has nothing to
    /// provision anything with, so there is no sensible no-op default
    /// the way `drive` has one.
    pub driver: DriverSection,
}

/// Errors loading or validating an `allocate` config file.
#[derive(Debug)]
pub(crate) enum Error {
    Io(std::io::Error),
    Syntax(toml::de::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Syntax(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl AllocateConfig {
    pub(crate) fn parse(text: &str) -> Result<Self, Error> {
        toml::from_str(text).map_err(Error::Syntax)
    }

    pub(crate) fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(Error::Io)?;
        Self::parse(&text)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    const BASE: &str = r#"
control_api_base = "https://example.test/api"
pat_file = "pat.txt"
poll_interval_secs = 15

[driver]
kind = "aws"
region = "us-west-2"
ami_id = "ami-0123456789abcdef0"
instance_type = "t3.micro"
subnet_id = "subnet-0123456789abcdef0"
security_group_ids = ["sg-0123456789abcdef0"]
enroll_pat_file = "enroll-pat.txt"
"#;

    #[test]
    fn parses_a_well_formed_config() {
        let config = AllocateConfig::parse(BASE).expect("parses");
        assert_eq!(config.control_api_base, "https://example.test/api");
        assert_eq!(config.driver.kind, "aws");
    }

    #[test]
    fn requires_a_driver_section() {
        let text = r#"
control_api_base = "https://example.test/api"
pat_file = "pat.txt"
poll_interval_secs = 15
"#;
        let err = AllocateConfig::parse(text).expect_err("missing driver refused");
        assert!(format!("{err}").contains("driver"), "{err}");
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let text = format!("{BASE}\ntypo_field = true\n");
        let err = AllocateConfig::parse(&text).expect_err("unknown field refused");
        assert!(format!("{err}").contains("typo_field"), "{err}");
    }
}
