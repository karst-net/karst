// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! `karst-anchor-scheduler`'s own config file — the same small-TOML-file
//! convention `bins/karst-scaler/src/advise_config.rs` uses for `advise`/
//! `drive`, for the identical reason: more than one mandatory setting with
//! no natural "unset" spelling as a positional CLI argument.

use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SchedulerConfig {
    /// The control server's own API base, e.g.
    /// `https://control.example.test/api` — `/karst/v1/ephemeral-anchors`
    /// and `/karst/v1/ephemeral-anchors/schedule` are appended to this
    /// directly, the same convention `AdviseConfig::control_api_base`
    /// documents for its own two paths. Operators running both `advise`/
    /// `drive` and this scheduler against the same control server reuse
    /// the identical value.
    pub control_api_base: String,
    /// Path to a file holding a `UserRoleAdvisor`-scoped PAT, trimmed of
    /// surrounding whitespace when read — the same role `AdviseConfig`
    /// uses for the identical reason (a non-interactive process reading
    /// admin-maintained deployment config over HTTP); never the token
    /// itself, so this config file can be committed or shared without
    /// carrying a credential.
    pub pat_file: String,
    pub poll_interval_secs: u64,
}

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

impl SchedulerConfig {
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
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn a_complete_config_parses() {
        let cfg = SchedulerConfig::parse(
            r#"
control_api_base = "https://control.example.test/api"
pat_file = "pat.txt"
poll_interval_secs = 30
"#,
        )
        .expect("parse");
        assert_eq!(cfg.control_api_base, "https://control.example.test/api");
        assert_eq!(cfg.poll_interval_secs, 30);
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let err = SchedulerConfig::parse(
            r#"
control_api_base = "https://control.example.test/api"
pat_file = "pat.txt"
poll_interval_secs = 30
typo_field = true
"#,
        );
        assert!(err.is_err());
    }
}
