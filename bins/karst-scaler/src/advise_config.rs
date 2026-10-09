// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The `karst-scaler advise` subcommand's config file — ADR-0045 §7 Phase 1
//! PR 4.
//!
//! Before this PR, `advise` took its four inputs as bare positional CLI
//! arguments (`COST_MODEL.toml CONTROL_API_BASE PAT_FILE POLL_SECS`) — fine
//! while every input was mandatory, matching Phase 0's `simulate`/`check`
//! convention. This PR adds the first *optional* setting (`[metrics]
//! listen`), and a fifth positional argument has no way to spell "unset"
//! that is not itself another magic value (an empty string? a sentinel
//! port?), so the same point moves `advise` onto a small TOML file instead
//! — matching `karstd`'s and `karst-relay`'s own `[metrics]`-section
//! convention (`bins/karstd/src/config.rs`'s `MetricsSection`) rather than
//! inventing a new shape for the same idea.

use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;

/// `karst-scaler advise`'s own config file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdviseConfig {
    pub cost_model_path: String,
    /// The control server's own API base, e.g. `https://control.example.test/api`
    /// — `/karst/v1/demand/regions` and `/karst/v1/demand/anchors` are
    /// appended to this directly.
    pub control_api_base: String,
    /// Path to a file holding a `UserRoleAdvisor`-scoped PAT, trimmed of
    /// surrounding whitespace when read — never the token itself, so this
    /// config file can be committed or shared without carrying a credential.
    pub pat_file: String,
    pub poll_interval_secs: u64,
    #[serde(default)]
    pub metrics: MetricsSection,
}

/// The `[metrics]` TOML table — same loopback-only posture as `karstd`'s own
/// `MetricsSection`, enforced the same way: refused at load time, not just
/// documented. Unset (the default) means no new listener at all, matching
/// every other opt-in network surface in this workspace.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct MetricsSection {
    /// A loopback-only HTTP listener serving `/metrics` (Prometheus text)
    /// and `/recommendations` (JSON) — see `metrics_http`'s own module doc.
    pub listen: Option<SocketAddr>,
}

/// Errors loading or validating an `advise` config file.
#[derive(Debug)]
pub(crate) enum Error {
    Io(std::io::Error),
    Syntax(toml::de::Error),
    /// A configured `[metrics] listen` address is not loopback.
    NonLoopbackListen(SocketAddr),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Syntax(e) => write!(f, "{e}"),
            Self::NonLoopbackListen(addr) => write!(
                f,
                "metrics.listen = {addr} is not a loopback address; the Prometheus/JSON \
                 listener may only bind 127.0.0.0/8 or ::1, never a network-facing interface"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl AdviseConfig {
    pub(crate) fn parse(text: &str) -> Result<Self, Error> {
        let config: Self = toml::from_str(text).map_err(Error::Syntax)?;
        if let Some(addr) = config.metrics.listen {
            if !addr.ip().is_loopback() {
                return Err(Error::NonLoopbackListen(addr));
            }
        }
        Ok(config)
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
cost_model_path = "cost-model.toml"
control_api_base = "https://example.test/api"
pat_file = "pat.txt"
poll_interval_secs = 30
"#;

    #[test]
    fn metrics_is_unset_by_default() {
        let config = AdviseConfig::parse(BASE).expect("parses");
        assert_eq!(config.metrics.listen, None);
    }

    #[test]
    fn a_loopback_listen_address_is_accepted() {
        let text = format!("{BASE}\n[metrics]\nlisten = \"127.0.0.1:9100\"\n");
        let config = AdviseConfig::parse(&text).expect("parses");
        assert_eq!(
            config.metrics.listen,
            Some("127.0.0.1:9100".parse().expect("addr"))
        );
    }

    #[test]
    fn a_non_loopback_listen_address_is_refused() {
        let text = format!("{BASE}\n[metrics]\nlisten = \"0.0.0.0:9100\"\n");
        let err = AdviseConfig::parse(&text).expect_err("non-loopback refused");
        assert!(format!("{err}").contains("loopback"), "{err}");
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let text = format!("{BASE}\ntypo_field = true\n");
        let err = AdviseConfig::parse(&text).expect_err("unknown field refused");
        assert!(format!("{err}").contains("typo_field"), "{err}");
    }
}
