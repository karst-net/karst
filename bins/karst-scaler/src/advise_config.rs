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
    /// Required by `drive`, ignored by `advise` — ADR-0045 §6's budget
    /// circuit breaker and independent region-allowlist re-check
    /// (`breaker.rs`) need their own config and persisted state. `None`
    /// here is refused at the point `drive` starts, not silently treated
    /// as "no limit."
    #[serde(default)]
    pub breaker: Option<BreakerSection>,
    /// Which concrete `Driver` `drive` actuates through — ADR-0045 §7
    /// Phase 2 PR 4. Absent means the no-op driver (today's only option
    /// before this PR), matching `drive`'s own prior behavior exactly.
    #[serde(default)]
    pub driver: Option<DriverSection>,
}

/// The `[breaker]` TOML table — see [`crate::breaker`]'s own module doc
/// for why these are separate files from the cost model.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BreakerSection {
    /// Path to a [`karst_scaler::breaker::BreakerLimitsDocument`] file.
    pub limits_path: String,
    /// Path to the breaker's persisted per-pool, per-period counters —
    /// created on first use, read and rewritten on every `create`.
    pub state_path: String,
}

/// The `[driver]` TOML table.
///
/// Every field below other than `kind` is only ever *read* by whichever
/// one of `main.rs`'s `#[cfg(feature = "k8s")]`/`#[cfg(feature = "turn-k8s")]`/
/// `#[cfg(feature = "aws")]` builders matches `kind` -- a default build still parses and carries
/// all of them (an operator's config must not silently lose fields
/// depending on how the binary happened to be compiled), it just never
/// looks at them. Each field below is `allow(dead_code)`d individually,
/// rather than once for the whole struct, because a single-feature build
/// (just `k8s`, or just `aws`) genuinely never reads the other kind's own
/// fields -- a struct-level `allow` would miss exactly that case.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DriverSection {
    /// `"noop"`, `"k8s"`, `"turn-k8s"`, or `"aws"` — anything else is
    /// refused at the point `drive` starts. `"k8s"`/`"turn-k8s"`/`"aws"`
    /// on a `karst-scaler` built without the matching Cargo feature (see
    /// `karst-scaler-k8s`/`karst-scaler-turn-k8s`/`karst-scaler-aws`'s
    /// own crate docs) is refused the same way, not silently downgraded
    /// to the no-op driver.
    pub kind: String,
    /// Required when `kind = "k8s"` or `"turn-k8s"`: the namespace every
    /// `StatefulSet`, `Pod`, and bundle `Secret` this driver touches
    /// lives in.
    #[cfg_attr(not(any(feature = "k8s", feature = "turn-k8s")), allow(dead_code))]
    #[serde(default)]
    pub namespace: Option<String>,
    /// Required when `kind = "k8s"`, `"turn-k8s"`, or `"aws"`: path to a
    /// file holding a `UserRoleScaler`-scoped PAT (ADR-0045 §7 Phase 2
    /// PR 3), trimmed of surrounding whitespace when read — same
    /// convention as `pat_file` above.
    #[cfg_attr(
        not(any(feature = "k8s", feature = "turn-k8s", feature = "aws")),
        allow(dead_code)
    )]
    #[serde(default)]
    pub enroll_pat_file: Option<String>,
    /// Required when `kind = "turn-k8s"`: must equal the control
    /// server's own `turncred.Minter` TTL, in seconds — see
    /// `karst_scaler_turn_k8s::K8sTurnDriverConfig::credential_ttl`'s own
    /// doc comment for what this bounds and why this driver cannot read
    /// it from the control server itself.
    #[cfg_attr(not(feature = "turn-k8s"), allow(dead_code))]
    #[serde(default)]
    pub credential_ttl_secs: Option<u64>,
    /// Required when `kind = "aws"`: the AWS region every EC2 call this
    /// driver makes targets — ADR-0045 §4c's region allowlist makes this
    /// a load-bearing fact `karst-scaler-aws` must be told explicitly,
    /// not left to ambient discovery (see that crate's own
    /// `AwsDriverConfig` doc).
    #[cfg_attr(not(feature = "aws"), allow(dead_code))]
    #[serde(default)]
    pub region: Option<String>,
    /// Required when `kind = "aws"`: the AMI every new instance of this
    /// pool launches from — expected to already have `karst-relay`
    /// installed and configured to run `enroll` from its own boot path.
    #[cfg_attr(not(feature = "aws"), allow(dead_code))]
    #[serde(default)]
    pub ami_id: Option<String>,
    /// Required when `kind = "aws"`: the EC2 instance type new instances
    /// launch as, e.g. `"t3.micro"`.
    #[cfg_attr(not(feature = "aws"), allow(dead_code))]
    #[serde(default)]
    pub instance_type: Option<String>,
    /// Required when `kind = "aws"`: the subnet new instances launch
    /// into.
    #[cfg_attr(not(feature = "aws"), allow(dead_code))]
    #[serde(default)]
    pub subnet_id: Option<String>,
    /// Required when `kind = "aws"`: the security groups new instances
    /// launch with. At least one entry.
    #[cfg_attr(not(feature = "aws"), allow(dead_code))]
    #[serde(default)]
    pub security_group_ids: Vec<String>,
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
    fn a_turn_k8s_driver_section_parses_its_credential_ttl() {
        let text = format!(
            "{BASE}\n[driver]\nkind = \"turn-k8s\"\nnamespace = \"karst-turn\"\n\
             enroll_pat_file = \"turn-enroll.pat\"\ncredential_ttl_secs = 86400\n"
        );
        let config = AdviseConfig::parse(&text).expect("parses");
        let driver = config.driver.expect("driver section present");
        assert_eq!(driver.kind, "turn-k8s");
        assert_eq!(driver.credential_ttl_secs, Some(86400));
    }

    #[test]
    fn credential_ttl_secs_defaults_to_unset() {
        let text = format!(
            "{BASE}\n[driver]\nkind = \"k8s\"\nnamespace = \"karst-relays\"\n\
             enroll_pat_file = \"enroll.pat\"\n"
        );
        let config = AdviseConfig::parse(&text).expect("parses");
        let driver = config.driver.expect("driver section present");
        assert_eq!(driver.credential_ttl_secs, None);
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let text = format!("{BASE}\ntypo_field = true\n");
        let err = AdviseConfig::parse(&text).expect_err("unknown field refused");
        assert!(format!("{err}").contains("typo_field"), "{err}");
    }
}
