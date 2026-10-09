// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The declarative cost-model schema — ADR-0045 §1 and §2.
//!
//! Cost is data, not code. A [`Pool`] is a capacity pool (on-prem or cloud);
//! its [`CostModel`] is composed of [`PriceSchedule`]s keyed by meter and by
//! edge class, plus [`Commitment`]s. Nothing here talks to a provider API —
//! that is a separate, not-yet-built helper (§2's precedence order item 2),
//! and an operator-maintained TOML file is precedence order item 1 either
//! way: "committed as a reviewable file, never silently hot-reloaded."
//!
//! [`Document::allowed_regions`] is §4c's deployment-wide backstop: a
//! region-bound pool's `(provider, region)` must appear there, checked by
//! [`Document::validate`] independently of how the pool was proposed and
//! fail-closed when the section (or the provider's own entry in it) is
//! absent entirely.

use std::collections::HashMap;

use serde::Deserialize;

/// Errors reading a cost-model file.
#[derive(Debug)]
pub enum Error {
    /// The file could not be read.
    Io(std::io::Error),
    /// The file is not valid TOML, or a field has the wrong type.
    Syntax(String),
    /// A value is present but cannot be satisfied — named so the operator
    /// does not have to guess which pool or schedule is at fault.
    Invalid(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cost model: {e}"),
            Self::Syntax(m) | Self::Invalid(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

/// `pool.provider` — ADR-0045 §1's enumerated set, plus `generic` for a
/// provider with no dedicated arm yet (the same "a plain function per
/// provider, not a trait, until a second real implementation exists" posture
/// §4b's anchor dispatcher uses; a cost model has no behavior per provider
/// today, only data, so there is nothing yet for a closed `match` to protect).
///
/// `AwsGovCloud` and `AzureGovCloud` are distinct arms, not a region under
/// `Aws`/`Azure`: each is its own partition of its parent provider —
/// separate account (AWS) or tenant/ARM endpoint (Azure), separate
/// ARN/resource-ID namespace, separate pricing — so each gets its own
/// `allowed_regions` key (`aws-gov-cloud`, `azure-gov-cloud`) an operator
/// must opt into independently of the commercial one, the same separation
/// a typo'd region code must not be able to cross. There is deliberately
/// no `GcpGovCloud`: GCP has no equivalent account/API boundary — its
/// government/compliance offerings are policy on the same commercial
/// account and region list `Gcp` already covers, so there is no second
/// partition for a second arm to name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Aws,
    #[serde(rename = "aws-gov-cloud")]
    AwsGovCloud,
    Azure,
    #[serde(rename = "azure-gov-cloud")]
    AzureGovCloud,
    Gcp,
    Onprem,
    Generic,
}

impl Provider {
    /// The lowercase spelling used by the TOML schema (via `Deserialize`)
    /// and by [`Document::validate`]'s own error messages — one mapping,
    /// matching [`EdgeClass::as_str`]'s reasoning.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::AwsGovCloud => "aws-gov-cloud",
            Self::Azure => "azure",
            Self::AzureGovCloud => "azure-gov-cloud",
            Self::Gcp => "gcp",
            Self::Onprem => "onprem",
            Self::Generic => "generic",
        }
    }

    /// Whether this provider is bound by §4c's region allowlist at all.
    /// On-prem and `generic` pools are exempt — ADR-0045 §4c: "their
    /// location is a single operator decision made once per pool, not
    /// something auto-discovered or auto-proposed."
    #[must_use]
    pub const fn is_region_bound(self) -> bool {
        match self {
            Self::Aws | Self::AwsGovCloud | Self::Azure | Self::AzureGovCloud | Self::Gcp => true,
            Self::Onprem | Self::Generic => false,
        }
    }
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A meter id — `instance_hours`, `egress_gb`, `ipv4_hours`, … — ADR-0045
/// §2's first bullet. Deliberately an open string rather than a closed enum:
/// §2's own precedence order puts operator-supplied entries first precisely
/// because the set of meters a provider bills on is not something this tool
/// gets to close over.
pub type MeterId = String;

/// `destination class` — ADR-0045 §2's edge-price bullet. Closed, unlike
/// [`MeterId`]: these five classes are the ones the ADR names, and a traffic
/// matrix with a sixth kind of destination is a new decision, not a new
/// value an operator should be able to spell into a TOML file unnoticed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EdgeClass {
    Internet,
    SameRegion,
    CrossRegion,
    CrossProvider,
    PrivateLink,
}

impl EdgeClass {
    /// The kebab-case spelling used by both the TOML schema (via `Deserialize`)
    /// and [`crate::usage`]'s plain-text records — one mapping, so the two
    /// input formats cannot drift apart on what a class is called.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Internet => "internet",
            Self::SameRegion => "same-region",
            Self::CrossRegion => "cross-region",
            Self::CrossProvider => "cross-provider",
            Self::PrivateLink => "private-link",
        }
    }

    /// The inverse of [`Self::as_str`]; `None` for anything else.
    #[must_use]
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "internet" => Some(Self::Internet),
            "same-region" => Some(Self::SameRegion),
            "cross-region" => Some(Self::CrossRegion),
            "cross-provider" => Some(Self::CrossProvider),
            "private-link" => Some(Self::PrivateLink),
            _ => None,
        }
    }
}

impl std::fmt::Display for EdgeClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a [`PriceSchedule`]'s bands are graduated or volume pricing —
/// ADR-0045 §2: "Tiers can be *graduated* (each band priced separately) or
/// *volume* (the whole quantity reprices at the tier reached)."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Graduated,
    Volume,
}

/// One band of a tiered price schedule: `{up_to, unit_price}` — ADR-0045 §2.
///
/// `up_to` is the cumulative quantity (for the period) at which this band
/// ends, in the meter's own unit, counted from zero — not from the previous
/// band's boundary. `None` means this band has no ceiling; it must be the
/// last band in the schedule, and exactly one band may say so.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceBand {
    pub up_to: Option<f64>,
    pub unit_price: f64,
}

/// A price schedule attached to a meter or an edge class — ADR-0045 §2.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceSchedule {
    pub mode: Mode,

    /// Ordered ascending by `up_to`; validated by [`CostModel::validate`],
    /// not here — `Deserialize` has no way to fail across fields, and a
    /// schedule with its bands out of order is exactly the kind of mistake
    /// that should be named rather than silently misread.
    pub bands: Vec<PriceBand>,

    /// ADR-0045 §2: "Free allowances are the same thing with X = 0" — a
    /// quantity subtracted from usage before the schedule applies, in the
    /// meter's own unit, before this period's bands are consulted at all.
    #[serde(default)]
    pub free_allowance: f64,

    /// Minimum billing increment, in the meter's own unit — ADR-0045 §2:
    /// "per-second vs per-hour, minimum one minute... set the *cost of
    /// churn*." Each individual usage record's quantity is rounded up to a
    /// multiple of this before it is added to the period total. `None`
    /// means no rounding (a meter that is naturally discrete, like
    /// `ipv4_hours` billed to the second already, has nothing to round).
    #[serde(default)]
    pub minimum_increment: Option<f64>,
}

/// A prepaid quantity at a (possibly discounted) price — ADR-0045 §2's
/// "commitments" paragraph: "a reserved or savings-plan quantity is a
/// prepaid band at price zero (or a discounted rate) that the optimizer
/// consumes before reaching on-demand, with the commitment's own cost
/// counted whether or not it is used."
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commitment {
    pub meter: MeterId,
    pub quantity: f64,
    /// The commitment's own cost for one period, charged regardless of how
    /// much of `quantity` is actually consumed.
    pub price: f64,
}

/// One pool's cost model — ADR-0045 §2. A pool with no cost model at all is
/// rejected at the TOML level: `[pools.*.cost_model]` has no `#[serde(default)]`,
/// so a pool table that omits it fails to parse rather than defaulting to
/// free, matching §2's precedence-order item 3 exactly: "A pool with no cost
/// model is rejected at validation, not defaulted to 'free.'"
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostModel {
    #[serde(default)]
    pub meters: HashMap<MeterId, PriceSchedule>,
    #[serde(default)]
    pub edges: HashMap<EdgeClass, PriceSchedule>,
    #[serde(default)]
    pub commitments: Vec<Commitment>,
}

/// A capacity pool — ADR-0045 §1.
///
/// This is the Phase 0 slice of a pool plus Phase 1's floor/ceiling: enough
/// to cost it and to bound how the Advisor (§7 Phase 1) may size it.
/// `driver` (§5) and the rest of `capacity` (`uplink_mbps_max`, …) are not
/// needed for either of those and are left for the phase that actuates
/// something or constrains bandwidth specifically — Phase 1's headroom is
/// sized in nodes, per §4.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pool {
    pub provider: Provider,
    pub region: String,
    pub cost_model: CostModel,

    /// ADR-0045 §1's `min_nodes`: "floor: N+1 / always-on presence." The
    /// Advisor (§7 Phase 1) never recommends fewer than this many nodes for
    /// this pool, regardless of cost. Zero (the default) means no floor.
    #[serde(default)]
    pub min_nodes: u32,

    /// ADR-0045 §1's `capacity.nodes_max`: a hard ceiling the Advisor never
    /// recommends exceeding. `None` (the default) means no ceiling —
    /// appropriate for a cloud pool ("large"); an on-prem pool's actual
    /// physical limit is the usual reason to set this.
    #[serde(default)]
    pub nodes_max: Option<u32>,
}

/// The whole cost-model file: one `[pools.<id>]` table per pool, keyed by
/// pool id — matching ADR-0045 §1's `pool { id, ... }` shape, with `id` as
/// the TOML key rather than a duplicated field.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    #[serde(default)]
    pub pools: HashMap<String, Pool>,

    /// `[allowed_regions]` — ADR-0045 §4c's deployment-wide backstop: the
    /// region codes a pool's provider may ever be declared in, keyed by
    /// provider. Deliberately `#[serde(default)]` rather than required:
    /// an operator who never writes this section gets the fail-closed
    /// behavior §4c specifies (every region-bound pool rejected), not a
    /// parse error, so the message that explains why lands in
    /// [`Self::validate`] where it can name the pool at fault.
    #[serde(default)]
    pub allowed_regions: HashMap<Provider, Vec<String>>,
}

impl Document {
    /// Parse a cost-model document from TOML.
    ///
    /// # Errors
    /// [`Error::Syntax`] for malformed TOML, a missing required field, or an
    /// unrecognized one.
    pub fn parse(text: &str) -> Result<Self, Error> {
        toml::from_str(text).map_err(|e| Error::Syntax(format!("cost model: {e}")))
    }

    /// Read a cost-model document from disk.
    ///
    /// # Errors
    /// [`Error::Io`] if the file cannot be read, plus everything
    /// [`Self::parse`] returns.
    pub fn load(path: &std::path::Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(Error::Io)?;
        Self::parse(&text)
    }

    /// Check what parsing cannot: band ordering, a schedule's own internal
    /// consistency, and that every commitment names a meter the pool
    /// actually has a schedule for.
    ///
    /// # Errors
    /// [`Error::Invalid`] naming the pool and field at fault.
    pub fn validate(&self) -> Result<(), Error> {
        for (pool_id, pool) in &self.pools {
            self.check_allowed_region(pool_id, pool)?;
            if let Some(max) = pool.nodes_max {
                if pool.min_nodes > max {
                    return Err(Error::Invalid(format!(
                        "pools.{pool_id}: min_nodes ({}) exceeds nodes_max ({max})",
                        pool.min_nodes
                    )));
                }
            }
            for (meter, schedule) in &pool.cost_model.meters {
                validate_schedule(
                    &format!("pools.{pool_id}.cost_model.meters.{meter}"),
                    schedule,
                )?;
            }
            for (class, schedule) in &pool.cost_model.edges {
                validate_schedule(
                    &format!("pools.{pool_id}.cost_model.edges.{class:?}"),
                    schedule,
                )?;
            }
            for commitment in &pool.cost_model.commitments {
                if !pool.cost_model.meters.contains_key(&commitment.meter) {
                    return Err(Error::Invalid(format!(
                        "pools.{pool_id}.cost_model.commitments: commitment names meter \
                         {:?}, which this pool has no price schedule for",
                        commitment.meter
                    )));
                }
                if commitment.quantity < 0.0 {
                    return Err(Error::Invalid(format!(
                        "pools.{pool_id}.cost_model.commitments: a negative quantity \
                         for meter {:?} is not a commitment",
                        commitment.meter
                    )));
                }
            }
        }
        Ok(())
    }

    /// ADR-0045 §4c: a region-bound pool (anything but `onprem`/`generic`)
    /// must be in its provider's `allowed_regions` list, independent of how
    /// the pool was proposed and independent of whether `allowed_regions`
    /// was configured at all. No default: a provider with no entry here
    /// rejects every pool for that provider, the same fail-closed posture
    /// `detect_location` and §4b's own opt-in flag already apply.
    ///
    /// # Errors
    /// [`Error::Invalid`] naming the pool, provider, and region at fault.
    fn check_allowed_region(&self, pool_id: &str, pool: &Pool) -> Result<(), Error> {
        if !pool.provider.is_region_bound() {
            return Ok(());
        }
        let allowed = self.allowed_regions.get(&pool.provider);
        if !allowed.is_some_and(|regions| regions.iter().any(|r| r == &pool.region)) {
            return Err(Error::Invalid(format!(
                "pools.{pool_id}: region {:?} is not in allowed_regions.{} \
                 (configure allowed_regions.{} to permit a {} pool in this region)",
                pool.region, pool.provider, pool.provider, pool.provider,
            )));
        }
        Ok(())
    }
}

/// Bands must be non-empty, ascending by `up_to`, and exactly the last one
/// may be unbounded — a schedule that could not price some quantity at all,
/// or that prices one twice, is a configuration error worth refusing rather
/// than resolving by whichever band `bands.iter().find` happens to hit first.
fn validate_schedule(path: &str, schedule: &PriceSchedule) -> Result<(), Error> {
    if schedule.bands.is_empty() {
        return Err(Error::Invalid(format!(
            "{path}: a price schedule needs at least one band"
        )));
    }
    if schedule.free_allowance < 0.0 {
        return Err(Error::Invalid(format!(
            "{path}: free_allowance must not be negative"
        )));
    }
    if let Some(inc) = schedule.minimum_increment {
        if inc <= 0.0 {
            return Err(Error::Invalid(format!(
                "{path}: minimum_increment must be positive, or omitted for none"
            )));
        }
    }
    let mut previous = 0.0_f64;
    for (index, band) in schedule.bands.iter().enumerate() {
        let is_last = index + 1 == schedule.bands.len();
        match band.up_to {
            // A bounded last band is fine here — it just means usage above
            // `up_to` has nowhere to go, which `simulate` reports as its own
            // error rather than silently clamping or extrapolating.
            Some(up_to) => {
                if up_to <= previous {
                    return Err(Error::Invalid(format!(
                        "{path}: band {index} has up_to = {up_to}, which does not exceed \
                         the previous band's boundary ({previous}); bands must be strictly \
                         ascending"
                    )));
                }
                previous = up_to;
            }
            None if !is_last => {
                return Err(Error::Invalid(format!(
                    "{path}: band {index} is unbounded (no up_to) but is not the last \
                     band; only the final band may be unbounded"
                )));
            }
            None => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    const MINIMAL: &str = r#"
[pools.onprem-mia]
provider = "onprem"
region = "us-east"

[pools.onprem-mia.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ up_to = 1000.0, unit_price = 0.0 }]
"#;

    #[test]
    fn a_minimal_document_parses_and_validates() {
        let d = Document::parse(MINIMAL).expect("parses");
        assert!(d.validate().is_ok());
        assert_eq!(d.pools.len(), 1);
    }

    #[test]
    fn a_pool_with_no_cost_model_fails_to_parse_rather_than_defaulting_to_free() {
        // §2's precedence order item 3: "A pool with no cost model is
        // rejected at validation, not defaulted to 'free.'" The TOML table
        // itself is required, so this is actually rejected a step earlier,
        // at parse time — which is a stronger guarantee than a validation
        // pass that a caller could skip.
        let text = r#"
[pools.mystery]
provider = "aws"
region = "us-east-1"
"#;
        let err = Document::parse(text).expect_err("missing cost_model");
        assert!(matches!(err, Error::Syntax(_)), "{err:?}");
    }

    #[test]
    fn an_unrecognized_field_is_an_error() {
        let text = format!("{MINIMAL}\nextra = 1\n");
        let err = Document::parse(&text).expect_err("unknown top-level field");
        assert!(matches!(err, Error::Syntax(_)), "{err:?}");
    }

    #[test]
    fn bands_must_be_strictly_ascending() {
        let text = r#"
[pools.p]
provider = "generic"
region = "x"

[pools.p.cost_model.meters.m]
mode = "graduated"
bands = [
  { up_to = 100.0, unit_price = 1.0 },
  { up_to = 50.0, unit_price = 2.0 },
]
"#;
        let d = Document::parse(text).expect("parses");
        let err = d.validate().expect_err("non-ascending bands");
        assert!(format!("{err}").contains("ascending"), "{err}");
    }

    #[test]
    fn only_the_last_band_may_be_unbounded() {
        let text = r#"
[pools.p]
provider = "generic"
region = "x"

[pools.p.cost_model.meters.m]
mode = "graduated"
bands = [
  { unit_price = 1.0 },
  { up_to = 50.0, unit_price = 2.0 },
]
"#;
        let d = Document::parse(text).expect("parses");
        let err = d.validate().expect_err("unbounded non-last band");
        assert!(format!("{err}").contains("unbounded"), "{err}");
    }

    #[test]
    fn an_empty_schedule_is_refused() {
        let text = r#"
[pools.p]
provider = "generic"
region = "x"

[pools.p.cost_model.meters.m]
mode = "graduated"
bands = []
"#;
        let d = Document::parse(text).expect("parses");
        let err = d.validate().expect_err("empty bands");
        assert!(format!("{err}").contains("at least one band"), "{err}");
    }

    #[test]
    fn a_commitment_must_name_a_meter_the_pool_has_a_schedule_for() {
        let text = format!(
            "{MINIMAL}\n[[pools.onprem-mia.cost_model.commitments]]\n\
             meter = \"ipv4_hours\"\nquantity = 10.0\nprice = 5.0\n"
        );
        let d = Document::parse(&text).expect("parses");
        let err = d.validate().expect_err("unknown meter");
        assert!(format!("{err}").contains("ipv4_hours"), "{err}");
    }

    #[test]
    fn a_negative_commitment_quantity_is_refused() {
        let text = format!(
            "{MINIMAL}\n[[pools.onprem-mia.cost_model.commitments]]\n\
             meter = \"egress_gb\"\nquantity = -1.0\nprice = 5.0\n"
        );
        let d = Document::parse(&text).expect("parses");
        let err = d.validate().expect_err("negative quantity");
        assert!(format!("{err}").contains("negative"), "{err}");
    }

    #[test]
    fn a_negative_free_allowance_is_refused() {
        let text = r#"
[pools.p]
provider = "generic"
region = "x"

[pools.p.cost_model.meters.m]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
free_allowance = -5.0
"#;
        let d = Document::parse(text).expect("parses");
        let err = d.validate().expect_err("negative free_allowance");
        assert!(format!("{err}").contains("free_allowance"), "{err}");
    }

    #[test]
    fn a_cloud_pool_is_refused_when_allowed_regions_has_no_entry_at_all() {
        // §4c: "No default" — a provider absent from allowed_regions
        // entirely rejects every pool for that provider, not "allow all."
        let text = r#"
[pools.p]
provider = "aws"
region = "us-east-1"

[pools.p.cost_model.meters.m]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
"#;
        let d = Document::parse(text).expect("parses");
        let err = d.validate().expect_err("no allowed_regions configured");
        assert!(format!("{err}").contains("allowed_regions.aws"), "{err}");
    }

    #[test]
    fn a_cloud_pool_outside_its_providers_allowlist_is_refused() {
        let text = r#"
[allowed_regions]
aws = ["us-east-1"]

[pools.p]
provider = "aws"
region = "us-west-2"

[pools.p.cost_model.meters.m]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
"#;
        let d = Document::parse(text).expect("parses");
        let err = d
            .validate()
            .expect_err("region not in that provider's allowlist");
        assert!(format!("{err}").contains("us-west-2"), "{err}");
        assert!(format!("{err}").contains("allowed_regions.aws"), "{err}");
    }

    #[test]
    fn a_cloud_pool_inside_its_providers_allowlist_is_accepted() {
        let text = r#"
[allowed_regions]
aws = ["us-east-1", "us-west-2"]

[pools.p]
provider = "aws"
region = "us-west-2"

[pools.p.cost_model.meters.m]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
"#;
        let d = Document::parse(text).expect("parses");
        assert!(d.validate().is_ok());
    }

    #[test]
    fn every_cloud_provider_is_bound_by_its_own_allowlist() {
        // §4c applies uniformly to every region-bound provider, not just
        // AWS — each of the "top 3" is checked here with its own region
        // code and its own allowlist entry.
        for (provider, allowed, outside) in [
            ("aws", "us-east-1", "us-west-2"),
            ("azure", "eastus", "westus2"),
            ("gcp", "us-central1", "europe-west1"),
        ] {
            let text = format!(
                "[allowed_regions]\n{provider} = [\"{allowed}\"]\n\n\
                 [pools.p]\nprovider = \"{provider}\"\nregion = \"{allowed}\"\n\n\
                 [pools.p.cost_model.meters.m]\nmode = \"graduated\"\n\
                 bands = [{{ unit_price = 1.0 }}]\n"
            );
            let d = Document::parse(&text).expect("parses");
            assert!(
                d.validate().is_ok(),
                "{provider}: {allowed} should be allowed"
            );

            let text = format!(
                "[allowed_regions]\n{provider} = [\"{allowed}\"]\n\n\
                 [pools.p]\nprovider = \"{provider}\"\nregion = \"{outside}\"\n\n\
                 [pools.p.cost_model.meters.m]\nmode = \"graduated\"\n\
                 bands = [{{ unit_price = 1.0 }}]\n"
            );
            let d = Document::parse(&text).expect("parses");
            let err = d
                .validate()
                .expect_err(&format!("{provider}: {outside} is not in its allowlist"));
            assert!(format!("{err}").contains(outside), "{provider}: {err}");
        }
    }

    #[test]
    fn aws_gov_cloud_is_a_distinct_provider_from_commercial_aws() {
        // Allowing a commercial region does not reach into GovCloud, and
        // vice versa — the two partitions never share an allowlist entry.
        let text = r#"
[allowed_regions]
aws = ["us-east-1"]

[pools.p]
provider = "aws-gov-cloud"
region = "us-gov-west-1"

[pools.p.cost_model.meters.m]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
"#;
        let d = Document::parse(text).expect("parses");
        let err = d
            .validate()
            .expect_err("commercial allowlist does not cover gov-cloud");
        assert!(
            format!("{err}").contains("allowed_regions.aws-gov-cloud"),
            "{err}"
        );

        let text = r#"
[allowed_regions]
"aws-gov-cloud" = ["us-gov-west-1"]

[pools.p]
provider = "aws-gov-cloud"
region = "us-gov-west-1"

[pools.p.cost_model.meters.m]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
"#;
        let d = Document::parse(text).expect("parses");
        assert!(d.validate().is_ok());
    }

    #[test]
    fn azure_gov_cloud_is_a_distinct_provider_from_commercial_azure() {
        // Same separation as AWS GovCloud, for Azure Government.
        let text = r#"
[allowed_regions]
azure = ["eastus"]

[pools.p]
provider = "azure-gov-cloud"
region = "usgovvirginia"

[pools.p.cost_model.meters.m]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
"#;
        let d = Document::parse(text).expect("parses");
        let err = d
            .validate()
            .expect_err("commercial allowlist does not cover azure government");
        assert!(
            format!("{err}").contains("allowed_regions.azure-gov-cloud"),
            "{err}"
        );

        let text = r#"
[allowed_regions]
"azure-gov-cloud" = ["usgovvirginia"]

[pools.p]
provider = "azure-gov-cloud"
region = "usgovvirginia"

[pools.p.cost_model.meters.m]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
"#;
        let d = Document::parse(text).expect("parses");
        assert!(d.validate().is_ok());
    }

    #[test]
    fn onprem_and_generic_pools_are_exempt_from_the_allowlist() {
        // §4c: "their location is a single operator decision made once per
        // pool" — no allowed_regions section at all, and these still pass.
        let text = r#"
[pools.mia]
provider = "onprem"
region = "us-east"

[pools.mia.cost_model.meters.m]
mode = "graduated"
bands = [{ unit_price = 0.0 }]

[pools.vps]
provider = "generic"
region = "wherever"

[pools.vps.cost_model.meters.m]
mode = "graduated"
bands = [{ unit_price = 1.0 }]
"#;
        let d = Document::parse(text).expect("parses");
        assert!(d.validate().is_ok());
    }

    #[test]
    fn min_nodes_and_nodes_max_default_to_no_floor_or_ceiling() {
        let d = Document::parse(MINIMAL).expect("parses");
        let pool = d.pools.get("onprem-mia").expect("pool");
        assert_eq!(pool.min_nodes, 0);
        assert_eq!(pool.nodes_max, None);
    }

    #[test]
    fn min_nodes_within_nodes_max_is_accepted() {
        let text = r#"
[pools.p]
provider = "onprem"
region = "x"
min_nodes = 2
nodes_max = 5

[pools.p.cost_model.meters.m]
mode = "graduated"
bands = [{ unit_price = 0.0 }]
"#;
        let d = Document::parse(text).expect("parses");
        assert!(d.validate().is_ok());
    }

    #[test]
    fn min_nodes_exceeding_nodes_max_is_refused() {
        let text = r#"
[pools.p]
provider = "onprem"
region = "x"
min_nodes = 6
nodes_max = 5

[pools.p.cost_model.meters.m]
mode = "graduated"
bands = [{ unit_price = 0.0 }]
"#;
        let d = Document::parse(text).expect("parses");
        let err = d.validate().expect_err("min_nodes above nodes_max");
        assert!(format!("{err}").contains("min_nodes"), "{err}");
        assert!(format!("{err}").contains("nodes_max"), "{err}");
    }

    #[test]
    fn min_nodes_with_no_nodes_max_is_never_refused() {
        // No ceiling means no check to fail, regardless of how large
        // min_nodes is.
        let text = r#"
[pools.p]
provider = "onprem"
region = "x"
min_nodes = 1000

[pools.p.cost_model.meters.m]
mode = "graduated"
bands = [{ unit_price = 0.0 }]
"#;
        let d = Document::parse(text).expect("parses");
        assert!(d.validate().is_ok());
    }

    #[test]
    fn edge_classes_round_trip_through_kebab_case() {
        let text = r#"
[allowed_regions]
aws = ["us-east-1"]

[pools.p]
provider = "aws"
region = "us-east-1"

[pools.p.cost_model.meters.egress_gb]
mode = "graduated"
bands = [{ unit_price = 0.01 }]

[pools.p.cost_model.edges.cross-region]
mode = "graduated"
bands = [{ unit_price = 0.02 }]
"#;
        let d = Document::parse(text).expect("parses");
        assert!(d.validate().is_ok());
        let pool = d.pools.get("p").expect("pool p");
        assert!(pool.cost_model.edges.contains_key(&EdgeClass::CrossRegion));
    }
}
