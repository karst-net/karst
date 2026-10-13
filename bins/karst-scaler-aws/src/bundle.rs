// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The enrollment-bundle shape and naming convention for the AWS driver —
//! pure functions and data, no AWS SDK, no network. See the crate doc for
//! why `address` is optional here, unlike `karst-scaler-k8s`'s own bundle.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// What a newly-launched EC2 instance's own `karst-relay enroll` reads from
/// its user-data — the same fields `karst-scaler-k8s`'s own `EnrollBundle`
/// carries, except `address`: an EC2 instance's own IP is not known until
/// after `RunInstances` returns, so this driver cannot write it into
/// user-data at launch time the way the Kubernetes driver writes a
/// pre-known per-pod DNS name. `karst-relay enroll` resolves a missing
/// `address` itself, via IMDS, once the instance has actually booted — see
/// this crate's own doc comment for the full reasoning.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnrollBundle {
    pub control_api_base: String,
    pub token: String,
    pub address: Option<String>,
    pub tls_server_name: String,
}

impl EnrollBundle {
    /// # Errors
    /// Only if `self` somehow cannot be represented as TOML — not expected
    /// for this struct's own shape.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }
}

/// The tag every instance this driver creates carries, and every
/// `list`/`destroy` call filters by independently of whatever the planner
/// believes exists — see the crate doc's "Tag convention and IAM" section.
pub const POOL_TAG_KEY: &str = "karst:pool";

/// The second tag every instance this driver creates carries, holding
/// that instance's own [`tls_server_name`] — issue #329. `destroy()` has
/// only ever had an EC2 instance id to act on, never the `token` that
/// produced this value (ephemeral, discarded after `create()` returns),
/// so there is nothing in the driver process itself to recompute it from
/// later. Tagging the instance at launch, rather than persisting a
/// separate `instance_id -> tls_server_name` map in the driver's own
/// memory, means this survives a `karst-scaler drive` restart for free —
/// AWS is already the durable store for this, the same way Kubernetes
/// already is for `karst-scaler-k8s`'s own deterministic `pod_address`.
pub const TLS_SERVER_NAME_TAG_KEY: &str = "karst:tls-server-name";

/// A `tls_server_name` for one new instance of `pool_id`. Unlike
/// `karst-scaler-k8s`'s `pod_fqdn` (a real, resolvable per-pod DNS name),
/// this is never resolved as DNS: `bins/karst-relay/src/tls.rs`'s own crate
/// doc is explicit that a relay's certificate is never what authenticates
/// it (that's an ML-DSA-65 signature over the registry key instead), so
/// this only has to be a stable, unique, whitespace-free ASCII label the
/// mesh dials by. Derived from `token` by hashing, not embedding it
/// verbatim — the raw enrollment token is a single-use credential, and
/// this label ends up in a registry entry other peers can see — so it is
/// knowable *before* `RunInstances` returns, unlike anything built from
/// the instance's own, still-unknown, EC2 instance ID.
#[must_use]
pub fn tls_server_name(pool_id: &str, token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let suffix = digest.iter().take(6).fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    format!("{pool_id}-{suffix}.aws.karst.internal")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn tls_server_name_is_stable_ascii_with_no_whitespace() {
        let name = tls_server_name("relay-pool", "some-token-value");
        assert!(name.is_ascii());
        assert!(!name.chars().any(char::is_whitespace));
        assert!(name.starts_with("relay-pool-"));
        assert!(name.ends_with(".aws.karst.internal"));
    }

    #[test]
    fn tls_server_name_differs_per_token() {
        let a = tls_server_name("p", "token-a");
        let b = tls_server_name("p", "token-b");
        assert_ne!(a, b);
    }

    #[test]
    fn tls_server_name_is_deterministic_for_the_same_inputs() {
        assert_eq!(tls_server_name("p", "t"), tls_server_name("p", "t"));
    }

    #[test]
    fn a_bundle_round_trips_through_toml_with_address_present_or_absent() {
        for address in [Some("203.0.113.5:443".to_owned()), None] {
            let bundle = EnrollBundle {
                control_api_base: "https://control.example.test/api".to_owned(),
                token: "SOME-SECRET".to_owned(),
                address,
                tls_server_name: "relay-pool-abc123.aws.karst.internal".to_owned(),
            };
            let text = bundle.to_toml().expect("serializes");
            let parsed: EnrollBundle = toml::from_str(&text).expect("parses");
            assert_eq!(parsed, bundle);
        }
    }
}
