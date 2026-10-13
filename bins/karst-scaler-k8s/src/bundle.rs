// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Naming conventions and the enrollment-bundle shape — pure functions and
//! data, no Kubernetes client, no network. See the crate doc for the
//! Secret/ordinal scheme this implements.

use serde::{Deserialize, Serialize};

/// What a scaled-up relay's init step reads from its own key in the bundle
/// `Secret` — everything `karst-relay enroll` needs that is not already in
/// its own `relay.toml` (`region` is; see ADR-0045 §7 Phase 2 PR 4's own
/// notes on why it is not duplicated here).
///
/// `address` is optional only for `karst-scaler-aws`'s sake — a
/// `StatefulSet` pod's address (its stable per-pod DNS name) is always
/// knowable in advance, so this driver always writes `Some`. See
/// `karst-scaler-aws`'s own crate doc for why EC2 cannot.
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
    /// for this struct's own all-`String` shape.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }
}

/// The `StatefulSet` pod name for `pool_id`'s ordinal `i` — Kubernetes's own
/// fixed naming convention for a `StatefulSet` pod, not a choice this crate
/// makes. [`karst_scaler::driver::Instance::id`] is always exactly this
/// string, since it must name a real pod for `drain`/`destroy` to act on.
#[must_use]
pub fn pod_name(pool_id: &str, ordinal: u32) -> String {
    format!("{pool_id}-{ordinal}")
}

/// The bundle `Secret`'s key for ordinal `i` — one `Secret`, one key per
/// ordinal; see the crate doc's "Bundle delivery" section.
#[must_use]
pub fn secret_key(pool_id: &str, ordinal: u32) -> String {
    format!("{}.toml", pod_name(pool_id, ordinal))
}

/// The one bundle `Secret`'s own name — shared by every ordinal of
/// `pool_id`, never per-ordinal (see the crate doc).
#[must_use]
pub fn bundle_secret_name(pool_id: &str) -> String {
    format!("{pool_id}-enroll")
}

/// The stable per-pod DNS name ordinal `i` has once its headless `Service`
/// (same name as `pool_id`, by the convention this driver assumes — see
/// the crate doc) is in place. Doubles as the relay's registry address.
#[must_use]
pub fn pod_fqdn(pool_id: &str, ordinal: u32, namespace: &str) -> String {
    format!(
        "{}.{pool_id}.{namespace}.svc.cluster.local",
        pod_name(pool_id, ordinal)
    )
}

/// The literal `address` ordinal `i` is enrolled under — [`pod_fqdn`] plus
/// the fixed `:443` port `create()` writes into every bundle. A single
/// function for both `create()` (which writes this into the bundle) and
/// `destroy()` (which must pass this exact string to `relayDeenroll`,
/// issue #319) so the two can never drift apart the way two independent
/// `format!` call sites could.
#[must_use]
pub fn pod_address(pool_id: &str, ordinal: u32, namespace: &str) -> String {
    format!("{}:443", pod_fqdn(pool_id, ordinal, namespace))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn pod_name_matches_statefulset_ordinal_convention() {
        assert_eq!(pod_name("relay", 0), "relay-0");
        assert_eq!(pod_name("relay", 12), "relay-12");
    }

    #[test]
    fn secret_key_is_the_pod_name_with_a_toml_extension() {
        assert_eq!(secret_key("relay", 3), "relay-3.toml");
    }

    #[test]
    fn bundle_secret_name_is_one_name_shared_across_every_ordinal() {
        assert_eq!(bundle_secret_name("relay"), "relay-enroll");
        assert_eq!(bundle_secret_name("relay"), bundle_secret_name("relay"));
    }

    #[test]
    fn pod_fqdn_assumes_a_headless_service_named_after_the_pool() {
        assert_eq!(
            pod_fqdn("relay", 2, "karst-system"),
            "relay-2.relay.karst-system.svc.cluster.local"
        );
    }

    #[test]
    fn pod_address_is_the_fqdn_with_the_fixed_create_time_port() {
        assert_eq!(
            pod_address("relay", 2, "karst-system"),
            "relay-2.relay.karst-system.svc.cluster.local:443"
        );
    }

    #[test]
    fn a_bundle_round_trips_through_toml() {
        let bundle = EnrollBundle {
            control_api_base: "https://control.example.test/api".to_owned(),
            token: "SOME-SECRET".to_owned(),
            address: Some("relay-3.relay.karst-system.svc.cluster.local:443".to_owned()),
            tls_server_name: "relay-3.relay.karst-system.svc.cluster.local".to_owned(),
        };
        let text = bundle.to_toml().expect("serializes");
        let parsed: EnrollBundle = toml::from_str(&text).expect("parses");
        assert_eq!(parsed, bundle);
    }
}
