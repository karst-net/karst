// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Naming conventions and the enrollment-bundle shape — pure functions and
//! data, no Kubernetes client, no network. Mirrors
//! `karst-scaler-k8s::bundle`'s own `StatefulSet`/ordinal/`Secret`
//! conventions exactly (same crate doc reasoning: a `Deployment`'s
//! interchangeable pods cannot be handed a per-instance token or address
//! before they exist); the one real difference is the bundle's own shape,
//! covered below.
//!
//! ## Why an env file, not TOML
//!
//! `karst-scaler-k8s`'s bundle is read by `karst-relay enroll`, a Karst
//! Rust subcommand that already links `toml`. A coturn instance has no
//! Karst code running inside it at all (see
//! `deploy/images/karst-turn-bootstrap-entrypoint.sh`'s own doc comment —
//! RFC 8656 authenticates the client to the server, never the reverse, so
//! there is nothing to integrate with) — its bootstrap is a POSIX `sh`
//! script with no TOML parser available or worth adding for one fixed
//! three-field shape. A plain `KEY='value'` file a shell can `. source`
//! directly is the simpler, dependency-free match for that caller.

use serde::{Deserialize, Serialize};

/// What a scaled-up TURN instance's own bootstrap reads from its own key
/// in the bundle `Secret` — everything
/// `karst-turn-bootstrap-entrypoint.sh` needs to enroll itself.
/// `KARST_TURN_STATIC_AUTH_SECRET` is deliberately not here: that is the
/// operator's own shared TURN-REST secret, baked into the pod template
/// directly (or mounted from a separate, pre-existing `Secret`), never
/// minted or carried by this driver — see that script's own doc comment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnrollBundle {
    pub control_api_base: String,
    pub token: String,
    pub uri: String,
}

impl EnrollBundle {
    /// Renders as a shell-sourceable `KEY='value'` file, one line per
    /// field, each value single-quoted with any embedded single quote
    /// escaped (`'` → `'\''`) — safe against a token or URI that happens
    /// to contain a shell metacharacter, without needing a real shell
    /// quoting library for three fixed fields.
    #[must_use]
    pub fn to_env(&self) -> String {
        format!(
            "KARST_CONTROL_API_BASE={}\nKARST_TURN_ENROLL_TOKEN={}\nKARST_TURN_URI={}\n",
            shell_quote(&self.control_api_base),
            shell_quote(&self.token),
            shell_quote(&self.uri),
        )
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// The `StatefulSet` pod name for `pool_id`'s ordinal `i` — identical
/// convention to `karst_scaler_k8s::bundle::pod_name`.
#[must_use]
pub fn pod_name(pool_id: &str, ordinal: u32) -> String {
    format!("{pool_id}-{ordinal}")
}

/// The bundle `Secret`'s key for ordinal `i` — `.env`, not `.toml` (see
/// the module doc).
#[must_use]
pub fn secret_key(pool_id: &str, ordinal: u32) -> String {
    format!("{}.env", pod_name(pool_id, ordinal))
}

/// The one bundle `Secret`'s own name — shared by every ordinal of
/// `pool_id`, never per-ordinal.
#[must_use]
pub fn bundle_secret_name(pool_id: &str) -> String {
    format!("{pool_id}-turn-enroll")
}

/// The stable per-pod DNS name a pod named `pod_name` has once its
/// headless `Service` (same name as `pool_id`, by convention) is in
/// place — identical convention to `karst_scaler_k8s::bundle::pod_fqdn`,
/// except parameterized by the pod name directly rather than
/// re-deriving it from an ordinal: [`Driver::drain`]/[`Driver::destroy`]
/// only ever have the pod name (`Instance::id`), never the ordinal
/// number alone, and re-deriving one from the other would be the same
/// fact spelled two ways.
#[must_use]
pub fn pod_fqdn(pod_name: &str, pool_id: &str, namespace: &str) -> String {
    format!("{pod_name}.{pool_id}.{namespace}.svc.cluster.local")
}

/// This driver's own fixed TURN port and scheme — `turn:`, not `turns:`:
/// a reference driver with no TLS certificate provisioning story of its
/// own. An operator who needs `turns:` configures it through
/// `KARST_TURN_BASE_CONF` on the bootstrap image and this driver's own
/// limitation is exactly that mismatch risk — see this crate's own
/// `driver.rs` doc.
pub const TURN_PORT: u16 = 3478;

/// The `turn:` URI a pod named `pod_name` registers under — the one
/// string that must agree exactly, byte for byte, between what
/// [`EnrollBundle::uri`] hands the bootstrap script at `create()` time
/// and what [`Driver::drain`] later passes to `/karst/v1/turn/deenroll`.
/// Computing both from this single function, rather than keeping two
/// separate string-building call sites in sync by eye, is what makes
/// that agreement a fact rather than a convention someone could drift
/// away from.
#[must_use]
pub fn turn_uri(pod_name: &str, pool_id: &str, namespace: &str) -> String {
    format!(
        "turn:{}:{TURN_PORT}",
        pod_fqdn(pod_name, pool_id, namespace)
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn pod_name_matches_statefulset_ordinal_convention() {
        assert_eq!(pod_name("turn", 0), "turn-0");
        assert_eq!(pod_name("turn", 12), "turn-12");
    }

    #[test]
    fn secret_key_is_the_pod_name_with_an_env_extension() {
        assert_eq!(secret_key("turn", 3), "turn-3.env");
    }

    #[test]
    fn bundle_secret_name_is_distinct_from_the_relay_drivers_own_convention() {
        // karst_scaler_k8s::bundle::bundle_secret_name("turn") would be
        // "turn-enroll" -- a shared namespace running both drivers for a
        // pool_id that happens to collide must not collide on the Secret
        // name too.
        assert_eq!(bundle_secret_name("turn"), "turn-turn-enroll");
    }

    #[test]
    fn pod_fqdn_assumes_a_headless_service_named_after_the_pool() {
        assert_eq!(
            pod_fqdn("turn-2", "turn", "karst-system"),
            "turn-2.turn.karst-system.svc.cluster.local"
        );
    }

    #[test]
    fn turn_uri_is_turn_scheme_on_the_fixed_port() {
        assert_eq!(
            turn_uri("turn-2", "turn", "karst-system"),
            "turn:turn-2.turn.karst-system.svc.cluster.local:3478"
        );
    }

    #[test]
    fn a_bundle_renders_as_a_sourceable_env_file() {
        let bundle = EnrollBundle {
            control_api_base: "https://control.example.test/api".to_owned(),
            token: "SOME-SECRET".to_owned(),
            uri: "turn:turn-3.turn.karst-system.svc.cluster.local:3478".to_owned(),
        };
        let text = bundle.to_env();
        assert_eq!(
            text,
            "KARST_CONTROL_API_BASE='https://control.example.test/api'\n\
             KARST_TURN_ENROLL_TOKEN='SOME-SECRET'\n\
             KARST_TURN_URI='turn:turn-3.turn.karst-system.svc.cluster.local:3478'\n"
        );
    }

    #[test]
    fn a_value_containing_a_single_quote_is_escaped_safely() {
        let bundle = EnrollBundle {
            control_api_base: "https://control.example.test/api".to_owned(),
            token: "weird'token".to_owned(),
            uri: "turn:turn-0.turn.karst-system.svc.cluster.local:3478".to_owned(),
        };
        let text = bundle.to_env();
        assert!(text.contains(r"KARST_TURN_ENROLL_TOKEN='weird'\''token'"));
    }
}
