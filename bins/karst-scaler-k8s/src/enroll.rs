// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The one HTTP call this crate makes to the control server directly —
//! everything else goes through `kube::Client` against the cluster's own
//! API server, a different host entirely. Mints ADR-0045 §7 Phase 2 PR 3's
//! relay-enroll token via `POST /karst/v1/relays/enroll-tokens`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct MintRequest<'a> {
    pool_id: &'a str,
}

#[derive(Debug, Deserialize)]
struct MintResponse {
    token: String,
}

/// An `Agent` with root certs loaded from the OS's own store via
/// `rustls-native-certs` and `aws-lc-rs` installed as the crypto provider
/// — identical to `bins/karst-scaler/src/advise_loop.rs::build_agent`; see
/// this crate's `Cargo.toml` for why that pattern is duplicated here rather
/// than shared (this crate cannot depend on `karst-scaler`'s own bin-only
/// modules, only its library).
pub(crate) fn build_agent() -> Result<ureq::Agent, String> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let loaded = rustls_native_certs::load_native_certs();
    if loaded.certs.is_empty() {
        return Err("the host has no usable certificate authority roots".to_owned());
    }
    let roots: ureq::tls::RootCerts = loaded
        .certs
        .into_iter()
        .map(|der| ureq::tls::Certificate::from_der(der.as_ref()).to_owned())
        .collect::<Vec<_>>()
        .into();
    let tls_config = ureq::tls::TlsConfig::builder().root_certs(roots).build();
    let config = ureq::Agent::config_builder().tls_config(tls_config).build();
    Ok(ureq::Agent::new_with_config(config))
}

/// Mints one relay-enroll token for `pool_id` — see
/// `DefaultAccountManager.MintRelayEnrollKey`
/// (`server/management/server/relayenroll.go`), the handler this calls.
///
/// # Errors
/// If the request fails, is refused (the PAT's `Scaler` role is checked
/// server-side, not here), or the response cannot be decoded.
pub(crate) fn mint_token(
    agent: &ureq::Agent,
    control_api_base: &str,
    pat: &str,
    pool_id: &str,
) -> Result<String, String> {
    let url = format!("{control_api_base}/karst/v1/relays/enroll-tokens");
    let response: MintResponse = agent
        .post(&url)
        .header("Authorization", &format!("Bearer {pat}"))
        .send_json(MintRequest { pool_id })
        .map_err(|e| format!("POST {url}: {e}"))?
        .body_mut()
        .read_json()
        .map_err(|e| format!("POST {url}: decoding response: {e}"))?;
    Ok(response.token)
}
