// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The two HTTP calls this crate makes to the control server directly —
//! everything else goes through `kube::Client` against the cluster's own
//! API server, a different host entirely. Mints ADR-0045 §7b's
//! turn-enroll token via `POST /karst/v1/turn/enroll-tokens` (#310), and
//! removes a drained instance's registry row via
//! `POST /karst/v1/turn/deenroll` (#320) — see that route's own doc
//! comment (`server/management/internals/karst/api/nodes.go`) for why
//! this is a POST, not the `DELETE` an ordinary admin session uses.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct MintResponse {
    token: String,
}

/// An `Agent` with root certs loaded from the OS's own store and
/// `aws-lc-rs` installed as the crypto provider — identical to
/// `karst_scaler_k8s::enroll::build_agent`; see that function's own doc
/// comment for why this is duplicated rather than shared (this crate
/// cannot depend on `karst-scaler`'s own bin-only modules, and depending
/// on `karst-scaler-k8s` just for this one function would pull in its
/// unrelated `kube` dependency tree for no reason).
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

/// Mints one turn-enroll token — see `turnEnrollTokensCreate`
/// (`server/management/internals/karst/api/nodes.go`), the handler this
/// calls. Unlike `karst_scaler_k8s::enroll::mint_token`, the request body
/// carries no `pool_id`: no pool concept exists for TURN servers in the
/// control server's own schema (that handler's own doc comment).
///
/// # Errors
/// If the request fails, is refused (the PAT's `Scaler` role is checked
/// server-side, not here), or the response cannot be decoded.
pub(crate) fn mint_token(
    agent: &ureq::Agent,
    control_api_base: &str,
    pat: &str,
) -> Result<String, String> {
    let url = format!("{control_api_base}/karst/v1/turn/enroll-tokens");
    let response: MintResponse = agent
        .post(&url)
        .header("Authorization", &format!("Bearer {pat}"))
        .send_json(serde_json::json!({}))
        .map_err(|e| format!("POST {url}: {e}"))?
        .body_mut()
        .read_json()
        .map_err(|e| format!("POST {url}: decoding response: {e}"))?;
    Ok(response.token)
}

#[derive(Debug, Serialize)]
struct DeenrollRequest<'a> {
    uri: &'a str,
}

/// Removes `uri`'s own `turncred.Store` row via `turnDeenroll`
/// (#320) — see this crate's `driver.rs` for why this call happens
/// synchronously inside `drain()`, before the credential-TTL-bounded
/// deferred teardown it schedules.
///
/// A `404` (the row is already gone — e.g. a retried `drain()` call, or
/// an instance whose own `create()` never actually finished enrolling)
/// is treated as success: there is nothing left to remove, which is the
/// state this call is trying to reach either way.
///
/// # Errors
/// If the request fails, is refused, or the response is neither success
/// nor 404.
pub(crate) fn deenroll(
    agent: &ureq::Agent,
    control_api_base: &str,
    pat: &str,
    uri: &str,
) -> Result<(), String> {
    let url = format!("{control_api_base}/karst/v1/turn/deenroll");
    match agent
        .post(&url)
        .header("Authorization", &format!("Bearer {pat}"))
        .send_json(DeenrollRequest { uri })
    {
        Ok(_) | Err(ureq::Error::StatusCode(404)) => Ok(()),
        Err(e) => Err(format!("POST {url}: {e}")),
    }
}
