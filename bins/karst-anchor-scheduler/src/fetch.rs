// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Reads ADR-0045 §4d's ephemeral-anchor list and duty-cycle schedule from
//! the control server's admin REST surface
//! (`server/management/internals/karst/api/nodes.go`'s
//! `ephemeralAnchorsList`/`ephemeralAnchorsSchedule`) — the same
//! `ureq`/Bearer-PAT fetch idiom `bins/karst-scaler/src/advise_loop.rs`'s
//! own `build_agent`/`fetch` use for `/karst/v1/demand/regions` and
//! `/karst/v1/demand/anchors`, not a second HTTP convention.

/// What a fetch needs — built once at startup from [`crate::config::SchedulerConfig`]
/// (the PAT file read and trimmed exactly once, not on every tick, mirroring
/// `advise_loop::Config`'s own shape).
pub(crate) struct Endpoint {
    pub control_api_base: String,
    pub pat: String,
}

/// One ephemeral anchor, as the admin REST surface returns it — mirrors
/// `server/management/internals/karst/api/nodes.go`'s `ephemeralAnchor`
/// wire shape exactly, including `region`/`instance_id` (this binary's own
/// reason to exist — `scheduler.rs` uses them to find and act on the real
/// EC2 instance) and `address`/`port` (part of the same wire shape, but
/// genuinely unused here: those two are what `ephemeral_anchor_probe.rs`
/// needs to connect, never this scheduler, which only starts/stops a
/// power state by instance id — `#[allow(dead_code)]` reflects that
/// honestly rather than inventing a use for them).
#[derive(Debug, Clone, serde::Deserialize)]
#[allow(dead_code)]
pub(crate) struct AnchorEntry {
    pub label: String,
    #[serde(default)]
    pub region: String,
    pub instance_id: String,
    pub address: String,
    #[serde(default)]
    pub port: u16,
}

/// The deployment-wide duty-cycle schedule, as the admin REST surface
/// returns it.
#[derive(Debug, Clone, Copy, Default, serde::Deserialize)]
pub(crate) struct Schedule {
    #[serde(default)]
    pub window_period_seconds: u32,
    #[serde(default)]
    pub duty_cycle_seconds: u32,
}

/// An `Agent` with root certs loaded from the OS's own store — byte-for-byte
/// `advise_loop::build_agent`'s own body; duplicated rather than shared
/// because no crate boundary between `karst-scaler` and this standalone
/// binary makes sharing natural (the same tradeoff this crate's own
/// window-arithmetic duplication in `window.rs` accepts).
pub(crate) fn build_agent() -> Result<ureq::Agent, String> {
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

pub(crate) fn fetch_anchors(
    agent: &ureq::Agent,
    endpoint: &Endpoint,
) -> Result<Vec<AnchorEntry>, String> {
    fetch(agent, endpoint, "/karst/v1/ephemeral-anchors")
}

pub(crate) fn fetch_schedule(agent: &ureq::Agent, endpoint: &Endpoint) -> Result<Schedule, String> {
    fetch(agent, endpoint, "/karst/v1/ephemeral-anchors/schedule")
}

fn fetch<T: serde::de::DeserializeOwned>(
    agent: &ureq::Agent,
    endpoint: &Endpoint,
    path: &str,
) -> Result<T, String> {
    let url = format!("{}{path}", endpoint.control_api_base);
    agent
        .get(&url)
        .header("Authorization", &format!("Bearer {}", endpoint.pat))
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?
        .body_mut()
        .read_json::<T>()
        .map_err(|e| format!("GET {url}: decoding response: {e}"))
}
