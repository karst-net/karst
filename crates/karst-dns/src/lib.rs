// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
// Public DNS and host-integration methods consistently return their concrete
// error type; repeating an identical `# Errors` section on each is noise that
// obscures the protocol and host-safety documentation.
#![allow(clippy::missing_errors_doc, clippy::doc_markdown)]
#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]
#![doc = "KarstDNS resolver policy, authoritative mesh zone, and split-DNS routing."]

mod split;
mod zone;

pub mod cache;
pub mod forward;
pub mod listener;
pub mod service;

pub mod message;

pub mod host;

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

pub use split::{Route, RoutingTable};
pub use zone::{MeshPeer, MeshZone, Record, RecordType, Response, ResponseKind};

/// The address exposed to host resolver integrations. It is deliberately not
/// accepted as an upstream: forwarding to it would recurse into this resolver.
pub const STUB_ADDRESS: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(100, 100, 100, 100));

/// A netmap-derived DNS configuration. Names are normalized when constructed,
/// so every lookup compares case-insensitively without depending on callers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub nameservers: Vec<SocketAddr>,
    pub search_domains: Vec<String>,
    pub routes: Vec<Route>,
    pub zone: String,
    pub magic_dns: bool,
}

impl Config {
    /// Validate configuration before it reaches a forwarding socket.
    pub fn new(
        nameservers: Vec<SocketAddr>,
        search_domains: Vec<String>,
        routes: Vec<Route>,
        zone: impl AsRef<str>,
        magic_dns: bool,
    ) -> Result<Self, Error> {
        if nameservers.iter().any(|server| server.ip() == STUB_ADDRESS) {
            return Err(Error::UpstreamLoop);
        }
        let zone = canonical_name(zone.as_ref())?;
        if zone.is_empty() {
            return Err(Error::InvalidName("mesh zone is empty".to_owned()));
        }
        let mut normalized_search = Vec::with_capacity(search_domains.len());
        for domain in search_domains {
            normalized_search.push(canonical_name(&domain)?);
        }
        let routes = RoutingTable::new(routes, &zone)?.into_routes();
        if routes
            .iter()
            .flat_map(|route| route.resolvers.iter())
            .any(|server| server.ip() == STUB_ADDRESS)
        {
            return Err(Error::UpstreamLoop);
        }
        Ok(Self {
            nameservers,
            search_domains: normalized_search,
            routes,
            zone,
            magic_dns,
        })
    }
}

/// Resolver policy independent of UDP/TCP transport. Transport hands it a
/// decoded DNS question and forwards only [`Resolution::Forward`] requests.
#[derive(Clone, Debug)]
pub struct Resolver {
    config: Config,
    zone: MeshZone,
    routes: RoutingTable,
    cache: Arc<Mutex<cache::Cache>>,
    failures: Arc<Mutex<VecDeque<String>>>,
}

impl Resolver {
    #[must_use]
    pub fn new(config: Config, peers: impl IntoIterator<Item = MeshPeer>) -> Self {
        let routes = RoutingTable::new(config.routes.clone(), &config.zone)
            .unwrap_or_else(|_| RoutingTable::empty());
        Self {
            zone: MeshZone::new(config.zone.clone(), peers),
            config,
            routes,
            cache: Arc::new(Mutex::new(cache::Cache::new(1024))),
            failures: Arc::new(Mutex::new(VecDeque::with_capacity(5))),
        }
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    pub(crate) fn cache_get(&self, key: &cache::Key) -> Option<Vec<u8>> {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
    }

    pub(crate) fn cache_insert(
        &self,
        key: cache::Key,
        response: Vec<u8>,
        ttl: std::time::Duration,
    ) {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, response, ttl);
    }

    #[must_use]
    pub fn cache_stats(&self) -> cache::Stats {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .stats()
    }

    pub(crate) fn record_failure(&self, name: &str, reason: impl std::fmt::Display) {
        let mut failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        if failures.len() == 5 {
            let _ = failures.pop_front();
        }
        failures.push_back(format!("{name}: {reason}"));
    }

    /// The five most recent forwarded lookup failures, oldest first.
    #[must_use]
    pub fn recent_failures(&self) -> Vec<String> {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    /// Resolve the policy decision for one recursive query. Mesh names are
    /// never forwarded, including unknown names, which is the DNS-leak guard.
    pub fn resolve(
        &self,
        name: &str,
        kind: RecordType,
        recursion_desired: bool,
    ) -> Result<Resolution, Error> {
        if !recursion_desired {
            return Ok(Resolution::Refused);
        }
        let name = canonical_name(name)?;
        if self.zone.contains_name(&name) || self.zone.contains_reverse_name(&name) {
            return Ok(Resolution::Authoritative(self.zone.lookup(&name, kind)));
        }
        if let Some(route) = self.routes.matching(&name) {
            return Ok(Resolution::Forward {
                resolvers: route.resolvers.clone(),
                split: true,
            });
        }
        Ok(Resolution::Forward {
            resolvers: self.config.nameservers.clone(),
            split: false,
        })
    }
}

/// The action a DNS socket takes after parsing a question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    Authoritative(Response),
    Forward {
        resolvers: Vec<SocketAddr>,
        split: bool,
    },
    Refused,
}

/// DNS configuration and normalization errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid DNS name: {0}")]
    InvalidName(String),
    #[error("a DNS upstream points at the KarstDNS stub")]
    UpstreamLoop,
    #[error("split-DNS route conflicts with the mesh zone: {0}")]
    RouteConflictsWithMesh(String),
}

/// Canonical DNS comparison form: ASCII lower-case, no trailing root dot.
pub(crate) fn canonical_name(raw: &str) -> Result<String, Error> {
    let name = raw.trim_end_matches('.');
    if name.is_empty() {
        return Ok(String::new());
    }
    if name.len() > 253 || !name.is_ascii() {
        return Err(Error::InvalidName(raw.to_owned()));
    }
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(Error::InvalidName(raw.to_owned()));
        }
    }
    Ok(name.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn config(routes: Vec<Route>) -> Config {
        Config::new(
            vec!["1.1.1.1:53".parse().expect("address")],
            vec![],
            routes,
            "aquifer.karst.",
            true,
        )
        .expect("config")
    }

    #[test]
    fn mesh_names_are_authoritative_and_case_insensitive() {
        let resolver = Resolver::new(
            config(vec![]),
            [MeshPeer::new(
                "Alpha",
                [Ipv4Addr::new(100, 64, 0, 2)],
                [Ipv6Addr::LOCALHOST],
            )],
        );
        let answer = resolver
            .resolve("ALPHA.AQUIFER.KARST.", RecordType::A, true)
            .expect("resolve");
        assert_eq!(
            answer,
            Resolution::Authoritative(Response::answer(vec![Record::A(Ipv4Addr::new(
                100, 64, 0, 2
            ))]))
        );
    }

    #[test]
    fn unknown_mesh_name_is_never_forwarded() {
        let resolver = Resolver::new(config(vec![]), []);
        assert_eq!(
            resolver
                .resolve("missing.aquifer.karst.", RecordType::A, true)
                .expect("resolve"),
            Resolution::Authoritative(Response::nxdomain())
        );
    }

    #[test]
    fn rejects_upstream_loop() {
        assert_eq!(
            Config::new(
                vec![SocketAddr::new(STUB_ADDRESS, 53)],
                vec![],
                vec![],
                "aquifer.karst",
                true
            ),
            Err(Error::UpstreamLoop)
        );
    }

    #[test]
    fn rejects_a_split_route_to_the_stub() {
        assert_eq!(
            Config::new(
                vec![],
                vec![],
                vec![Route {
                    match_domain: "internal.example".to_owned(),
                    resolvers: vec![SocketAddr::new(STUB_ADDRESS, 53)],
                }],
                "aquifer.karst",
                true
            ),
            Err(Error::UpstreamLoop)
        );
    }
}
