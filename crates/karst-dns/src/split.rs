// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

use std::net::SocketAddr;

use crate::{canonical_name, Error};

/// One split-DNS suffix and its mesh-reachable resolvers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub match_domain: String,
    pub resolvers: Vec<SocketAddr>,
}

/// Longest-suffix split-DNS routing table.
#[derive(Clone, Debug)]
pub struct RoutingTable {
    routes: Vec<Route>,
}

impl RoutingTable {
    pub fn new(routes: Vec<Route>, mesh_zone: &str) -> Result<Self, Error> {
        let mut normalized = Vec::with_capacity(routes.len());
        for mut route in routes {
            route.match_domain = canonical_name(&route.match_domain)?;
            if route.match_domain == mesh_zone
                || mesh_zone.ends_with(&format!(".{}", route.match_domain))
            {
                return Err(Error::RouteConflictsWithMesh(route.match_domain));
            }
            if !route.resolvers.is_empty() {
                normalized.push(route);
            }
        }
        normalized.sort_by(|left, right| {
            right
                .match_domain
                .len()
                .cmp(&left.match_domain.len())
                .then_with(|| left.match_domain.cmp(&right.match_domain))
        });
        Ok(Self { routes: normalized })
    }

    #[must_use]
    pub fn empty() -> Self {
        Self { routes: Vec::new() }
    }

    #[must_use]
    pub fn into_routes(self) -> Vec<Route> {
        self.routes
    }

    #[must_use]
    pub fn matching(&self, name: &str) -> Option<&Route> {
        self.routes.iter().find(|route| {
            name == route.match_domain || name.ends_with(&format!(".{}", route.match_domain))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_suffix_wins() {
        let table = RoutingTable::new(
            vec![
                Route {
                    match_domain: "internal.example".to_owned(),
                    resolvers: vec!["100.64.0.2:53".parse().expect("address")],
                },
                Route {
                    match_domain: "db.internal.example".to_owned(),
                    resolvers: vec!["100.64.0.3:53".parse().expect("address")],
                },
            ],
            "aquifer.karst",
        )
        .expect("table");
        assert_eq!(
            table
                .matching("api.db.internal.example")
                .map(|route| route.match_domain.as_str()),
            Some("db.internal.example")
        );
    }
}
