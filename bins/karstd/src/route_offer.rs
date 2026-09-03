// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Validated subnet and exit-route offers from the authenticated netmap.

use std::collections::BTreeSet;

use karst_control_client::{netmap::RouteView, transport::pb};

use crate::routing::Prefix;

pub const MIN_METRIC: u32 = 1;
pub const MAX_METRIC: u32 = 9_999;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Subnet,
    Exit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Recipient,
    Gateway,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub route_id: String,
    pub prefix: Prefix,
    prefix_text: String,
    pub gateway_id: Vec<u8>,
    pub metric: u32,
    pub kind: Kind,
    pub masquerade: bool,
    pub keep_route: bool,
    pub role: Role,
}

impl Offer {
    /// Validate one authenticated wire offer for this node.
    ///
    /// # Errors
    /// A description when any identity, prefix, metric, kind, or role is invalid.
    pub fn from_wire(wire: pb::KarstRouteOffer, self_id: &[u8]) -> Result<Self, String> {
        if wire.route_id.is_empty() {
            return Err("route_id is empty".to_owned());
        }
        if wire.gateway_id.is_empty() {
            return Err(format!("route {:?} has no gateway", wire.route_id));
        }
        if !(MIN_METRIC..=MAX_METRIC).contains(&wire.metric) {
            return Err(format!(
                "route {:?} has invalid metric {}",
                wire.route_id, wire.metric
            ));
        }

        let prefix: Prefix = wire
            .prefix
            .parse()
            .map_err(|e| format!("route {:?}: {e}", wire.route_id))?;
        if prefix.to_string() != wire.prefix {
            return Err(format!("route {:?} prefix is not canonical", wire.route_id));
        }

        let kind = match pb::KarstRouteKind::try_from(wire.kind) {
            Ok(pb::KarstRouteKind::Subnet) if prefix.len() != 0 => Kind::Subnet,
            Ok(pb::KarstRouteKind::Exit) if prefix.len() == 0 => Kind::Exit,
            Ok(pb::KarstRouteKind::Subnet | pb::KarstRouteKind::Exit) => {
                return Err(format!(
                    "route {:?} kind contradicts its prefix",
                    wire.route_id
                ));
            }
            _ => return Err(format!("route {:?} has an unknown kind", wire.route_id)),
        };
        let role = match pb::KarstRouteRole::try_from(wire.role) {
            Ok(pb::KarstRouteRole::Recipient) if wire.gateway_id != self_id => Role::Recipient,
            Ok(pb::KarstRouteRole::Gateway) if wire.gateway_id == self_id => Role::Gateway,
            Ok(pb::KarstRouteRole::Recipient | pb::KarstRouteRole::Gateway) => {
                return Err(format!(
                    "route {:?} role contradicts its gateway",
                    wire.route_id
                ));
            }
            _ => return Err(format!("route {:?} has an unknown role", wire.route_id)),
        };

        Ok(Self {
            route_id: wire.route_id,
            prefix,
            prefix_text: wire.prefix,
            gateway_id: wire.gateway_id,
            metric: wire.metric,
            kind,
            masquerade: wire.masquerade,
            keep_route: wire.keep_route,
            role,
        })
    }

    #[must_use]
    pub fn to_wire(&self) -> pb::KarstRouteOffer {
        pb::KarstRouteOffer {
            route_id: self.route_id.clone(),
            prefix: self.prefix_text.clone(),
            gateway_id: self.gateway_id.clone(),
            metric: self.metric,
            kind: match self.kind {
                Kind::Subnet => pb::KarstRouteKind::Subnet as i32,
                Kind::Exit => pb::KarstRouteKind::Exit as i32,
            },
            masquerade: self.masquerade,
            keep_route: self.keep_route,
            role: match self.role {
                Role::Recipient => pb::KarstRouteRole::Recipient as i32,
                Role::Gateway => pb::KarstRouteRole::Gateway as i32,
            },
        }
    }

    #[must_use]
    pub fn view(&self) -> RouteView<'_> {
        RouteView {
            route_id: &self.route_id,
            prefix: &self.prefix_text,
            gateway_id: &self.gateway_id,
            metric: self.metric,
            kind: match self.kind {
                Kind::Subnet => 1,
                Kind::Exit => 2,
            },
            masquerade: self.masquerade,
            keep_route: self.keep_route,
            role: match self.role {
                Role::Recipient => 1,
                Role::Gateway => 2,
            },
        }
    }
}

/// Validate a complete offer set and reject duplicate route identities.
///
/// # Errors
/// A description of the first malformed offer or duplicate route identifier.
pub fn parse_all(wire: Vec<pb::KarstRouteOffer>, self_id: &[u8]) -> Result<Vec<Offer>, String> {
    let mut prefixes = BTreeSet::new();
    let mut offers = Vec::with_capacity(wire.len());
    for route in wire {
        let offer = Offer::from_wire(route, self_id)?;
        let ownership = (offer.prefix_text.clone(), offer.role);
        if !prefixes.insert(ownership) {
            return Err(format!("duplicate effective route {}", offer.prefix));
        }
        offers.push(offer);
    }
    Ok(offers)
}
#[cfg(test)]
mod tests {
    use super::*;

    fn wire(
        prefix: &str,
        kind: pb::KarstRouteKind,
        role: pb::KarstRouteRole,
    ) -> pb::KarstRouteOffer {
        pb::KarstRouteOffer {
            route_id: "route-a".to_owned(),
            prefix: prefix.to_owned(),
            gateway_id: b"gateway".to_vec(),
            metric: 100,
            kind: kind as i32,
            masquerade: true,
            keep_route: false,
            role: role as i32,
        }
    }

    #[test]
    fn accepts_canonical_subnet_and_exit_offers() {
        let subnet = Offer::from_wire(
            wire(
                "10.20.0.0/16",
                pb::KarstRouteKind::Subnet,
                pb::KarstRouteRole::Recipient,
            ),
            b"client",
        )
        .unwrap();
        assert_eq!(subnet.kind, Kind::Subnet);
        assert_eq!(subnet.role, Role::Recipient);

        let exit = Offer::from_wire(
            wire(
                "0.0.0.0/0",
                pb::KarstRouteKind::Exit,
                pb::KarstRouteRole::Recipient,
            ),
            b"client",
        )
        .unwrap();
        assert_eq!(exit.kind, Kind::Exit);
    }

    #[test]
    fn rejects_noncanonical_contradictory_and_unknown_offers() {
        for mut bad in [
            wire(
                "10.20.0.9/16",
                pb::KarstRouteKind::Subnet,
                pb::KarstRouteRole::Recipient,
            ),
            wire(
                "10.20.0.0/16",
                pb::KarstRouteKind::Exit,
                pb::KarstRouteRole::Recipient,
            ),
            wire(
                "10.20.0.0/16",
                pb::KarstRouteKind::Subnet,
                pb::KarstRouteRole::Gateway,
            ),
        ] {
            assert!(Offer::from_wire(bad.clone(), b"client").is_err());
            bad.kind = 99;
            assert!(Offer::from_wire(bad, b"client").is_err());
        }
    }

    #[test]
    fn gateway_role_requires_this_nodes_handle() {
        let gateway = wire(
            "10.20.0.0/16",
            pb::KarstRouteKind::Subnet,
            pb::KarstRouteRole::Gateway,
        );
        assert!(Offer::from_wire(gateway.clone(), b"client").is_err());
        assert_eq!(
            Offer::from_wire(gateway, b"gateway").unwrap().role,
            Role::Gateway
        );
    }

    #[test]
    fn duplicate_effective_ownership_is_rejected() {
        let route = wire(
            "10.20.0.0/16",
            pb::KarstRouteKind::Subnet,
            pb::KarstRouteRole::Recipient,
        );
        assert!(parse_all(vec![route.clone(), route], b"client").is_err());
    }
}
