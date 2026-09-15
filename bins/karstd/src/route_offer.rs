// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Validated subnet and exit-route offers from the authenticated netmap.

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

/// Validate a complete offer set from the wire.
///
/// The result is hashed byte-for-byte against the server's own
/// `content_version` (`netmap.rs`'s `Netmap::content_version`, pinned by
/// `spec/vectors/karst-control-v1.json`), so this **must** preserve every
/// offer the server sent, in wire order — it validates and rejects
/// genuinely conflicting definitions, but it does not drop or reorder
/// anything else. In particular, a route advertised through a gateway
/// *group* legitimately produces one offer per group member (confirmed
/// against `getRoutesToSync`/`routesByPeer` in
/// `server/shared/management/types/networkmap_components.go`: the inherited
/// netbird network-map builder does not select a single gateway
/// server-side, the same as any other netbird HA route), and all of them
/// belong in the result. Picking *one effective* candidate to actually route
/// through is a separate, later, unauthenticated step — see
/// [`select_effective`] — precisely so it can never affect this hash.
///
/// # Errors
/// A description of the first malformed offer, or of two offers sharing a
/// `(prefix, role)` that disagree on kind, masquerade, or `keep_route` —
/// genuinely conflicting route definitions, not one HA family (plan §3.4
/// still fails closed on that ambiguity).
pub fn parse_all(wire: Vec<pb::KarstRouteOffer>, self_id: &[u8]) -> Result<Vec<Offer>, String> {
    let mut seen: std::collections::BTreeMap<(String, Role), (Kind, bool, bool)> =
        std::collections::BTreeMap::new();
    let mut offers = Vec::with_capacity(wire.len());
    for route in wire {
        let offer = Offer::from_wire(route, self_id)?;
        let key = (offer.prefix_text.clone(), offer.role);
        let fields = (offer.kind, offer.masquerade, offer.keep_route);
        if let Some(&first) = seen.get(&key) {
            if first != fields {
                return Err(format!(
                    "duplicate effective route {} with conflicting definitions",
                    offer.prefix
                ));
            }
        } else {
            seen.insert(key, fields);
        }
        offers.push(offer);
    }
    Ok(offers)
}

/// Reduce an authenticated offer set to one effective offer per
/// `(prefix, role)`, for actually building the local routing/forwarding
/// configuration from — never for hashing (see [`parse_all`]'s doc comment).
///
/// This is load-bearing beyond tidiness: `routing.rs`'s `AllowedIps::build`
/// hard-rejects two peers claiming the same prefix, by design, so handing
/// `config.rs` more than one candidate for the same prefix would only move
/// the old whole-netmap rejection one layer deeper into a config-build
/// failure. Candidates that agree on kind, masquerade, and `keep_route`
/// (already enforced by `parse_all`) are one HA family: the lowest metric
/// wins, tied by the lexicographically smallest gateway id — a pure
/// function of the candidate set, so every recipient presented with the
/// same candidates picks the same winner and no two of them can disagree
/// about who the effective gateway is.
///
/// This selection is a pure function of the current candidate set, not of
/// live reachability — it does not know whether the winning gateway's
/// session is actually established. A route stays assigned to it until the
/// server stops offering it (the route is disabled/deleted, or the gateway
/// leaves the group), not merely because that gateway's process died. There
/// is no automatic client-side failover for that case yet; see the
/// discussion on GitHub issue #109.
#[must_use]
pub fn select_effective(offers: &[Offer]) -> Vec<Offer> {
    let mut winners: std::collections::BTreeMap<(&str, Role), &Offer> =
        std::collections::BTreeMap::new();
    for offer in offers {
        winners
            .entry((offer.prefix_text.as_str(), offer.role))
            .and_modify(|best| {
                if (offer.metric, &offer.gateway_id) < (best.metric, &best.gateway_id) {
                    *best = offer;
                }
            })
            .or_insert(offer);
    }
    let mut out: Vec<Offer> = winners.into_values().cloned().collect();
    out.sort_by(|a, b| {
        a.route_id
            .cmp(&b.route_id)
            .then_with(|| a.prefix_text.cmp(&b.prefix_text))
    });
    out
}
#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]

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

    /// An exact repeated wire entry (same route, same gateway) is the
    /// degenerate case of one HA family with one member: it must dedupe to
    /// a single offer, not be treated as a conflict.
    /// `parse_all` must preserve every offer — including an exact repeat —
    /// in wire order: its output is hashed against the server's own
    /// `content_version`, so dropping or reordering anything here would
    /// desync that hash from a server that legitimately sent duplicates
    /// (a gateway *group* route sends one per member).
    #[test]
    fn parse_all_preserves_every_offer_for_hashing() {
        let route = wire(
            "10.20.0.0/16",
            pb::KarstRouteKind::Subnet,
            pb::KarstRouteRole::Recipient,
        );
        let offers = parse_all(vec![route.clone(), route], b"client").unwrap();
        assert_eq!(offers.len(), 2, "the exact wire shape must survive parsing");
    }

    /// A route advertised through a gateway *group* arrives as one offer per
    /// member, all agreeing on kind/masquerade/keep_route — the netbird-
    /// inherited HA shape (see `select_effective`'s doc comment). The lowest
    /// metric must win, and the loser must not appear in `select_effective`'s
    /// result: passing both through to `config.rs` would hand
    /// `AllowedIps::build` two peers claiming the same prefix, which it
    /// hard-rejects by design.
    #[test]
    fn ha_candidates_resolve_to_the_lowest_metric() {
        let mut low = wire(
            "10.20.0.0/16",
            pb::KarstRouteKind::Subnet,
            pb::KarstRouteRole::Recipient,
        );
        low.route_id = "route-a:gw-primary".to_owned();
        low.gateway_id = b"gw-primary".to_vec();
        low.metric = 100;
        let mut high = wire(
            "10.20.0.0/16",
            pb::KarstRouteKind::Subnet,
            pb::KarstRouteRole::Recipient,
        );
        high.route_id = "route-a:gw-standby".to_owned();
        high.gateway_id = b"gw-standby".to_vec();
        high.metric = 200;

        let parsed = parse_all(vec![high, low], b"client").unwrap();
        assert_eq!(
            parsed.len(),
            2,
            "parse_all itself must keep both candidates"
        );
        let effective = select_effective(&parsed);
        assert_eq!(
            effective.len(),
            1,
            "only the effective candidate is used for routing"
        );
        assert_eq!(effective[0].gateway_id, b"gw-primary");
    }

    /// Candidates tied on metric (the common case for a route created
    /// through one gateway *group*, where every member inherits the same
    /// route-level metric) must still resolve deterministically, and to the
    /// same winner regardless of wire order — every recipient that sees the
    /// same candidates must agree on who the effective gateway is.
    #[test]
    fn ha_candidates_tied_on_metric_resolve_by_gateway_id_and_order_independently() {
        let mut a = wire(
            "10.20.0.0/16",
            pb::KarstRouteKind::Subnet,
            pb::KarstRouteRole::Recipient,
        );
        a.route_id = "route-a:gw-a".to_owned();
        a.gateway_id = b"gw-a".to_vec();
        let mut z = wire(
            "10.20.0.0/16",
            pb::KarstRouteKind::Subnet,
            pb::KarstRouteRole::Recipient,
        );
        z.route_id = "route-a:gw-z".to_owned();
        z.gateway_id = b"gw-z".to_vec();

        for wire_order in [vec![a.clone(), z.clone()], vec![z, a]] {
            let effective = select_effective(&parse_all(wire_order, b"client").unwrap());
            assert_eq!(effective.len(), 1);
            assert_eq!(
                effective[0].gateway_id, b"gw-a",
                "the lexicographically first id must win regardless of wire order"
            );
        }
    }

    /// Two different route definitions that happen to claim the same prefix
    /// but disagree on masquerade are a real conflict, not an HA family —
    /// this must still fail closed (plan §3.4), at `parse_all` itself so the
    /// whole netmap is distrusted rather than silently picking a winner.
    #[test]
    fn conflicting_definitions_for_the_same_prefix_are_rejected() {
        let mut masqueraded = wire(
            "10.20.0.0/16",
            pb::KarstRouteKind::Subnet,
            pb::KarstRouteRole::Recipient,
        );
        masqueraded.gateway_id = b"gw-a".to_vec();
        let mut not_masqueraded = wire(
            "10.20.0.0/16",
            pb::KarstRouteKind::Subnet,
            pb::KarstRouteRole::Recipient,
        );
        not_masqueraded.gateway_id = b"gw-b".to_vec();
        not_masqueraded.masquerade = false;

        assert!(parse_all(vec![masqueraded, not_masqueraded], b"client").is_err());
    }
}
