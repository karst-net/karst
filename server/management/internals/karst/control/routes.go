// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control

import (
	"sort"

	"github.com/netbirdio/netbird/management/server/types"
	nbroute "github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// projectRouteOffers adapts the inherited, per-peer effective route set into
// Karst's authenticated contract. The inherited network-map builder remains
// the owner of distribution, access-control, and HA selection semantics.
func projectRouteOffers(networkMap *types.NetworkMap, self string) ([]*proto.KarstRouteOffer, error) {
	if networkMap == nil {
		return nil, nil
	}
	offers := make([]*proto.KarstRouteOffer, 0, len(networkMap.Routes))
	for _, route := range networkMap.Routes {
		if route == nil || !route.Enabled {
			continue
		}
		if route.NetworkType != nbroute.IPv4Network && route.NetworkType != nbroute.IPv6Network {
			return nil, status.Errorf(codes.InvalidArgument, "route %q is not a supported CIDR route", route.ID)
		}
		prefix := route.Network.Masked()
		if !prefix.IsValid() || route.Peer == "" {
			return nil, status.Errorf(codes.InvalidArgument, "route %q has no valid prefix or gateway", route.ID)
		}
		if route.Metric < nbroute.MinMetric || route.Metric > nbroute.MaxMetric {
			return nil, status.Errorf(codes.InvalidArgument, "route %q has invalid metric %d", route.ID, route.Metric)
		}
		kind := proto.KarstRouteKind_KARST_ROUTE_KIND_SUBNET
		if prefix.Bits() == 0 {
			kind = proto.KarstRouteKind_KARST_ROUTE_KIND_EXIT
		}
		role := proto.KarstRouteRole_KARST_ROUTE_ROLE_RECIPIENT
		if route.Peer == self {
			role = proto.KarstRouteRole_KARST_ROUTE_ROLE_GATEWAY
		}
		offers = append(offers, &proto.KarstRouteOffer{
			RouteId: string(route.GetResourceID()), Prefix: prefix.String(),
			GatewayId: []byte(route.Peer), Metric: uint32(route.Metric), Kind: kind,
			Masquerade: route.Masquerade, KeepRoute: route.KeepRoute, Role: role,
		})
	}
	sort.Slice(offers, func(i, j int) bool {
		if offers[i].GetRouteId() != offers[j].GetRouteId() {
			return offers[i].GetRouteId() < offers[j].GetRouteId()
		}
		if offers[i].GetPrefix() != offers[j].GetPrefix() {
			return offers[i].GetPrefix() < offers[j].GetPrefix()
		}
		return string(offers[i].GetGatewayId()) < string(offers[j].GetGatewayId())
	})
	return offers, nil
}
