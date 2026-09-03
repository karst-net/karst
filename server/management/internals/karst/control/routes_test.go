// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control

import (
	"testing"

	"github.com/netbirdio/netbird/shared/management/proto"
)

func routeOffer() *proto.KarstRouteOffer {
	return &proto.KarstRouteOffer{
		RouteId:    "corp-lan",
		Prefix:     "10.20.0.0/16",
		GatewayId:  []byte("gateway-a"),
		Metric:     100,
		Kind:       proto.KarstRouteKind_KARST_ROUTE_KIND_SUBNET,
		Masquerade: true,
		Role:       proto.KarstRouteRole_KARST_ROUTE_ROLE_RECIPIENT,
	}
}

// A route is effective network-map content, not presentation metadata. If it
// were absent from the version hash, adding or withdrawing it could receive an
// "unchanged" response forever.
func TestNetmapVersionCoversRouteOffers(t *testing.T) {
	without := NetmapVersion(&proto.KarstNetmapResponse{})
	with := NetmapVersion(&proto.KarstNetmapResponse{
		Routes: []*proto.KarstRouteOffer{routeOffer()},
	})
	if with == without {
		t.Fatal("adding a route offer did not move the netmap version")
	}
}

// Every field controls routing or forwarding behavior and must therefore move
// the version independently. This also pins the bool and enum encodings.
func TestNetmapVersionCoversEveryRouteOfferField(t *testing.T) {
	base := routeOffer()
	version := NetmapVersion(&proto.KarstNetmapResponse{
		Routes: []*proto.KarstRouteOffer{base},
	})
	cases := map[string]func(*proto.KarstRouteOffer){
		"route id":   func(r *proto.KarstRouteOffer) { r.RouteId = "other" },
		"prefix":     func(r *proto.KarstRouteOffer) { r.Prefix = "10.30.0.0/16" },
		"gateway":    func(r *proto.KarstRouteOffer) { r.GatewayId = []byte("gateway-b") },
		"metric":     func(r *proto.KarstRouteOffer) { r.Metric++ },
		"kind":       func(r *proto.KarstRouteOffer) { r.Kind = proto.KarstRouteKind_KARST_ROUTE_KIND_EXIT },
		"masquerade": func(r *proto.KarstRouteOffer) { r.Masquerade = false },
		"keep route": func(r *proto.KarstRouteOffer) { r.KeepRoute = true },
		"role":       func(r *proto.KarstRouteOffer) { r.Role = proto.KarstRouteRole_KARST_ROUTE_ROLE_GATEWAY },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			changed := *base
			changed.GatewayId = append([]byte(nil), base.GatewayId...)
			change(&changed)
			got := NetmapVersion(&proto.KarstNetmapResponse{
				Routes: []*proto.KarstRouteOffer{&changed},
			})
			if got == version {
				t.Fatalf("changing %s did not move the netmap version", name)
			}
		})
	}
}
