// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control

import (
	"net/netip"
	"testing"

	"github.com/netbirdio/netbird/management/server/types"
	nbroute "github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func effectiveRoute(id, prefix, gateway string) *nbroute.Route {
	network := netip.MustParsePrefix(prefix)
	networkType := nbroute.IPv4Network
	if network.Addr().Is6() {
		networkType = nbroute.IPv6Network
	}
	return &nbroute.Route{
		ID: nbroute.ID(id), Network: network, NetworkType: networkType, Peer: gateway,
		Metric: 100, Enabled: true, Masquerade: true,
	}
}

func TestProjectRouteOffersPreservesStableIdentityAndRole(t *testing.T) {
	route := effectiveRoute("route-a:selected-peer-id", "10.20.0.9/16", "gateway-a")
	offers, err := projectRouteOffers(&types.NetworkMap{Routes: []*nbroute.Route{route}}, "client-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(offers) != 1 {
		t.Fatalf("got %d offers, want 1", len(offers))
	}
	got := offers[0]
	if got.GetRouteId() != "route-a" || got.GetPrefix() != "10.20.0.0/16" {
		t.Fatalf("identity/prefix = %q %q", got.GetRouteId(), got.GetPrefix())
	}
	if got.GetRole() != proto.KarstRouteRole_KARST_ROUTE_ROLE_RECIPIENT {
		t.Fatalf("role = %s, want recipient", got.GetRole())
	}

	gateway, err := projectRouteOffers(&types.NetworkMap{Routes: []*nbroute.Route{route}}, "gateway-a")
	if err != nil {
		t.Fatal(err)
	}
	if gateway[0].GetRole() != proto.KarstRouteRole_KARST_ROUTE_ROLE_GATEWAY {
		t.Fatalf("gateway role = %s", gateway[0].GetRole())
	}
}

func TestProjectRouteOffersMarksDefaultsAsExitAndSorts(t *testing.T) {
	routes := []*nbroute.Route{
		effectiveRoute("z", "::/0", "gateway-v6"),
		effectiveRoute("a", "0.0.0.0/0", "gateway-v4"),
	}
	offers, err := projectRouteOffers(&types.NetworkMap{Routes: routes}, "client-a")
	if err != nil {
		t.Fatal(err)
	}
	if offers[0].GetRouteId() != "a" || offers[1].GetRouteId() != "z" {
		t.Fatalf("offers are not canonical: %q, %q", offers[0].GetRouteId(), offers[1].GetRouteId())
	}
	for _, offer := range offers {
		if offer.GetKind() != proto.KarstRouteKind_KARST_ROUTE_KIND_EXIT {
			t.Fatalf("%s kind = %s, want exit", offer.GetPrefix(), offer.GetKind())
		}
	}
}

func TestProjectRouteOffersRejectsUnsupportedOrAmbiguousRows(t *testing.T) {
	cases := map[string]*nbroute.Route{
		"domain": {
			ID: "domain", NetworkType: nbroute.DomainNetwork, Peer: "gateway",
			Metric: 100, Enabled: true,
		},
		"missing gateway": effectiveRoute("missing", "10.0.0.0/8", ""),
		"bad metric": func() *nbroute.Route {
			r := effectiveRoute("metric", "10.0.0.0/8", "gateway")
			r.Metric = 0
			return r
		}(),
	}
	for name, route := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := projectRouteOffers(&types.NetworkMap{Routes: []*nbroute.Route{route}}, "client")
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("error = %v, want InvalidArgument", err)
			}
		})
	}
}

func TestProjectRouteOffersOmitsDisabledRows(t *testing.T) {
	route := effectiveRoute("disabled", "10.0.0.0/8", "gateway")
	route.Enabled = false
	offers, err := projectRouteOffers(&types.NetworkMap{Routes: []*nbroute.Route{route}}, "client")
	if err != nil {
		t.Fatal(err)
	}
	if len(offers) != 0 {
		t.Fatalf("got %d offers for a disabled route", len(offers))
	}
}
