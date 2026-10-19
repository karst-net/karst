// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control

import (
	"context"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/routetelemetry"
	"github.com/netbirdio/netbird/management/server/types"
	nbroute "github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func newRouteTelemetryTestStore(t *testing.T) *routetelemetry.Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	store, err := routetelemetry.NewStore(db)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return store
}

// This node (self) is route-a's gateway, so its egress and ingress report
// must both be recorded — the same defense-in-depth role check already
// covered by the non-gateway rejection test below, exercised here on its
// accepting path.
func TestRecordRouteObservationsStoresEgressAndIngress(t *testing.T) {
	store := newRouteTelemetryTestStore(t)
	h := &NetmapHandler{RouteTelemetry: store}
	route := effectiveRoute("route-a:selected-peer-id", "10.20.0.0/16", "gateway-a")
	offers, err := projectRouteOffers(&types.NetworkMap{Routes: []*nbroute.Route{route}}, "gateway-a")
	if err != nil {
		t.Fatal(err)
	}

	reports := []*proto.KarstRouteObservation{{
		RouteId: "route-a", Bytes: 1000, Packets: 10, IngressBytes: 400, IngressPackets: 4,
	}}
	h.recordRouteObservations(context.Background(), "gateway-a", "acct-a", reports, offers)

	byRoute, err := store.LatestByRoute(context.Background(), "acct-a")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := byRoute["route-a"]
	if !ok {
		t.Fatalf("route-a not recorded in %+v", byRoute)
	}
	if got.Bytes != 1000 || got.Packets != 10 || got.IngressBytes != 400 || got.IngressPackets != 4 {
		t.Fatalf("got %+v, want bytes=1000 packets=10 ingress_bytes=400 ingress_packets=4", got)
	}
}

// self is route-a's recipient, not its gateway — the report must be
// rejected outright, egress and ingress alike, rather than partially
// recorded, or a node could pollute another gateway's NOC-visible
// throughput for a route it never actually forwarded.
func TestRecordRouteObservationsRejectsNonGatewayReportsEvenWithIngress(t *testing.T) {
	store := newRouteTelemetryTestStore(t)
	h := &NetmapHandler{RouteTelemetry: store}
	route := effectiveRoute("route-a:selected-peer-id", "10.20.0.0/16", "gateway-a")
	offers, err := projectRouteOffers(&types.NetworkMap{Routes: []*nbroute.Route{route}}, "not-the-gateway")
	if err != nil {
		t.Fatal(err)
	}

	reports := []*proto.KarstRouteObservation{{
		RouteId: "route-a", Bytes: 1000, Packets: 10, IngressBytes: 400, IngressPackets: 4,
	}}
	h.recordRouteObservations(context.Background(), "not-the-gateway", "acct-a", reports, offers)

	byRoute, err := store.LatestByRoute(context.Background(), "acct-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(byRoute) != 0 {
		t.Fatalf("got %+v, want nothing recorded for a non-gateway report", byRoute)
	}
}
