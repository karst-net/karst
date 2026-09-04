// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package main

import (
	"context"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	nbroute "github.com/netbirdio/netbird/route"
)

func TestRouteRegistryUpsertAndDelete(t *testing.T) {
	account := newMemoryAccount()
	account.register("gateway-handle", "gateway-host")
	registry := newRouteRegistry(account)
	ctx := context.Background()

	req := routeOfferRequest{
		RouteID:       "subnet-a",
		Prefix:        "10.20.0.0/16",
		GatewayHandle: "gateway-handle",
		Metric:        50,
		Masquerade:    true,
		KeepRoute:     true,
	}
	if err := registry.upsert(ctx, req); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	nm, err := registry.GetNetworkMap(ctx, "irrelevant")
	if err != nil {
		t.Fatalf("GetNetworkMap: %v", err)
	}
	if len(nm.Routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(nm.Routes))
	}
	got := nm.Routes[0]
	if string(got.GetResourceID()) != "subnet-a" {
		t.Errorf("route id = %q, want subnet-a", got.GetResourceID())
	}
	if got.Network.String() != "10.20.0.0/16" {
		t.Errorf("network = %v, want 10.20.0.0/16", got.Network)
	}
	if got.NetworkType != nbroute.IPv4Network {
		t.Errorf("network type = %v, want IPv4Network", got.NetworkType)
	}
	if got.Peer != "gateway-handle" {
		t.Errorf("peer = %q, want the gateway's handle %q", got.Peer, "gateway-handle")
	}
	if got.Metric != 50 || !got.Masquerade || !got.KeepRoute || !got.Enabled {
		t.Errorf("fields did not round-trip: %+v", got)
	}

	// An unmasked prefix is masked on the way in, matching production's own
	// projectRouteOffers, which calls Network.Masked() again but must not
	// need to.
	if err := registry.upsert(ctx, routeOfferRequest{
		RouteID: "subnet-b", Prefix: "10.30.5.0/24", GatewayHandle: "gateway-handle",
	}); err != nil {
		t.Fatalf("upsert with an unmasked prefix: %v", err)
	}
	nm, _ = registry.GetNetworkMap(ctx, "irrelevant")
	if len(nm.Routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(nm.Routes))
	}

	// Upsert replaces rather than accumulating a second entry for the same ID.
	if err := registry.upsert(ctx, routeOfferRequest{
		RouteID: "subnet-a", Prefix: "10.20.0.0/16", GatewayHandle: "gateway-handle", Metric: 99,
	}); err != nil {
		t.Fatalf("upsert (update): %v", err)
	}
	nm, _ = registry.GetNetworkMap(ctx, "irrelevant")
	if len(nm.Routes) != 2 {
		t.Fatalf("update grew the registry to %d routes, want 2", len(nm.Routes))
	}

	if !registry.delete("subnet-a") {
		t.Fatal("delete of an existing route reported false")
	}
	if registry.delete("subnet-a") {
		t.Fatal("delete of an already-deleted route reported true")
	}
	nm, _ = registry.GetNetworkMap(ctx, "irrelevant")
	if len(nm.Routes) != 1 {
		t.Fatalf("got %d routes after delete, want 1", len(nm.Routes))
	}
}

func TestRouteRegistryUpsertRejectsAnUnknownGateway(t *testing.T) {
	registry := newRouteRegistry(newMemoryAccount())
	err := registry.upsert(context.Background(), routeOfferRequest{
		RouteID: "subnet-a", Prefix: "10.20.0.0/16", GatewayHandle: "no-such-handle",
	})
	if err == nil {
		t.Fatal("upsert with an unregistered gateway handle succeeded")
	}
}

func TestRouteRegistryUpsertRejectsAMalformedPrefix(t *testing.T) {
	account := newMemoryAccount()
	account.register("gateway-handle", "gateway-host")
	registry := newRouteRegistry(account)
	err := registry.upsert(context.Background(), routeOfferRequest{
		RouteID: "subnet-a", Prefix: "not-a-prefix", GatewayHandle: "gateway-handle",
	})
	if err == nil {
		t.Fatal("upsert with a malformed prefix succeeded")
	}
}

func TestRouteRegistryEnabledFieldDefaultsTrue(t *testing.T) {
	account := newMemoryAccount()
	account.register("gateway-handle", "gateway-host")
	registry := newRouteRegistry(account)
	ctx := context.Background()

	if err := registry.upsert(ctx, routeOfferRequest{
		RouteID: "subnet-a", Prefix: "10.20.0.0/16", GatewayHandle: "gateway-handle",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	nm, _ := registry.GetNetworkMap(ctx, "irrelevant")
	if !nm.Routes[0].Enabled {
		t.Error("a route offer with no explicit enabled field was not enabled")
	}

	disabled := false
	if err := registry.upsert(ctx, routeOfferRequest{
		RouteID: "subnet-a", Prefix: "10.20.0.0/16", GatewayHandle: "gateway-handle",
		Enabled: &disabled,
	}); err != nil {
		t.Fatalf("upsert (disable): %v", err)
	}
	nm, _ = registry.GetNetworkMap(ctx, "irrelevant")
	if nm.Routes[0].Enabled {
		t.Error("an explicit \"enabled\": false did not take effect")
	}
}

// TestRouteRegistryChangesPushToEveryRegisteredPeer covers W7 item 2's "wait
// for push rather than forcing a refresh": upsert and delete must both reach
// production's real notification path
// (`network_map.PeersUpdateManager.SendNotification`, the one
// `control.Service.subscribeOnce` actually subscribes to — see
// `memoryAccount.remove`'s own doc comment on why `SendUpdate` alone is not
// enough), not just mutate the in-memory map and leave a connected node to
// find out on its next unrelated poll.
func TestRouteRegistryChangesPushToEveryRegisteredPeer(t *testing.T) {
	account := newMemoryAccount()
	gateway := account.register("gateway-handle", "gateway-host")
	recipient := account.register("recipient-handle", "recipient-host")
	updates := update_channel.NewPeersUpdateManager(nil)
	account.updates = updates
	registry := newRouteRegistry(account)
	ctx := context.Background()

	await := func(t *testing.T, ch <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not push a notification", what)
		}
	}

	gatewayCh := updates.CreateNotificationChannel(ctx, gateway.ID)
	recipientCh := updates.CreateNotificationChannel(ctx, recipient.ID)

	if err := registry.upsert(ctx, routeOfferRequest{
		RouteID: "subnet-a", Prefix: "10.20.0.0/16", GatewayHandle: "gateway-handle",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	await(t, gatewayCh, "upsert (gateway)")
	await(t, recipientCh, "upsert (recipient)")

	if !registry.delete("subnet-a") {
		t.Fatal("delete of an existing route reported false")
	}
	await(t, gatewayCh, "delete (gateway)")
	await(t, recipientCh, "delete (recipient)")
}
