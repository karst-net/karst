// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package main

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/netbirdio/netbird/management/server/types"
	nbroute "github.com/netbirdio/netbird/route"
)

// routeRegistry is the fixture's stand-in for the inherited account
// manager's route/group/policy projection — `control.NetmapHandler`'s
// `Routes` field needs a `GetNetworkMap(ctx, peerID)` implementation, and
// production's real one (distribution groups, access-control groups, HA
// gateway selection) already has its own Go tests
// (`server/management/internals/karst/control/routes_test.go` and the
// inherited `route`/`networkmap` package suites).
//
// This fixture skips all of that: every registered route is visible to
// every peer, tagged Gateway for whichever one holds it and Recipient for
// everybody else — `projectRouteOffers` does that tagging, unchanged from
// production. That is enough to drive what an `aquifer.rs` row needs to
// prove — the wire protocol, kernel-level route installation and
// forwarding, and local exit-node consent — without reimplementing group
// and ACL semantics a second time in a test fixture.
type routeRegistry struct {
	mu      sync.Mutex
	account *memoryAccount
	routes  map[string]*nbroute.Route
}

func newRouteRegistry(account *memoryAccount) *routeRegistry {
	return &routeRegistry{account: account, routes: map[string]*nbroute.Route{}}
}

// GetNetworkMap implements the interface `control.NetmapHandler.Routes` wants.
func (r *routeRegistry) GetNetworkMap(_ context.Context, _ string) (*types.NetworkMap, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*nbroute.Route, 0, len(r.routes))
	for _, rt := range r.routes {
		out = append(out, rt)
	}
	return &types.NetworkMap{Routes: out}, nil
}

// routeOfferRequest is the admin surface's create/update body.
//
// `Enabled` is a pointer so an absent field defaults to `true` — the common
// case for a `POST /routes` a test makes to advertise a route, as opposed to
// the "disable without deleting" case, which sends `"enabled": false`
// explicitly. `projectRouteOffers` already skips a disabled route entirely,
// matching production.
type routeOfferRequest struct {
	RouteID       string `json:"route_id"`
	Prefix        string `json:"prefix"`
	GatewayHandle string `json:"gateway_handle"`
	Metric        int    `json:"metric"`
	Masquerade    bool   `json:"masquerade"`
	KeepRoute     bool   `json:"keep_route"`
	Enabled       *bool  `json:"enabled"`
}

// upsert creates or replaces a route offer by ID — `POST /routes`'s "create"
// and "update" both land here, since a route offer is a value object with no
// meaningful partial-update shape a test needs.
func (r *routeRegistry) upsert(ctx context.Context, req routeOfferRequest) error {
	if req.RouteID == "" {
		return fmt.Errorf("route_id is required")
	}
	prefix, err := netip.ParsePrefix(req.Prefix)
	if err != nil {
		return fmt.Errorf("prefix: %w", err)
	}
	if _, err := r.account.GetPeerByPeerPubKey(ctx, req.GatewayHandle); err != nil {
		return fmt.Errorf("gateway_handle %q: %w", req.GatewayHandle, err)
	}
	networkType := nbroute.IPv4Network
	if prefix.Addr().Is6() {
		networkType = nbroute.IPv6Network
	}
	metric := req.Metric
	if metric == 0 {
		metric = nbroute.MinMetric
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	r.mu.Lock()
	r.routes[req.RouteID] = &nbroute.Route{
		// GetResourceID() splits on the first colon; a route_id a test
		// supplies has none, so it round-trips unchanged.
		ID:          nbroute.ID(req.RouteID),
		Network:     prefix.Masked(),
		NetworkType: networkType,
		// The handle, not `gateway.ID` — `projectRouteOffers` compares `Peer`
		// against `self`, and `self` is `node.Handle(identity)`
		// (`control/netmap.go`), which is the same string as `p.Key` for every
		// peer entry on the wire. Karst repurposes the inherited route model's
		// `Peer` field to hold that handle rather than netbird's internal peer
		// ID, and `routeRegistry` has to follow the same convention or a
		// recipient's `handles.position(...)` lookup in `bins/karstd/src/
		// config.rs` never finds the gateway it was just told about.
		Peer:       req.GatewayHandle,
		Metric:     metric,
		Masquerade: req.Masquerade,
		KeepRoute:  req.KeepRoute,
		Enabled:    enabled,
	}
	r.mu.Unlock()

	// Every registered peer, not just the gateway or a known recipient: this
	// fixture does not model distribution groups (its own doc comment above
	// explains why), so it cannot narrow who a route change actually affects
	// any more precisely than production's own group-scoped fan-out would —
	// see `memoryAccount.remove`'s identical reasoning for the same
	// broadcast-to-everyone simplification.
	r.account.notify(r.account.allPeerIDs())
	return nil
}

// delete removes a route offer entirely — `DELETE /routes?id=<route_id>`.
// Reports whether anything was there, matching `memoryAccount.remove`'s own
// convention.
func (r *routeRegistry) delete(routeID string) bool {
	r.mu.Lock()
	if _, ok := r.routes[routeID]; !ok {
		r.mu.Unlock()
		return false
	}
	delete(r.routes, routeID)
	r.mu.Unlock()

	r.account.notify(r.account.allPeerIDs())
	return true
}
