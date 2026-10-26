// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/karst/routetelemetry"
)

type gatewaySources struct {
	t      *testing.T
	routes []*route.Route
	groups []*types.Group
	err    error
}

func (s gatewaySources) ListRoutes(_ context.Context, account, user string) ([]*route.Route, error) {
	require.Equal(s.t, "account-a", account)
	require.Equal(s.t, "admin-a", user)
	return s.routes, s.err
}
func (s gatewaySources) GetAllGroups(_ context.Context, account, user string) ([]*types.Group, error) {
	require.Equal(s.t, "account-a", account)
	require.Equal(s.t, "admin-a", user)
	return s.groups, nil
}
func gatewayRequest(h *handler) *httptest.ResponseRecorder {
	r := nbcontext.SetUserAuthInRequest(httptest.NewRequest("GET", "/karst/v1/gateways?account_id=other", nil), auth.UserAuth{AccountId: "account-a", UserId: "admin-a"})
	w := httptest.NewRecorder()
	h.gateways(w, r)
	return w
}

func TestGatewayInventoryResolvesBothBehaviorsOncePerVisibleNode(t *testing.T) {
	sources := gatewaySources{t: t, groups: []*types.Group{{ID: "g1", Peers: []string{"node-a", "hidden-node"}}, {ID: "g2", Peers: []string{"node-a"}}}, routes: []*route.Route{
		{ID: "subnet", NetID: "office", NetworkType: route.IPv4Network, Network: netip.MustParsePrefix("10.0.0.0/8"), PeerGroups: []string{"g1", "g2"}, Enabled: true, Masquerade: true, Metric: 100},
		{ID: "exit", NetworkType: route.IPv4Network, Network: netip.MustParsePrefix("0.0.0.0/0"), Peer: "node-a", Enabled: true},
		{ID: "v6", NetworkType: route.IPv6Network, Network: netip.MustParsePrefix("::/0"), Peer: "node-a", Enabled: false},
		{ID: "empty-group", NetworkType: route.IPv4Network, Network: netip.MustParsePrefix("192.168.0.0/16"), PeerGroups: []string{"missing"}},
		{ID: "domain", NetworkType: route.DomainNetwork},
	}}
	h := &handler{routes: sources, peers: fakePeers{{ID: "node-a", Key: "gateway-key", Name: "Combined Gateway", Status: &peer.PeerStatus{Connected: true}}, {ID: "unused-node", Name: "unused"}}}
	w := gatewayRequest(h)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	var got gatewayInventory
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Len(t, got.Gateways, 1)
	node := got.Gateways[0]
	require.Equal(t, "gateway-key", node.NodeHandle)
	require.True(t, node.ControlConnected)
	require.Equal(t, "unreported", node.ForwardingReadiness)
	require.Len(t, node.Offers, 3, "duplicate routing-group membership must not duplicate offers")
	require.Equal(t, "default_ipv4", node.Offers[0].Kind)
	require.True(t, node.Offers[0].RequiresClientConsent)
	require.Equal(t, "subnet", node.Offers[1].Kind)
	require.False(t, node.Offers[1].RequiresClientConsent)
	require.False(t, node.Offers[2].Enabled, "disabled default configuration is retained without implying active egress")
	require.Equal(t, []string{"empty-group"}, got.UnresolvedRoutes)
	require.Equal(t, []string{"domain"}, got.UnsupportedRoutes)
	require.NotContains(t, w.Body.String(), "hidden-node")
	require.NotContains(t, w.Body.String(), "unused-node")
	var response any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	spec := loadKarstOpenAPISchemas(t)
	assertDeclaredResponseFields(t, spec, responseSchema(spec, "/gateways", "GET", "200"), response, "Gateway inventory")
}

func TestGatewayInventoryPreservesPermissionsAndFailsExplicitlyWithoutSources(t *testing.T) {
	h := &handler{routes: gatewaySources{t: t, err: status.NewPermissionDeniedError()}, peers: fakePeers{}}
	require.Equal(t, http.StatusForbidden, gatewayRequest(h).Code)
	h.routes = gatewaySources{t: t}
	h.peers = deniedAdminPeers{}
	require.Equal(t, http.StatusForbidden, gatewayRequest(h).Code)
	h.routes = fixedRoutes{}
	require.Equal(t, http.StatusPreconditionFailed, gatewayRequest(h).Code)
}

type fakeGatewayTelemetry struct {
	byRoute map[string]routetelemetry.StoredRouteBytes
	err     error
}

func (f fakeGatewayTelemetry) LatestByRoute(_ context.Context, accountID string) (map[string]routetelemetry.StoredRouteBytes, error) {
	if accountID != "account-a" {
		return nil, fmt.Errorf("unexpected account %q", accountID)
	}
	return f.byRoute, f.err
}

func (f fakeGatewayTelemetry) LatestByGateway(ctx context.Context, accountID string) (map[string]map[string]routetelemetry.StoredGatewayHealth, error) {
	rows, err := f.LatestByRoute(ctx, accountID)
	reports := map[string]routetelemetry.StoredGatewayHealth{}
	for id, row := range rows {
		reports[id] = routetelemetry.StoredGatewayHealth{ForwardingActive: row.ForwardingActive, ReadinessReported: true}
	}
	return map[string]map[string]routetelemetry.StoredGatewayHealth{"node-a": reports}, err
}

func TestGatewayInventoryJoinsForwardingReadinessByResourceIDNotRouteRow(t *testing.T) {
	// "office" and "office-2" share one resource ID ("office") but are two
	// distinct route rows (e.g. a group route expanded per candidate) --
	// the join must key off GetResourceID(), the same way nodes.go's own
	// throughput join already does, not the per-row route.ID.
	sources := gatewaySources{t: t, routes: []*route.Route{
		{ID: "office:a", NetID: "office", NetworkType: route.IPv4Network, Network: netip.MustParsePrefix("10.0.0.0/8"), Peer: "node-a", Enabled: true},
		{ID: "exit", NetworkType: route.IPv4Network, Network: netip.MustParsePrefix("0.0.0.0/0"), Peer: "node-a", Enabled: true},
		{ID: "unreported", NetworkType: route.IPv4Network, Network: netip.MustParsePrefix("172.16.0.0/12"), Peer: "node-a", Enabled: true},
	}}
	h := &handler{
		routes: sources,
		peers:  fakePeers{{ID: "node-a", Name: "Combined Gateway", Status: &peer.PeerStatus{Connected: true}}},
		routeTelemetry: fakeGatewayTelemetry{byRoute: map[string]routetelemetry.StoredRouteBytes{
			"office": {ForwardingActive: true},
			"exit":   {ForwardingActive: false},
		}},
	}
	w := gatewayRequest(h)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var got gatewayInventory
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Len(t, got.Gateways, 1)
	node := got.Gateways[0]
	require.Len(t, node.Offers, 3)
	byID := map[string]gatewayOffer{}
	for _, offer := range node.Offers {
		byID[offer.ID] = offer
	}
	require.Equal(t, "ready", byID["office:a"].ForwardingReadiness, "joined by resource ID (office), not the row ID (office:a)")
	require.Equal(t, "degraded", byID["exit"].ForwardingReadiness)
	require.Equal(t, "unreported", byID["unreported"].ForwardingReadiness)
	// Degraded-first aggregation: the node's own summary must surface the
	// problem even though another of its routes is ready.
	require.Equal(t, "degraded", node.ForwardingReadiness)

	var response any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	spec := loadKarstOpenAPISchemas(t)
	assertDeclaredResponseFields(t, spec, responseSchema(spec, "/gateways", "GET", "200"), response, "Gateway inventory")
}

func TestGatewayInventoryFailsExplicitlyWhenRouteTelemetryErrors(t *testing.T) {
	sources := gatewaySources{t: t, routes: []*route.Route{
		{ID: "office", NetID: "office", NetworkType: route.IPv4Network, Network: netip.MustParsePrefix("10.0.0.0/8"), Peer: "node-a", Enabled: true},
	}}
	h := &handler{
		routes:         sources,
		peers:          fakePeers{{ID: "node-a", Name: "Combined Gateway"}},
		routeTelemetry: fakeGatewayTelemetry{err: fmt.Errorf("route telemetry store unavailable")},
	}
	require.Equal(t, http.StatusInternalServerError, gatewayRequest(h).Code)
}

func TestGatewayInventoryUsesExistingKarstRoleGate(t *testing.T) {
	for _, role := range []types.UserRole{types.UserRoleUser, types.UserRoleScaler} {
		t.Run(string(role), func(t *testing.T) {
			h := &handler{}
			r := nbcontext.SetUserAuthInRequest(httptest.NewRequest("GET", "/karst/v1/gateways", nil), auth.UserAuth{AccountId: "account-a", UserId: "admin-a"})
			w := httptest.NewRecorder()
			karstAuthorization(scanPermissions{role: role})(http.HandlerFunc(h.gateways)).ServeHTTP(w, r)
			require.Equal(t, http.StatusForbidden, w.Code)
		})
	}
}

func TestGatewayInventoryDoesNotCopyOneCandidatesReadinessToAnother(t *testing.T) {
	sources := gatewaySources{t: t, groups: []*types.Group{{ID: "ha", Peers: []string{"node-a", "node-b"}}}, routes: []*route.Route{
		{ID: "office", NetworkType: route.IPv4Network, Network: netip.MustParsePrefix("10.0.0.0/8"), PeerGroups: []string{"ha"}, Enabled: true},
	}}
	h := &handler{routes: sources, peers: fakePeers{{ID: "node-a"}, {ID: "node-b"}}, routeTelemetry: fakeGatewayTelemetry{byRoute: map[string]routetelemetry.StoredRouteBytes{"office": {ForwardingActive: true}}}}
	w := gatewayRequest(h)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var got gatewayInventory
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Len(t, got.Gateways, 2)
	require.Equal(t, "ready", got.Gateways[0].ForwardingReadiness)
	require.Equal(t, "unreported", got.Gateways[1].ForwardingReadiness)
}

func TestDisabledGatewayOffersDoNotDegradeTheNode(t *testing.T) {
	require.Equal(t, "ready", aggregateForwardingReadiness([]gatewayOffer{
		{Enabled: true, ForwardingReadiness: "ready"},
		{Enabled: false, ForwardingReadiness: "degraded"},
	}))
	require.Equal(t, "unreported", offerForwardingReadiness(map[string]routetelemetry.StoredGatewayHealth{
		"legacy": {ForwardingActive: false},
	}, "legacy"))
}
