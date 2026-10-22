// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"encoding/json"
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
	h := &handler{routes: sources, peers: fakePeers{{ID: "node-a", Name: "Combined Gateway", Status: &peer.PeerStatus{Connected: true}}, {ID: "unused-node", Name: "unused"}}}
	w := gatewayRequest(h)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	var got gatewayInventory
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Len(t, got.Gateways, 1)
	node := got.Gateways[0]
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
