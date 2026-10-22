// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"net/http"
	"sort"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type gatewayGroupReader interface {
	GetAllGroups(context.Context, string, string) ([]*types.Group, error)
}

type gatewayOffer struct {
	ID                    string `json:"id"`
	NetworkID             string `json:"network_id"`
	Prefix                string `json:"prefix"`
	Kind                  string `json:"kind"`
	Enabled               bool   `json:"enabled"`
	Masquerade            bool   `json:"masquerade"`
	Metric                int    `json:"metric"`
	RequiresClientConsent bool   `json:"requires_client_consent"`
}

type gatewayNode struct {
	NodeID              string         `json:"node_id"`
	Name                string         `json:"name"`
	ControlConnected    bool           `json:"control_connected"`
	ForwardingReadiness string         `json:"forwarding_readiness"`
	Offers              []gatewayOffer `json:"offers"`
}

type gatewayInventory struct {
	SchemaVersion     int           `json:"schema_version"`
	Gateways          []gatewayNode `json:"gateways"`
	UnresolvedRoutes  []string      `json:"unresolved_routes"`
	UnsupportedRoutes []string      `json:"unsupported_routes"`
}

// gateways projects existing account route/group/peer records; it owns no
// second route database or consent authority. Each source enforces its own
// caller permissions. Resolve groups only against visible enrolled peers;
// never disclose an unseen peer merely because a group references it.
func (h *handler) gateways(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	groupsReader, ok := h.routes.(gatewayGroupReader)
	if !ok || h.peers == nil {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Gateway inventory sources are unavailable"), w)
		return
	}
	routes, err := h.routes.ListRoutes(r.Context(), user.AccountId, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	groups, err := groupsReader.GetAllGroups(r.Context(), user.AccountId, user.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	peers, err := h.peers.GetAdminPeers(r.Context(), user.AccountId, user.UserId, "", "")
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	nodes := make(map[string]gatewayNode)
	for _, p := range peers {
		if p == nil {
			continue
		}
		nodes[p.ID] = gatewayNode{NodeID: p.ID, Name: p.Name, ControlConnected: p.Status != nil && p.Status.Connected, ForwardingReadiness: "unreported", Offers: []gatewayOffer{}}
	}
	members := make(map[string][]string)
	for _, group := range groups {
		if group != nil {
			members[group.ID] = group.Peers
		}
	}
	result := gatewayInventory{SchemaVersion: 1, Gateways: []gatewayNode{}, UnresolvedRoutes: []string{}, UnsupportedRoutes: []string{}}
	for _, offer := range routes {
		if offer == nil {
			continue
		}
		if !offer.Network.IsValid() || len(offer.Domains) > 0 || !(offer.NetworkType == route.IPv4Network && offer.Network.Addr().Is4() || offer.NetworkType == route.IPv6Network && offer.Network.Addr().Is6()) {
			result.UnsupportedRoutes = append(result.UnsupportedRoutes, string(offer.ID))
			continue
		}
		kind := "subnet"
		if offer.Network.Bits() == 0 {
			if offer.Network.Addr().Is4() {
				kind = "default_ipv4"
			} else {
				kind = "default_ipv6"
			}
		}
		view := gatewayOffer{ID: string(offer.ID), NetworkID: string(offer.NetID), Prefix: offer.Network.Masked().String(), Kind: kind, Enabled: offer.Enabled, Masquerade: offer.Masquerade, Metric: offer.Metric, RequiresClientConsent: offer.Network.Bits() == 0}
		candidates := map[string]bool{}
		if offer.Peer != "" {
			candidates[offer.Peer] = true
		}
		for _, group := range offer.PeerGroups {
			for _, id := range members[group] {
				candidates[id] = true
			}
		}
		resolved := false
		for id := range candidates {
			if current, ok := nodes[id]; ok {
				current.Offers = append(current.Offers, view)
				nodes[id] = current
				resolved = true
			}
		}
		if !resolved {
			result.UnresolvedRoutes = append(result.UnresolvedRoutes, view.ID)
		}
	}
	for _, current := range nodes {
		if len(current.Offers) > 0 {
			sort.Slice(current.Offers, func(i, j int) bool { return current.Offers[i].ID < current.Offers[j].ID })
			result.Gateways = append(result.Gateways, current)
		}
	}
	sort.Slice(result.Gateways, func(i, j int) bool { return result.Gateways[i].NodeID < result.Gateways[j].NodeID })
	sort.Strings(result.UnresolvedRoutes)
	sort.Strings(result.UnsupportedRoutes)
	util.WriteJSONObject(r.Context(), w, result)
}
