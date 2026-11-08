// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package api

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"sort"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"

	karstnode "github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/netbirdio/netbird/management/internals/karst/routetelemetry"
	karstcontract "github.com/netbirdio/netbird/shared/management/http/api/karst"
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
	// ForwardingReadiness is issue #404's Gateway readiness signal,
	// self-reported by this offer's gateway over the existing
	// authenticated control channel (karst_control.proto's
	// KarstRouteObservation.forwarding_active) and joined here by this
	// route's resource ID and authenticated node -- never inferred from
	// connectivity or traffic. "unreported": no attributable readiness
	// report (including older counter-only agents). "ready": the forward-accept rule
	// was live as of the gateway's last report. "degraded": the gateway
	// holds this offer but its last report said the rule was not live
	// (e.g. an nftables apply failure).
	ForwardingReadiness string `json:"forwarding_readiness"`
	// PinnedEgressIP is ADR-0068's operator declaration (route.Route's own
	// field, #553), carried here unchanged so the console can show it
	// alongside what this candidate actually observes.
	PinnedEgressIP string `json:"pinned_egress_ip,omitempty"`
	// ObservedEgressIP is issue #554's verification half: this candidate's
	// own self-reported outbound address toward the route, joined by
	// resource ID the same way ForwardingReadiness is. Empty when the
	// route has no PinnedEgressIP (nothing to probe for) or no report has
	// been received yet.
	ObservedEgressIP string `json:"observed_egress_ip,omitempty"`
	// EgressDrift is true only on a confident, comparable mismatch between
	// PinnedEgressIP and ObservedEgressIP -- never when either side is
	// absent or fails to parse as an address. An operator seeing this
	// false must not read it as "confirmed matching," only as "no drift
	// detected yet."
	EgressDrift bool `json:"egress_drift"`
}

type gatewayNode struct {
	ControlCheck        *karstcontract.NodeControlCheck `json:"control_check,omitempty"`
	Software            *karstcontract.NodeSoftware     `json:"software,omitempty"`
	NodeID              string                          `json:"node_id"`
	NodeHandle          string                          `json:"node_handle"`
	Name                string                          `json:"name"`
	ControlConnected    bool                            `json:"control_connected"`
	ForwardingReadiness string                          `json:"forwarding_readiness"`
	Offers              []gatewayOffer                  `json:"offers"`
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
	// Same propagate-on-error join nodes.go's own throughput telemetry
	// already uses -- a nil h.routeTelemetry (not configured at all) is
	// the "feature not enabled" case and reports unreported throughout;
	// a configured store that fails to read is a real backend error.
	var telemetry map[string]map[string]routetelemetry.StoredGatewayHealth
	if reader, ok := h.routeTelemetry.(interface {
		LatestByGateway(context.Context, string) (map[string]map[string]routetelemetry.StoredGatewayHealth, error)
	}); ok {
		telemetry, err = reader.LatestByGateway(r.Context(), user.AccountId)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	}
	nodes := make(map[string]gatewayNode)
	for _, p := range peers {
		if p == nil {
			continue
		}
		nodes[p.ID] = gatewayNode{NodeID: p.ID, NodeHandle: p.Key, Name: p.Name, ControlConnected: p.Status != nil && p.Status.Connected, Offers: []gatewayOffer{}}
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
		view := gatewayOffer{ID: string(offer.ID), NetworkID: string(offer.NetID), Prefix: offer.Network.Masked().String(), Kind: kind, Enabled: offer.Enabled, Masquerade: offer.Masquerade, Metric: offer.Metric, RequiresClientConsent: offer.Network.Bits() == 0, ForwardingReadiness: "unreported", PinnedEgressIP: offer.PinnedEgressIP}
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
				candidateView := view
				candidateView.ForwardingReadiness = offerForwardingReadiness(telemetry[id], string(offer.GetResourceID()))
				candidateView.ObservedEgressIP, candidateView.EgressDrift = offerEgressDrift(telemetry[id], string(offer.GetResourceID()), offer.PinnedEgressIP)
				current.Offers = append(current.Offers, candidateView)
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
			// Resolve software only for visible gateway candidates, through
			// the same authenticated-node record used by machine details.
			if h.nodes != nil {
				identity, readErr := h.nodes.Get(current.NodeHandle)
				if readErr != nil && !errors.Is(readErr, karstnode.ErrUnknownNode) {
					util.WriteError(r.Context(), readErr, w)
					return
				}
				if readErr == nil {
					current.Software = nodeSoftware(identity)
					current.ControlCheck = nodeControlCheck(identity)
				}
			}
			sort.Slice(current.Offers, func(i, j int) bool { return current.Offers[i].ID < current.Offers[j].ID })
			current.ForwardingReadiness = aggregateForwardingReadiness(current.Offers)
			result.Gateways = append(result.Gateways, current)
		}
	}
	sort.Slice(result.Gateways, func(i, j int) bool { return result.Gateways[i].NodeID < result.Gateways[j].NodeID })
	sort.Strings(result.UnresolvedRoutes)
	sort.Strings(result.UnsupportedRoutes)
	util.WriteJSONObject(r.Context(), w, result)
}

// offerForwardingReadiness reads one offer's readiness back from its
// gateway's latest self-report, joined by resource ID -- the same key
// nodes.go's throughput join already uses, since route_observations are
// reported per resource (one record may expand into several per-candidate
// route rows sharing it), not per route row.
func offerForwardingReadiness(telemetry map[string]routetelemetry.StoredGatewayHealth, resourceID string) string {
	report, ok := telemetry[resourceID]
	if !ok || !report.ReadinessReported {
		return "unreported"
	}
	if report.ForwardingActive {
		return "ready"
	}
	return "degraded"
}

// offerEgressDrift is issue #554's verification half of ADR-0068's
// pinned_egress_ip: compares this candidate's latest self-reported
// observed_egress_ip against the route's own declared PinnedEgressIP,
// joined by resource ID the same way offerForwardingReadiness is.
//
// Drift is reported true only for a confident, comparable mismatch --
// never merely because one side is absent. An unpinned route, a pinned
// route no report has arrived for yet, or either value failing to parse
// as an address all return "no drift detected," which is a true but
// weaker claim than "confirmed matching." Comparing parsed addresses
// rather than raw strings tolerates textual differences (leading zeros,
// IPv6 compression) that do not represent an actual mismatch.
func offerEgressDrift(telemetry map[string]routetelemetry.StoredGatewayHealth, resourceID, pinnedEgressIP string) (observed string, drift bool) {
	report, ok := telemetry[resourceID]
	if !ok {
		return "", false
	}
	observed = report.ObservedEgressIP
	if pinnedEgressIP == "" || observed == "" {
		return observed, false
	}
	pinned, err := netip.ParseAddr(pinnedEgressIP)
	if err != nil {
		return observed, false
	}
	seen, err := netip.ParseAddr(observed)
	if err != nil {
		return observed, false
	}
	return observed, pinned != seen
}

// aggregateForwardingReadiness rolls one node's offers into a single
// summary of enabled offers, degraded-first: an operator checking a node's row should
// see a problem on any of its routes before an unrelated healthy route
// masks it.
func aggregateForwardingReadiness(offers []gatewayOffer) string {
	reported := false
	for _, offer := range offers {
		if !offer.Enabled {
			continue
		}
		switch offer.ForwardingReadiness {
		case "degraded":
			return "degraded"
		case "ready":
			reported = true
		}
	}
	if reported {
		return "ready"
	}
	return "unreported"
}
