// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package rollout

import (
	"context"
	"fmt"

	"gorm.io/gorm"
)

// fleetChecker is node.Store's own CountRelayLifecycleBelow/
// CountGatewayIngressBelow, accepted as an interface so this package does
// not import node directly -- the same narrow-interface convention
// relayalloc's relayAllocationRegistry/relayAllocationGrantStore already
// use for their own cross-package dependencies.
type fleetChecker interface {
	CountRelayLifecycleBelow(ctx context.Context, account string, required uint32, tx *gorm.DB) (int64, error)
	CountGatewayIngressBelow(ctx context.Context, account string, required uint32, tx *gorm.DB) (int64, error)
}

// ComponentCompatibility is one capability's fleet-wide compatibility
// result for one plan component. Blocking is the authoritative signal;
// IncompatiblePeerCount and the message both exist only to explain it.
type ComponentCompatibility struct {
	Component             string `json:"component"`
	Capability            string `json:"capability"`
	Required              uint32 `json:"required"`
	IncompatiblePeerCount int64  `json:"incompatible_peer_count"`
	Blocking              bool   `json:"blocking"`
	Message               string `json:"message,omitempty"`
}

// Preview computes the live, uncached cross-component compatibility answer
// ADR-0066 describes: for each component that declares a required schema,
// count enrolled Karst peers in account whose persisted schema falls below
// it, using the same counting-query shape node.Store.CheckRelayLifecycle
// already uses in production (control/netmap.go), parameterized instead of
// hardcoded to 1. v1 does not infer a required schema from TargetDigest or
// TargetRelease -- there is no release-to-schema manifest anywhere in the
// release pipeline -- so a component with no Requires* field set simply
// contributes no compatibility rows at all, not a "compatible" one either:
// absence here means "this release introduces no new schema requirement
// control knows about," never a verified fact about a fleet that does not
// yet exist in the code calling this. Called fresh at Create, at Start, and
// on every read -- never cached on the Plan/PlanComponent rows -- since
// fleet state drifts between those calls.
func Preview(ctx context.Context, account string, components []PlanComponent, fleet fleetChecker) ([]ComponentCompatibility, error) {
	if fleet == nil {
		return nil, fmt.Errorf("rollout: fleet compatibility checker is not configured")
	}
	results := make([]ComponentCompatibility, 0, len(components)*2)
	for _, component := range components {
		if component.RequiresRelayLifecycleSchema != nil {
			result, err := componentCompatibility(ctx, account, component.Name, "relay_lifecycle_schema", *component.RequiresRelayLifecycleSchema, fleet.CountRelayLifecycleBelow)
			if err != nil {
				return nil, err
			}
			results = append(results, result)
		}
		if component.RequiresGatewayIngressSchema != nil {
			result, err := componentCompatibility(ctx, account, component.Name, "gateway_ingress_schema", *component.RequiresGatewayIngressSchema, fleet.CountGatewayIngressBelow)
			if err != nil {
				return nil, err
			}
			results = append(results, result)
		}
	}
	return results, nil
}

// AnyBlocking is a small helper the API layer uses to turn a Preview result
// into the single boolean Store.Start requires as stillBlocking, so the
// override check cannot silently miss a row a caller forgot to inspect.
func AnyBlocking(compatibility []ComponentCompatibility) bool {
	for _, result := range compatibility {
		if result.Blocking {
			return true
		}
	}
	return false
}

func componentCompatibility(ctx context.Context, account, component, capability string, required uint32, count func(context.Context, string, uint32, *gorm.DB) (int64, error)) (ComponentCompatibility, error) {
	incompatible, err := count(ctx, account, required, nil)
	if err != nil {
		return ComponentCompatibility{}, err
	}
	result := ComponentCompatibility{Component: component, Capability: capability, Required: required, IncompatiblePeerCount: incompatible, Blocking: incompatible > 0}
	if result.Blocking {
		result.Message = fmt.Sprintf("%d enrolled Karst agents have not reported %s %d; upgrade them and refresh their netmaps, or remove retired agents, before rolling out %s", incompatible, capability, required, component)
	}
	return result, nil
}
