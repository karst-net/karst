// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package rollout_test

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/rollout"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// fakeFleet is a minimal, hand-rolled fleetChecker double: no live DB
// needed to test Preview's own logic, since the counting query itself is
// already covered by node package's CheckRelayLifecycle tests.
type fakeFleet struct {
	relayBelow, gatewayBelow int64
}

func (f fakeFleet) CountRelayLifecycleBelow(_ context.Context, _ string, _ uint32, _ *gorm.DB) (int64, error) {
	return f.relayBelow, nil
}

func (f fakeFleet) CountGatewayIngressBelow(_ context.Context, _ string, _ uint32, _ *gorm.DB) (int64, error) {
	return f.gatewayBelow, nil
}

func requireSchema(v uint32) *uint32 { return &v }

func TestPreviewSkipsComponentsWithNoRequirement(t *testing.T) {
	components := []rollout.PlanComponent{{Name: rollout.ComponentControl}, {Name: rollout.ComponentConsole}}
	result, err := rollout.Preview(context.Background(), "a", components, fakeFleet{relayBelow: 5, gatewayBelow: 5})
	require.NoError(t, err)
	require.Empty(t, result, "no Requires* field set means no compatibility row at all, not a vacuously compatible one")
	require.False(t, rollout.AnyBlocking(result))
}

func TestPreviewNotBlockingWhenFleetIsCompatible(t *testing.T) {
	components := []rollout.PlanComponent{{Name: rollout.ComponentControl, RequiresRelayLifecycleSchema: requireSchema(1)}}
	result, err := rollout.Preview(context.Background(), "a", components, fakeFleet{relayBelow: 0})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.False(t, result[0].Blocking)
	require.Zero(t, result[0].IncompatiblePeerCount)
	require.Empty(t, result[0].Message)
	require.False(t, rollout.AnyBlocking(result))
}

func TestPreviewBlocksAndExplainsWhenFleetIsIncompatible(t *testing.T) {
	components := []rollout.PlanComponent{{Name: rollout.ComponentControl, RequiresRelayLifecycleSchema: requireSchema(2)}}
	result, err := rollout.Preview(context.Background(), "a", components, fakeFleet{relayBelow: 7})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.True(t, result[0].Blocking)
	require.EqualValues(t, 7, result[0].IncompatiblePeerCount)
	require.Equal(t, "relay_lifecycle_schema", result[0].Capability)
	require.EqualValues(t, 2, result[0].Required)
	require.Contains(t, result[0].Message, "7 enrolled Karst agents")
	require.Contains(t, result[0].Message, "relay_lifecycle_schema 2")
	require.True(t, rollout.AnyBlocking(result))
}

func TestPreviewCoversMultipleComponentsAndBothCapabilitiesIndependently(t *testing.T) {
	components := []rollout.PlanComponent{
		{Name: rollout.ComponentControl, RequiresRelayLifecycleSchema: requireSchema(1), RequiresGatewayIngressSchema: requireSchema(1)},
		{Name: rollout.ComponentRelayJob, RequiresRelayLifecycleSchema: requireSchema(1)},
		{Name: rollout.ComponentConsole},
	}
	result, err := rollout.Preview(context.Background(), "a", components, fakeFleet{relayBelow: 3, gatewayBelow: 0})
	require.NoError(t, err)
	require.Len(t, result, 3, "control contributes two rows, relay_job one, console none")

	byComponentAndCapability := map[string]rollout.ComponentCompatibility{}
	for _, row := range result {
		byComponentAndCapability[row.Component+"/"+row.Capability] = row
	}
	require.True(t, byComponentAndCapability[rollout.ComponentControl+"/relay_lifecycle_schema"].Blocking)
	require.False(t, byComponentAndCapability[rollout.ComponentControl+"/gateway_ingress_schema"].Blocking, "gatewayBelow is 0")
	require.True(t, byComponentAndCapability[rollout.ComponentRelayJob+"/relay_lifecycle_schema"].Blocking)
	require.True(t, rollout.AnyBlocking(result))
}

func TestPreviewRequiresAFleetChecker(t *testing.T) {
	_, err := rollout.Preview(context.Background(), "a", []rollout.PlanComponent{{Name: rollout.ComponentControl, RequiresRelayLifecycleSchema: requireSchema(1)}}, nil)
	require.Error(t, err)
}
