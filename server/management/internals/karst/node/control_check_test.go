// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package node_test

import (
	"context"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/stretchr/testify/require"
)

func TestControlCheckPersistsRejectionAndClearsItOnlyOnAcceptance(t *testing.T) {
	s := newStore(t)
	handle, err := s.Register(newIdentity(t).Public(), testKeys())
	require.NoError(t, err)
	observed := time.Now().UTC()
	check := node.ControlCheck{Status: "incompatible", Capability: "gateway_ingress_schema", RequiredSchema: 1, ObservedAt: &observed}
	require.NoError(t, s.RecordControlCheck(context.Background(), handle, check))
	stored, err := s.Get(handle)
	require.NoError(t, err)
	require.Equal(t, check.Status, stored.ControlCheck.Status)
	require.Equal(t, check.Capability, stored.ControlCheck.Capability)
	require.True(t, stored.ControlCheck.ObservedAt.Equal(observed))

	for _, invalid := range []node.ControlCheck{
		{Status: "accepted"},
		{Status: "unknown", ObservedAt: &observed},
		{Status: "accepted", Capability: "gateway_ingress_schema", ObservedAt: &observed},
		{Status: "incompatible", Capability: "arbitrary", RequiredSchema: 1, ObservedAt: &observed},
		{Status: "incompatible", Capability: "gateway_ingress_schema", RequiredSchema: 1, ReportedSchema: 1, ObservedAt: &observed},
	} {
		require.Error(t, s.RecordControlCheck(context.Background(), handle, invalid))
	}
	stored, err = s.Get(handle)
	require.NoError(t, err)
	require.Equal(t, "incompatible", stored.ControlCheck.Status)

	later := observed.Add(time.Minute)
	require.NoError(t, s.RecordControlCheck(context.Background(), handle, node.ControlCheck{Status: "accepted", ObservedAt: &later}))
	stored, err = s.Get(handle)
	require.NoError(t, err)
	require.Equal(t, "accepted", stored.ControlCheck.Status)
	require.Empty(t, stored.ControlCheck.Capability)
	require.Zero(t, stored.ControlCheck.RequiredSchema)
	require.Zero(t, stored.ControlCheck.ReportedSchema)
	require.True(t, stored.ControlCheck.ObservedAt.Equal(later))
	require.ErrorIs(t, s.RecordControlCheck(context.Background(), "missing", check), node.ErrUnknownNode)
}
