// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/stretchr/testify/require"
)

type grantAccount struct{ account *types.Account }

func (s grantAccount) GetAccount(context.Context, string) (*types.Account, error) {
	return s.account, nil
}

func TestNetmapRegistryGrantTracksCurrentMembership(t *testing.T) {
	f := newNetmapFixture(t, 1)
	account := &types.Account{Id: "acct", Groups: map[string]*types.Group{"engineering": {ID: "engineering", Peers: []string{f.peers.byKey[f.peerH[0]].ID}}}}
	f.handler.DNS = grantAccount{account}
	f.handler.Policy = &policy.Document{Grants: []policy.Grant{{ID: "g", Name: "Web", SourceGroups: []string{"engineering"}, TargetNodes: []string{f.selfH}, Ports: "443"}}}
	first := requestNetmap(t, f, 0)
	require.Len(t, first.PacketFilter, 1)
	require.Equal(t, []string{f.peerH[0]}, first.PacketFilter[0].Srcs)
	account.Groups["engineering"].Name = "Renamed"
	renamed := requestNetmap(t, f, 0)
	require.Equal(t, first.PacketFilter, renamed.PacketFilter)
	account.Groups["engineering"].Peers = nil
	revoked := requestNetmap(t, f, 0)
	require.Empty(t, revoked.PacketFilter)
	require.NotEqual(t, first.Version, revoked.Version)
	f.handler.DNS = nil
	require.Error(t, netmapErr(t, f))
}
