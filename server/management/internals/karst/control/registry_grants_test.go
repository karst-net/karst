// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/control"
	"github.com/netbirdio/netbird/shared/management/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "google.golang.org/protobuf/proto"

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

func TestScopedGatewayIngressRequiresVersionedAgentAndHashesScope(t *testing.T) {
	f := newNetmapFixture(t, 1)
	account := &types.Account{Id: "acct", Groups: map[string]*types.Group{"engineering": {ID: "engineering", Peers: []string{f.peers.byKey[f.peerH[0]].ID}}}}
	f.handler.DNS = grantAccount{account}
	f.handler.Policy = &policy.Document{Grants: []policy.Grant{{ID: "exit", Name: "Internet", SourceGroups: []string{"engineering"}, Gateway: f.selfH, Networks: []string{"0.0.0.0/0", "::/0"}, Ports: "*"}}}
	request := func(schema uint32, known uint64) (*proto.KarstNetmapResponse, error) {
		payload, err := pb.Marshal(&proto.KarstNetmapRequest{GatewayIngressSchema: schema, KnownVersion: known})
		require.NoError(t, err)
		raw, err := f.handler.Handle(context.Background(), nil, f.self.Public(), payload)
		if err != nil {
			return nil, err
		}
		response := &proto.KarstNetmapResponse{}
		require.NoError(t, pb.Unmarshal(raw, response))
		return response, nil
	}
	for _, schema := range []uint32{0, 2} {
		_, err := request(schema, 0)
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		recorded, readErr := f.handler.Nodes.Get(f.selfH)
		require.NoError(t, readErr)
		require.Equal(t, "incompatible", recorded.ControlCheck.Status)
		require.Equal(t, "gateway_ingress_schema", recorded.ControlCheck.Capability)
		require.Equal(t, uint32(1), recorded.ControlCheck.RequiredSchema)
		require.Equal(t, schema, recorded.ControlCheck.ReportedSchema)
		require.NotNil(t, recorded.ControlCheck.ObservedAt)
	}
	response, err := request(1, 0)
	require.NoError(t, err)
	require.Equal(t, uint32(1), response.GatewayIngressSchema)
	require.Len(t, response.PacketFilter, 1)
	require.Equal(t, []string{f.peerH[0]}, response.PacketFilter[0].Srcs)
	require.Equal(t, []string{"0.0.0.0/0", "::/0"}, response.PacketFilter[0].DstCidrs)
	// An old decoder ignores field 3, and therefore computes a different hash.
	legacy := pb.Clone(response).(*proto.KarstNetmapResponse)
	legacy.PacketFilter[0].DstCidrs = nil
	require.NotEqual(t, control.NetmapVersion(response), control.NetmapVersion(legacy))
	unchanged, err := request(1, response.Version)
	require.NoError(t, err)
	require.True(t, unchanged.Unchanged)
	recorded, err := f.handler.Nodes.Get(f.selfH)
	require.NoError(t, err)
	require.Equal(t, "accepted", recorded.ControlCheck.Status)
	require.Empty(t, recorded.ControlCheck.Capability)
	lastCheck := recorded.ControlCheck.ObservedAt
	// An unrelated authorization failure must not erase or refresh a check.
	delete(f.peers.accountOf, f.selfH)
	_, err = request(1, response.Version)
	require.Error(t, err)
	stillRecorded, readErr := f.handler.Nodes.Get(f.selfH)
	require.NoError(t, readErr)
	require.True(t, lastCheck.Equal(*stillRecorded.ControlCheck.ObservedAt))
	f.peers.accountOf[f.selfH] = "acct"
	_, err = request(0, response.Version)
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "known version must not bypass schema check")
	account.Groups["engineering"].Peers = nil
	revoked, err := request(1, response.Version)
	require.NoError(t, err)
	require.Empty(t, revoked.PacketFilter)
	require.False(t, revoked.Unchanged)
}
