// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/control"
	nbroute "github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/stretchr/testify/require"
)

// fakeRoutes is a Routes source whose NetworkMap is fixed at construction,
// so a test controls exactly which route offers a netmap request sees
// without a database -- the real NetmapHandler.Handle build/gate/hash path
// still runs on top of it.
type fakeRoutes struct{ routes []*nbroute.Route }

func (f fakeRoutes) GetNetworkMap(context.Context, string) (*types.NetworkMap, error) {
	return &types.NetworkMap{Routes: f.routes}, nil
}

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
	f.handler.Policy = &policy.Document{Grants: []policy.Grant{{ID: "exit", Name: "Internet", SourceGroups: []string{"engineering"}, Aven: f.selfH, Networks: []string{"0.0.0.0/0", "::/0"}, Ports: "*"}}}
	request := func(schema uint32, known uint64) (*proto.KarstNetmapResponse, error) {
		payload, err := pb.Marshal(&proto.KarstNetmapRequest{AvenIngressSchema: schema, KnownVersion: known})
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
		require.Equal(t, "aven_ingress_schema", recorded.ControlCheck.Capability)
		require.Equal(t, uint32(1), recorded.ControlCheck.RequiredSchema)
		require.Equal(t, schema, recorded.ControlCheck.ReportedSchema)
		require.NotNil(t, recorded.ControlCheck.ObservedAt)
	}
	response, err := request(1, 0)
	require.NoError(t, err)
	require.Equal(t, uint32(1), response.AvenIngressSchema)
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

// TestGatewayIngressSchemaPersistsUnconditionally confirms
// AvenIngressSchema is recorded on node.Identity for every netmap
// request, not only for a node whose policy happens to produce a
// destination-scoped filter rule and therefore trips the gated
// FailedPrecondition check above -- the same unconditional-persistence
// property TestRelayServicePublicationPreservesWireIdentityAndExplicitRollback
// already covers for EstavelleLifecycleSchema (ADR-0066).
func TestGatewayIngressSchemaPersistsUnconditionally(t *testing.T) {
	f := newNetmapFixture(t, 1)
	// No Policy/DNS configured at all, so compileFilter produces no
	// destination-scoped rule -- the gated check in netmap.go never runs.
	payload, err := pb.Marshal(&proto.KarstNetmapRequest{AvenIngressSchema: 1})
	require.NoError(t, err)
	_, err = f.handler.Handle(context.Background(), nil, f.self.Public(), payload)
	require.NoError(t, err)
	recorded, err := f.handler.Nodes.Get(f.selfH)
	require.NoError(t, err)
	require.Equal(t, uint32(1), recorded.AvenIngressSchema)

	// A later legacy declaration replaces the earlier one, same as
	// EstavelleLifecycleSchema's own downgrade behavior.
	payload, err = pb.Marshal(&proto.KarstNetmapRequest{AvenIngressSchema: 0})
	require.NoError(t, err)
	_, err = f.handler.Handle(context.Background(), nil, f.self.Public(), payload)
	require.NoError(t, err)
	recorded, err = f.handler.Nodes.Get(f.selfH)
	require.NoError(t, err)
	require.Zero(t, recorded.AvenIngressSchema)
}

// TestScopedDnsZoneAffinityRequiresVersionedAgentAndHashesScope is
// TestScopedGatewayIngressRequiresVersionedAgentAndHashesScope's
// dns_zone_affinity_schema counterpart (ADR-0068) -- issue #553's
// end-to-end acceptance test, exercising the real netmap build/gate/hash
// path in NetmapHandler.Handle, not just route_offer.rs/zone_route.rs's own
// client-side unit tests.
func TestScopedDnsZoneAffinityRequiresVersionedAgentAndHashesScope(t *testing.T) {
	f := newNetmapFixture(t, 1)
	f.handler.Routes = fakeRoutes{routes: []*nbroute.Route{{
		ID: "legacy", Network: netip.MustParsePrefix("10.70.0.0/16"), NetworkType: nbroute.IPv4Network,
		Peer: f.selfH, Metric: 100, Enabled: true, Masquerade: true,
		DnsZone: "legacy.example.internal", PinnedEgressIP: "203.0.113.10",
	}}}
	request := func(schema uint32, known uint64) (*proto.KarstNetmapResponse, error) {
		payload, err := pb.Marshal(&proto.KarstNetmapRequest{DnsZoneAffinitySchema: schema, KnownVersion: known})
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
		require.Equal(t, "dns_zone_affinity_schema", recorded.ControlCheck.Capability)
		require.Equal(t, uint32(1), recorded.ControlCheck.RequiredSchema)
		require.Equal(t, schema, recorded.ControlCheck.ReportedSchema)
		require.NotNil(t, recorded.ControlCheck.ObservedAt)
	}
	response, err := request(1, 0)
	require.NoError(t, err)
	require.Equal(t, uint32(1), response.DnsZoneAffinitySchema)
	require.Len(t, response.Routes, 1)
	require.Equal(t, "legacy.example.internal", response.Routes[0].GetDnsZone())
	require.Equal(t, "203.0.113.10", response.Routes[0].GetPinnedEgressIp())
	// An old decoder ignores dns_zone/pinned_egress_ip, and therefore
	// computes a different hash.
	legacy, ok := pb.Clone(response).(*proto.KarstNetmapResponse)
	require.True(t, ok)
	legacy.Routes[0].DnsZone = ""
	legacy.Routes[0].PinnedEgressIp = ""
	require.NotEqual(t, control.NetmapVersion(response), control.NetmapVersion(legacy))
	unchanged, err := request(1, response.Version)
	require.NoError(t, err)
	require.True(t, unchanged.Unchanged)
	// known version must not bypass the schema gate.
	_, err = request(0, response.Version)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// TestDnsZoneAffinitySchemaPersistsUnconditionally is
// TestGatewayIngressSchemaPersistsUnconditionally's dns_zone_affinity_schema
// counterpart: recorded on node.Identity for every netmap request, not only
// one whose routes happen to trip the gated FailedPrecondition check above.
func TestDnsZoneAffinitySchemaPersistsUnconditionally(t *testing.T) {
	f := newNetmapFixture(t, 1)
	// No Routes source configured at all, so the gated check in netmap.go
	// never runs.
	payload, err := pb.Marshal(&proto.KarstNetmapRequest{DnsZoneAffinitySchema: 1})
	require.NoError(t, err)
	_, err = f.handler.Handle(context.Background(), nil, f.self.Public(), payload)
	require.NoError(t, err)
	recorded, err := f.handler.Nodes.Get(f.selfH)
	require.NoError(t, err)
	require.Equal(t, uint32(1), recorded.DnsZoneAffinitySchema)

	// A later legacy declaration replaces the earlier one.
	payload, err = pb.Marshal(&proto.KarstNetmapRequest{DnsZoneAffinitySchema: 0})
	require.NoError(t, err)
	_, err = f.handler.Handle(context.Background(), nil, f.self.Public(), payload)
	require.NoError(t, err)
	recorded, err = f.handler.Nodes.Get(f.selfH)
	require.NoError(t, err)
	require.Zero(t, recorded.DnsZoneAffinitySchema)
}
