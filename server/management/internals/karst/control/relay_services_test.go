// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/relayservice"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "google.golang.org/protobuf/proto"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type compatibleLifecycleAgents struct{}

func (compatibleLifecycleAgents) CheckRelayLifecycle(context.Context, string, *gorm.DB) error {
	return nil
}

func TestRelayServicePublicationPreservesWireIdentityAndExplicitRollback(t *testing.T) {
	f := newNetmapFixture(t, 2)
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	ponor, err := relayreg.NewStore(db)
	require.NoError(t, err)
	services, err := relayservice.NewStore(db)
	require.NoError(t, err)
	services.LifecycleAgents = compatibleLifecycleAgents{}
	entry := relayreg.Entry{Address: "203.0.113.2:443", TLSServerName: "relay.example.com", IdentityKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, relayreg.IdentityKeySize)), Region: "eu", Location: &relayreg.Location{Lat: 40, Lon: 10, Label: "declared"}}
	p, err := ponor.Create(relayreg.WithAccount(context.Background(), "acct"), entry)
	require.NoError(t, err)
	ctx := relayservice.WithAccount(context.Background(), "acct")
	_, err = services.Create(ctx, relayservice.Service{ID: "primary", PonorID: p.ID})
	require.NoError(t, err)
	f.handler.RelayServices = services
	f.handler.Relays = []*proto.KarstRelay{{Address: "203.0.113.9:443"}}
	lifecycleRequest := func(known uint64) *proto.KarstNetmapResponse {
		payload, err := pb.Marshal(&proto.KarstNetmapRequest{KnownVersion: known, RelayLifecycleSchema: 1})
		require.NoError(t, err)
		raw, err := f.handler.Handle(context.Background(), nil, f.self.Public(), payload)
		require.NoError(t, err)
		response := &proto.KarstNetmapResponse{}
		require.NoError(t, pb.Unmarshal(raw, response))
		return response
	}
	legacy := lifecycleRequest(0)
	require.Equal(t, "203.0.113.9:443", legacy.Relays[0].Address)
	_, err = services.SetPublication(ctx, "services")
	require.NoError(t, err)
	managed := lifecycleRequest(legacy.Version)
	require.NotEqual(t, legacy.Version, managed.Version)
	require.Len(t, managed.Relays, 1)
	want, err := relayreg.Compile(entry)
	require.NoError(t, err)
	require.True(t, pb.Equal(want, managed.Relays[0]), "identity, region, TLS name and declared location must be preserved")
	_, err = services.SetModes(ctx, "primary", false)
	require.NoError(t, err)
	legacyPayload, err := pb.Marshal(&proto.KarstNetmapRequest{Software: &proto.KarstSoftwareIdentity{Version: "incompatible-release"}})
	require.NoError(t, err)
	_, err = f.handler.Handle(context.Background(), nil, f.self.Public(), legacyPayload)
	require.ErrorContains(t, err, "upgrade")
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	recorded, err := f.handler.Nodes.Get(node.Handle(f.self.Public()))
	require.NoError(t, err)
	require.Zero(t, recorded.RelayLifecycleSchema, "a downgrade replaces the previous declaration even when netmap is refused")
	require.Equal(t, "incompatible-release", recorded.SoftwareVersion, "software identity must be observable even when capabilities reject the netmap")
	require.NotNil(t, recorded.SoftwareObservedAt)
	require.Equal(t, "incompatible", recorded.ControlCheck.Status)
	require.Equal(t, "relay_lifecycle_schema", recorded.ControlCheck.Capability)
	require.Equal(t, uint32(1), recorded.ControlCheck.RequiredSchema)
	require.Zero(t, recorded.ControlCheck.ReportedSchema)
	require.NotNil(t, recorded.ControlCheck.ObservedAt)
	withdrawn := lifecycleRequest(managed.Version)
	recovered, err := f.handler.Nodes.Get(f.selfH)
	require.NoError(t, err)
	require.Equal(t, "accepted", recovered.ControlCheck.Status)
	require.Empty(t, recovered.ControlCheck.Capability)
	require.Zero(t, recovered.ControlCheck.RequiredSchema)
	require.Zero(t, recovered.ControlCheck.ReportedSchema)
	require.Empty(t, withdrawn.Relays)
	require.NotEqual(t, managed.Version, withdrawn.Version)
	_, err = services.SetModes(ctx, "primary", true)
	require.NoError(t, err)
	restored := lifecycleRequest(withdrawn.Version)
	require.Len(t, restored.Relays, 1)
	require.NotEqual(t, withdrawn.Version, restored.Version)
	require.NoError(t, services.Delete(ctx, "primary"))
	empty := lifecycleRequest(restored.Version)
	require.NotEqual(t, restored.Version, empty.Version)
	require.Empty(t, empty.Relays)
	_, err = services.SetPublication(ctx, "legacy")
	require.NoError(t, err)
	rollback := lifecycleRequest(empty.Version)
	require.Equal(t, "203.0.113.9:443", rollback.Relays[0].Address)
}
