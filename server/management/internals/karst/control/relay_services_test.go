// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/relayservice"
	"github.com/netbirdio/netbird/management/internals/karst/turncred"
	"github.com/netbirdio/netbird/shared/management/proto"
	hmac "github.com/netbirdio/netbird/shared/relay/auth/hmac"
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

func TestRelayServicePublicationPreservesWireIdentityCredentialsAndExplicitRollback(t *testing.T) {
	f := newNetmapFixture(t, 2)
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	ponor, err := relayreg.NewStore(db)
	require.NoError(t, err)
	turn, err := turncred.NewStore(db)
	require.NoError(t, err)
	services, err := relayservice.NewStore(db)
	require.NoError(t, err)
	services.LifecycleAgents = compatibleLifecycleAgents{}
	entry := relayreg.Entry{Address: "203.0.113.2:443", TLSServerName: "relay.example.com", IdentityKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, relayreg.IdentityKeySize)), Region: "eu", Location: &relayreg.Location{Lat: 40, Lon: 10, Label: "declared"}}
	p, err := ponor.Create(relayreg.WithAccount(context.Background(), "acct"), entry)
	require.NoError(t, err)
	tb, err := turn.Create(turncred.WithAccount(context.Background(), "acct"), turncred.Entry{URI: "turn:turn.example.com:3478"})
	require.NoError(t, err)
	ctx := relayservice.WithAccount(context.Background(), "acct")
	_, err = services.Create(ctx, relayservice.Service{ID: "primary", PonorID: p.ID, TurnID: tb.ID, BackendKind: "external", BackendOperator: "provider"})
	require.NoError(t, err)
	f.handler.RelayServices = services
	f.handler.Relays = []*proto.KarstRelay{{Address: "203.0.113.9:443"}}
	f.handler.TurnServers = []turncred.Entry{{URI: "turn:legacy.example.com:3478"}}
	f.handler.TurnMinter, err = turncred.NewMinter("test-secret", time.Hour)
	require.NoError(t, err)
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
	_, err = services.SetPublication(ctx, "services", true)
	require.NoError(t, err)
	managed := lifecycleRequest(legacy.Version)
	require.NotEqual(t, legacy.Version, managed.Version)
	require.Len(t, managed.Relays, 1)
	want, err := relayreg.Compile(entry)
	require.NoError(t, err)
	require.True(t, pb.Equal(want, managed.Relays[0]), "identity, region, TLS name and declared location must be preserved")
	require.Len(t, managed.TurnServers, 1)
	credential := managed.TurnServers[0]
	require.Equal(t, tb.URI, credential.Uri)
	require.NoError(t, hmac.NewTimedHMAC("test-secret", time.Hour).Validate(sha1.New, hmac.Token{Payload: credential.Username, Signature: credential.Password}))
	require.Greater(t, credential.ExpiresAt, uint64(time.Now().Unix()))
	require.NotEqual(t, "test-secret", credential.Password)
	_, err = services.SetModes(ctx, "primary", true, false, true)
	require.NoError(t, err)
	legacyPayload, err := pb.Marshal(&proto.KarstNetmapRequest{})
	require.NoError(t, err)
	_, err = f.handler.Handle(context.Background(), nil, f.self.Public(), legacyPayload)
	require.ErrorContains(t, err, "upgrade")
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	recorded, err := f.handler.Nodes.Get(node.Handle(f.self.Public()))
	require.NoError(t, err)
	require.Zero(t, recorded.RelayLifecycleSchema, "a downgrade replaces the previous declaration even when netmap is refused")
	ponorOnly := lifecycleRequest(managed.Version)
	require.Len(t, ponorOnly.Relays, 1)
	require.Empty(t, ponorOnly.TurnServers)
	require.Equal(t, managed.Version, ponorOnly.Version, "TURN is refreshed independently of the peer-content hash")
	require.True(t, ponorOnly.Unchanged)
	_, err = services.SetModes(ctx, "primary", true, true, true)
	require.NoError(t, err)
	// Removing credential configuration after activation must fail visibly,
	// not silently produce a service whose TURN mode disappeared.
	minter := f.handler.TurnMinter
	f.handler.TurnMinter = nil
	credentialCheck, err := pb.Marshal(&proto.KarstNetmapRequest{RelayLifecycleSchema: 1})
	require.NoError(t, err)
	_, err = f.handler.Handle(context.Background(), nil, f.self.Public(), credentialCheck)
	require.ErrorContains(t, err, "TURN credential minting")
	f.handler.TurnMinter = minter
	require.NoError(t, services.Delete(ctx, "primary"))
	empty := lifecycleRequest(managed.Version)
	require.NotEqual(t, managed.Version, empty.Version)
	require.Empty(t, empty.Relays)
	require.Empty(t, empty.TurnServers)
	_, err = services.SetPublication(ctx, "legacy", false)
	require.NoError(t, err)
	rollback := lifecycleRequest(empty.Version)
	require.Equal(t, "203.0.113.9:443", rollback.Relays[0].Address)
	require.Equal(t, "turn:legacy.example.com:3478", rollback.TurnServers[0].Uri)
}
