// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayservice

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/turncred"
)

type compatibleAgents struct{}

func (compatibleAgents) CheckRelayLifecycle(context.Context, string, *gorm.DB) error { return nil }

func fixture(t *testing.T) (*Store, *relayreg.Store, *turncred.Store, Service) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	ponor, err := relayreg.NewStore(db)
	require.NoError(t, err)
	turn, err := turncred.NewStore(db)
	require.NoError(t, err)
	store, err := NewStore(db)
	require.NoError(t, err)
	store.LifecycleAgents = compatibleAgents{}
	p, err := ponor.Create(relayreg.WithAccount(context.Background(), "a"), relayreg.Entry{
		Address: "203.0.113.1:443", TLSServerName: "relay.example.com",
		IdentityKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, relayreg.IdentityKeySize)),
	})
	require.NoError(t, err)
	b, err := turn.Create(turncred.WithAccount(context.Background(), "a"), turncred.Entry{URI: "turn:other-provider.example.com:3478"})
	require.NoError(t, err)
	return store, ponor, turn, Service{ID: "primary", PonorID: p.ID, TurnID: b.ID, BackendKind: "external", BackendOperator: "Other provider"}
}

func TestExplicitAssociationSurvivesReopenWithoutChangingBackends(t *testing.T) {
	store, ponor, turn, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	// Nothing is inferred from existing backend rows.
	views, err := store.List(ctx)
	require.NoError(t, err)
	require.Empty(t, views)
	service.AccountID = "spoofed"
	created, err := store.Create(ctx, service)
	require.NoError(t, err)
	require.Equal(t, "a", created.AccountID)
	reopened, err := NewStore(store.db)
	require.NoError(t, err)
	views, err = reopened.List(ctx)
	require.NoError(t, err)
	require.Len(t, views, 1)
	require.True(t, views[0].PonorPresent)
	require.True(t, views[0].TurnPresent)
	require.Equal(t, *created, views[0].Service)
	raw, err := json.Marshal(views)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "identity_key")
	require.NotContains(t, string(raw), "AccountID")
	require.NoError(t, reopened.Delete(ctx, service.ID))
	ps, err := ponor.List(relayreg.WithAccount(context.Background(), "a"))
	require.NoError(t, err)
	require.Len(t, ps, 1)
	ts, err := turn.List(turncred.WithAccount(context.Background(), "a"))
	require.NoError(t, err)
	require.Len(t, ts, 1)
}

func TestAssociationsRequireAccountAndAccountLocalReferences(t *testing.T) {
	store, _, _, service := fixture(t)
	_, err := store.Create(context.Background(), service)
	require.ErrorIs(t, err, ErrNoAccount)
	_, err = store.List(context.Background())
	require.ErrorIs(t, err, ErrNoAccount)
	require.ErrorIs(t, store.Delete(context.Background(), service.ID), ErrNoAccount)
	_, err = store.Create(WithAccount(context.Background(), "b"), service)
	require.ErrorIs(t, err, ErrInvalid)
	_, err = store.Create(WithAccount(context.Background(), "a"), service)
	require.NoError(t, err)
	views, err := store.List(WithAccount(context.Background(), "b"))
	require.NoError(t, err)
	require.Empty(t, views)
	require.ErrorIs(t, store.Delete(WithAccount(context.Background(), "b"), service.ID), ErrNotFound)
}

func TestLegacyDeletionExposesEachMissingModeWithoutReassociation(t *testing.T) {
	store, ponor, turn, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.Create(ctx, service)
	require.NoError(t, err)
	require.NoError(t, turn.Delete(turncred.WithAccount(context.Background(), "a"), service.TurnID))
	views, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, views, 1)
	require.True(t, views[0].PonorPresent)
	require.False(t, views[0].TurnPresent)
	require.Equal(t, service.TurnID, views[0].TurnID)
	// The same backend in another account must not hide the outage.
	_, err = turn.Create(turncred.WithAccount(context.Background(), "b"), turncred.Entry{URI: "turn:other-provider.example.com:3478"})
	require.NoError(t, err)
	require.NoError(t, ponor.Delete(relayreg.WithAccount(context.Background(), "a"), service.PonorID))
	views, err = store.List(ctx)
	require.NoError(t, err)
	require.False(t, views[0].PonorPresent)
	require.False(t, views[0].TurnPresent)
}

func TestOptionalAndSharedTurnAndDuplicateService(t *testing.T) {
	store, _, _, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.Create(ctx, service)
	require.NoError(t, err)
	_, err = store.Create(ctx, service)
	require.ErrorIs(t, err, ErrExists)
	service.ID = "shared-backend"
	_, err = store.Create(ctx, service)
	require.NoError(t, err)
	service.ID, service.TurnID, service.BackendKind, service.BackendOperator = "ponor-only", "", "", ""
	_, err = store.Create(ctx, service)
	require.NoError(t, err)
	views, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, views, 3)
}

func TestInvalidAssociationNeverWrites(t *testing.T) {
	store, _, _, valid := fixture(t)
	for _, mutate := range []func(*Service){
		func(s *Service) { s.ID = "../bad" },
		func(s *Service) { s.PonorID = "missing" },
		func(s *Service) { s.TurnID = "missing" },
		func(s *Service) { s.BackendKind = "embedded" },
		func(s *Service) { s.BackendOperator = " " },
		func(s *Service) { s.TurnID = "" },
	} {
		service := valid
		mutate(&service)
		_, err := store.Create(WithAccount(context.Background(), "a"), service)
		require.ErrorIs(t, err, ErrInvalid)
	}
	views, err := store.List(WithAccount(context.Background(), "a"))
	require.NoError(t, err)
	require.Empty(t, views)
}
