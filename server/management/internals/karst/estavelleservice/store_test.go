// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package estavelleservice

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

	"github.com/netbirdio/netbird/management/internals/karst/estavellereg"
	"github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/server/types"
)

type compatibleAgents struct{}

func (compatibleAgents) CheckEstavelleLifecycle(context.Context, string, *gorm.DB) error { return nil }

func fixture(t *testing.T) (*Store, *estavellereg.Store, Service) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	ponor, err := estavellereg.NewStore(db)
	require.NoError(t, err)
	store, err := NewStore(db)
	require.NoError(t, err)
	store.LifecycleAgents = compatibleAgents{}
	p, err := ponor.Create(estavellereg.WithAccount(context.Background(), "a"), estavellereg.Entry{
		Address: "203.0.113.1:443", TLSServerName: "relay.example.com",
		IdentityKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, estavellereg.IdentityKeySize)),
	})
	require.NoError(t, err)
	return store, ponor, Service{ID: "primary", PonorID: p.ID}
}

// fixtureManaged sets up the group, live admission lease and "services"
// publication that Create now always requires, since it no longer accepts
// an unmanaged association.
func fixtureManaged(t *testing.T) (*Store, *estavellereg.Store, Service) {
	t.Helper()
	store, ponor, service := fixture(t)
	require.NoError(t, store.db.AutoMigrate(&types.Group{}, &policy.Version{}))
	require.NoError(t, store.db.Create(&types.Group{ID: "engineering", AccountID: "a", Name: "Engineering"}).Error)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.SetPublication(ctx, "services")
	require.NoError(t, err)
	require.NoError(t, store.RefreshAdmissionLease(service.PonorID))
	service.AccessManaged = true
	service.AllowedGroups = []string{"engineering"}
	return store, ponor, service
}

// legacyRow directly persists a pre-existing unmanaged association, the kind
// Create can no longer write but the store must still read, migrate and
// project correctly (grandfathered rows; see issue #530's "Open question").
func legacyRow(t *testing.T, store *Store, service Service) Service {
	t.Helper()
	service.AccountID = "a"
	service.Revision = 1
	require.NoError(t, store.db.Create(&service).Error)
	return service
}

func TestExplicitAssociationSurvivesReopenWithoutChangingBackends(t *testing.T) {
	store, ponor, service := fixtureManaged(t)
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
	require.Equal(t, *created, views[0].Service)
	raw, err := json.Marshal(views)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "identity_key")
	require.NotContains(t, string(raw), "AccountID")
	require.NoError(t, reopened.Delete(ctx, service.ID))
	ps, err := ponor.List(estavellereg.WithAccount(context.Background(), "a"))
	require.NoError(t, err)
	require.Len(t, ps, 1)
}

func TestAssociationsRequireAccountAndAccountLocalReferences(t *testing.T) {
	store, _, service := fixtureManaged(t)
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

func TestLegacyDeletionExposesMissingBackendWithoutReassociation(t *testing.T) {
	store, ponor, service := fixtureManaged(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.Create(ctx, service)
	require.NoError(t, err)
	require.NoError(t, ponor.Delete(estavellereg.WithAccount(context.Background(), "a"), service.PonorID))
	views, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, views, 1)
	require.False(t, views[0].PonorPresent)
	require.Equal(t, service.PonorID, views[0].PonorID)
}

func TestDuplicateService(t *testing.T) {
	store, _, service := fixtureManaged(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.Create(ctx, service)
	require.NoError(t, err)
	_, err = store.Create(ctx, service)
	require.ErrorIs(t, err, ErrExists)
	views, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, views, 1)
}

func TestInvalidAssociationNeverWrites(t *testing.T) {
	store, _, valid := fixtureManaged(t)
	for _, mutate := range []func(*Service){
		func(s *Service) { s.ID = "../bad" },
		func(s *Service) { s.PonorID = "missing" },
		func(s *Service) { s.AccessManaged = false },
		func(s *Service) { s.AllowedGroups = nil },
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

// TestCreateRejectsUnmanagedAssociation covers issue #530: a RelayService can
// no longer be created without access_managed and at least one allowed
// group, closing the account-wide "legacy association" bypass.
func TestCreateRejectsUnmanagedAssociation(t *testing.T) {
	store, _, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.Create(ctx, service)
	require.ErrorIs(t, err, ErrInvalid)
	views, err := store.List(ctx)
	require.NoError(t, err)
	require.Empty(t, views)
}
