// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayservice

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestModesPersistWithdrawAndRestoreWithoutReinterpretingLegacyState(t *testing.T) {
	store, _, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.Create(ctx, service)
	require.NoError(t, err)
	_, err = store.SetPublication(ctx, "services")
	require.NoError(t, err)
	_, err = store.SetModes(ctx, service.ID, true)
	require.NoError(t, err)
	reopened, err := NewStore(store.db)
	require.NoError(t, err)
	reopened.LifecycleAgents = store.LifecycleAgents
	active, ponor, err := reopened.Netmap(ctx)
	require.NoError(t, err)
	require.True(t, active)
	require.Len(t, ponor, 1)
	var persisted Publication
	require.NoError(t, store.db.Where("account_id = ?", "a").First(&persisted).Error)
	require.Equal(t, "services", persisted.Mode)
	value, err := reopened.Publication(ctx)
	require.NoError(t, err)
	require.Equal(t, "services", value.Mode)
	_, err = reopened.SetModes(ctx, service.ID, false)
	require.NoError(t, err)
	active, ponor, err = reopened.Netmap(ctx)
	require.NoError(t, err)
	require.True(t, active)
	require.Empty(t, ponor)
	var persistedAfterDisable Publication
	require.NoError(t, store.db.Where("account_id = ?", "a").First(&persistedAfterDisable).Error)
	require.Equal(t, "services-v2", persistedAfterDisable.Mode, "older service-aware readers reject the unknown schema instead of ignoring disabled flags")
	views, err := reopened.List(ctx)
	require.NoError(t, err)
	require.True(t, views[0].PonorDisabled)
	_, err = reopened.SetModes(ctx, service.ID, true)
	require.NoError(t, err)
	_, ponor, err = reopened.Netmap(ctx)
	require.NoError(t, err)
	require.Len(t, ponor, 1)
	value, err = reopened.SetPublication(ctx, "legacy")
	require.NoError(t, err)
	require.Zero(t, value.SchemaVersion, "reset flags plus explicit authority selection permits a prepared downgrade")
	_, err = reopened.SetModes(WithAccount(context.Background(), "other"), service.ID, false)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = reopened.SetModes(context.Background(), service.ID, false)
	require.ErrorIs(t, err, ErrNoAccount)
}

func TestUpgradeDefaultsPreserveExistingBackendAssociations(t *testing.T) {
	store, _, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	created, err := store.Create(ctx, service)
	require.NoError(t, err)
	require.NoError(t, store.db.Migrator().DropColumn(&Service{}, "PonorDisabled"))
	require.False(t, store.db.Migrator().HasColumn(&Service{}, "PonorDisabled"))
	upgraded, err := NewStore(store.db)
	require.NoError(t, err)
	views, err := upgraded.List(ctx)
	require.NoError(t, err)
	require.Len(t, views, 1)
	require.Equal(t, *created, views[0].Service)
	require.False(t, views[0].PonorDisabled)
}

func TestLifecycleTrackingRequiredForAllActivationPaths(t *testing.T) {
	store, _, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.Create(ctx, service)
	require.NoError(t, err)
	_, err = store.SetPublication(ctx, "services")
	require.NoError(t, err) // v1 remains additive for existing agents.
	store.LifecycleAgents = nil
	_, err = store.SetModes(ctx, service.ID, true)
	require.ErrorIs(t, err, ErrInvalid)
	views, err := store.List(ctx)
	require.NoError(t, err)
	require.False(t, views[0].PonorDisabled, "failed capability checks roll back mode changes")
	_, err = store.SetPublication(ctx, "legacy")
	require.NoError(t, err)
	_, err = store.SetModes(ctx, "primary", true)
	require.NoError(t, err, "legacy authority permits staging")
	_, err = store.SetPublication(ctx, "services")
	require.NoError(t, err)
	publication, err := store.Publication(ctx)
	require.NoError(t, err)
	require.Equal(t, "services", publication.Mode)
}
