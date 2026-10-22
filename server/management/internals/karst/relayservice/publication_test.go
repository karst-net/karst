// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayservice

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/stretchr/testify/require"
)

func TestDeletedBackendWithdrawsOnlyItsMode(t *testing.T) {
	store, ponor, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.Create(ctx, service)
	require.NoError(t, err)
	_, err = store.SetPublication(ctx, "services")
	require.NoError(t, err)
	require.NoError(t, ponor.Delete(relayreg.WithAccount(context.Background(), "a"), service.PonorID))
	active, ps, err := store.Netmap(ctx)
	require.NoError(t, err)
	require.True(t, active)
	require.Empty(t, ps)
	views, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, views, 1, "retain the explicit association for diagnosis")
	require.False(t, views[0].PonorPresent)
}

func TestPublicationIsExplicitDurableAndNeverFallsBackWhenEmpty(t *testing.T) {
	store, _, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.Create(ctx, service)
	require.NoError(t, err)
	preview, err := store.Preview(ctx)
	require.NoError(t, err)
	require.Len(t, preview, 1)
	active, _, err := store.Netmap(ctx)
	require.NoError(t, err)
	require.False(t, active, "preview and association must not change authority")
	_, err = store.SetPublication(ctx, "services")
	require.NoError(t, err)
	reopened, err := NewStore(store.db)
	require.NoError(t, err)
	active, relays, err := reopened.Netmap(ctx)
	require.NoError(t, err)
	require.True(t, active)
	require.Len(t, relays, 1)
	require.Equal(t, "203.0.113.1:443", relays[0].Address)
	require.NoError(t, reopened.Delete(ctx, service.ID))
	active, relays, err = reopened.Netmap(ctx)
	require.NoError(t, err)
	require.True(t, active)
	require.Empty(t, relays)
	active, _, err = reopened.Netmap(WithAccount(context.Background(), "b"))
	require.NoError(t, err)
	require.False(t, active)
	_, err = reopened.SetPublication(ctx, "legacy")
	require.NoError(t, err)
	active, _, err = reopened.Netmap(ctx)
	require.NoError(t, err)
	require.False(t, active)
}

func TestPublicationRejectsUnknownModesAndMissingReferences(t *testing.T) {
	store, ponor, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.SetPublication(ctx, "automatic")
	require.ErrorIs(t, err, ErrInvalid)
	_, err = store.Create(ctx, service)
	require.NoError(t, err)
	_, err = store.SetPublication(ctx, "services")
	require.NoError(t, err)
	_, err = store.Create(ctx, service)
	require.ErrorIs(t, err, ErrExists)
	require.NoError(t, ponor.Delete(relayreg.WithAccount(context.Background(), "a"), service.PonorID))
	active, relays, err := store.Netmap(ctx)
	require.True(t, active)
	require.NoError(t, err)
	require.Empty(t, relays, "missing Ponor backend cannot fall back to global configuration")
	_, err = store.Preview(ctx)
	require.ErrorIs(t, err, ErrInvalid, "new activation must reject missing references")
	_, err = store.SetPublication(ctx, "legacy")
	require.NoError(t, err, "rollback remains available with broken references")
}
