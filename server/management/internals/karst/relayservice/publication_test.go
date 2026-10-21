// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayservice

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/turncred"
	"github.com/stretchr/testify/require"
)

func TestDeletedBackendWithdrawsOnlyItsMode(t *testing.T) {
	for _, mode := range []string{"ponor", "turn"} {
		t.Run(mode, func(t *testing.T) {
			store, ponor, turn, service := fixture(t)
			ctx := WithAccount(context.Background(), "a")
			_, err := store.Create(ctx, service)
			require.NoError(t, err)
			_, err = store.SetPublication(ctx, "services", true)
			require.NoError(t, err)
			if mode == "ponor" {
				require.NoError(t, ponor.Delete(relayreg.WithAccount(context.Background(), "a"), service.PonorID))
			} else {
				require.NoError(t, turn.Delete(turncred.WithAccount(context.Background(), "a"), service.TurnID))
			}
			active, ps, ts, err := store.Netmap(ctx)
			require.NoError(t, err)
			require.True(t, active)
			if mode == "ponor" {
				require.Empty(t, ps)
				require.Len(t, ts, 1)
			} else {
				require.Len(t, ps, 1)
				require.Empty(t, ts)
			}
			views, err := store.List(ctx)
			require.NoError(t, err)
			require.Len(t, views, 1, "retain the explicit association for diagnosis")
			require.Equal(t, mode != "ponor", views[0].PonorPresent)
			require.Equal(t, mode != "turn", views[0].TurnPresent)
		})
	}
}

func TestPublicationIsExplicitDurableAndNeverFallsBackWhenEmpty(t *testing.T) {
	store, _, _, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.Create(ctx, service)
	require.NoError(t, err)
	preview, err := store.Preview(ctx, true)
	require.NoError(t, err)
	require.Len(t, preview, 1)
	active, _, _, err := store.Netmap(ctx)
	require.NoError(t, err)
	require.False(t, active, "preview and association must not change authority")
	_, err = store.SetPublication(ctx, "services", false)
	require.ErrorIs(t, err, ErrInvalid)
	_, err = store.SetPublication(ctx, "services", true)
	require.NoError(t, err)
	reopened, err := NewStore(store.db)
	require.NoError(t, err)
	active, relays, turns, err := reopened.Netmap(ctx)
	require.NoError(t, err)
	require.True(t, active)
	require.Len(t, relays, 1)
	require.Len(t, turns, 1)
	require.Equal(t, "203.0.113.1:443", relays[0].Address)
	require.Equal(t, "turn:other-provider.example.com:3478", turns[0].URI)
	require.NoError(t, reopened.Delete(ctx, service.ID))
	active, relays, turns, err = reopened.Netmap(ctx)
	require.NoError(t, err)
	require.True(t, active)
	require.Empty(t, relays)
	require.Empty(t, turns)
	active, _, _, err = reopened.Netmap(WithAccount(context.Background(), "b"))
	require.NoError(t, err)
	require.False(t, active)
	_, err = reopened.SetPublication(ctx, "legacy", false)
	require.NoError(t, err)
	active, _, _, err = reopened.Netmap(ctx)
	require.NoError(t, err)
	require.False(t, active)
}

func TestPublicationRejectsUnknownModesMissingReferencesAndUnsupportedTurnTopology(t *testing.T) {
	store, _, turns, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.SetPublication(ctx, "automatic", true)
	require.ErrorIs(t, err, ErrInvalid)
	_, err = store.Create(ctx, service)
	require.NoError(t, err)
	second, err := turns.Create(turncred.WithAccount(context.Background(), "a"), turncred.Entry{URI: "turn:second.example.com:3478"})
	require.NoError(t, err)
	service.ID, service.TurnID = "second", second.ID
	_, err = store.Create(ctx, service)
	require.NoError(t, err, "legacy configuration can be staged before validation")
	_, err = store.Preview(ctx, true)
	require.ErrorContains(t, err, "one shared TURN backend")
	_, err = store.SetPublication(ctx, "services", true)
	require.ErrorIs(t, err, ErrInvalid)
	require.NoError(t, store.Delete(ctx, "second"))
	_, err = store.SetPublication(ctx, "services", true)
	require.NoError(t, err)
	_, err = store.Create(ctx, service)
	require.ErrorIs(t, err, ErrInvalid, "invalid active edits must roll back")
	views, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, views, 1)
	require.NoError(t, turns.Delete(turncred.WithAccount(context.Background(), "a"), views[0].TurnID))
	active, relays, publishedTurns, err := store.Netmap(ctx)
	require.True(t, active)
	require.NoError(t, err)
	require.Len(t, relays, 1, "healthy Ponor remains available")
	require.Empty(t, publishedTurns, "missing TURN cannot fall back to global configuration")
	_, err = store.Preview(ctx, true)
	require.ErrorIs(t, err, ErrInvalid, "new activation must reject missing references")
	_, err = store.SetPublication(ctx, "legacy", false)
	require.NoError(t, err, "rollback remains available with broken references")
}
