// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayservice

import (
	"context"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/turncred"
	"github.com/netbirdio/netbird/management/internals/karst/turnhealth"
	"github.com/stretchr/testify/require"
)

func TestModesPersistWithdrawAndRestoreWithoutReinterpretingLegacyState(t *testing.T) {
	store, _, _, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.Create(ctx, service)
	require.NoError(t, err)
	_, err = store.SetPublication(ctx, "services", true)
	require.NoError(t, err)
	_, err = store.SetModes(ctx, service.ID, true, false, true)
	require.NoError(t, err)
	reopened, err := NewStore(store.db)
	require.NoError(t, err)
	reopened.LifecycleAgents = store.LifecycleAgents
	active, ponor, turn, err := reopened.Netmap(ctx)
	require.NoError(t, err)
	require.True(t, active)
	require.Len(t, ponor, 1)
	require.Empty(t, turn)
	var persisted Publication
	require.NoError(t, store.db.Where("account_id = ?", "a").First(&persisted).Error)
	require.Equal(t, "services-v2", persisted.Mode, "older service-aware readers reject the unknown schema instead of ignoring disabled flags")
	value, err := reopened.Publication(ctx)
	require.NoError(t, err)
	require.Equal(t, "services", value.Mode)
	require.Equal(t, 2, value.SchemaVersion)
	minter, err := turncred.NewMinter("secret", time.Minute)
	require.NoError(t, err)
	require.NoError(t, reopened.CheckHealth(context.Background(), minter, func(context.Context, string, turncred.Credential) turnhealth.Result {
		t.Fatal("disabled TURN must not be probed")
		return turnhealth.Result{}
	}))
	_, err = reopened.SetModes(ctx, service.ID, false, false, true)
	require.NoError(t, err)
	active, ponor, turn, err = reopened.Netmap(ctx)
	require.NoError(t, err)
	require.True(t, active)
	require.Empty(t, ponor)
	require.Empty(t, turn)
	_, err = reopened.SetModes(ctx, service.ID, false, true, true)
	require.ErrorContains(t, err, "Ponor bootstrap")
	views, err := reopened.List(ctx)
	require.NoError(t, err)
	require.True(t, views[0].PonorDisabled)
	require.True(t, views[0].TurnDisabled, "failed enable must roll back both states")
	_, err = reopened.SetModes(ctx, service.ID, true, true, false)
	require.ErrorContains(t, err, "credential minting")
	_, err = reopened.SetModes(ctx, service.ID, true, true, true)
	require.NoError(t, err)
	_, ponor, turn, err = reopened.Netmap(ctx)
	require.NoError(t, err)
	require.Len(t, ponor, 1)
	require.Len(t, turn, 1)
	value, err = reopened.SetPublication(ctx, "legacy", false)
	require.NoError(t, err)
	require.Zero(t, value.SchemaVersion, "reset flags plus explicit authority selection permits a prepared downgrade")
	_, err = reopened.SetModes(WithAccount(context.Background(), "other"), service.ID, false, false, true)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = reopened.SetModes(context.Background(), service.ID, false, false, true)
	require.ErrorIs(t, err, ErrNoAccount)
}

func TestSharedBackendStaysPublishedWhileAnyServiceModeIsEnabled(t *testing.T) {
	store, _, _, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.Create(ctx, service)
	require.NoError(t, err)
	service.ID = "shared"
	_, err = store.Create(ctx, service)
	require.NoError(t, err)
	_, err = store.SetPublication(ctx, "services", true)
	require.NoError(t, err)
	_, err = store.SetModes(ctx, "primary", false, false, true)
	require.NoError(t, err)
	_, ps, ts, err := store.Netmap(ctx)
	require.NoError(t, err)
	require.Len(t, ps, 1)
	require.Len(t, ts, 1)
	_, err = store.SetModes(ctx, "shared", true, false, true)
	require.NoError(t, err)
	_, ps, ts, err = store.Netmap(ctx)
	require.NoError(t, err)
	require.Len(t, ps, 1)
	require.Empty(t, ts)
}

func TestUpgradeDefaultsPreserveExistingBackendAssociations(t *testing.T) {
	store, _, _, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	created, err := store.Create(ctx, service)
	require.NoError(t, err)
	require.NoError(t, store.db.Migrator().DropColumn(&Service{}, "PonorDisabled"))
	require.NoError(t, store.db.Migrator().DropColumn(&Service{}, "TurnDisabled"))
	require.False(t, store.db.Migrator().HasColumn(&Service{}, "PonorDisabled"))
	upgraded, err := NewStore(store.db)
	require.NoError(t, err)
	views, err := upgraded.List(ctx)
	require.NoError(t, err)
	require.Len(t, views, 1)
	require.Equal(t, *created, views[0].Service)
	require.False(t, views[0].PonorDisabled)
	require.False(t, views[0].TurnDisabled)
}

func TestUnsupportedClientTransportMustBeDisabledBeforeServicePublication(t *testing.T) {
	store, _, turns, service := fixture(t)
	backend, err := turns.Create(turncred.WithAccount(context.Background(), "a"), turncred.Entry{URI: "turns:provider.example.com:5349"})
	require.NoError(t, err)
	service.TurnID = backend.ID
	ctx := WithAccount(context.Background(), "a")
	_, err = store.Create(ctx, service)
	require.NoError(t, err, "external backend can be staged and probed independently of client support")
	_, err = store.SetPublication(ctx, "services", true)
	require.ErrorContains(t, err, "supported by current agents")
	_, err = store.SetModes(ctx, service.ID, true, false, true)
	require.NoError(t, err)
	_, err = store.SetPublication(ctx, "services", true)
	require.NoError(t, err)
	_, ps, ts, err := store.Netmap(ctx)
	require.NoError(t, err)
	require.Len(t, ps, 1)
	require.Empty(t, ts)
}

func TestLifecycleTrackingRequiredForAllActivationPaths(t *testing.T) {
	store, _, _, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.Create(ctx, service)
	require.NoError(t, err)
	_, err = store.SetPublication(ctx, "services", true)
	require.NoError(t, err) // v1 remains additive for existing agents.
	store.LifecycleAgents = nil
	_, err = store.SetModes(ctx, service.ID, true, false, true)
	require.ErrorIs(t, err, ErrInvalid)
	views, err := store.List(ctx)
	require.NoError(t, err)
	require.False(t, views[0].TurnDisabled, "failed capability checks roll back mode changes")
	service.ID = "disabled"
	service.TurnDisabled = true
	_, err = store.Create(ctx, service)
	require.ErrorIs(t, err, ErrInvalid, "creation must not bypass live-mode gate")
	_, err = store.SetPublication(ctx, "legacy", true)
	require.NoError(t, err)
	_, err = store.SetModes(ctx, "primary", true, false, true)
	require.NoError(t, err, "legacy authority permits staging")
	_, err = store.SetPublication(ctx, "services", true)
	require.ErrorIs(t, err, ErrInvalid, "staged modes require capabilities on activation")
	publication, err := store.Publication(ctx)
	require.NoError(t, err)
	require.Equal(t, "legacy", publication.Mode)
}
