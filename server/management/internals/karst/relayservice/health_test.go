// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayservice

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/turncred"
	"github.com/netbirdio/netbird/management/internals/karst/turnhealth"
	"github.com/stretchr/testify/require"
)

func TestHealthBatchBoundsConcurrentAllocationsAndStoresEveryBackend(t *testing.T) {
	store, _, turns, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	for index := range 6 {
		backend, err := turns.Create(turncred.WithAccount(context.Background(), "a"), turncred.Entry{URI: fmt.Sprintf("turn:backend-%d.example.com:3478", index)})
		require.NoError(t, err)
		service.ID, service.TurnID = fmt.Sprintf("service-%d", index), backend.ID
		_, err = store.Create(ctx, service)
		require.NoError(t, err)
	}
	minter, err := turncred.NewMinter("secret", time.Minute)
	require.NoError(t, err)
	var active, maximum, calls atomic.Int32
	err = store.CheckHealth(context.Background(), minter, func(context.Context, string, turncred.Credential) turnhealth.Result {
		current := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); current > old; old = maximum.Load() {
			if maximum.CompareAndSwap(old, current) {
				break
			}
		}
		calls.Add(1)
		time.Sleep(10 * time.Millisecond)
		return turnhealth.Result{State: "ready", ObservedAt: time.Now().UTC()}
	})
	require.NoError(t, err)
	require.EqualValues(t, 6, calls.Load())
	require.LessOrEqual(t, maximum.Load(), int32(4))
	views, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, views, 6)
	for _, view := range views {
		require.Equal(t, "ready", view.TurnHealth.State)
	}
}

func TestHealthWorkerDeduplicatesAssociationsAndSeparatesObservationFromConfiguration(t *testing.T) {
	store, _, _, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.Create(ctx, service)
	require.NoError(t, err)
	service.ID = "another"
	_, err = store.Create(ctx, service)
	require.NoError(t, err)
	views, err := store.List(ctx)
	require.NoError(t, err)
	require.Equal(t, "unknown", views[0].TurnHealth.State)
	minter, err := turncred.NewMinter("backend-secret", time.Minute)
	require.NoError(t, err)
	calls := 0
	var secret string
	err = store.CheckHealth(context.Background(), minter, func(ctx context.Context, uri string, credential turncred.Credential) turnhealth.Result {
		calls++
		secret = credential.Password
		require.Equal(t, "turn:other-provider.example.com:3478", uri)
		require.True(t, credential.ExpiresAt.After(time.Now()))
		require.NotEmpty(t, credential.Username)
		_, deadline := ctx.Deadline()
		require.True(t, deadline)
		return turnhealth.Result{State: "ready", ObservedAt: time.Now().UTC(), DurationMS: 12}
	})
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	views, err = store.List(ctx)
	require.NoError(t, err)
	require.True(t, views[0].TurnPresent)
	require.Equal(t, "ready", views[0].TurnHealth.State)
	require.EqualValues(t, 12, *views[0].TurnHealth.DurationMS)
	raw, err := json.Marshal(views)
	require.NoError(t, err)
	require.NotContains(t, string(raw), secret)
	require.NotContains(t, string(raw), "backend-secret")
	health, err := store.turnHealth(ctx, "a", service.TurnID, time.Now().Add(healthMaxAge+time.Second))
	require.NoError(t, err)
	require.Equal(t, "stale", health.State)
	require.Equal(t, "ready", health.LastResult)
	health, err = store.turnHealth(ctx, "b", service.TurnID, time.Now())
	require.NoError(t, err)
	require.Equal(t, "unknown", health.State, "identical protocol IDs do not cross account boundaries")
	// An admission failure updates only observed readiness, not the registry
	// or the operator's association or publication choice.
	err = store.CheckHealth(context.Background(), minter, func(context.Context, string, turncred.Credential) turnhealth.Result {
		return turnhealth.Result{State: "denied", ObservedAt: time.Now().UTC()}
	})
	require.NoError(t, err)
	views, err = store.List(ctx)
	require.NoError(t, err)
	require.Equal(t, "denied", views[0].TurnHealth.State)
	require.True(t, views[0].TurnPresent)
	require.True(t, views[0].PonorPresent)
	publication, err := store.Publication(ctx)
	require.NoError(t, err)
	require.Equal(t, "legacy", publication.Mode)
}

func TestHealthWithoutCredentialAuthorityNeverCallsBackend(t *testing.T) {
	store, _, _, service := fixture(t)
	ctx := WithAccount(context.Background(), "a")
	_, err := store.Create(ctx, service)
	require.NoError(t, err)
	err = store.CheckHealth(context.Background(), nil, func(context.Context, string, turncred.Credential) turnhealth.Result {
		t.Fatal("no probe without credentials")
		return turnhealth.Result{}
	})
	require.NoError(t, err)
	views, err := store.List(ctx)
	require.NoError(t, err)
	require.Equal(t, "credentials_unavailable", views[0].TurnHealth.State)
}
