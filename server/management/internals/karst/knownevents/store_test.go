// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package knownevents_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/knownevents"
)

func newStore(t *testing.T) *knownevents.Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:knownevents-store-%s?mode=memory&cache=shared", t.Name())), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	store, err := knownevents.NewStore(db)
	require.NoError(t, err)
	return store
}

func TestCreateAndListRoundTrip(t *testing.T) {
	store := newStore(t)
	ctx := knownevents.WithAccount(context.Background(), "account-a")
	starts := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	ends := time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC)

	created, err := store.Create(ctx, knownevents.Entry{Label: "Company all-hands", StartsAt: starts, EndsAt: ends})
	require.NoError(t, err)
	require.Equal(t, "Company all-hands", created.Label)
	require.True(t, created.StartsAt.Equal(starts))
	require.True(t, created.EndsAt.Equal(ends))
	require.NotEmpty(t, created.ID)

	list, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, created.ID, list[0].ID)
}

func TestCreateRefusesAnEmptyLabel(t *testing.T) {
	store := newStore(t)
	ctx := knownevents.WithAccount(context.Background(), "account-a")
	_, err := store.Create(ctx, knownevents.Entry{
		Label:    "   ",
		StartsAt: time.Now(),
		EndsAt:   time.Now().Add(time.Hour),
	})
	require.Error(t, err)
}

func TestCreateRefusesEndsAtNotAfterStartsAt(t *testing.T) {
	store := newStore(t)
	ctx := knownevents.WithAccount(context.Background(), "account-a")
	now := time.Now()
	_, err := store.Create(ctx, knownevents.Entry{Label: "bad", StartsAt: now, EndsAt: now})
	require.Error(t, err)
	_, err = store.Create(ctx, knownevents.Entry{Label: "bad", StartsAt: now, EndsAt: now.Add(-time.Hour)})
	require.Error(t, err)
}

func TestTwoEventsMayLegitimatelyShareALabel(t *testing.T) {
	store := newStore(t)
	ctx := knownevents.WithAccount(context.Background(), "account-a")
	a, err := store.Create(ctx, knownevents.Entry{
		Label: "Quarterly all-hands", StartsAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), EndsAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	})
	require.NoError(t, err)
	b, err := store.Create(ctx, knownevents.Entry{
		Label: "Quarterly all-hands", StartsAt: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), EndsAt: time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC),
	})
	require.NoError(t, err)
	require.NotEqual(t, a.ID, b.ID)

	list, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 2)
}

func TestListKeepsDifferentAccountsSeparate(t *testing.T) {
	store := newStore(t)
	a := knownevents.WithAccount(context.Background(), "account-a")
	b := knownevents.WithAccount(context.Background(), "account-b")
	_, err := store.Create(a, knownevents.Entry{Label: "a's event", StartsAt: time.Now(), EndsAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)

	listA, err := store.List(a)
	require.NoError(t, err)
	require.Len(t, listA, 1)

	listB, err := store.List(b)
	require.NoError(t, err)
	require.Empty(t, listB)
}

func TestDeleteRemovesOnlyTheNamedEventInItsOwnAccount(t *testing.T) {
	store := newStore(t)
	a := knownevents.WithAccount(context.Background(), "account-a")
	created, err := store.Create(a, knownevents.Entry{Label: "to delete", StartsAt: time.Now(), EndsAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)

	b := knownevents.WithAccount(context.Background(), "account-b")
	err = store.Delete(b, created.ID)
	require.ErrorIs(t, err, knownevents.ErrNotFound, "a different account must not be able to delete it")

	err = store.Delete(a, created.ID)
	require.NoError(t, err)

	list, err := store.List(a)
	require.NoError(t, err)
	require.Empty(t, list)
}

func TestDeleteOfAnUnknownIDIsNotFound(t *testing.T) {
	store := newStore(t)
	ctx := knownevents.WithAccount(context.Background(), "account-a")
	err := store.Delete(ctx, "nope")
	require.ErrorIs(t, err, knownevents.ErrNotFound)
}
