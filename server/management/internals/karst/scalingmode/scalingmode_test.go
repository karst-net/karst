// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package scalingmode_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/scalingmode"
)

func newStore(t *testing.T) *scalingmode.Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:scalingmode-store-%s?mode=memory&cache=shared", t.Name())), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	store, err := scalingmode.NewStore(db)
	require.NoError(t, err)
	return store
}

// TestNoSetMeansAutomated is the default-when-no-row guarantee: every
// deployment running karst-scaler drive today gets Phase 2's
// unconditional reconcile with no setting at all, so an un-set store
// must answer "automated," not an empty/zero mode a caller would have
// to specially handle.
func TestNoSetMeansAutomated(t *testing.T) {
	store := newStore(t)
	mode, err := store.Mode(context.Background())
	require.NoError(t, err)
	require.Equal(t, scalingmode.ModeAutomated, mode)
}

func TestSetThenGetRoundTrips(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.SetMode(ctx, scalingmode.ModeManual))

	mode, err := store.Mode(ctx)
	require.NoError(t, err)
	require.Equal(t, scalingmode.ModeManual, mode)
}

func TestSetOverwritesThePreviousMode(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.SetMode(ctx, scalingmode.ModeManual))
	require.NoError(t, store.SetMode(ctx, scalingmode.ModeAutomated))

	mode, err := store.Mode(ctx)
	require.NoError(t, err)
	require.Equal(t, scalingmode.ModeAutomated, mode)
}

// A set is an upsert against the fixed singleton row, not an insert —
// setting the same mode twice must not create a second row or error on
// a unique-constraint violation.
func TestSettingTheSameModeTwiceIsIdempotent(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.SetMode(ctx, scalingmode.ModeManual))
	require.NoError(t, store.SetMode(ctx, scalingmode.ModeManual))

	mode, err := store.Mode(ctx)
	require.NoError(t, err)
	require.Equal(t, scalingmode.ModeManual, mode)
}
