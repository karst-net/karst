// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package ephemeralanchor_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/karst/ephemeralanchor"
)

func newStore(t *testing.T) *ephemeralanchor.Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:ephemeralanchor-store-%s?mode=memory&cache=shared", t.Name())), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	store, err := ephemeralanchor.NewStore(db)
	require.NoError(t, err)
	return store
}

// TestNoReconcileMeansNoAnchorsAndNoSchedule is the Go-side proof of the
// empty-table guarantee: an un-Reconciled store has nothing for either
// karstd's probe pass or bins/karst-anchor-scheduler to act on.
func TestNoReconcileMeansNoAnchorsAndNoSchedule(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	anchors, err := store.Anchors(ctx)
	require.NoError(t, err)
	require.Empty(t, anchors)

	windowPeriod, dutyCycle, err := store.Schedule(ctx)
	require.NoError(t, err)
	require.Zero(t, windowPeriod)
	require.Zero(t, dutyCycle)
}

func TestReconcileAddsListedAnchorsAndSetsSchedule(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.Reconcile(ctx, ephemeralanchor.Document{
		Anchors: []ephemeralanchor.AnchorEntry{
			{Label: "aws:us-west-2-den-1a", Region: "us-west-2", InstanceID: "i-0123456789abcdef0", Address: "10.0.0.1", Port: 22},
		},
		WindowPeriodSeconds: 900,
		DutyCycleSeconds:    300,
	}))

	anchors, err := store.Anchors(ctx)
	require.NoError(t, err)
	require.Equal(t, []ephemeralanchor.AnchorEntry{
		{Label: "aws:us-west-2-den-1a", Region: "us-west-2", InstanceID: "i-0123456789abcdef0", Address: "10.0.0.1", Port: 22},
	}, anchors)

	windowPeriod, dutyCycle, err := store.Schedule(ctx)
	require.NoError(t, err)
	require.Equal(t, uint32(900), windowPeriod)
	require.Equal(t, uint32(300), dutyCycle)
}

func TestReconcileIsDeclarativeNotAdditive(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.Reconcile(ctx, ephemeralanchor.Document{
		Anchors: []ephemeralanchor.AnchorEntry{
			{Label: "a", Address: "10.0.0.1", InstanceID: "i-a"},
			{Label: "b", Address: "10.0.0.2", InstanceID: "i-b"},
		},
		WindowPeriodSeconds: 900,
		DutyCycleSeconds:    300,
	}))
	require.NoError(t, store.Reconcile(ctx, ephemeralanchor.Document{
		Anchors: []ephemeralanchor.AnchorEntry{
			{Label: "a", Address: "10.0.0.1", InstanceID: "i-a"},
		},
		WindowPeriodSeconds: 900,
		DutyCycleSeconds:    300,
	}))

	anchors, err := store.Anchors(ctx)
	require.NoError(t, err)
	require.Len(t, anchors, 1)
	require.Equal(t, "a", anchors[0].Label)
}

func TestReconcileWithNothingClearsAnchorsAndSchedule(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.Reconcile(ctx, ephemeralanchor.Document{
		Anchors:             []ephemeralanchor.AnchorEntry{{Label: "a", Address: "10.0.0.1", InstanceID: "i-a"}},
		WindowPeriodSeconds: 900,
		DutyCycleSeconds:    300,
	}))
	require.NoError(t, store.Reconcile(ctx, ephemeralanchor.Document{}))

	anchors, err := store.Anchors(ctx)
	require.NoError(t, err)
	require.Empty(t, anchors)

	windowPeriod, dutyCycle, err := store.Schedule(ctx)
	require.NoError(t, err)
	require.Zero(t, windowPeriod)
	require.Zero(t, dutyCycle)
}

func TestAddAnchorRejectsADuplicateLabel(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddAnchor(ctx, ephemeralanchor.AnchorEntry{Label: "a", Region: "us-west-2", Address: "10.0.0.1", InstanceID: "i-a"}))
	require.ErrorIs(t, store.AddAnchor(ctx, ephemeralanchor.AnchorEntry{Label: "a", Region: "us-west-2", Address: "10.0.0.2", InstanceID: "i-a2"}), ephemeralanchor.ErrExists)
}

func TestAddAnchorDefaultsPortTo22(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddAnchor(ctx, ephemeralanchor.AnchorEntry{Label: "a", Region: "us-west-2", Address: "10.0.0.1", InstanceID: "i-a"}))

	anchors, err := store.Anchors(ctx)
	require.NoError(t, err)
	require.Equal(t, uint32(22), anchors[0].Port)
}

func TestRemoveAnchorOnAMissingLabelReturnsErrNotFound(t *testing.T) {
	store := newStore(t)
	require.ErrorIs(t, store.RemoveAnchor(context.Background(), "nope"), ephemeralanchor.ErrNotFound)
}

func TestSetScheduleOverwritesThePreviousSchedule(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	require.NoError(t, store.SetSchedule(ctx, 900, 300))
	require.NoError(t, store.SetSchedule(ctx, 600, 120))

	windowPeriod, dutyCycle, err := store.Schedule(ctx)
	require.NoError(t, err)
	require.Equal(t, uint32(600), windowPeriod)
	require.Equal(t, uint32(120), dutyCycle)
}

func TestParseRejectsADuplicateLabel(t *testing.T) {
	_, err := ephemeralanchor.Parse([]byte(`{
		"ephemeral_anchors": [
			{"label": "a", "address": "10.0.0.1", "instance_id": "i-a"},
			{"label": "a", "address": "10.0.0.2", "instance_id": "i-a2"}
		]
	}`))
	require.Error(t, err)
}

func TestParseRejectsAnEmptyAddress(t *testing.T) {
	_, err := ephemeralanchor.Parse([]byte(`{
		"ephemeral_anchors": [{"label": "a", "address": "", "instance_id": "i-a"}]
	}`))
	require.Error(t, err)
}

func TestParseDefaultsPortTo22(t *testing.T) {
	doc, err := ephemeralanchor.Parse([]byte(`{
		"ephemeral_anchors": [{"label": "a", "region": "us-west-2", "address": "10.0.0.1", "instance_id": "i-a"}]
	}`))
	require.NoError(t, err)
	require.Equal(t, uint32(22), doc.Anchors[0].Port)
}
