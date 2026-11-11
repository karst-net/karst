// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package node_test

import (
	"context"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestRelayLifecycleAccountScopeDowngradeAndTransaction(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	defer sqlDB.Close()
	sqlDB.SetMaxOpenConns(1)
	store, err := node.NewStore(db)
	require.NoError(t, err)
	require.NoError(t, db.Exec("CREATE TABLE peers (key TEXT PRIMARY KEY, account_id TEXT)").Error)
	for _, item := range []struct{ handle, account string }{{"old", "a"}, {"other", "b"}} {
		require.NoError(t, db.Create(&node.Identity{Handle: item.handle, PublicKey: []byte{1}}).Error)
		require.NoError(t, db.Exec("INSERT INTO peers VALUES (?, ?)", item.handle, item.account).Error)
	}
	// Inherited peers without Karst identities do not consume this netmap.
	require.NoError(t, db.Exec("INSERT INTO peers VALUES ('inherited', 'a')").Error)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	require.ErrorContains(t, store.CheckEstavelleLifecycle(ctx, "a", nil), "1 enrolled")
	require.NoError(t, store.SetEstavelleLifecycleSchema(ctx, "old", 1))
	require.NoError(t, db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return store.CheckEstavelleLifecycle(ctx, "a", tx)
	}))
	require.ErrorContains(t, store.CheckEstavelleLifecycle(ctx, "b", nil), "1 enrolled")
	require.NoError(t, store.SetEstavelleLifecycleSchema(ctx, "old", 0))
	require.ErrorContains(t, store.CheckEstavelleLifecycle(ctx, "a", nil), "1 enrolled")
	require.NoError(t, db.Exec("DELETE FROM peers WHERE key = 'old'").Error)
	require.NoError(t, store.CheckEstavelleLifecycle(ctx, "a", nil))
	require.ErrorIs(t, store.SetEstavelleLifecycleSchema(ctx, "missing", 1), node.ErrUnknownNode)
}

func TestGatewayIngressSchemaAndParameterizedCounts(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	defer sqlDB.Close()
	sqlDB.SetMaxOpenConns(1)
	store, err := node.NewStore(db)
	require.NoError(t, err)
	require.NoError(t, db.Exec("CREATE TABLE peers (key TEXT PRIMARY KEY, account_id TEXT)").Error)
	for _, item := range []struct{ handle, account string }{{"old", "a"}, {"new", "a"}} {
		require.NoError(t, db.Create(&node.Identity{Handle: item.handle, PublicKey: []byte{1}}).Error)
		require.NoError(t, db.Exec("INSERT INTO peers VALUES (?, ?)", item.handle, item.account).Error)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Both agents start at schema 0 -- below any required schema >= 1.
	below, err := store.CountAvenIngressBelow(ctx, "a", 1, nil)
	require.NoError(t, err)
	require.EqualValues(t, 2, below)

	require.NoError(t, store.SetAvenIngressSchema(ctx, "old", 1))
	below, err = store.CountAvenIngressBelow(ctx, "a", 1, nil)
	require.NoError(t, err)
	require.EqualValues(t, 1, below)

	// A later legacy declaration replaces the earlier one -- a downgrade
	// is not sticky, the same property SetEstavelleLifecycleSchema already has.
	require.NoError(t, store.SetAvenIngressSchema(ctx, "old", 0))
	below, err = store.CountAvenIngressBelow(ctx, "a", 1, nil)
	require.NoError(t, err)
	require.EqualValues(t, 2, below)

	// A higher required schema than any agent has reported counts everyone,
	// including an agent that satisfies a lower bar.
	require.NoError(t, store.SetAvenIngressSchema(ctx, "new", 1))
	below, err = store.CountAvenIngressBelow(ctx, "a", 2, nil)
	require.NoError(t, err)
	require.EqualValues(t, 2, below)

	// CountEstavelleLifecycleBelow is independent of the gateway column, and
	// CheckEstavelleLifecycle's own error-returning behavior is unchanged by
	// having been refactored onto it.
	relayBelow, err := store.CountEstavelleLifecycleBelow(ctx, "a", 1, nil)
	require.NoError(t, err)
	require.EqualValues(t, 2, relayBelow)
	require.ErrorContains(t, store.CheckEstavelleLifecycle(ctx, "a", nil), "2 enrolled")

	require.NoError(t, db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		count, err := store.CountAvenIngressBelow(ctx, "a", 1, tx)
		if err != nil {
			return err
		}
		require.EqualValues(t, 1, count) // "old" is still at schema 0; "new" is at 1
		return nil
	}))
	_, err = store.CountAvenIngressBelow(ctx, "", 1, nil)
	require.Error(t, err)
}
