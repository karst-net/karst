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
	require.ErrorContains(t, store.CheckRelayLifecycle(ctx, "a", nil), "1 enrolled")
	require.NoError(t, store.SetRelayLifecycleSchema(ctx, "old", 1))
	require.NoError(t, db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return store.CheckRelayLifecycle(ctx, "a", tx)
	}))
	require.ErrorContains(t, store.CheckRelayLifecycle(ctx, "b", nil), "1 enrolled")
	require.NoError(t, store.SetRelayLifecycleSchema(ctx, "old", 0))
	require.ErrorContains(t, store.CheckRelayLifecycle(ctx, "a", nil), "1 enrolled")
	require.NoError(t, db.Exec("DELETE FROM peers WHERE key = 'old'").Error)
	require.NoError(t, store.CheckRelayLifecycle(ctx, "a", nil))
	require.ErrorIs(t, store.SetRelayLifecycleSchema(ctx, "missing", 1), node.ErrUnknownNode)
}
