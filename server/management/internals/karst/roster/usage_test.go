// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package roster

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/usage"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestUsagePublicationPersistsBeforeAdvertisingAndSurvivesLedgerFailure(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "mapping.db")), &gorm.Config{})
	require.NoError(t, err)
	sql, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sql.Close() })
	require.NoError(t, usage.Migrate(db))
	path := filepath.Join(t.TempDir(), "roster.toml")
	rows := []Entry{entry("a", key(1), "account"), entry("b", key(2), "account")}
	r, err := New(fixed{rows: rows}, Config{Path: path, Usage: &UsageConfig{DB: db, DeploymentID: "deployment"}}, nil)
	require.NoError(t, err)
	require.NoError(t, r.Once())
	var mappings []usage.RelayMapping
	require.NoError(t, db.Find(&mappings).Error)
	require.Len(t, mappings, 1)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), "usage_mapping = \""+mappings[0].Version+"\"")
	resolved, err := usage.ResolveRelayMapping(context.Background(), db, "deployment", mappings[0].Version)
	require.NoError(t, err)
	require.Equal(t, "account", resolved.AccountID)
	require.NoError(t, sql.Close())
	require.NoError(t, r.Once(), "ledger failure must not stop roster renewal")
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, Render(rows, ""), data, "failure must remove stale attribution while retaining admission")
}

func TestUsagePublicationRejectsUncommittedHandle(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "mapping.db")), &gorm.Config{})
	require.NoError(t, err)
	sql, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sql.Close() })
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		_, err := New(fixed{}, Config{Path: "unused", Usage: &UsageConfig{DB: tx, DeploymentID: "deployment"}}, nil)
		require.Error(t, err)
		return nil
	}))
}
