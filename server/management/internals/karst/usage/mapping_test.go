// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package usage_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/usage"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestRelayMappingsRetainHistoryAcrossReassignmentAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mapping.db")
	db := database(t, path)
	ctx := context.Background()
	first, err := usage.PersistRelayMapping(ctx, db, "deployment", "prefix:opaque", "account-a")
	require.NoError(t, err)
	retry, err := usage.PersistRelayMapping(ctx, db, "deployment", "prefix:opaque", "account-a")
	require.NoError(t, err)
	require.Equal(t, first, retry)
	second, err := usage.PersistRelayMapping(ctx, db, "deployment", "prefix:opaque", "account-b")
	require.NoError(t, err)
	require.NotEqual(t, first.Version, second.Version)
	reopened := database(t, path)
	old, err := usage.ResolveRelayMapping(ctx, reopened, "deployment", first.Version)
	require.NoError(t, err)
	require.Equal(t, first, old)
	_, err = usage.ResolveRelayMapping(ctx, reopened, "other-deployment", first.Version)
	require.ErrorIs(t, err, usage.ErrMapping)
	var count int64
	require.NoError(t, reopened.Model(&usage.RelayMapping{}).Count(&count).Error)
	require.EqualValues(t, 2, count)
}

func TestRelayMappingPublicationMustFollowCommit(t *testing.T) {
	db := fixture(t)
	ctx := context.Background()
	failure := errors.New("publication preparation failed")
	var mapping usage.RelayMapping
	err := db.Transaction(func(tx *gorm.DB) error {
		var err error
		mapping, err = usage.PersistRelayMapping(ctx, tx, "deployment", "aquifer", "account")
		if err != nil {
			return err
		}
		return failure
	})
	require.ErrorIs(t, err, failure)
	_, err = usage.ResolveRelayMapping(ctx, db, "deployment", mapping.Version)
	require.ErrorIs(t, err, usage.ErrMapping)
	_, err = usage.PersistRelayMapping(ctx, db, "deployment", "bad\naquifer", "account")
	require.ErrorIs(t, err, usage.ErrMapping)
}
