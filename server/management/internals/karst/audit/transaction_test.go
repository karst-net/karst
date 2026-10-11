// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package audit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/karst/audit"
)

func TestCallerTransactionOwnsAuditCommit(t *testing.T) {
	log, db := newLog(t)
	ctx := audit.WithAccount(context.Background(), "a")
	_, err := log.AppendInTransaction(ctx, db, "actor", "action", "target", "")
	require.Error(t, err, "root handles must not accidentally commit separately")
	failure := errors.New("business operation failed")
	err = db.Transaction(func(tx *gorm.DB) error {
		if _, err := log.AppendInTransaction(ctx, tx, "operator", "enable", "a", ""); err != nil {
			return err
		}
		return failure
	})
	require.ErrorIs(t, err, failure)
	var count int64
	require.NoError(t, db.Model(&audit.Entry{}).Count(&count).Error)
	require.Zero(t, count)
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		_, err := log.AppendInTransaction(ctx, tx, "operator", "enable", "a", "")
		return err
	}))
	require.NoError(t, db.Model(&audit.Entry{}).Count(&count).Error)
	require.EqualValues(t, 1, count)
}
