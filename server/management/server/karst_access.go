// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package server

import (
	"context"
	"errors"
	"github.com/netbirdio/netbird/management/internals/karst/policy"
	"gorm.io/gorm"
)

// The inherited dependency graph does not include form-managed grants. A
// changed source group can revoke access at every destination in the account.
func (am *DefaultAccountManager) karstRegistryAccess(ctx context.Context, accountID string) bool {
	sql, ok := am.Store.(interface{ GetDB() *gorm.DB })
	if !ok || sql.GetDB() == nil || !sql.GetDB().Migrator().HasTable(&policy.Version{}) {
		return false
	}
	var current policy.Version
	err := sql.GetDB().WithContext(ctx).Where("account_id = ?", accountID).Order("version DESC").First(&current).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false
	}
	if err != nil {
		return true
	}
	doc, err := policy.Parse([]byte(current.Document))
	return err != nil || doc.UsesRegistryGroups()
}
