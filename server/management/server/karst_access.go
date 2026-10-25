// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package server

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/internals/karst/relayservice"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
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

// validateKarstGroupDeletion runs on the same transaction as native group
// deletion. The inherited graph knows neither structured grants nor relay
// admission settings, so checking only native policies can leave those records
// pointing at a deleted group. Historical policy versions are intentionally
// ignored: only the current version grants access.
func validateKarstGroupDeletion(ctx context.Context, transaction store.Store, group *types.Group) error {
	sql, ok := transaction.(interface{ GetDB() *gorm.DB })
	if !ok || sql.GetDB() == nil {
		return nil // Non-SQL inherited stores do not contain Karst side tables.
	}
	db := sql.GetDB().WithContext(ctx)
	tables, err := db.Migrator().GetTables()
	if err != nil {
		return fmt.Errorf("cannot check group dependency tables: %w", err)
	}
	if slices.Contains(tables, (policy.Version{}).TableName()) {
		var current policy.Version
		err := db.Where("account_id = ?", group.AccountID).Order("version DESC").First(&current).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("cannot check group access dependencies: %w", err)
		}
		if err == nil {
			doc, err := policy.Parse([]byte(current.Document))
			if err != nil {
				return fmt.Errorf("cannot check current group access dependencies: %w", err)
			}
			for _, grant := range doc.Grants {
				if slices.Contains(grant.SourceGroups, group.ID) || slices.Contains(grant.TargetGroups, group.ID) {
					return &GroupLinkError{Resource: "access grant", Name: grant.Name}
				}
			}
			for name, id := range doc.GroupBindings {
				if id == group.ID {
					return &GroupLinkError{Resource: "legacy membership mapping", Name: name}
				}
			}
		}
	}
	if slices.Contains(tables, (relayservice.Service{}).TableName()) {
		var services []relayservice.Service
		if err := db.Select([]string{"id", "allowed_groups"}).Where("account_id = ?", group.AccountID).Find(&services).Error; err != nil {
			return fmt.Errorf("cannot check relay group dependencies: %w", err)
		}
		for _, service := range services {
			if slices.Contains(service.AllowedGroups, group.ID) {
				return &GroupLinkError{Resource: "relay", Name: service.ID}
			}
		}
	}
	// Admission records can outlive their association. Do not ignore an
	// independently retained restriction even when the service row is absent.
	if slices.Contains(tables, (relayservice.BackendAccess{}).TableName()) {
		var access []relayservice.BackendAccess
		if err := db.Select([]string{"relay_id", "groups"}).Where("account_id = ?", group.AccountID).Find(&access).Error; err != nil {
			return fmt.Errorf("cannot check relay admission dependencies: %w", err)
		}
		for _, backend := range access {
			if slices.Contains(backend.Groups, group.ID) {
				return &GroupLinkError{Resource: "relay admission", Name: backend.RelayID}
			}
		}
	}
	return nil
}
