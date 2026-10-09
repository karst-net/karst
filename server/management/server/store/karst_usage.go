// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package store

import (
	"context"
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/internals/karst/usage"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
)

// InitializeDeviceUsage installs transaction hooks before serving requests.
// Collection remains disabled until explicitly configured per account. Every
// replica sharing the database must run these hooks before activation.
func (s *SqlStore) InitializeDeviceUsage() error {
	if err := usage.Migrate(s.db); err != nil {
		return err
	}
	s.deviceUsage = &usage.Collector{}
	return nil
}

func deviceMembership(accountID string) usage.Snapshot {
	return func(tx *gorm.DB) ([]string, error) {
		var ids []string
		err := tx.Model(&nbpeer.Peer{}).Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("account_id = ?", accountID).Order("id").Pluck("id", &ids).Error
		return ids, err
	}
}

func (s *SqlStore) membershipTransaction(ctx context.Context, accountID string, removeAccount bool, mutate func(*gorm.DB) error) error {
	return s.transaction(func(tx *gorm.DB) error {
		return s.trackMembership(tx.WithContext(ctx), accountID, removeAccount, mutate)
	})
}

// Peer writes retain their original FK checks. Only account association
// replacement uses the existing MySQL-specific s.transaction wrapper above.
func (s *SqlStore) peerMembershipTransaction(ctx context.Context, accountID string, mutate func(*gorm.DB) error) error {
	if s.deviceUsage == nil {
		return mutate(s.db.WithContext(ctx))
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return s.trackMembership(tx, accountID, false, mutate)
	})
}

func (s *SqlStore) trackMembership(tx *gorm.DB, accountID string, removeAccount bool, mutate func(*gorm.DB) error) error {
	if s.deviceUsage == nil {
		return mutate(tx)
	}
	if err := s.deviceUsage.Track(tx, accountID, deviceMembership(accountID), mutate); err != nil {
		return err
	}
	if removeAccount {
		return s.deviceUsage.Configure(tx, accountID, false, deviceMembership(accountID))
	}
	return nil
}

// SetDeviceUsageCollection is an internal operator integration seam, not a
// customer endpoint. Its caller must authorize the account and configuration
// change. No public API or environment flag enables collection in this slice.
func (s *SqlStore) SetDeviceUsageCollection(ctx context.Context, accountID string, enabled bool) error {
	if s.deviceUsage == nil {
		return errors.New("device usage hooks are not initialized")
	}
	return s.transaction(func(tx *gorm.DB) error {
		tx = tx.WithContext(ctx)
		// Validate account existence without changing accounting semantics.
		// Deletion and activation serialize via the collection row; the
		// activation snapshot rechecks existence under that lock below.
		var account types.Account
		if err := tx.Select("id").Where("id = ?", accountID).Take(&account).Error; err != nil {
			return err
		}
		snapshot := func(tx *gorm.DB) ([]string, error) {
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").Where("id = ?", accountID).Take(&account).Error; err != nil {
				return nil, err
			}
			return deviceMembership(accountID)(tx)
		}
		return s.deviceUsage.Configure(tx, accountID, enabled, snapshot)
	})
}

// ReconcileDeviceUsage records an explicit discrepancy and restarts coverage at
// the observation boundary. It must never be used to manufacture past usage.
func (s *SqlStore) ReconcileDeviceUsage(ctx context.Context, accountID string) error {
	if s.deviceUsage == nil {
		return errors.New("device usage hooks are not initialized")
	}
	return s.transaction(func(tx *gorm.DB) error {
		return s.deviceUsage.Reconcile(tx.WithContext(ctx), accountID, deviceMembership(accountID))
	})
}
