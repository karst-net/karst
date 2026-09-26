// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package tenancy backs ADR-0037's operator-granted cross-tenant account
// access: an explicit (user, account) grant table that
// BaseServer.IsValidChildAccount consults instead of the upstream stub's
// unconditional false.
//
// Grants are declarative and boot-time only (karst-control/main.go's
// KARST_TENANCY_GRANTS_FILE), the same operational shape as the relay and
// TURN registries — see Reconcile.
package tenancy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"gorm.io/gorm"
)

// Grant is one (user, account) pair: userID may view accountID's data
// through the existing ?account= override, subject to
// BaseServer.IsValidChildAccount actually being asked.
type Grant struct {
	UserID    string `json:"user_id"`
	AccountID string `json:"account_id"`
}

type grantRow struct {
	UserID    string `gorm:"primaryKey;size:64"`
	AccountID string `gorm:"primaryKey;size:64"`
	CreatedAt time.Time
}

func (grantRow) TableName() string { return "karst_tenancy_grants" }

// Store is the grant table. Safe for concurrent use.
type Store struct {
	db *gorm.DB
}

// NewStore migrates and returns the grant store.
func NewStore(db *gorm.DB) (*Store, error) {
	if err := db.AutoMigrate(&grantRow{}); err != nil {
		return nil, fmt.Errorf("tenancy: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// HasAccess reports whether userID has been granted access to accountID.
// This is the only question BaseServer.IsValidChildAccount asks.
func (s *Store) HasAccess(ctx context.Context, userID, accountID string) (bool, error) {
	if userID == "" || accountID == "" {
		return false, nil
	}
	var count int64
	err := s.db.WithContext(ctx).Model(&grantRow{}).
		Where("user_id = ? AND account_id = ?", userID, accountID).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("tenancy: has access: %w", err)
	}
	return count > 0, nil
}

// AccessibleAccounts returns every account userID has been granted access
// to. Never includes userID's own home account — that is not a grant, it is
// ordinary authentication, and this store has no way to know a caller's home
// account in the first place.
func (s *Store) AccessibleAccounts(ctx context.Context, userID string) ([]string, error) {
	var rows []grantRow
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Order("account_id").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("tenancy: accessible accounts: %w", err)
	}
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r.AccountID
	}
	return ids, nil
}

// Reconcile makes the grant table match wanted exactly: grants present in
// wanted but missing from the table are created, grants present in the
// table but absent from wanted are revoked. Declarative, not additive — the
// file is the source of truth on every boot, the same convention the relay
// and TURN registries already use.
func (s *Store) Reconcile(ctx context.Context, wanted []Grant) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing []grantRow
		if err := tx.Find(&existing).Error; err != nil {
			return fmt.Errorf("tenancy: reconcile: list existing: %w", err)
		}

		want := make(map[Grant]bool, len(wanted))
		for _, g := range wanted {
			want[g] = true
		}
		have := make(map[Grant]bool, len(existing))
		for _, r := range existing {
			have[Grant{UserID: r.UserID, AccountID: r.AccountID}] = true
		}

		for g := range have {
			if !want[g] {
				if err := tx.Where("user_id = ? AND account_id = ?", g.UserID, g.AccountID).Delete(&grantRow{}).Error; err != nil {
					return fmt.Errorf("tenancy: reconcile: revoke %s -> %s: %w", g.UserID, g.AccountID, err)
				}
			}
		}
		for g := range want {
			if !have[g] {
				if err := tx.Create(&grantRow{UserID: g.UserID, AccountID: g.AccountID, CreatedAt: time.Now().UTC()}).Error; err != nil {
					return fmt.Errorf("tenancy: reconcile: grant %s -> %s: %w", g.UserID, g.AccountID, err)
				}
			}
		}
		return nil
	})
}

type document struct {
	Grants []Grant `json:"grants"`
}

// Parse validates a KARST_TENANCY_GRANTS_FILE document.
func Parse(raw []byte) ([]Grant, error) {
	var doc document
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("tenancy grants: %w", err)
	}
	for i, g := range doc.Grants {
		if g.UserID == "" || g.AccountID == "" {
			return nil, fmt.Errorf("tenancy grants: entry %d: user_id and account_id are both required", i)
		}
	}
	return doc.Grants, nil
}

// Load reads and validates a KARST_TENANCY_GRANTS_FILE document.
func Load(path string) ([]Grant, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tenancy grants: %w", err)
	}
	grants, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("tenancy grants %s: %w", path, err)
	}
	return grants, nil
}
