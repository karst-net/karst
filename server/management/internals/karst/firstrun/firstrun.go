// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package firstrun tracks whether an account has completed the console's
// first-run setup wizard (default domain + initial groups). The console
// hides every other nav item until this flips to true (main.tsx).
//
// New rows are never created by hooking NetBird's own account-creation path
// -- bootstrap.go's own doc comment explains why forked files stay
// untouched. Instead, NewStore backfills Completed=true for every account
// that already existed before this package shipped, the same moment it
// creates the table. From then on, "no row for this account" unambiguously
// means "created after this shipped", so a missing row correctly defaults
// to incomplete without any hook into account signup.
package firstrun

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrNoAccount = errors.New("first-run setup: account scope missing")

type accountContextKey struct{}

func WithAccount(ctx context.Context, accountID string) context.Context {
	return context.WithValue(ctx, accountContextKey{}, accountID)
}

func accountFromContext(ctx context.Context) (string, error) {
	accountID, _ := ctx.Value(accountContextKey{}).(string)
	if accountID == "" {
		return "", ErrNoAccount
	}
	return accountID, nil
}

// StoredState is one account's first-run completion record. Absence means
// "not completed" -- see the package doc comment for why that is safe.
type StoredState struct {
	AccountID   string `gorm:"primaryKey;size:64"`
	Completed   bool
	CompletedAt *time.Time
}

func (StoredState) TableName() string { return "karst_first_run" }

type Store struct{ db *gorm.DB }

// NewStore migrates the table and backfills Completed=true for every
// account that already exists, so this feature never interrupts an
// existing deployment's admins.
func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("first-run setup: nil database")
	}
	if err := db.AutoMigrate(&StoredState{}); err != nil {
		return nil, fmt.Errorf("first-run setup: migrate: %w", err)
	}
	if err := backfillExistingAccounts(db); err != nil {
		return nil, fmt.Errorf("first-run setup: backfill: %w", err)
	}
	return &Store{db: db}, nil
}

func backfillExistingAccounts(db *gorm.DB) error {
	// A handle with no "accounts" table isn't running against NetBird's
	// real schema -- a lighter-weight test fixture, most likely. Either
	// way there is nothing to backfill, and failing here would make every
	// such fixture unable to construct this store at all.
	if !db.Migrator().HasTable("accounts") {
		return nil
	}
	var accountIDs []string
	if err := db.Table("accounts").Pluck("id", &accountIDs).Error; err != nil {
		return fmt.Errorf("list accounts: %w", err)
	}
	if len(accountIDs) == 0 {
		return nil
	}
	now := time.Now().UTC()
	rows := make([]StoredState, 0, len(accountIDs))
	for _, id := range accountIDs {
		rows = append(rows, StoredState{AccountID: id, Completed: true, CompletedAt: &now})
	}
	// OnConflict{DoNothing: true} makes this safe to run on every boot --
	// an account that already has a row (because it finished the wizard,
	// or because an earlier boot already backfilled it) is left alone.
	return db.Clauses(clause.OnConflict{DoNothing: true}).Create(&rows).Error
}

// Get returns the account's first-run state. A missing row reports
// Completed=false rather than an error -- that is the ordinary case for a
// brand-new account, not a failure.
func (s *Store) Get(ctx context.Context) (*StoredState, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var record StoredState
	err = s.db.WithContext(ctx).Where("account_id = ?", accountID).First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return &StoredState{AccountID: accountID, Completed: false}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("first-run setup: get: %w", err)
	}
	return &record, nil
}

// Complete marks the account's first-run setup as done. Idempotent.
func (s *Store) Complete(ctx context.Context) (*StoredState, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	record := &StoredState{AccountID: accountID, Completed: true, CompletedAt: &now}
	if err := s.db.WithContext(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(record).Error; err != nil {
		return nil, fmt.Errorf("first-run setup: complete: %w", err)
	}
	return record, nil
}
