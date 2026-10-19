// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package tutorialmode is the account-scoped on/off switch for the
// console's per-page "what is this" guidance text. Default-on: a missing
// row means a brand-new account, and new admins are exactly who the
// guidance text is for, so absence reads as enabled rather than disabled --
// the inverse of most singleton settings in this codebase, which default
// to their Go zero value.
package tutorialmode

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrNoAccount = errors.New("tutorial mode: account scope missing")

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

type StoredState struct {
	AccountID string `gorm:"primaryKey;size:64"`
	Enabled   bool
}

func (StoredState) TableName() string { return "karst_tutorial_mode" }

type Store struct{ db *gorm.DB }

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("tutorial mode: nil database")
	}
	if err := db.AutoMigrate(&StoredState{}); err != nil {
		return nil, fmt.Errorf("tutorial mode: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Get reports whether guidance text is enabled. Absence defaults to true --
// see the package doc comment.
func (s *Store) Get(ctx context.Context) (bool, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return false, err
	}
	var record StoredState
	err = s.db.WithContext(ctx).Where("account_id = ?", accountID).First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("tutorial mode: get: %w", err)
	}
	return record.Enabled, nil
}

// Set declares the account's preference explicitly, including "true" --
// writing the default is not a no-op, so a later schema change to the
// default does not silently flip an admin's past choice.
func (s *Store) Set(ctx context.Context, enabled bool) error {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return err
	}
	record := &StoredState{AccountID: accountID, Enabled: enabled}
	if err := s.db.WithContext(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(record).Error; err != nil {
		return fmt.Errorf("tutorial mode: set: %w", err)
	}
	return nil
}
