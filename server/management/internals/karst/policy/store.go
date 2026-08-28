// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package policy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrNoVersion = errors.New("policy: no stored version")
var ErrVersionConflict = errors.New("policy: version conflict")
var ErrNoAccount = errors.New("policy: account scope missing")

type accountContextKey struct{}

// WithAccount binds a store operation to one management account.
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

// Version is an immutable policy document revision. The raw document is kept
// alongside its parsed use so an administrator can retrieve exactly what was
// reviewed, including HuJSON formatting once that preprocessor is enabled.
type Version struct {
	AccountID string `gorm:"primaryKey;size:64"`
	Version   uint64 `gorm:"primaryKey;autoIncrement:false"`
	Document  string `gorm:"not null"`
	Author    string `gorm:"not null"`
	CreatedAt time.Time
}

func (Version) TableName() string { return "karst_policy_versions" }

type Store struct{ db *gorm.DB }

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("policy: nil database")
	}
	if err := db.AutoMigrate(&Version{}); err != nil {
		return nil, fmt.Errorf("policy: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Current(ctx context.Context) (*Version, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var version Version
	if err := s.db.WithContext(ctx).Where("account_id = ?", accountID).Order("version DESC").First(&version).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNoVersion
		}
		return nil, fmt.Errorf("policy: current: %w", err)
	}
	return &version, nil
}

func (s *Store) Get(ctx context.Context, number uint64) (*Version, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var version Version
	if err := s.db.WithContext(ctx).Where("account_id = ? AND version = ?", accountID, number).First(&version).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNoVersion
		}
		return nil, err
	}
	return &version, nil
}

func (s *Store) List(ctx context.Context, offset, limit int) ([]Version, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var versions []Version
	if err := s.db.WithContext(ctx).Where("account_id = ?", accountID).Order("version DESC").Offset(offset).Limit(limit).Find(&versions).Error; err != nil {
		return nil, err
	}
	return versions, nil
}

// ValidateDocument validates without persisting, so editor lint calls cannot
// change the network policy.
func ValidateDocument(document string) error { _, err := Parse([]byte(document)); return err }

// Write validates and appends a new immutable version if expected is current.
func (s *Store) Write(ctx context.Context, document, author string, expected uint64) (*Version, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := ValidateDocument(document); err != nil {
		return nil, err
	}
	var written Version
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current Version
		err := tx.Where("account_id = ?", accountID).Order("version DESC").First(&current).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if expected != 0 {
				return ErrVersionConflict
			}
			current.Version = 0
		} else if err != nil {
			return err
		} else if current.Version != expected {
			return ErrVersionConflict
		}
		written = Version{AccountID: accountID, Version: current.Version + 1, Document: document, Author: author, CreatedAt: time.Now().UTC()}
		// The optimistic version check above is necessary but not sufficient:
		// two requests can both read the same current revision before either
		// inserts. Let the composite primary key decide that race and translate
		// the losing insert into the contract's version-conflict response rather
		// than leaking a database constraint error or creating two revisions.
		result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&written)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrVersionConflict
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &written, nil
}
