// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package bedrock persists the small piece of Bedrock state owned by the
// coordination server. Authority signatures and private material never enter
// this store: it tracks coverage and the operator-selected enforcement mode.
package bedrock

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"gorm.io/gorm"
)

const (
	ModeOff       = "off"
	ModeAdvisory  = "advisory"
	ModeEnforcing = "enforcing"
)

var ErrAcknowledgementMismatch = errors.New("bedrock: acknowledgement list does not match uncovered nodes")

// Configuration is the account-scoped operator-controlled Bedrock configuration.
// It intentionally has no key columns: roots and authority private keys stay
// on offline signer devices.
type Configuration struct {
	AccountID string `gorm:"primaryKey;size:64"`
	Mode      string `gorm:"not null"`
	Quorum    uint   `gorm:"not null"`
	UpdatedAt time.Time
}

func (Configuration) TableName() string { return "karst_bedrock_configuration" }

// Coverage records the result of importing a valid authority-signed response.
// The signature bundle itself is handled by the offline workflow; this table is
// the derived state needed to make the enforcement decision deterministic.
type Coverage struct {
	AccountID string `gorm:"primaryKey;size:64"`
	Handle    string `gorm:"primaryKey;size:64"`
	CoveredAt time.Time
}

func (Coverage) TableName() string { return "karst_bedrock_coverage" }

type Store struct{ db *gorm.DB }

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("bedrock: nil database")
	}
	if err := db.AutoMigrate(&Configuration{}, &Coverage{}); err != nil {
		return nil, fmt.Errorf("bedrock: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Configuration(ctx context.Context, accountID string) (*Configuration, error) {
	var c Configuration
	if err := s.db.WithContext(ctx).Where("account_id = ?", accountID).Attrs(Configuration{AccountID: accountID, Mode: ModeOff, Quorum: 1}).FirstOrCreate(&c).Error; err != nil {
		return nil, fmt.Errorf("bedrock: configuration: %w", err)
	}
	return &c, nil
}

// SetMode requires an exact acknowledgement set when moving to enforcing.
// Exactness matters: accepting a superset makes a stale console confirmation
// appear valid after a new uncovered node joins; accepting a subset hides a
// node that will be cut off.
func (s *Store) SetMode(ctx context.Context, accountID, mode string, acknowledged, enrolled []string) (*Configuration, error) {
	if mode != ModeOff && mode != ModeAdvisory && mode != ModeEnforcing {
		return nil, fmt.Errorf("bedrock: invalid mode %q", mode)
	}
	if mode == ModeEnforcing {
		uncovered, err := s.Uncovered(ctx, accountID, enrolled)
		if err != nil {
			return nil, err
		}
		if !sameStrings(uncovered, acknowledged) {
			return nil, fmt.Errorf("%w: required %v", ErrAcknowledgementMismatch, uncovered)
		}
	}
	if _, err := s.Configuration(ctx, accountID); err != nil {
		return nil, err
	}
	if err := s.db.WithContext(ctx).Model(&Configuration{}).Where("account_id = ?", accountID).Update("mode", mode).Error; err != nil {
		return nil, fmt.Errorf("bedrock: update mode: %w", err)
	}
	return s.Configuration(ctx, accountID)
}

func (s *Store) Uncovered(ctx context.Context, accountID string, enrolled []string) ([]string, error) {
	var covered []Coverage
	if err := s.db.WithContext(ctx).Where("account_id = ?", accountID).Find(&covered).Error; err != nil {
		return nil, fmt.Errorf("bedrock: coverage: %w", err)
	}
	known := make(map[string]struct{}, len(covered))
	for _, c := range covered {
		known[c.Handle] = struct{}{}
	}
	missing := make([]string, 0)
	for _, handle := range enrolled {
		if _, ok := known[handle]; !ok {
			missing = append(missing, handle)
		}
	}
	sort.Strings(missing)
	return missing, nil
}

func sameStrings(a, b []string) bool {
	a = append([]string(nil), a...)
	b = append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
