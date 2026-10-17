// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package cplocation declares the control plane's own position on the NOC
// map (ADR-0046 §1's last named component). There is no multi-replica
// identity/address registry yet — ADR-0054, which would give each replica
// its own placement, is still Proposed — so this is a single, account-scoped
// declared point, the same singleton shape bedrock.Configuration already
// uses for Bedrock's own account-scoped config, not a per-replica list.
package cplocation

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/karst/geo"
)

var ErrNotFound = errors.New("control plane location: not set")
var ErrNoAccount = errors.New("control plane location: account scope missing")

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

type StoredLocation struct {
	AccountID string  `gorm:"primaryKey;size:64" json:"-"`
	Lat       float64 `gorm:"not null" json:"lat"`
	Lon       float64 `gorm:"not null" json:"lon"`
	Label     string  `json:"label,omitempty"`
}

func (StoredLocation) TableName() string { return "karst_control_plane_location" }

type Store struct{ db *gorm.DB }

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("control plane location: nil database")
	}
	if err := db.AutoMigrate(&StoredLocation{}); err != nil {
		return nil, fmt.Errorf("control plane location: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Set(ctx context.Context, lat, lon float64, label string) (*StoredLocation, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := geo.ValidLocation(lat, lon); err != nil {
		return nil, err
	}
	record := &StoredLocation{AccountID: accountID, Lat: lat, Lon: lon, Label: label}
	if err := s.db.Save(record).Error; err != nil {
		return nil, fmt.Errorf("control plane location: set: %w", err)
	}
	return record, nil
}

func (s *Store) Get(ctx context.Context) (*StoredLocation, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var record StoredLocation
	err = s.db.Where("account_id = ?", accountID).First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("control plane location: get: %w", err)
	}
	return &record, nil
}

func (s *Store) Delete(ctx context.Context) error {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return err
	}
	return s.db.Where("account_id = ?", accountID).Delete(&StoredLocation{}).Error
}
