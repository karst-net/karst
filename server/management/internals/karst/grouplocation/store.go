// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package grouplocation

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrNotFound = errors.New("group location: not found")
var ErrNoAccount = errors.New("group location: account scope missing")

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

// StoredGroupLocation is at most one row per (account, group): a group's
// declared location is a property an admin sets and may later change, not
// an append-only registry like relayreg/turncred — there is never a reason
// for two locations to exist for the same group at once.
type StoredGroupLocation struct {
	AccountID string  `gorm:"primaryKey;size:64" json:"-"`
	GroupID   string  `gorm:"primaryKey" json:"group_id"`
	Lat       float64 `gorm:"not null" json:"lat"`
	Lon       float64 `gorm:"not null" json:"lon"`
	Label     string  `json:"label,omitempty"`
}

func (StoredGroupLocation) TableName() string { return "karst_group_locations" }

type Store struct{ db *gorm.DB }

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("group location: nil database")
	}
	if err := db.AutoMigrate(&StoredGroupLocation{}); err != nil {
		return nil, fmt.Errorf("group location: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Set declares (or replaces) the location for one group — an upsert, since
// "declare a group's location" and "change a group's declared location" are
// the same operation from an admin's point of view.
func (s *Store) Set(ctx context.Context, entry Entry) (*StoredGroupLocation, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	validated, err := Compile(entry)
	if err != nil {
		return nil, err
	}
	record := &StoredGroupLocation{AccountID: accountID, GroupID: validated.GroupID, Lat: validated.Lat, Lon: validated.Lon, Label: validated.Label}
	err = s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "account_id"}, {Name: "group_id"}},
		UpdateAll: true,
	}).Create(record).Error
	if err != nil {
		return nil, fmt.Errorf("group location: set: %w", err)
	}
	return record, nil
}

func (s *Store) List(ctx context.Context) ([]StoredGroupLocation, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var records []StoredGroupLocation
	if err := s.db.Where("account_id = ?", accountID).Order("group_id").Find(&records).Error; err != nil {
		return nil, err
	}
	return records, nil
}

func (s *Store) Get(ctx context.Context, groupID string) (*StoredGroupLocation, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var record StoredGroupLocation
	err = s.db.Where("account_id = ? AND group_id = ?", accountID, groupID).First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("group location: get: %w", err)
	}
	return &record, nil
}

func (s *Store) Delete(ctx context.Context, groupID string) error {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return err
	}
	result := s.db.Where("account_id = ? AND group_id = ?", accountID, groupID).Delete(&StoredGroupLocation{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}
