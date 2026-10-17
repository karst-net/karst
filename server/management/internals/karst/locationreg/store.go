// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package locationreg

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrNotFound = errors.New("location registry: location not found")
	ErrExists   = errors.New("location registry: location already exists")
)

var ErrNoAccount = errors.New("location registry: account scope missing")

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

// StoredLocation is the database form of a validated registry entry. Unlike
// relayreg.StoredRelay (keyed by identity key) or turncred.StoredTurnServer
// (keyed by URI), a location has no natural identifier of its own, so the ID
// is derived from its full content — two entries with identical lat/lon/
// label/kind are one entry, the same "two names for one thing" posture
// relayreg.Parse already takes for a repeated identity key.
type StoredLocation struct {
	AccountID string  `gorm:"primaryKey;size:64" json:"-"`
	ID        string  `gorm:"primaryKey" json:"id"`
	Lat       float64 `gorm:"not null" json:"lat"`
	Lon       float64 `gorm:"not null" json:"lon"`
	Label     string  `json:"label,omitempty"`
	Kind      string  `json:"kind,omitempty"`
}

func (StoredLocation) TableName() string { return "karst_locations" }

func deriveID(e Entry) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%v\x00%v\x00%s\x00%s", e.Lat, e.Lon, e.Label, e.Kind)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type Store struct {
	db *gorm.DB
}

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("location registry: nil database")
	}
	if err := db.AutoMigrate(&StoredLocation{}); err != nil {
		return nil, fmt.Errorf("location registry: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Create(ctx context.Context, entry Entry) (*StoredLocation, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	validated, err := Compile(entry)
	if err != nil {
		return nil, err
	}
	record := &StoredLocation{
		AccountID: accountID,
		ID:        deriveID(validated),
		Lat:       validated.Lat,
		Lon:       validated.Lon,
		Label:     validated.Label,
		Kind:      validated.Kind,
	}
	var existing StoredLocation
	if err := s.db.Where("account_id = ? AND id = ?", accountID, record.ID).First(&existing).Error; err == nil {
		return nil, ErrExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("location registry: lookup: %w", err)
	}
	// The preflight gives a clear response in the ordinary case; the conflict
	// clause handles two simultaneous creates without exposing a driver-specific
	// unique-constraint message to either caller — mirrors relayreg.Store.Create.
	result := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(record)
	if result.Error != nil {
		return nil, fmt.Errorf("location registry: create: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, ErrExists
	}
	return record, nil
}

func (s *Store) List(ctx context.Context) ([]StoredLocation, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var records []StoredLocation
	if err := s.db.Where("account_id = ?", accountID).Order("id").Find(&records).Error; err != nil {
		return nil, err
	}
	return records, nil
}

func (s *Store) Delete(ctx context.Context, id string) error {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return err
	}
	result := s.db.Where("account_id = ? AND id = ?", accountID, id).Delete(&StoredLocation{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}
