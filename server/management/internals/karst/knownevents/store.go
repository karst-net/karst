// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package knownevents is ADR-0045 §8 (Phase 3)'s "known events are
// first-class operator inputs" — a planned migration, a company all-hands,
// a holiday calendar, "often more valuable than inferred seasonality."
// Account-scoped, not deployment-wide like the demand history
// (relayreg.RegionDemandSample) it is meant to sit alongside later: when an
// organization's own traffic is expected to change is that organization's
// own calendar, not the deployment's, and §8 separately treats
// pattern-of-life data as sensitive metadata about the organization.
//
// Each entry is one concrete [StartsAt, EndsAt) interval, not a recurrence
// rule — an operator with an annual holiday enters it each year. Adding
// recurrence is a real but separate expansion or this package's own scope,
// not assumed here.
//
// Deliberately capture-only: no forecaster yet consumes these. See
// relayreg.RegionDemandSample's own doc comment for the same reasoning
// applied to demand history — this is an input Phase 3 eventually needs,
// not the phase itself.
package knownevents

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/xid"
	"gorm.io/gorm"
)

var ErrNotFound = errors.New("known events: event not found")

var ErrNoAccount = errors.New("known events: account scope missing")

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

// Entry is one operator-entered known event, before validation.
type Entry struct {
	Label    string    `json:"label"`
	StartsAt time.Time `json:"starts_at"`
	EndsAt   time.Time `json:"ends_at"`
}

func (e Entry) validate() (Entry, error) {
	label := strings.TrimSpace(e.Label)
	if label == "" {
		return Entry{}, errors.New("label is required")
	}
	if e.StartsAt.IsZero() || e.EndsAt.IsZero() {
		return Entry{}, errors.New("starts_at and ends_at are both required")
	}
	if !e.EndsAt.After(e.StartsAt) {
		return Entry{}, errors.New("ends_at must be after starts_at")
	}
	e.Label = label
	return e, nil
}

// StoredKnownEvent is the database form of a validated Entry. ID is a
// generated identifier, not derived from content the way
// relayreg.StoredRelay's or turncred.StoredTurnServer's are — two known
// events can legitimately share a label and even overlap (an operator
// might record "company all-hands" every quarter), so there is no natural
// content-derived key to deduplicate against.
type StoredKnownEvent struct {
	AccountID string    `gorm:"primaryKey;size:64" json:"-"`
	ID        string    `gorm:"primaryKey" json:"id"`
	Label     string    `gorm:"not null" json:"label"`
	StartsAt  time.Time `gorm:"not null;index:idx_known_events_account_range" json:"starts_at"`
	EndsAt    time.Time `gorm:"not null;index:idx_known_events_account_range" json:"ends_at"`
}

func (StoredKnownEvent) TableName() string { return "karst_known_events" }

type Store struct {
	db *gorm.DB
}

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("known events: nil database")
	}
	if err := db.AutoMigrate(&StoredKnownEvent{}); err != nil {
		return nil, fmt.Errorf("known events: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Create(ctx context.Context, entry Entry) (*StoredKnownEvent, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	validated, err := entry.validate()
	if err != nil {
		return nil, err
	}
	record := &StoredKnownEvent{
		AccountID: accountID,
		ID:        xid.New().String(),
		Label:     validated.Label,
		StartsAt:  validated.StartsAt.UTC(),
		EndsAt:    validated.EndsAt.UTC(),
	}
	if err := s.db.WithContext(ctx).Create(record).Error; err != nil {
		return nil, fmt.Errorf("known events: create: %w", err)
	}
	return record, nil
}

// List returns the account's own known events, ordered by StartsAt.
func (s *Store) List(ctx context.Context) ([]StoredKnownEvent, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var records []StoredKnownEvent
	if err := s.db.WithContext(ctx).Where("account_id = ?", accountID).Order("starts_at").Find(&records).Error; err != nil {
		return nil, fmt.Errorf("known events: list: %w", err)
	}
	return records, nil
}

func (s *Store) Delete(ctx context.Context, id string) error {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return err
	}
	result := s.db.WithContext(ctx).Where("account_id = ? AND id = ?", accountID, id).Delete(&StoredKnownEvent{})
	if result.Error != nil {
		return fmt.Errorf("known events: delete: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}
