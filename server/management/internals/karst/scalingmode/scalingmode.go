// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package scalingmode stores issue #356's one deployment-wide,
// admin-switchable setting: whether karst-scaler's drive loop actuates
// automatically (ADR-0045 §7 Phase 2) or only computes and reports,
// leaving a human to act on it by hand (Phase 1). A single setting for
// the whole deployment, not one per pool (Spike 0002 §1: sizing is
// already per-pool, but actuation is one `drive` process reconciling
// every pool in one tick, so a per-pool mode would require splitting
// that for no signal anyone has asked for).
package scalingmode

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Mode is ADR-0045 §7's Phase 1/Phase 2 split as a live setting.
type Mode string

const (
	// ModeAutomated is Phase 2: drive reconciles through a Driver.
	ModeAutomated Mode = "automated"
	// ModeManual is Phase 1 behavior from drive: compute, don't act.
	ModeManual Mode = "manual"
)

// modeRow is the one deployment-wide mode setting. A fixed,
// always-present singleton row (ID always 1, never created a second
// time) — the same shape ephemeralanchor.scheduleRow already has for
// its own single deployment-wide value.
type modeRow struct {
	ID   uint8 `gorm:"primaryKey"`
	Mode string
}

func (modeRow) TableName() string { return "karst_scaling_mode" }

const modeRowID = 1

// Store is the scaling-mode singleton. Safe for concurrent use.
type Store struct {
	db *gorm.DB
}

// NewStore migrates and returns the scaling-mode store.
func NewStore(db *gorm.DB) (*Store, error) {
	if err := db.AutoMigrate(&modeRow{}); err != nil {
		return nil, fmt.Errorf("scaling mode: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// SetMode replaces the deployment's scaling mode. An upsert against the
// fixed singleton row, not an insert — the same clause.OnConflict
// pattern ephemeralanchor.Store.SetSchedule already uses for its own
// singleton.
func (s *Store) SetMode(ctx context.Context, mode Mode) error {
	row := modeRow{ID: modeRowID, Mode: string(mode)}
	if err := s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"mode"}),
	}).Create(&row).Error; err != nil {
		return fmt.Errorf("scaling mode: set: %w", err)
	}
	return nil
}

// Mode returns the deployment's current scaling mode, defaulting to
// ModeAutomated when no row has ever been written — every deployment
// running karst-scaler drive today gets Phase 2's unconditional
// reconcile with no setting at all, and a manual default would silently
// stop actuating for every one of them the moment it upgrades.
func (s *Store) Mode(ctx context.Context) (Mode, error) {
	var row modeRow
	if err := s.db.WithContext(ctx).Where("id = ?", modeRowID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ModeAutomated, nil
		}
		return "", fmt.Errorf("scaling mode: get: %w", err)
	}
	return Mode(row.Mode), nil
}
