// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ComplianceDraftVersion is an immutable, tenant-scoped guardrail-draft
// revision (#363, ADR-0055). Unlike Version's raw HuJSON document, this
// stores structured JSON: ComplianceDraft is a Go struct the wire layer never
// serializes as an editable document today.
type ComplianceDraftVersion struct {
	AccountID string `gorm:"primaryKey;size:64"`
	Version   uint64 `gorm:"primaryKey;autoIncrement:false"`
	DraftJSON string `gorm:"not null"`
	Author    string `gorm:"not null"`
	CreatedAt time.Time
}

func (ComplianceDraftVersion) TableName() string { return "karst_compliance_draft_versions" }

// Draft deserializes the stored JSON. A version that failed to write never
// reaches a reader, so a decode error here means stored data has changed
// shape incompatibly, not a request-time condition to recover from.
func (v *ComplianceDraftVersion) Draft() (ComplianceDraft, error) {
	var draft ComplianceDraft
	if err := json.Unmarshal([]byte(v.DraftJSON), &draft); err != nil {
		return ComplianceDraft{}, fmt.Errorf("policy: decode compliance draft: %w", err)
	}
	return draft, nil
}

type ComplianceDraftStore struct{ db *gorm.DB }

func NewComplianceDraftStore(db *gorm.DB) (*ComplianceDraftStore, error) {
	if db == nil {
		return nil, errors.New("policy: nil database")
	}
	if err := db.AutoMigrate(&ComplianceDraftVersion{}); err != nil {
		return nil, fmt.Errorf("policy: migrate compliance draft: %w", err)
	}
	return &ComplianceDraftStore{db: db}, nil
}

func (s *ComplianceDraftStore) Current(ctx context.Context) (*ComplianceDraftVersion, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var version ComplianceDraftVersion
	if err := s.db.WithContext(ctx).Where("account_id = ?", accountID).Order("version DESC").First(&version).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNoVersion
		}
		return nil, fmt.Errorf("policy: compliance draft current: %w", err)
	}
	return &version, nil
}

func (s *ComplianceDraftStore) Get(ctx context.Context, number uint64) (*ComplianceDraftVersion, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var version ComplianceDraftVersion
	if err := s.db.WithContext(ctx).Where("account_id = ? AND version = ?", accountID, number).First(&version).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNoVersion
		}
		return nil, err
	}
	return &version, nil
}

func (s *ComplianceDraftStore) List(ctx context.Context, offset, limit int) ([]ComplianceDraftVersion, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var versions []ComplianceDraftVersion
	if err := s.db.WithContext(ctx).Where("account_id = ?", accountID).Order("version DESC").Offset(offset).Limit(limit).Find(&versions).Error; err != nil {
		return nil, err
	}
	return versions, nil
}

// Write appends a new immutable version if expected is current. Unlike
// Store.Write, it does not validate the draft itself — ValidateComplianceDraft
// needs the account's identity Document and device inventory, neither of
// which this package's store layer has access to; the caller validates
// before calling Write, exactly as policyWrite calls validateRegistryGrants
// before policy.Store.Write.
func (s *ComplianceDraftStore) Write(ctx context.Context, draft ComplianceDraft, author string, expected uint64) (*ComplianceDraftVersion, error) {
	accountID, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if draft.TenantID != accountID {
		return nil, fmt.Errorf("policy: compliance draft tenant %q does not match account scope %q", draft.TenantID, accountID)
	}
	data, err := json.Marshal(draft)
	if err != nil {
		return nil, fmt.Errorf("policy: encode compliance draft: %w", err)
	}
	var written ComplianceDraftVersion
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current ComplianceDraftVersion
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
		written = ComplianceDraftVersion{AccountID: accountID, Version: current.Version + 1, DraftJSON: string(data), Author: author, CreatedAt: time.Now().UTC()}
		// Same race as policy.Store.Write: two requests can read the same
		// current revision before either inserts. The composite primary key
		// decides that race; translate the losing insert into the contract's
		// version-conflict response.
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

// CurrentDraft adapts the store to control.PermitHandler's Draft field type:
// func(ctx, tenantID) (ComplianceDraft, revision string, err error). It
// returns an empty, unconfigured draft (revision "") on ErrNoVersion rather
// than an error, matching PermitHandler's own "no persisted draft yet" shape.
// The version number itself is the revision: it is already unique,
// monotonic and account-scoped, so a separate revision token would be a
// second moving part tracking the same fact.
func (s *ComplianceDraftStore) CurrentDraft(ctx context.Context, tenantID string) (ComplianceDraft, string, error) {
	version, err := s.Current(WithAccount(ctx, tenantID))
	if errors.Is(err, ErrNoVersion) {
		return ComplianceDraft{}, "", nil
	}
	if err != nil {
		return ComplianceDraft{}, "", err
	}
	draft, err := version.Draft()
	if err != nil {
		return ComplianceDraft{}, "", err
	}
	return draft, strconv.FormatUint(version.Version, 10), nil
}
