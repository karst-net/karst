// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package relayservice stores explicit Ponor/TURN associations (ADR-0056).
// It does not infer associations from endpoints, regions, or providers and
// does not copy credentials or identity keys into the service record.
package relayservice

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	"github.com/netbirdio/netbird/management/internals/karst/turncred"
)

var (
	ErrNoAccount = errors.New("relay service: account scope missing")
	ErrInvalid   = errors.New("relay service: invalid association")
	ErrExists    = errors.New("relay service: service already exists")
	ErrNotFound  = errors.New("relay service: service not found")
)

type accountKey struct{}

func WithAccount(ctx context.Context, account string) context.Context {
	return context.WithValue(ctx, accountKey{}, account)
}

func accountFromContext(ctx context.Context) (string, error) {
	account, _ := ctx.Value(accountKey{}).(string)
	if strings.TrimSpace(account) == "" {
		return "", ErrNoAccount
	}
	return account, nil
}

// Service has its own stable operator-selected ID, independent of protocol
// identities. TURN is optional. Multiple Ponor services may explicitly refer
// to the same TURN backend; this preserves the shared-host fallback topology.
// BackendKind describes deployment ownership, not a claim of runtime health
// or authority to stop an external process.
type Service struct {
	AccountID       string `gorm:"primaryKey;size:64" json:"-"`
	ID              string `gorm:"primaryKey;size:64" json:"id"`
	PonorID         string `gorm:"not null" json:"ponor_id"`
	TurnID          string `json:"turn_id,omitempty"`
	BackendKind     string `json:"backend_kind,omitempty"`
	BackendOperator string `json:"backend_operator,omitempty"`
}

func (Service) TableName() string { return "karst_relay_services" }

// View keeps configuration availability separate for each protocol. Present
// means the referenced registry record exists, not that a health probe passed.
// Legacy registry deletion can leave an association dangling; retain it for
// diagnosis instead of silently reassigning the service to a different backend.
type View struct {
	Service
	PonorPresent bool `json:"ponor_present"`
	TurnPresent  bool `json:"turn_present"`
}

type Store struct{ db *gorm.DB }

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("relay service: nil database")
	}
	if err := db.AutoMigrate(&Service{}); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

var validID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func validate(service Service) error {
	if !validID.MatchString(service.ID) || service.PonorID == "" {
		return fmt.Errorf("%w: id must be 1-64 letters, digits, underscores or hyphens and ponor_id is required", ErrInvalid)
	}
	if service.TurnID == "" {
		if service.BackendKind != "" || service.BackendOperator != "" {
			return fmt.Errorf("%w: backend metadata requires turn_id", ErrInvalid)
		}
		return nil
	}
	if service.BackendKind != "external" && service.BackendKind != "coturn-companion" {
		return fmt.Errorf("%w: backend_kind must be external or coturn-companion", ErrInvalid)
	}
	if strings.TrimSpace(service.BackendOperator) == "" || len(service.BackendOperator) > 256 {
		return fmt.Errorf("%w: backend_operator must identify the operator in 1-256 bytes", ErrInvalid)
	}
	return nil
}

// Create validates references in the caller's account. No endpoint is
// published, credential minted, or backend process changed by association.
func (s *Store) Create(ctx context.Context, service Service) (*Service, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	// Never accept account ownership from a caller-supplied record.
	service.AccountID = account
	if err := validate(service); err != nil {
		return nil, err
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&relayreg.StoredRelay{}).Where("account_id = ? AND id = ?", account, service.PonorID).Count(&count).Error; err != nil {
			return err
		}
		if count != 1 {
			return fmt.Errorf("%w: ponor_id is not registered in this account", ErrInvalid)
		}
		if service.TurnID != "" {
			if err := tx.Model(&turncred.StoredTurnServer{}).Where("account_id = ? AND id = ?", account, service.TurnID).Count(&count).Error; err != nil {
				return err
			}
			if count != 1 {
				return fmt.Errorf("%w: turn_id is not registered in this account", ErrInvalid)
			}
		}
		result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&service)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrExists
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &service, nil
}

func (s *Store) List(ctx context.Context) ([]View, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]View, 0)
	// Account equality is part of both joins, even when protocol IDs happen
	// to be identical across tenants. No telemetry or credentials are joined.
	err = s.db.WithContext(ctx).Table("karst_relay_services AS service").
		Select("service.*, ponor.id IS NOT NULL AS ponor_present, turn_backend.id IS NOT NULL AS turn_present").
		Joins("LEFT JOIN karst_relays AS ponor ON ponor.account_id = service.account_id AND ponor.id = service.ponor_id").
		Joins("LEFT JOIN karst_turn_servers AS turn_backend ON turn_backend.account_id = service.account_id AND turn_backend.id = service.turn_id").
		Where("service.account_id = ?", account).Order("service.id").Scan(&views).Error
	return views, err
}

// Delete removes only the association. In particular it cannot stop an
// external TURN provider or delete a shared backend's legacy registry record.
func (s *Store) Delete(ctx context.Context, id string) error {
	account, err := accountFromContext(ctx)
	if err != nil {
		return err
	}
	result := s.db.WithContext(ctx).Where("account_id = ? AND id = ?", account, id).Delete(&Service{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}
