// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package relayservice stores an explicit, operator-selected Ponor
// association (ADR-0056). It does not infer associations from endpoints,
// regions, or providers and does not copy credentials or identity keys into
// the service record.
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

// Service has its own stable operator-selected ID, independent of the
// Ponor relay's own identity.
type Service struct {
	Revision      uint64   `gorm:"not null;default:0" json:"revision,omitempty"`
	AccessManaged bool     `gorm:"not null;default:false" json:"access_managed,omitempty"`
	AllowedGroups []string `gorm:"serializer:json" json:"allowed_groups,omitempty"`
	GatewayHandle string   `json:"gateway_handle,omitempty"`
	ExitIPv4      bool     `json:"exit_ipv4,omitempty"`
	ExitIPv6      bool     `json:"exit_ipv6,omitempty"`
	Metric        int      `json:"metric,omitempty"`

	AccountID     string `gorm:"primaryKey;size:64" json:"-"`
	ID            string `gorm:"primaryKey;size:64" json:"id"`
	PonorID       string `gorm:"not null" json:"ponor_id"`
	PonorDisabled bool   `gorm:"not null;default:false" json:"ponor_disabled,omitempty"`
}

func (Service) TableName() string { return "karst_relay_services" }

// View keeps configuration availability separate from the record itself.
// Present means the referenced registry record exists, not that a health
// probe passed. Legacy registry deletion can leave an association dangling;
// retain it for diagnosis instead of silently reassigning the service to a
// different backend.
type View struct {
	Service
	PonorPresent bool `json:"ponor_present"`
}

type Store struct {
	db              *gorm.DB
	LifecycleAgents interface {
		CheckRelayLifecycle(context.Context, string, *gorm.DB) error
	}
}

func NewStore(db *gorm.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("relay service: nil database")
	}
	if err := db.AutoMigrate(&Service{}, &Publication{}, &AdmissionLease{}, &BackendAccess{}); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

var validID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func validate(service Service) error {
	if !service.AccessManaged && (len(service.AllowedGroups) > 0 || service.GatewayHandle != "" || service.ExitIPv4 || service.ExitIPv6) {
		return fmt.Errorf("%w: access settings require managed admission", ErrInvalid)
	}
	if !validID.MatchString(service.ID) || service.PonorID == "" {
		return fmt.Errorf("%w: id must be 1-64 letters, digits, underscores or hyphens and ponor_id is required", ErrInvalid)
	}
	return nil
}

// Create validates references in the caller's account. In service publication
// mode the association contributes endpoints to future netmaps. Credentials
// are minted separately and no backend process is changed.
func (s *Store) Create(ctx context.Context, service Service) (*Service, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	// Never accept account ownership from a caller-supplied record.
	service.AccountID = account
	service.Revision = 1
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
		if !service.AccessManaged {
			var locked int64
			if err := tx.Model(&BackendAccess{}).Where("account_id = ? AND relay_id = ?", account, service.PonorID).Count(&locked).Error; err != nil {
				return err
			}
			if locked > 0 {
				return fmt.Errorf("%w: backend requires explicit group access", ErrInvalid)
			}
		}
		if err := s.configureAccess(ctx, tx, service); err != nil {
			return err
		}
		result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&service)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrExists
		}
		mode, err := publication(tx, account)
		if err != nil {
			return err
		}
		if mode.Mode == "services" {
			_, _, err = project(tx, account, true)
		}
		if err != nil {
			return err
		}
		return s.protectModeSchema(ctx, tx, account, mode)
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
	// Account equality is part of the join, even when protocol IDs happen to
	// be identical across tenants. No telemetry or credentials are joined.
	err = s.db.WithContext(ctx).Table("karst_relay_services AS service").
		Select("service.*, ponor.id IS NOT NULL AS ponor_present").
		Joins("LEFT JOIN karst_relays AS ponor ON ponor.account_id = service.account_id AND ponor.id = service.ponor_id").
		Where("service.account_id = ?", account).Order("service.id").Scan(&views).Error
	if err != nil {
		return nil, err
	}
	return views, nil
}

// Delete removes only the association. In particular it cannot delete a
// shared backend's legacy registry record.
func (s *Store) Delete(ctx context.Context, id string) error {
	account, err := accountFromContext(ctx)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current Service
		if err := tx.Where("account_id = ? AND id = ?", account, id).First(&current).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return ErrNotFound
			}
			return err
		}
		if err := clearManagedExit(tx, current); err != nil {
			return err
		}
		if current.AccessManaged {
			access := BackendAccess{AccountID: account, RelayID: current.PonorID, Groups: []string{}}
			if err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&access).Error; err != nil {
				return err
			}
		}
		return tx.Where("account_id = ? AND id = ?", account, id).Delete(&Service{}).Error
	})
}
