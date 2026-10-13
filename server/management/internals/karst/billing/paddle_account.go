// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package billing

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrPaddleAccountNotConfigured = errors.New("billing: Paddle account is not explicitly configured")

type paddleAccountRow struct {
	AccountID  string    `gorm:"primaryKey;size:128"`
	Enabled    bool      `gorm:"not null;default:false"`
	CustomerID string    `gorm:"size:30"`
	ProductID  string    `gorm:"size:30"`
	UpdatedAt  time.Time `gorm:"not null"`
}

func (paddleAccountRow) TableName() string { return "karst_billing_paddle_accounts" }

// PaddleAccount contains only non-secret provider identifiers. API and
// webhook credentials remain deployment secrets and are never stored here.
type PaddleAccount struct {
	AccountID  string    `json:"account_id"`
	Enabled    bool      `json:"enabled"`
	CustomerID string    `json:"customer_id,omitempty"`
	ProductID  string    `json:"product_id,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ConfigurePaddleAccount is an explicit per-account opt-in. A missing row or
// disabled row never queues payment work, even when global Paddle credentials
// exist. Disabling preserves provider references for audit and reactivation.
func (s *Store) ConfigurePaddleAccount(ctx context.Context, enabled bool, customerID, productID string) (PaddleAccount, error) {
	accountID, err := billingAccountFromContext(ctx)
	if err != nil {
		return PaddleAccount{}, err
	}
	if enabled && (!validPaddleID(customerID, "ctm_") || !validPaddleID(productID, "pro_")) {
		return PaddleAccount{}, ErrInvalidPaddleInvoice
	}
	if !enabled {
		if customerID != "" && !validPaddleID(customerID, "ctm_") {
			return PaddleAccount{}, ErrInvalidPaddleInvoice
		}
		if productID != "" && !validPaddleID(productID, "pro_") {
			return PaddleAccount{}, ErrInvalidPaddleInvoice
		}
	}
	row := paddleAccountRow{AccountID: accountID, Enabled: enabled, CustomerID: customerID, ProductID: productID, UpdatedAt: time.Now().UTC()}
	if !enabled {
		var existing paddleAccountRow
		err := s.db.WithContext(ctx).First(&existing, "account_id = ?", accountID).Error
		if err == nil {
			row.CustomerID, row.ProductID = existing.CustomerID, existing.ProductID
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return PaddleAccount{}, err
		}
	}
	if err := s.db.WithContext(ctx).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "account_id"}}, DoUpdates: clause.AssignmentColumns([]string{"enabled", "customer_id", "product_id", "updated_at"})}).Create(&row).Error; err != nil {
		return PaddleAccount{}, err
	}
	return PaddleAccount{AccountID: row.AccountID, Enabled: row.Enabled, CustomerID: row.CustomerID, ProductID: row.ProductID, UpdatedAt: row.UpdatedAt}, nil
}

func (s *Store) PaddleAccount(ctx context.Context) (PaddleAccount, error) {
	accountID, err := billingAccountFromContext(ctx)
	if err != nil {
		return PaddleAccount{}, err
	}
	var row paddleAccountRow
	if err := s.db.WithContext(ctx).First(&row, "account_id = ? AND enabled = ?", accountID, true).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		return PaddleAccount{}, ErrPaddleAccountNotConfigured
	} else if err != nil {
		return PaddleAccount{}, err
	}
	return PaddleAccount{AccountID: row.AccountID, Enabled: row.Enabled, CustomerID: row.CustomerID, ProductID: row.ProductID, UpdatedAt: row.UpdatedAt}, nil
}
