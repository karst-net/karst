// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayservice

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// SetModes changes publication and probe participation, not backend processes.
// Both desired states are explicit. Active publication is validated in the
// transaction so a failed enable cannot leave a partially changed service.
func (s *Store) SetModes(ctx context.Context, id string, ponorEnabled, turnEnabled, turnConfigured bool) (*Service, error) {
	account, err := accountFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var service Service
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Where("account_id = ? AND id = ?", account, id).First(&service).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if turnEnabled && service.TurnID == "" {
			return fmt.Errorf("%w: service has no TURN backend", ErrInvalid)
		}
		service.PonorDisabled, service.TurnDisabled = !ponorEnabled, service.TurnID != "" && !turnEnabled
		if err := tx.Model(&Service{}).Where("account_id = ? AND id = ?", account, id).Updates(map[string]any{"ponor_disabled": service.PonorDisabled, "turn_disabled": service.TurnDisabled}).Error; err != nil {
			return err
		}
		mode, err := publication(tx, account)
		if err != nil {
			return err
		}
		if mode.Mode == "services" {
			_, _, turns, err := project(tx, account, true)
			if err != nil {
				return err
			}
			if len(turns) > 0 && !turnConfigured {
				return fmt.Errorf("%w: TURN credential minting is not configured", ErrInvalid)
			}
		}
		return protectModeSchema(tx, account, mode)
	})
	if err != nil {
		return nil, err
	}
	return &service, nil
}
