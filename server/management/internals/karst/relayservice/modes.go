// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayservice

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

// SetModes changes publication participation, not backend processes. The
// desired state is explicit. Active publication is validated in the
// transaction so a failed enable cannot leave a partially changed service.
func (s *Store) SetModes(ctx context.Context, id string, ponorEnabled bool) (*Service, error) {
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
		service.PonorDisabled = !ponorEnabled
		if err := tx.Model(&Service{}).Where("account_id = ? AND id = ?", account, id).Updates(map[string]any{"ponor_disabled": service.PonorDisabled}).Error; err != nil {
			return err
		}
		mode, err := publication(tx, account)
		if err != nil {
			return err
		}
		if mode.Mode == "services" {
			if err := s.requireLifecycle(ctx, account, tx); err != nil {
				return err
			}
			if _, _, err := project(tx, account, true); err != nil {
				return err
			}
		}
		return s.protectModeSchema(ctx, tx, account, mode)
	})
	if err != nil {
		return nil, err
	}
	return &service, nil
}
