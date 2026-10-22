// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package relayservice

import (
	"context"
	"fmt"
	"gorm.io/gorm"
)

func (s *Store) requireLifecycle(ctx context.Context, account string, transaction *gorm.DB) error {
	if s.LifecycleAgents == nil {
		return fmt.Errorf("%w: agent lifecycle capability tracking is not configured", ErrInvalid)
	}
	if err := s.LifecycleAgents.CheckRelayLifecycle(ctx, account, transaction); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalid, err)
	}
	return nil
}
