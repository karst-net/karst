// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package bootstrap

import "errors"

func validatePaddleMode(enabled, sandbox, liveApproved bool) error {
	if enabled && !sandbox && !liveApproved {
		return errors.New("karst: live Paddle collection requires KARST_PADDLE_LIVE_APPROVED=true")
	}
	return nil
}
