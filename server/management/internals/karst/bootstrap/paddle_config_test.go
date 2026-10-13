// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package bootstrap

import "testing"

func TestValidatePaddleMode(t *testing.T) {
	tests := []struct {
		name         string
		enabled      bool
		sandbox      bool
		liveApproved bool
		wantErr      bool
	}{
		{name: "disabled is inert"},
		{name: "enabled sandbox is allowed", enabled: true, sandbox: true},
		{name: "live mode requires explicit approval", enabled: true, wantErr: true},
		{name: "approved live mode is allowed", enabled: true, liveApproved: true},
		{name: "approval does not enable collection", liveApproved: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePaddleMode(test.enabled, test.sandbox, test.liveApproved)
			if (err != nil) != test.wantErr {
				t.Fatalf("validatePaddleMode() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
