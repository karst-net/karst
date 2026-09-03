// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package main

import (
	"testing"

	nbserver "github.com/netbirdio/netbird/management/internals/server"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
)

func TestCheckLegacyTurnConfig(t *testing.T) {
	t.Run("nil server config", func(t *testing.T) {
		if err := checkLegacyTurnConfig(nil); err != nil {
			t.Fatalf("nil *nbserver.Config: got %v, want nil", err)
		}
	})

	t.Run("nil NbConfig", func(t *testing.T) {
		if err := checkLegacyTurnConfig(&nbserver.Config{}); err != nil {
			t.Fatalf("nil NbConfig: got %v, want nil", err)
		}
	})

	t.Run("no turn block", func(t *testing.T) {
		cfg := &nbserver.Config{NbConfig: &nbconfig.Config{}}
		if err := checkLegacyTurnConfig(cfg); err != nil {
			t.Fatalf("no TURNConfig: got %v, want nil", err)
		}
	})

	t.Run("inert placeholder block, as bootstrap.sh writes", func(t *testing.T) {
		cfg := &nbserver.Config{NbConfig: &nbconfig.Config{
			TURNConfig: &nbconfig.TURNConfig{Secret: "s", TimeBasedCredentials: false},
		}}
		if err := checkLegacyTurnConfig(cfg); err != nil {
			t.Fatalf("inert block (TimeBasedCredentials=false, no Turns): got %v, want nil", err)
		}
	})

	t.Run("time-based credentials enabled", func(t *testing.T) {
		cfg := &nbserver.Config{NbConfig: &nbconfig.Config{
			TURNConfig: &nbconfig.TURNConfig{Secret: "s", TimeBasedCredentials: true},
		}}
		if err := checkLegacyTurnConfig(cfg); err == nil {
			t.Fatal("TimeBasedCredentials=true: got nil error, want a rejection")
		}
	})

	t.Run("turn servers listed", func(t *testing.T) {
		cfg := &nbserver.Config{NbConfig: &nbconfig.Config{
			TURNConfig: &nbconfig.TURNConfig{Turns: []*nbconfig.Host{{URI: "turn:example.com:3478"}}},
		}}
		if err := checkLegacyTurnConfig(cfg); err == nil {
			t.Fatal("non-empty Turns: got nil error, want a rejection")
		}
	})
}
