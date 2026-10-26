// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/node"
	"github.com/netbirdio/netbird/management/internals/karst/roster"
	"github.com/stretchr/testify/require"
)

type installRosterSource struct{}

func (installRosterSource) All() ([]roster.Entry, error) {
	return []roster.Entry{{Identity: node.Identity{Handle: "allowed"}, AccountID: "account"}, {Identity: node.Identity{Handle: "denied"}, AccountID: "account"}, {Identity: node.Identity{Handle: "orphan"}}}, nil
}

type installAdmission struct{ fail bool }

func (installAdmission) AllowedOnRelay(context.Context, string, string, string) (bool, error) {
	return true, nil
}
func (s installAdmission) AllowedOnManagedRelay(_ context.Context, relay, account, handle string) (bool, error) {
	if s.fail {
		return false, errors.New("membership unavailable")
	}
	return relay == "relay" && account == "account" && handle == "allowed", nil
}
func TestInstallationRosterUsesManagedAuthorizationAndPropagatesFailure(t *testing.T) {
	source := scopedRelayRoster{source: installRosterSource{}, store: installAdmission{}, relayID: "relay", requireManaged: true}
	entries, err := source.All()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "allowed", entries[0].Handle)
	source.store = installAdmission{fail: true}
	entries, err = source.All()
	require.Error(t, err)
	require.Nil(t, entries)
	source.requireManaged = false
	entries, err = source.All()
	require.NoError(t, err)
	require.Len(t, entries, 2)
}
