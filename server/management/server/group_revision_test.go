// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package server

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/stretchr/testify/require"
)

func TestGroupUpdateRejectsStaleRevision(t *testing.T) {
	am, _, err := createManager(t)
	require.NoError(t, err)
	_, account, err := initTestGroupAccount(am)
	require.NoError(t, err)
	group := &types.Group{Name: "Optimistic editing", Issued: types.GroupIssuedAPI}
	require.NoError(t, am.CreateGroup(context.Background(), account.Id, groupAdminUserID, group))
	original, err := am.GetGroup(context.Background(), account.Id, group.ID, groupAdminUserID)
	require.NoError(t, err)
	revision := types.GroupRevision(original)
	changed := original.Copy()
	changed.Name = "Renamed by another admin"
	require.NoError(t, am.UpdateGroup(types.WithGroupRevision(context.Background(), revision), account.Id, groupAdminUserID, changed))
	stale := original.Copy()
	stale.Name = "Stale name"
	err = am.UpdateGroup(types.WithGroupRevision(context.Background(), revision), account.Id, groupAdminUserID, stale)
	var conflict *status.Error
	require.ErrorAs(t, err, &conflict)
	require.Equal(t, status.PreconditionFailed, conflict.Type())
	current, err := am.GetGroup(context.Background(), account.Id, group.ID, groupAdminUserID)
	require.NoError(t, err)
	require.Equal(t, changed.Name, current.Name)
	// Existing API clients without If-Match retain their compatibility behavior.
	require.NoError(t, am.UpdateGroup(context.Background(), account.Id, groupAdminUserID, stale))
}
