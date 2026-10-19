// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package manager

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/stretchr/testify/require"
)

func TestRootRenameRequiresAccountWideAuthority(t *testing.T) {
	ctx := context.Background()
	mgr, s, cleanup := setupTest(t)
	defer cleanup()
	require.NoError(t, s.(*store.SqlStore).InitializeMeshDomains(ctx, ""))
	root, err := s.GetAccountRootDomain(ctx, store.LockingStrengthNone, testAccountID)
	require.NoError(t, err)
	_, err = mgr.PreviewRootRename(ctx, testAccountID, "member", "corp.example")
	require.Error(t, err)
	// Even administration delegated at the root is not account-wide authority.
	_, err = mgr.DelegateDomainAdmin(ctx, testAccountID, "owner", root.ID, "member")
	require.NoError(t, err)
	_, err = mgr.PreviewRootRename(ctx, testAccountID, "member", "corp.example")
	require.Error(t, err)
	preview, err := mgr.PreviewRootRename(ctx, testAccountID, "owner", "corp.example")
	require.NoError(t, err)
	_, err = mgr.CommitRootRename(ctx, testAccountID, "member", "corp.example", preview.Revision)
	require.Error(t, err)
	_, err = mgr.CommitRootRename(ctx, "another-account", "owner", "corp.example", preview.Revision)
	require.Error(t, err)
	// Ownership revoked between preview and confirmation must be rechecked.
	owner, err := s.GetUserByUserID(ctx, store.LockingStrengthNone, "owner")
	require.NoError(t, err)
	owner.Role = types.UserRoleUser
	require.NoError(t, s.SaveUser(ctx, owner))
	_, err = mgr.CommitRootRename(ctx, testAccountID, "owner", "corp.example", preview.Revision)
	require.Error(t, err)
}

func TestRootRenameAuditsAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	mgr, s, cleanup := setupTest(t)
	defer cleanup()
	require.NoError(t, s.(*store.SqlStore).InitializeMeshDomains(ctx, ""))
	var events, publications int
	mgr.(*managerImpl).accountManager = &mock_server.MockAccountManager{
		StoreEventFunc: func(_ context.Context, actor, target, account string, event activity.ActivityDescriber, meta map[string]any) {
			events++
			require.Equal(t, "owner", actor)
			require.Equal(t, testAccountID, account)
			require.Equal(t, activity.MeshRootRenamed, event)
			require.Equal(t, "karst", meta["old_suffix"])
			require.Equal(t, "corp.example", meta["new_suffix"])
			require.Equal(t, uint64(1), meta["naming_revision"])
			root, err := s.GetAccountRootDomain(ctx, store.LockingStrengthNone, account)
			require.NoError(t, err)
			require.Equal(t, root.ID, target)
			require.Equal(t, "corp.example", root.DNSSuffix)
		},
		UpdateAccountPeersFunc: func(_ context.Context, account string, reason types.UpdateReason) {
			publications++
			require.Equal(t, testAccountID, account)
			require.Equal(t, types.UpdateResourceDNSSettings, reason.Resource)
		},
	}
	preview, err := mgr.PreviewRootRename(ctx, testAccountID, "owner", "corp.example")
	require.NoError(t, err)
	_, err = mgr.CommitRootRename(ctx, testAccountID, "owner", "corp.example", "stale")
	require.Error(t, err)
	require.Zero(t, events)
	require.Zero(t, publications)
	_, err = mgr.CommitRootRename(ctx, testAccountID, "owner", "corp.example", preview.Revision)
	require.NoError(t, err)
	require.Equal(t, 1, events)
	require.Equal(t, 1, publications)
	// Stable root identity is still used for default child placement.
	mgr.(*managerImpl).accountManager = &mock_server.MockAccountManager{}
	child, err := mgr.CreateDomain(ctx, testAccountID, "owner", "", "engineering")
	require.NoError(t, err)
	require.Equal(t, preview.RootID, child.ParentID)
	require.Equal(t, "engineering", child.Path)
}
