// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package permissions

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/meshdomain"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

func TestValidateDomainScopedPermissionUsesStableIdentity(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	defer cleanup()
	require.NoError(t, s.SaveAccount(ctx, &types.Account{Id: "account"}))
	user := types.NewRegularUser("user", "", "")
	user.AccountID = "account"
	require.NoError(t, s.SaveUser(ctx, user))
	root := meshdomain.NewDomain("account", "", "root", "")
	engineering := meshdomain.NewDomain("account", root.ID, "engineering", root.Path)
	child := meshdomain.NewDomain("account", engineering.ID, "build", "completely-different")
	sibling := meshdomain.NewDomain("account", root.ID, "sibling", "cached-path")
	for _, d := range []*meshdomain.Domain{root, engineering, child, sibling} {
		require.NoError(t, s.CreateDomain(ctx, d))
	}
	// The cache intentionally claims a different subtree. Only the binding ID
	// and graph edges should contribute authority.
	binding := meshdomain.NewDomainRoleBinding("account", engineering.ID, "cached-path", user.Id)
	require.NoError(t, s.CreateDomainRoleBinding(ctx, binding))
	mgr := NewManager(s)
	for _, tc := range []struct {
		id      string
		allowed bool
	}{{engineering.ID, true}, {child.ID, true}, {sibling.ID, false}, {root.ID, false}, {"", false}, {"missing", false}} {
		allowed, _, err := mgr.ValidateDomainScopedPermission(ctx, "account", user.Id, tc.id, modules.Peers, operations.Update)
		require.NoError(t, err)
		require.Equal(t, tc.allowed, allowed, "domain %s", tc.id)
	}
	allowed, _, err := mgr.ValidateDomainScopedPermission(ctx, "account", user.Id, engineering.ID, modules.Policies, operations.Update)
	require.NoError(t, err)
	require.False(t, allowed, "domain administration cannot grant account-wide policy authority")

	require.NoError(t, s.DeleteDomainRoleBinding(ctx, "account", binding.ID))
	allowed, _, err = mgr.ValidateDomainScopedPermission(ctx, "account", user.Id, child.ID, modules.Peers, operations.Update)
	require.NoError(t, err)
	require.False(t, allowed, "a revoked binding must stop granting access")
}
