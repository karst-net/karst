// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package manager

import (
	"context"
	"testing"

	"github.com/rs/xid"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/mock_server"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

const testAccountID = "test-account-id"

// setupTest wires a real store and a real permissions.Manager against it,
// rather than mocking permission decisions -- ADR-0032's delegated-admin
// behavior is exactly the thing worth exercising for real here, not
// stubbing out.
func setupTest(t *testing.T) (Manager, store.Store, func()) {
	t.Helper()
	ctx := context.Background()
	testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)

	require.NoError(t, testStore.SaveAccount(ctx, &types.Account{Id: testAccountID}))

	owner := types.NewAdminUser("owner")
	owner.AccountID = testAccountID
	owner.Role = types.UserRoleOwner
	require.NoError(t, testStore.SaveUser(ctx, owner))

	member := types.NewRegularUser("member", "", "")
	member.AccountID = testAccountID
	require.NoError(t, testStore.SaveUser(ctx, member))

	permissionsManager := permissions.NewManager(testStore)
	mgr := NewManager(testStore, &mock_server.MockAccountManager{}, permissionsManager)
	return mgr, testStore, cleanup
}

func TestCreateDomain_TopLevelRequiresAccountWideGrant(t *testing.T) {
	mgr, _, cleanup := setupTest(t)
	defer cleanup()
	ctx := context.Background()

	_, err := mgr.CreateDomain(ctx, testAccountID, "member", "", "acme")
	require.Error(t, err, "an ordinary member has no domain-scoped grant to fall back to for a root domain")

	d, err := mgr.CreateDomain(ctx, testAccountID, "owner", "", "acme")
	require.NoError(t, err)
	require.Equal(t, "acme", d.Path)
	require.Equal(t, "", d.ParentID)
}

func TestCreateDomain_SiblingLabelConflict(t *testing.T) {
	mgr, _, cleanup := setupTest(t)
	defer cleanup()
	ctx := context.Background()

	root, err := mgr.CreateDomain(ctx, testAccountID, "owner", "", "acme")
	require.NoError(t, err)
	_, err = mgr.CreateDomain(ctx, testAccountID, "owner", root.ID, "engineering")
	require.NoError(t, err)
	_, err = mgr.CreateDomain(ctx, testAccountID, "owner", root.ID, "engineering")
	require.Error(t, err, "two subdomains of the same parent cannot share a label")

	// A sibling at a different level may reuse the label with no conflict.
	otherRoot, err := mgr.CreateDomain(ctx, testAccountID, "owner", "", "beta")
	require.NoError(t, err)
	_, err = mgr.CreateDomain(ctx, testAccountID, "owner", otherRoot.ID, "engineering")
	require.NoError(t, err, "the same label under a different parent is not a conflict")
}

func TestCreateDomain_SubdomainPathNesting(t *testing.T) {
	mgr, _, cleanup := setupTest(t)
	defer cleanup()
	ctx := context.Background()

	root, err := mgr.CreateDomain(ctx, testAccountID, "owner", "", "acme")
	require.NoError(t, err)
	child, err := mgr.CreateDomain(ctx, testAccountID, "owner", root.ID, "engineering")
	require.NoError(t, err)
	require.Equal(t, "engineering.acme", child.Path)
	grandchild, err := mgr.CreateDomain(ctx, testAccountID, "owner", child.ID, "backend")
	require.NoError(t, err)
	require.Equal(t, "backend.engineering.acme", grandchild.Path)
}

func TestCreateDomain_RejectsInvalidLabel(t *testing.T) {
	mgr, _, cleanup := setupTest(t)
	defer cleanup()
	ctx := context.Background()

	_, err := mgr.CreateDomain(ctx, testAccountID, "owner", "", "!!!")
	require.Error(t, err)
}

func TestListDomains_DelegatedAdminSeesOnlyTheirSubtree(t *testing.T) {
	mgr, _, cleanup := setupTest(t)
	defer cleanup()
	ctx := context.Background()

	root, err := mgr.CreateDomain(ctx, testAccountID, "owner", "", "acme")
	require.NoError(t, err)
	engineering, err := mgr.CreateDomain(ctx, testAccountID, "owner", root.ID, "engineering")
	require.NoError(t, err)
	backend, err := mgr.CreateDomain(ctx, testAccountID, "owner", engineering.ID, "backend")
	require.NoError(t, err)
	sales, err := mgr.CreateDomain(ctx, testAccountID, "owner", root.ID, "sales")
	require.NoError(t, err)

	// No account-wide grant and no delegation at all: refused outright, not
	// just handed an empty list -- those are different facts to a caller.
	_, err = mgr.ListDomains(ctx, testAccountID, "member")
	require.Error(t, err)

	_, err = mgr.DelegateDomainAdmin(ctx, testAccountID, "owner", engineering.ID, "member")
	require.NoError(t, err)

	visible, err := mgr.ListDomains(ctx, testAccountID, "member")
	require.NoError(t, err)
	ids := make([]string, len(visible))
	for i, d := range visible {
		ids[i] = d.ID
	}
	require.ElementsMatch(t, []string{engineering.ID, backend.ID}, ids, "sees its own delegated domain and its descendant, not its parent or its unrelated sibling")
	require.NotContains(t, ids, root.ID)
	require.NotContains(t, ids, sales.ID)

	// The owner is unaffected by any of this: always the full list.
	all, err := mgr.ListDomains(ctx, testAccountID, "owner")
	require.NoError(t, err)
	require.Len(t, all, 4)
}

func TestGetDomain_DelegatedAdminCanReadTheirOwnSubtree(t *testing.T) {
	mgr, _, cleanup := setupTest(t)
	defer cleanup()
	ctx := context.Background()

	root, err := mgr.CreateDomain(ctx, testAccountID, "owner", "", "acme")
	require.NoError(t, err)
	engineering, err := mgr.CreateDomain(ctx, testAccountID, "owner", root.ID, "engineering")
	require.NoError(t, err)

	_, err = mgr.GetDomain(ctx, testAccountID, "member", engineering.ID)
	require.Error(t, err)

	_, err = mgr.DelegateDomainAdmin(ctx, testAccountID, "owner", engineering.ID, "member")
	require.NoError(t, err)

	got, err := mgr.GetDomain(ctx, testAccountID, "member", engineering.ID)
	require.NoError(t, err)
	require.Equal(t, engineering.ID, got.ID)

	_, err = mgr.GetDomain(ctx, testAccountID, "member", root.ID)
	require.Error(t, err, "a delegated admin cannot read their own parent domain")
}

func TestDeleteDomain_RefusesWithChildrenOrMembers(t *testing.T) {
	mgr, testStore, cleanup := setupTest(t)
	defer cleanup()
	ctx := context.Background()

	root, err := mgr.CreateDomain(ctx, testAccountID, "owner", "", "acme")
	require.NoError(t, err)
	child, err := mgr.CreateDomain(ctx, testAccountID, "owner", root.ID, "engineering")
	require.NoError(t, err)

	require.Error(t, mgr.DeleteDomain(ctx, testAccountID, "owner", root.ID), "a domain with a subdomain cannot be deleted")

	require.NoError(t, mgr.DeleteDomain(ctx, testAccountID, "owner", child.ID))
	require.NoError(t, mgr.DeleteDomain(ctx, testAccountID, "owner", root.ID), "now empty, deletion succeeds")

	root2, err := mgr.CreateDomain(ctx, testAccountID, "owner", "", "beta")
	require.NoError(t, err)
	require.NoError(t, testStore.AddPeerToAccount(ctx, &nbpeer.Peer{
		ID: xid.New().String(), AccountID: testAccountID, Key: "peer-key", DNSLabel: "device.beta", DomainID: root2.ID,
	}))
	require.Error(t, mgr.DeleteDomain(ctx, testAccountID, "owner", root2.ID), "a domain with a member peer cannot be deleted")
}

func TestDelegateDomainAdmin_GrantsScopedAccessOnly(t *testing.T) {
	mgr, _, cleanup := setupTest(t)
	defer cleanup()
	ctx := context.Background()

	root, err := mgr.CreateDomain(ctx, testAccountID, "owner", "", "acme")
	require.NoError(t, err)
	engineering, err := mgr.CreateDomain(ctx, testAccountID, "owner", root.ID, "engineering")
	require.NoError(t, err)
	sales, err := mgr.CreateDomain(ctx, testAccountID, "owner", root.ID, "sales")
	require.NoError(t, err)

	_, err = mgr.DelegateDomainAdmin(ctx, testAccountID, "member", engineering.ID, "member")
	require.Error(t, err, "member has no domain-scoped grant yet to delegate from")

	binding, err := mgr.DelegateDomainAdmin(ctx, testAccountID, "owner", engineering.ID, "member")
	require.NoError(t, err)

	// The delegated admin can now manage their own subtree...
	backend, err := mgr.CreateDomain(ctx, testAccountID, "member", engineering.ID, "backend")
	require.NoError(t, err)
	require.Equal(t, "backend.engineering.acme", backend.Path)

	// ...and can deputize another admin for their own subtree...
	sub, err := mgr.DelegateDomainAdmin(ctx, testAccountID, "member", backend.ID, "member")
	require.NoError(t, err)
	require.NotEmpty(t, sub.ID)

	// ...but cannot reach a sibling subtree they were not delegated.
	_, err = mgr.CreateDomain(ctx, testAccountID, "member", sales.ID, "eu")
	require.Error(t, err, "a delegated admin must not reach outside their own subtree")

	// Revoking the binding removes the delegated access.
	require.NoError(t, mgr.RevokeDomainDelegation(ctx, testAccountID, "owner", binding.ID))
	_, err = mgr.CreateDomain(ctx, testAccountID, "member", engineering.ID, "frontend")
	require.Error(t, err, "revoked delegation must no longer grant access")
}

func TestListDelegations(t *testing.T) {
	mgr, testStore, cleanup := setupTest(t)
	defer cleanup()
	ctx := context.Background()

	other := types.NewRegularUser("outsider", "", "")
	other.AccountID = testAccountID
	require.NoError(t, testStore.SaveUser(ctx, other))

	root, err := mgr.CreateDomain(ctx, testAccountID, "owner", "", "acme")
	require.NoError(t, err)
	_, err = mgr.DelegateDomainAdmin(ctx, testAccountID, "owner", root.ID, "member")
	require.NoError(t, err)

	list, err := mgr.ListDelegations(ctx, testAccountID, "owner", root.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, "member", list[0].UserID)

	// The delegate themself can see who administers their own domain...
	list, err = mgr.ListDelegations(ctx, testAccountID, "member", root.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)

	// ...but an account member with no relationship to this domain cannot.
	_, err = mgr.ListDelegations(ctx, testAccountID, "outsider", root.ID)
	require.Error(t, err, "an unrelated member has no read access to this domain's delegations")
}
