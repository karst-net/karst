// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package meshdomain

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAdminScopeUsesIDsAndParents(t *testing.T) {
	root := &Domain{ID: "root", AccountID: "account", Path: ""}
	engineering := &Domain{ID: "engineering", AccountID: "account", ParentID: root.ID, Path: "renamed"}
	child := &Domain{ID: "child", AccountID: "account", ParentID: engineering.ID, Path: "no-dns-suffix-match"}
	sibling := &Domain{ID: "sibling", AccountID: "account", ParentID: root.ID, Path: "forged.cached-name"}
	binding := NewDomainRoleBinding("account", engineering.ID, "cached-name", "user")
	scope := NewAdminScope("account", "user", []*Domain{root, engineering, child, sibling}, []*DomainRoleBinding{binding})
	require.True(t, scope.Covers(engineering.ID), "a renamed path cannot remove the domain's own grant")
	require.True(t, scope.Covers(child.ID), "ancestry, not a DNS suffix, grants descendants")
	require.False(t, scope.Covers(sibling.ID), "a matching cached path cannot grant a sibling")
	require.False(t, scope.Covers(root.ID), "a child grant never covers the parent")
	require.False(t, scope.Covers(""), "the legacy implicit root remains account-wide only")

	// Scope is an operation-local snapshot, not an alias of mutable inputs.
	child.ParentID = sibling.ID
	binding.DomainID = sibling.ID
	require.True(t, scope.Covers(child.ID))
	require.False(t, scope.Covers(sibling.ID))
}

func TestAdminScopeExplicitRoot(t *testing.T) {
	root := &Domain{ID: "root", AccountID: "account", Path: ""}
	child := &Domain{ID: "child", AccountID: "account", ParentID: root.ID, Path: "engineering"}
	binding := NewDomainRoleBinding("account", root.ID, "", "user")
	scope := NewAdminScope("account", "user", []*Domain{root, child}, []*DomainRoleBinding{binding})
	require.True(t, scope.Covers(root.ID), "an explicit root can be delegated despite its empty relative path")
	require.True(t, scope.Covers(child.ID))
}

func TestAdminScopeRejectsInvalidAncestryAndBindings(t *testing.T) {
	for _, mode := range []string{"missing-parent", "foreign-parent", "cycle", "self-cycle", "deleted-binding", "recreated-path", "foreign-binding", "other-user-binding", "empty-binding"} {
		t.Run(mode, func(t *testing.T) {
			parent := &Domain{ID: "parent", AccountID: "account", Path: "engineering"}
			child := &Domain{ID: "child", AccountID: "account", ParentID: parent.ID, Path: "build.engineering"}
			binding := NewDomainRoleBinding("account", child.ID, child.Path, "user")
			switch mode {
			case "missing-parent":
				child.ParentID = "missing"
			case "foreign-parent":
				parent.AccountID = "another-account"
			case "cycle":
				parent.ParentID = child.ID
			case "self-cycle":
				child.ParentID = child.ID
			case "deleted-binding", "recreated-path":
				binding.DomainID = "deleted-domain-with-the-same-path"
			case "foreign-binding":
				binding.AccountID = "another-account"
			case "other-user-binding":
				binding.UserID = "another-user"
			case "empty-binding":
				binding.DomainID = ""
			}
			scope := NewAdminScope("account", "user", []*Domain{parent, child}, []*DomainRoleBinding{binding})
			require.False(t, scope.Covers(child.ID), "corrupt ancestry or stale bindings cannot grant access")
			require.False(t, scope.Covers("missing"))
		})
	}
}
