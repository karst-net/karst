// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package manager

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/management/internals/modules/meshdomain"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

// Manager administers an account's mesh-domain tree and its delegated
// sub-administration (ADR-0032).
type Manager interface {
	// CreateDomain creates a top-level domain (parentID == "") or a
	// subdomain (parentID naming an existing domain in the same account).
	// Account-wide Domains permission always suffices; a domain-scoped
	// delegated admin may create a subdomain under their own delegated
	// subtree even without the account-wide grant.
	CreateDomain(ctx context.Context, accountID, userID, parentID, label string) (*meshdomain.Domain, error)
	ListDomains(ctx context.Context, accountID, userID string) ([]*meshdomain.Domain, error)
	GetDomain(ctx context.Context, accountID, userID, domainID string) (*meshdomain.Domain, error)
	// DeleteDomain refuses a domain that still has subdomains or member
	// peers -- a domain tree unwinds leaf-first, like removing a directory.
	DeleteDomain(ctx context.Context, accountID, userID, domainID string) error

	// DelegateDomainAdmin grants targetUserID admin rights over domainID and
	// everything beneath it. Requires the same domain-scoped Update
	// permission a domain admin already has over that subtree -- a domain
	// admin can deputize another admin for their own subtree, but cannot
	// grant a scope wider than their own.
	DelegateDomainAdmin(ctx context.Context, accountID, userID, domainID, targetUserID string) (*meshdomain.DomainRoleBinding, error)
	RevokeDomainDelegation(ctx context.Context, accountID, userID, bindingID string) error
	ListDelegations(ctx context.Context, accountID, userID, domainID string) ([]*meshdomain.DomainRoleBinding, error)
}

type managerImpl struct {
	store              store.Store
	accountManager     account.Manager
	permissionsManager permissions.Manager
}

func NewManager(store store.Store, accountManager account.Manager, permissionsManager permissions.Manager) Manager {
	return &managerImpl{store: store, accountManager: accountManager, permissionsManager: permissionsManager}
}

func (m *managerImpl) CreateDomain(ctx context.Context, accountID, userID, parentID, label string) (*meshdomain.Domain, error) {
	var parent *meshdomain.Domain
	if parentID != "" {
		var err error
		parent, err = m.store.GetDomainByID(ctx, store.LockingStrengthNone, accountID, parentID)
		if err != nil {
			return nil, err
		}
	}

	parentPath := ""
	if parent != nil {
		parentPath = parent.Path
	}

	allowed, ctx, err := m.permissionsManager.ValidateDomainScopedPermission(ctx, accountID, userID, parentPath, modules.Domains, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	newDomain := meshdomain.NewDomain(accountID, parentID, label, parentPath)
	if err := newDomain.Validate(); err != nil {
		return nil, status.Errorf(status.InvalidArgument, "%s", err.Error())
	}

	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		siblings, err := transaction.GetAccountDomains(ctx, store.LockingStrengthNone, accountID)
		if err != nil {
			return fmt.Errorf("failed to check existing domains: %w", err)
		}
		for _, sibling := range siblings {
			if sibling.ParentID == parentID && sibling.Label == newDomain.Label {
				return status.Errorf(status.AlreadyExists, "a domain named %q already exists at this level", newDomain.Label)
			}
		}
		return transaction.CreateDomain(ctx, newDomain)
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, newDomain.ID, accountID, activity.MeshDomainCreated, newDomain.EventMeta())
	return newDomain, nil
}

func (m *managerImpl) ListDomains(ctx context.Context, accountID, userID string) ([]*meshdomain.Domain, error) {
	allowed, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Domains, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}
	return m.store.GetAccountDomains(ctx, store.LockingStrengthNone, accountID)
}

func (m *managerImpl) GetDomain(ctx context.Context, accountID, userID, domainID string) (*meshdomain.Domain, error) {
	allowed, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Domains, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}
	return m.store.GetDomainByID(ctx, store.LockingStrengthNone, accountID, domainID)
}

func (m *managerImpl) DeleteDomain(ctx context.Context, accountID, userID, domainID string) error {
	target, err := m.store.GetDomainByID(ctx, store.LockingStrengthNone, accountID, domainID)
	if err != nil {
		return err
	}

	allowed, ctx, err := m.permissionsManager.ValidateDomainScopedPermission(ctx, accountID, userID, target.Path, modules.Domains, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		all, err := transaction.GetAccountDomains(ctx, store.LockingStrengthNone, accountID)
		if err != nil {
			return fmt.Errorf("failed to check child domains: %w", err)
		}
		for _, d := range all {
			if d.ParentID == domainID {
				return status.Errorf(status.PreconditionFailed, "domain has subdomains; delete them first")
			}
		}
		members, err := transaction.GetDomainMemberCount(ctx, accountID, domainID)
		if err != nil {
			return fmt.Errorf("failed to check domain members: %w", err)
		}
		if members > 0 {
			return status.Errorf(status.PreconditionFailed, "domain still has %d device(s); move or remove them first", members)
		}
		return transaction.DeleteDomain(ctx, accountID, domainID)
	})
	if err != nil {
		return err
	}

	m.accountManager.StoreEvent(ctx, userID, target.ID, accountID, activity.MeshDomainDeleted, target.EventMeta())
	return nil
}

func (m *managerImpl) DelegateDomainAdmin(ctx context.Context, accountID, userID, domainID, targetUserID string) (*meshdomain.DomainRoleBinding, error) {
	target, err := m.store.GetDomainByID(ctx, store.LockingStrengthNone, accountID, domainID)
	if err != nil {
		return nil, err
	}

	// Update, not Create/Delete: delegating admin over a subtree is a change
	// to who administers it, and it is the same permission a domain admin
	// already needs to otherwise manage that subtree -- deliberately not a
	// wider grant than the delegator already holds there.
	allowed, ctx, err := m.permissionsManager.ValidateDomainScopedPermission(ctx, accountID, userID, target.Path, modules.Domains, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	grantee, err := m.store.GetUserByUserID(ctx, store.LockingStrengthNone, targetUserID)
	if err != nil {
		return nil, err
	}
	if grantee.AccountID != accountID || grantee.IsBlocked() || grantee.PendingApproval {
		return nil, status.Errorf(status.InvalidArgument, "target user is not an eligible member of this account")
	}

	binding := meshdomain.NewDomainRoleBinding(accountID, target.ID, target.Path, targetUserID)
	if err := m.store.CreateDomainRoleBinding(ctx, binding); err != nil {
		return nil, err
	}
	return binding, nil
}

func (m *managerImpl) RevokeDomainDelegation(ctx context.Context, accountID, userID, bindingID string) error {
	binding, err := m.store.GetDomainRoleBindingByID(ctx, accountID, bindingID)
	if err != nil {
		return err
	}

	allowed, ctx, err := m.permissionsManager.ValidateDomainScopedPermission(ctx, accountID, userID, binding.DomainPath, modules.Domains, operations.Update)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	return m.store.DeleteDomainRoleBinding(ctx, accountID, bindingID)
}

func (m *managerImpl) ListDelegations(ctx context.Context, accountID, userID, domainID string) ([]*meshdomain.DomainRoleBinding, error) {
	target, err := m.store.GetDomainByID(ctx, store.LockingStrengthNone, accountID, domainID)
	if err != nil {
		return nil, err
	}

	allowed, ctx, err := m.permissionsManager.ValidateDomainScopedPermission(ctx, accountID, userID, target.Path, modules.Domains, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetDomainRoleBindingsByDomain(ctx, accountID, domainID)
}
