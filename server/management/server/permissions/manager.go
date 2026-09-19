package permissions

//go:generate go run github.com/golang/mock/mockgen -package permissions -destination=manager_mock.go -source=./manager.go -build_flags=-mod=mod

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/permissions/roles"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

type Manager interface {
	ValidateUserPermissions(ctx context.Context, accountID, userID string, module modules.Module, operation operations.Operation) (bool, context.Context, error)
	// ValidateDomainScopedPermission is ValidateUserPermissions, plus a
	// fallback to the user's delegated mesh-domain admin bindings
	// (ADR-0032) when the account-wide check fails. domainPath is the
	// resource's mesh-domain Path, or "" for a resource with no domain
	// (only an account-wide grant can ever satisfy that, since there is no
	// domain to hold a delegation against).
	ValidateDomainScopedPermission(ctx context.Context, accountID, userID, domainPath string, module modules.Module, operation operations.Operation) (bool, context.Context, error)
	ValidateRoleModuleAccess(ctx context.Context, accountID string, role roles.RolePermissions, module modules.Module, operation operations.Operation) bool
	ValidateAccountAccess(ctx context.Context, accountID string, user *types.User, allowOwnerAndAdmin bool) (context.Context, error)

	GetPermissionsByRole(ctx context.Context, role types.UserRole) (roles.Permissions, error)
	SetAccountManager(accountManager account.Manager)
}

type managerImpl struct {
	store store.Store
}

func NewManager(store store.Store) Manager {
	return &managerImpl{
		store: store,
	}
}

func (m *managerImpl) ValidateUserPermissions(
	ctx context.Context,
	accountID string,
	userID string,
	module modules.Module,
	operation operations.Operation,
) (bool, context.Context, error) {
	if userID == activity.SystemInitiator {
		return true, ctx, nil
	}

	user, err := m.store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
	if err != nil {
		return false, ctx, err
	}

	if user == nil {
		return false, ctx, status.NewUserNotFoundError(userID)
	}

	if user.IsBlocked() && !user.PendingApproval {
		return false, ctx, status.NewUserBlockedError()
	}

	if user.IsBlocked() && user.PendingApproval {
		return false, ctx, status.NewUserPendingApprovalError()
	}

	ctxEnriched, err := m.ValidateAccountAccess(ctx, accountID, user, false)
	if err != nil {
		return false, ctx, err
	}

	if operation == operations.Read && user.IsServiceUser {
		return true, ctxEnriched, nil // this should be replaced by proper granular access role
	}

	role, ok := roles.RolesMap[user.Role]
	if !ok {
		return false, ctxEnriched, status.NewUserRoleNotFoundError(string(user.Role))
	}

	return m.ValidateRoleModuleAccess(ctx, accountID, role, module, operation), ctxEnriched, nil
}

// domainDelegableModules are the only modules a mesh-domain admin binding
// (ADR-0032) can ever grant, regardless of what operations it lists --
// delegation exists so a subdomain admin can manage that subdomain's peers,
// invitations, and further subdomains, not to reach any wider account
// surface (users, billing, KarstControl, ...).
var domainDelegableModules = map[modules.Module]struct{}{
	modules.Domains:   {},
	modules.Peers:     {},
	modules.SetupKeys: {},
}

func (m *managerImpl) ValidateDomainScopedPermission(
	ctx context.Context,
	accountID string,
	userID string,
	domainPath string,
	module modules.Module,
	operation operations.Operation,
) (bool, context.Context, error) {
	allowed, ctxOut, err := m.ValidateUserPermissions(ctx, accountID, userID, module, operation)
	if err != nil || allowed {
		return allowed, ctxOut, err
	}
	if domainPath == "" {
		return false, ctxOut, nil
	}
	if _, ok := domainDelegableModules[module]; !ok {
		return false, ctxOut, nil
	}

	bindings, err := m.store.GetUserDomainRoleBindings(ctx, accountID, userID)
	if err != nil {
		return false, ctxOut, err
	}
	for _, binding := range bindings {
		if binding.Covers(domainPath) {
			return true, ctxOut, nil
		}
	}
	return false, ctxOut, nil
}

// ValidateRoleModuleAccess resolves an operation against the role's explicit
// grant for the module, then the grant for its parent module when the module
// is a dotted submodule, and finally the role's AutoAllowNew default.
func (m *managerImpl) ValidateRoleModuleAccess(
	ctx context.Context,
	accountID string,
	role roles.RolePermissions,
	module modules.Module,
	operation operations.Operation,
) bool {
	if permissions, ok := lookupModulePermissions(role, module); ok {
		if allowed, exists := permissions[operation]; exists {
			return allowed
		}
		log.WithContext(ctx).Tracef("operation %s not found on module %s for role %s", operation, module, role.Role)
		return false
	}

	return role.AutoAllowNew[operation]
}

// lookupModulePermissions returns the role's explicit permission set for the
// module, falling back to the parent module's set for dotted submodules. The
// second return reports whether any explicit set was found.
func lookupModulePermissions(role roles.RolePermissions, module modules.Module) (map[operations.Operation]bool, bool) {
	if permissions, ok := role.Permissions[module]; ok {
		return permissions, true
	}
	if parent, hasParent := module.Parent(); hasParent {
		if permissions, ok := role.Permissions[parent]; ok {
			return permissions, true
		}
	}
	return nil, false
}

func (m *managerImpl) ValidateAccountAccess(ctx context.Context, accountID string, user *types.User, allowOwnerAndAdmin bool) (context.Context, error) {
	if user.AccountID != accountID {
		return ctx, status.NewUserNotPartOfAccountError()
	}

	ctx = nbcontext.WithRole(ctx, string(user.Role))

	return ctx, nil
}

func (m *managerImpl) GetPermissionsByRole(ctx context.Context, role types.UserRole) (roles.Permissions, error) {
	roleMap, ok := roles.RolesMap[role]
	if !ok {
		return roles.Permissions{}, status.NewUserRoleNotFoundError(string(role))
	}

	permissions := roles.Permissions{}

	for k := range modules.All {
		if rolePermissions, ok := lookupModulePermissions(roleMap, k); ok {
			permissions[k] = rolePermissions
			continue
		}
		permissions[k] = roleMap.AutoAllowNew
	}

	return permissions, nil
}

func (m *managerImpl) SetAccountManager(accountManager account.Manager) {
	// no-op
}
