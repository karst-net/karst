package roles

import (
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
)

// NOC is the NOC view's read-only role (#241, ADR-0046 §6) — deliberately
// identical in shape to [Auditor]: this RBAC model's only module granularity
// today is the single modules.KarstControl gate, so a role narrower than
// "read everything under that module, write nothing" would need new
// permission-module infrastructure this pass does not add.
var NOC = RolePermissions{
	Role: types.UserRoleNOC,
	AutoAllowNew: map[operations.Operation]bool{
		operations.Read:   true,
		operations.Create: false,
		operations.Update: false,
		operations.Delete: false,
	},
	Permissions: Permissions{
		modules.KarstControl: {operations.Read: true, operations.Create: false, operations.Update: false, operations.Delete: false},
	},
}
