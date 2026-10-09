package roles

import (
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
)

// Advisor is ADR-0045 §7 Phase 1's read-only role for the demand-side input
// endpoints (/karst/v1/demand/...) a continuously-running Advisor process
// polls. Deliberately identical in shape to [NOC]: this RBAC model's only
// module granularity today is the single modules.KarstControl gate, so a
// role narrower than "read everything under that module, write nothing"
// would need new permission-module infrastructure this pass does not add.
//
// See types.UserRoleAdvisor's own doc comment for why this is a new role
// rather than a reuse of NOC or Auditor: /karst/v1/demand/regions is
// deliberately cross-account, and no existing role's grant should silently
// start meaning "see every tenant's data" the day that endpoint ships.
var Advisor = RolePermissions{
	Role: types.UserRoleAdvisor,
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
