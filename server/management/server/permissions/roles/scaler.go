// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package roles

import (
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
)

// Scaler is ADR-0045 §7 Phase 2's role for karst-scaler's own `drive` loop.
// Create access on modules.KarstControl — this RBAC model's only module
// granularity, same limitation [Advisor]'s own doc comment names — is
// wider than this role is actually meant to reach (every mutation under
// /karst/v1, not just minting a relay-enroll token), so karstAuthorization
// (nodes.go) additionally hard-allowlists this role to exactly the
// `/karst/v1/relays/enroll-tokens` route, overriding what the module-level
// grant below would otherwise permit. That allowlist, not this struct, is
// what actually keeps this role narrow; see its own doc comment for why.
var Scaler = RolePermissions{
	Role: types.UserRoleScaler,
	AutoAllowNew: map[operations.Operation]bool{
		operations.Read:   false,
		operations.Create: true,
		operations.Update: false,
		operations.Delete: false,
	},
	Permissions: Permissions{
		modules.KarstControl: {operations.Read: false, operations.Create: true, operations.Update: false, operations.Delete: false},
	},
}
