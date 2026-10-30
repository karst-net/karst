// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package roles

import (
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
)

// Scaler is ADR-0045 §7 Phase 2's role for karst-scaler's own `drive` loop,
// extended by ADR-0063/#455 for the sibling `allocate` loop that drives
// admin-triggered relay allocations. Create access on modules.KarstControl
// — this RBAC model's only module granularity, same limitation [Advisor]'s
// own doc comment names — is wider than this role is actually meant to
// reach (every mutation under /karst/v1, not just minting a relay-enroll
// token, requesting a relay de-enrollment, or driving one allocation
// through its own steps), so karstAuthorization (nodes.go) additionally
// hard-allowlists this role to exactly `/karst/v1/relays/enroll-tokens`,
// `/karst/v1/relays/deenroll`, `/karst/v1/relay-allocations/pending`, and
// `/karst/v1/relay-allocations/{id}/{provisioning,grant,revoke,deprovisioned,failed}`,
// overriding what the module-level grant below would otherwise permit —
// relay-services' own routes are deliberately not included; see
// RegisterRelayAllocationEndpoints' own doc comment for why. That
// allowlist, not this struct, is what actually keeps this role narrow; see
// its own doc comment for why.
//
// Delete stays false even though relayDeenroll removes a relayreg.Store row
// (ADR-0045 §7, issue #319): the route is a POST, deliberately shaped as a
// Create-permission request naming the one resource this role is allowed
// to remove, rather than a widened generic Delete grant that would need
// its own allowlist entry remembered for every future DELETE route added
// under this same module gate.
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
