<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Manual tests: administration and portal

Use real OIDC roles where possible; the API mock is suitable for visual and
error-state checks but is not evidence of server authorization.

| ID | Exercise | Steps | Expected result |
| --- | --- | --- | --- |
| ADM-01 | Authentication and roles | Sign in as administrator, ordinary user, and auditor; sign out and let a session expire. | Each sees only permitted routes/actions; sign-out/expiry returns to authentication without stale protected data. |
| ADM-02 | User lifecycle | Invite/create a throwaway user; assign role and auto-groups; block/unblock; deprovision. | Changes take effect, are reversible only where documented, and appear in audit. Deprovisioned users cannot enter portal/console. |
| ADM-03 | Groups | Create, rename and delete a local group; attempt edits to `All` and IdP-sourced groups. | Local operations succeed; fixed/external groups state why editing is unavailable. |
| ADM-04 | Auth keys and machines | Create limited, expiring and ephemeral keys; consume/revoke/delete them. Filter, rename and deprovision the resulting machine. | Limits/expiry work; keys are immutable; machine creation is correctly mediated by a key and only the name is editable. |
| ADM-05 | Policy authoring | Create a default-deny policy with one allow rule; validate, preview/test it, save, create a second version, and roll back. | Validation errors are actionable; preview/test matches packet behavior; versions and rollback are visible and audited; stale edits cannot silently overwrite. |
| ADM-06 | DNS administration | Create/edit/delete nameserver groups and excluded groups; verify invalid data feedback and client projection. | Valid configuration reaches eligible clients only; invalid data is rejected before unsafe publication. |
| ADM-07 | Routes and relays | Create/edit/enable/disable/delete a subnet route and an exit route; create/remove a relay. | UI requires gateway, recipient and access choices; exit routes show consent behavior; relay address validation rejects hostnames. |
| ADM-08 | Portal devices | As Alice, request a device credential, view/rename/revoke only Alice's device, and attempt Bob's device URL/API action. | Self-service actions work for owned devices only; cross-user access is forbidden server-side. |
| ADM-09 | Portal access and sessions | Inspect access explanation and sessions before/after a policy change and device revoke. | Explanation reflects current policy; session/device state changes promptly and clearly. |
| ADM-10 | Portal download | Download the platform-appropriate installer/instructions and complete enrollment on a clean test endpoint. | Artifact/instructions match the intended platform and do not expose another user's credentials. |
| ADM-11 | Accessibility and errors | Keyboard-navigate every console/portal route; test loading, empty, validation, forbidden, and server-error states. | Focus, labels, headings, skip link, status/error messages and recovery are usable without a mouse; errors do not disclose sensitive API detail. |

Cleanup: remove throwaway identities, keys, groups, policy versions, routes and relay entries; reset the tested policy to the approved baseline.

