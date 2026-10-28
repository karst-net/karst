<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Explicit mesh domain acceptance validation

Validated on 2026-10-19 for [#362](https://github.com/karst-net/karst/issues/362).
The implementation is described in [ADR-0032](adr/0032-hierarchical-mesh-domains-and-admin-assigned-names.md)
and the [operator workflow](mesh-domains.md#rename-workflow).

## Acceptance evidence

| Requirement | Evidence |
|---|---|
| Exactly one stable root, protected lifecycle | Store tests `TestMeshRootProvisioningIsAtomicAndUnique` and `TestMeshRootConcurrentProvisioning`; `TestEnrollmentRootHTTPProtectedLifecycle` verifies deletion and unsupported reparent/update requests leave the root intact. |
| Name-preserving legacy migration | `TestMeshRootMigrationPreservesNamesAndAuthority`, ambiguity/collision rejection, legacy fallback/default, and injected write-failure/restart tests. |
| Default enrollment follows the root ID | `TestEnrollmentExplicitDefaultRoot`, `TestEnrollmentDefaultAndExistingInvitationAfterRootRename`; ordinary members cannot gain root enrollment authority through omission. |
| Invalid targets fail without fallback | `TestDeviceInvitationRejectsUnavailableEnrollmentDomain`, issuance recheck, concurrent redemption/expiry, and domain deletion dependency tests. |
| Authorized, atomic rename and rollback | Root store/manager/control API tests cover account-wide permission, revoked authority, stale previews, concurrent confirmation, placement changes, split-DNS conflicts, audit/publication, transaction failure, and increasing revisions after rollback. |
| Visible root and complete names | Console tests cover rename confirmation and rollback, renamed-root default invitation preview, nested machine/move/invitation names, and delegated views without a visible root. API tests verify complete names do not widen the visible subtree or mix naming revisions. |
| Delegated boundaries and independent access | Stable-ID scope and permission tests, deletion/recreation regression, tenant/invalid-ancestry cases, filtered peer/invitation lists, and move authorization at both endpoints. The cross-language rename test also checks unchanged network and SSH decisions. |
| Real client DNS propagation | `root_rename_propagates_to_live_dns_and_offline_reconnect` exercises production Go REST handlers, the SQL root store, authenticated control transport/netmaps, the Rust client, and the daemon's live DNS reconciliation. |

## Client propagation test

The opt-in `--root-domain-dir` test-server mode wires the production SQL root
store, permission manager, domain manager, REST handlers and DNS projection.
Its existing in-memory peer source still supplies datapath peers and enrollment;
it is not a substitute for the separate real-account-manager enrollment tests.
The explicitly enabled fixture control listener supplies one test owner identity.

The Rust test performs the following sequence:

1. Enroll clients through authenticated Go/Rust control transport and start real
   UDP/TCP DNS listeners on private loopback ports with a nested peer name.
2. Save an encrypted netmap cache and drop one control client, retaining its old
   DNS configuration. Populate the online resolver's response cache.
3. Preview and commit `karst` to `corp.example` through the production root
   rename REST handlers. Refresh the online client through its normal sync and
   configuration conversion, then invoke the same DNS reconciliation as the daemon.
4. Verify UDP/TCP forward and PTR responses, the 60-second answer TTL, removal
   of the old authoritative name, and replacement of the resolver cache.
5. Verify the offline listener still serves its old suffix. Restart its client
   from the encrypted cache, reconnect, and verify the new suffix without changing
   its node identity. The tested peer's handle, KEM key, address and PSK also remain
   unchanged. Network port restrictions and the separate SSH gate stay enforced.
6. Preview and commit rollback, verify the same root ID and an increasing naming
   revision, refresh the client and verify the original name returns while the
   intermediate suffix no longer has an alias.

The test is included in the existing CI command that runs ignored Rust control
integration tests against the Go server. To reproduce with the project toolchains:

```sh
cargo test -p karstd --test control root_rename_propagates_to_live_dns_and_offline_reconnect -- --ignored --test-threads=1
cargo test -p karst-dns --lib
```

## Host integration and validation limits

The DNS library suite verifies host integration using private paths and recorded
platform commands. The root rename/rollback test replaces macOS resolver files
and search-list commands, requests a cache flush for each transition, and restores
the pre-Karst state. Existing tests cover scoped Linux routing domains, temporary
`resolv.conf` replacement/restoration, crash recovery and external-change detection.
The local DNS library run passed 67 tests; four public-network/live-interface
tests and their helper remained opt-in.

Validation did not modify the workstation's resolver settings or claim a live
Windows/Linux/macOS fleet cutover. Operators verify the selected host mechanism
and DNS status during rollout. The current protocol has no client application
acknowledgment: the console correctly reports committed configuration and
**unobserved** client convergence. Offline clients update after reconnect; external
caches can retain answers for their TTL. There are no automatic old-suffix aliases.

## Presentation correction

Validation found that nested machine names and invitation/move previews displayed
only a root-relative path. The domains API now projects `dns_name`, the complete
namespace including the current root suffix, after authorization has filtered the
tree. A delegated administrator receives complete names for their subtree without
receiving the root or siblings. Root suffix metadata and naming revision are taken
from one root snapshot to avoid mixed values during a concurrent rename.

The console preserves the actual `dns_label` for machines, including any
deduplication suffix, and appends the root suffix exactly once. Invitation defaults
show the current root name. `path` and peer `dns_label` remain root-relative;
`dns_suffix` remains root-only. This is an additive API projection, not a naming
or permission migration.
