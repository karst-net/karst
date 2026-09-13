<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Manual release matrix

Use this as the final sign-off sheet.  Link each cell to the scenario result;
do not replace a failed applicable scenario with a `Not applicable` mark.

| Surface | Linux x86-64 | Linux arm64 | macOS Apple Silicon | macOS Intel | Windows x64 |
| --- | --- | --- | --- | --- | --- |
| Install, service, upgrade, uninstall (CLI-01) |  |  |  |  |  |
| Normal TUN connectivity (CLI-02, FND-09) |  |  |  |  |  |
| Userspace connectivity (CLI-03) |  |  |  |  |  |
| Enrollment/recovery (FND-06–07, CLI-04) |  |  |  |  |  |
| DNS apply/query/revert (NET-01–04) |  |  |  |  |  |
| Direct and relay paths (FND-09–10) |  |  |  |  |  |
| Explicit exit-node use/disable (NET-06) |  |  |  |  |  |

| Shared service or browser surface | Required evidence |
| --- | --- |
| Control and relay | FND-01 through FND-12; restart/reconnect result; redacted health logs |
| Console and portal | ADM-01 through ADM-11 in a supported browser; keyboard-only and error-state result |
| Routing/DNS | NET-05 through NET-07 with before/after route and resolver evidence |
| Bedrock/audit/operations | OPS-01 through OPS-09 in isolated account |

## Upgrade and recovery gate

For every supported packaged client, install the preceding approved build,
enroll it, upgrade in place, reboot, and verify its identity/handle, service,
DNS restoration, routes, policy and peer connectivity.  Then simulate a
control restart, relay restart, client crash, and network loss.  No test may
leave an unwanted default route, altered resolver configuration, duplicate
identity, or unrecoverable service state.

## Sign-off

Release owner: ______  Build: ______  Date: ______

All applicable scenarios passed: ______  Known exceptions and linked approval: ______

