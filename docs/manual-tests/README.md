<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Manual test suite

This suite is the human-executed complement to the automated checks.  It is
for release candidates and design-partner evaluations, where an operator must
verify the product boundary: installers, browser workflows, real identity
providers, host networking, and an independently deployed relay.

Run every applicable case against a named build, recording the environment,
tester, time, result, and links to the evidence.  A case passes only when its
expected result is observed and its stated cleanup is complete.  Do not record
credentials, private keys, PSKs, enrollment bundles, or unredacted bug reports
as evidence.

| Document | Components and use cases covered |
| --- | --- |
| [00-command-procedures.md](00-command-procedures.md) | Command-by-command procedures for every scenario ID below |
| [01-foundation-and-connectivity.md](01-foundation-and-connectivity.md) | `karst-control`, `karst-relay`, `karstd`, `karst`; UC-01, UC-02, UC-04, UC-08 |
| [02-clients-and-networking.md](02-clients-and-networking.md) | Linux, macOS, Windows clients; TUN/userspace, KarstDNS, subnet routing and exit nodes; UC-01, UC-06, UC-07, UC-08 |
| [03-administration-and-portal.md](03-administration-and-portal.md) | Admin console, user portal, IdP/SCIM, policy, lifecycle, DNS, routes and relay registry; UC-03 through UC-08 |
| [04-bedrock-audit-and-operations.md](04-bedrock-audit-and-operations.md) | `karst-bedrock`, control, relay telemetry, audit, posture, metrics and support tooling; UC-09 and UC-10 |
| [05-release-matrix.md](05-release-matrix.md) | Cross-component, platform, accessibility, upgrade, recovery and regression sign-off |

## Shared test fixture

Use an isolated account and a disposable domain.  Prepare two ordinary users
(`alice`, `bob`), one administrator, one auditor, and groups `engineering`,
`production`, and `gateway`.  Enroll at least two clients on independently
routed networks so that direct and relayed paths can both be exercised.  Have
a reachable relay, a control server with OIDC configured, an upstream DNS
server for a test split zone, and a gateway with a reachable private subnet.

For destructive tests, use throwaway users, nodes, routes, and policy versions.
Never deliberately invalidate a shared production Bedrock chain or DNS setup.

## Result notation

Each scenario has a stable ID.  Record `Pass`, `Fail`, `Blocked`, or `Not
applicable`, followed by the observed result and evidence reference.  A failed
negative test is a defect: rejection must be explicit, safe, and must not leave
partially applied host or account state behind.

