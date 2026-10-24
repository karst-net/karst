<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Gateway migration and verification (#421)

## Local configuration

The canonical capability table is:

```toml
[gateway]
forwarding = true
# Optional; preserve the deployed consent file during migration.
exit_state_file = "/var/lib/karst/exit-route"
```

Omit `exit_state_file` to preserve the agent's existing default. Relative paths
resolve against the config directory. `forwarding = false` refuses forwarding
for all authenticated specific-prefix and default-prefix Gateway offers; it
does not hide offers, change client consent, or disable client subnet use.
The authenticated ingress path rejects transit packets even if the host already
has forwarding enabled; explicit refusal also removes an owned nftables table
left by a crashed process, without resetting unowned host sysctls.
Defaults preserve existing deployments. No table setting creates a server route.

Move `[node].gateway_exit_state_file` or `[node].exit_node_state_file` into
`[gateway].exit_state_file` with the **same path**. Remove the old key: setting
both is an error even when equal. Retain the existing state file and permissions.
For an agent rollback, restore the old key and remove `[gateway]` before starting
the old binary, whose strict TOML parser rejects unknown tables.

## Naming audit

| Surface | Canonical surface / compatibility decision |
|---|---|
| Local TOML | `[gateway]` policy/storage table. Both historical node path spellings remain readable, with ambiguity rejected. |
| Node CLI | `karst gateway status`, `karst gateway exit list/use/disable`; `exit-node` remains a compatibility alias with the same IPC requests. |
| Console | Gateway inventory and one behavior editor for specific/IPv4 default/IPv6 default prefixes; existing route API and IDs remain authoritative. Routing-group prefill is visible/editable and may include other group members. |
| API and wire | `/karst/v1/gateways`; retain `/routes`, route kinds, consent semantics, field numbers and older reader support. Field 7 adds explicit readiness presence. |
| Metrics | `karst_gateway_offers{state="ready\|degraded\|disabled"}` counts local Gateway offers. Existing `karst_exit_route_active` describes client selection and is retained for collectors. |
| Operator guides | Current customer scenarios, manual procedures and macOS operational commands use `karst gateway exit`; historical ADRs/reviews and explicit alias descriptions retain old names. |
| Deployment generators | macOS lab generator emits `[gateway]` and retains its consent filename. Other checked-in deployment templates do not configure a legacy exit-state key. |
| Persistent state / IPC / platform rights | Keep the deployed `exit-route` file (or custom `exit-node.json`), legacy IPC verbs, macOS `dev.karst.exit-node.consent` and managed exit-consent settings. These are deployed contracts; renaming them would reset consent or invalidate platform integrations. |
| Implementation and historical plans | Keep `exit_node.rs`, `exit_policy.rs`, subnet/exit test names and archived plans where they describe different semantics or historical work. |

## Diagnostics and alerting

The inventory joins last health by authenticated candidate node and resource ID,
not route row ID or routing-group membership alone. It shows enabled-behavior
counts alongside node readiness and independent control connectivity. Older
route-wide telemetry cannot establish any candidate's health after upgrade;
wait for a fresh node report. Latest reports have no expiry: disconnected nodes
may retain last readiness, so check connectivity independently.

`karst metrics` and the optional loopback metrics listener expose local aggregate
counts. Disabled forwarding has its own state and does not fire the example
[Prometheus rule](../deploy/observability/gateway-alerts.yml). Existing scrape
`up` alerts should cover missing collectors; counts alone cannot detect a node
that cannot report. This signal proves neither destination reachability nor DNS.

## Verification record — 2026-10-24

| Check | Evidence / boundary |
|---|---|
| Config aliases, table conflicts, paths and shared forwarding switch | Rust config/Gateway unit tests cover both address families and retain visible offers when forwarding is disabled. |
| New agent → #422 control schema | Go compatibility test decodes field-7 reports using the actual older six-field descriptor; counters and field 6 retain their values. |
| Older agents → new control | Counter-only false remains unreported; #422 true is ready; #422 false is ambiguous/unreported; new explicit false is degraded. Authenticated role checks still gate storage. |
| Old control → new agent, removed TURN field | Rust fixture injects reserved field 16 into a valid encoded netmap; known fields survive and the removed field is discarded. This does not restore TURN support. |
| Candidate/account isolation | Store and inventory regressions keep ready primary and unreported/degraded standby independent. |
| Console compatibility | Gateway browser tests cover old route links, missing inventory endpoint, unknown schema, combined inventory and unified behavior selection. |
| Linux namespace integration | All 27 existing scenarios passed (685.80 seconds). The updated combined-Gateway scenario separately passed, including subnet/default coexistence, consent removal and local forwarding refusal after a crash. The runner uses disposable namespaces and a fixture control server, not production management. |
| IPv6 Gateway forwarding | Two new namespace scenarios passed: NAT66 specific/default-prefix forwarding, independent consent, retained subnet access after withdrawal, and non-NAT explicit return routing under an overlapping default offer. |
| DNS through IPv6 Gateway | Real UDP/TCP stub queries forward to an exit-only IPv6 DNS upstream after consent and fresh names fail after withdrawal. Upstream traffic is UDP; TCP upstream fallback and DoT are not established. |
| Production control and native platforms | Production management deployment/database upgrade, macOS/Windows routing/resolver integration and broader exit-DNS policy remain release verification work for #421. Do not claim the issue complete based on fixture results. |

Schema compatibility is deliberately narrower than a real two-release rolling
deployment. No production configuration or control service was changed by this work.

### Local check results

- Daemon unit suite: 529 passed; packet-policy integration: 6 passed.
- Linux namespace suite: 27 passed. The updated combined-Gateway crash/refusal
  scenario separately passed against the subsequent ingress/cleanup changes.
- Gateway browser suite: 9 passed, including consent-preserving route writes.
- Go telemetry, inventory and control package tests passed, including both schema directions.
- Rust formatting, strict daemon clippy, workspace compilation with all features,
  dependency policy, TypeScript build/lint and changed-source SPDX checks passed.
- `just check` could not start because `just` is not installed; the checks above
  were invoked directly. This is not a claim that the entire workspace test
  suite or every CI job ran.

### Follow-up: IPv6 forwarding and mixed-version execution

The IPv6 explicit-return-route scenario exposed NAT fallthrough: a specific
route with `masquerade = false` still matched a broader default route's NAT rule.
Non-NAT grants now emit a terminating `return` in Karst's postrouting chain,
ordered before broader prefixes. Unit coverage covers both IP families; the
namespace scenario observes the recipient's real IPv6 address on the destination
instead of the gateway's masquerade address. Operator-owned NAT tables retain
their existing authority.

The [container runner](../deploy/lab/aquifer/README.md) documents executable
overrides for old/new agents and control fixtures, including a real client
upgrade across the persisted-consent restart boundary. Execution results below
use the pre-#429 revision `cb649849438ca1b25d4bea81ac9d4bf234709888` and this
follow-up to merged revision `532dda0`.

| Actual binary combination | Scenarios | Result |
|---|---|---|
| Old gateway, current recipient, current control fixture | IPv4 subnet and consent-gated exit | 2 passed |
| Current gateway, old recipient, current control fixture | IPv4 subnet and consent-gated exit | 2 passed |
| Old recipient replaced by current binary, same identity/config/consent file | Exit consent and egress survive the binary upgrade without re-consent | 1 passed |
| Current agents, old control fixture | IPv4 subnet and consent-gated exit | 2 passed |
| Current agents/control, dual-stack verification fixture | IPv6 specific/default forwarding and DNS over IPv6 | 2 passed |

The seven mixed-version executions use actual binaries built from the stated
revisions. The old control binary still uses the fixture's account manager and
SQLite database; production management rollout/database migration is not tested.
The earlier schema tests retain their separate readiness-presence and removed
TURN-field coverage. Native-platform runner details are still required.

Follow-up validation: all 530 daemon unit tests passed, as did strict daemon
clippy (including integration-test targets), formatting, shell syntax and
changed-source SPDX checks. Go testserver, control and policy package tests
passed. The seven mixed-version and two IPv6/DNS namespace executions above
passed; the entire 29-scenario namespace suite was not rerun for this follow-up.
`just` remains unavailable, so this does not claim a complete `just check` run.
