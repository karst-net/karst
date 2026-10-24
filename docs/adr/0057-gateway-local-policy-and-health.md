<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0057: Gateway local policy and candidate health

- **Status:** Proposed (implementation accompanies issue #421)
- **Date:** 2026-10-24
- **Related:** ADR-0056, issues #404, #408, #419, #421, #422

## Context

Specific and default prefixes already share route authority and forwarding.
The remaining local setting lives in `[node]`; operators cannot independently
refuse Gateway forwarding on a managed node. Route-wide telemetry also keeps
only the most recent candidate's report, so joining that report to every node
in a routing group misattributes readiness. Pre-readiness agents report
counters without a readiness field; proto3 false alone cannot identify failure.

## Decision

Use one `[gateway]` table for host forwarding policy and exit-consent storage.
`forwarding` gates both specific and default prefixes and defaults to true for
existing deployments. It neither advertises routes nor grants client consent.
Enforce refusal before ingress flow tracking as well as in the ruleset builder,
so host sysctls and stale rules cannot bypass it. Explicit refusal removes the
owned table left after a crash while preserving sysctls whose ownership is unknown.
Keep the two historical node path spellings as read compatibility, but refuse
configurations setting both the table path and a node path.

Keep route-wide counters for existing consumers. Store latest health separately
by account, authenticated node and route resource. Do not backfill node health
from unattributed route-wide rows. Add observation field 7 as a readiness
presence marker. A true field 6 from #422 agents also establishes readiness;
false without field 7 remains unreported because failure cannot be proven.

The admin editor presents both kinds as behaviors of one Gateway, preserving
route IDs and the existing write API. Local metrics expose counts of ready,
degraded and locally disabled offers; Prometheus owns alert history/delivery.

### Alternatives rejected

- Separate subnet/exit configuration switches: repeats the roles being unified.
- A second route database/API: duplicates authority and complicates rollback.
- Reusing the last route-wide report for all nodes: misattributes health.
- Treating every absent bool as degraded: produces false alarms during upgrades.
- Renaming consent files, IPC verbs and macOS authorization rights: loses durable
  state or breaks deployed integrations without changing the capability model.

## Consequences

The health table adds one latest row per candidate/resource. Rollbacks can
ignore it, but it is not automatically pruned when routes are removed. Inventory
only joins currently visible declarations. Health remains a last-report signal,
not a reachability probe or an assertion of DNS/return-path correctness. A
#422 agent reporting false must upgrade before its failure can be distinguished
from an older counter-only agent. New TOML tables require a new agent; rollbacks
must restore the older config before restarting the older binary.

Reconsider the default-on compatibility policy at a deliberately versioned
configuration transition, rather than silently disabling deployed Gateways.
