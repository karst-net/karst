<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0059: Unified relay inventory

- **Status:** Accepted
- **Date:** 2026-10-25
- **Deciders:** Project owner direction to consolidate Relays, Services and Ponor endpoints
- **Related:** ADR-0056, ADR-0058

## Context

Relays contained separate Services and Ponor endpoint views. Administrators
had to register an endpoint in one view, find it in another, and infer which
health and access settings belonged together. Both views presented themselves
as relay management. An endpoint without a configuration could disappear from
the administrator's normal workflow.

## Decision

Expose one relay inventory joining configurations with endpoint registration
and signed admission health. Include unassociated registrations and orphaned
configurations, preserving legacy shared endpoint associations. Configure
existing endpoints from their row. Add relay registers an endpoint, then opens
the existing reviewed access/exit form with that endpoint selected.

Keep transport details and registration deletion in the row's endpoint dialog.
Require configuration removal before offering endpoint deletion. Keep legacy
associations and publication migration under advanced settings with their
existing preview and acknowledgment. Preserve APIs and publication semantics.
Load registrations independently so configuration API failure does not prevent
endpoint diagnosis; show unknown access and disable dependent mutations.

## Alternatives rejected

- Renaming the tabs preserves the cross-view registration/configuration handoff.
- Removing the service model would break existing publication and shared legacy
  associations and is unnecessary for consolidating the administrator workflow.
- Silently switching publication on registration could change connectivity for
  unrelated clients without a reviewed preview.

## Costs and limitations

Registration and access configuration remain separate server operations. If the
second step is cancelled or fails, the registration remains visible. Legacy
publication can expose a newly registered endpoint account-wide; the add form
states that effect. Service publication keeps unassociated endpoints unpublished.
Cloud/cluster provisioning remains outside this workflow. Legacy shared
endpoints can appear under multiple configurations, and separate APIs can be
observed at different moments during refresh. The console's deletion guard does
not introduce a new server-side integrity constraint.
