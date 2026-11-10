<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0069: Resurgence, Estavelle, and Aven — renaming AVEN, Relay, and Gateway

- **Status:** Accepted
- **Date:** 2026-11-08
- **Deciders:** Project owner
- **Related:** ADR-0010, ADR-0056, ADR-0008
- **Supersedes in part:** ADR-0010's naming of the path-discovery protocol as AVEN; ADR-0056's "old command and field names must coexist with new presentation during rollout" principle, for this rename only. Both ADRs' other decisions remain in force.

## Context

ADR-0010 established that invented proper nouns in this project get karst-geology
theming (Ponor, AVEN, PHREATIC, Bedrock, KarstDNS) while standard technical terms
do not. Working through the actual deployment roles of Relay and Gateway surfaced
a mismatch between name and connotation:

- **Relay** (`bins/karst-relay`, Go `relayreg`/`relayalloc`/`relayservice`/
  `relaytelemetry`/`relayusage`) is the operator-facing transport-infrastructure
  component. But the thing that actually *needs* it — a node behind NAT with no
  external IP, depending on the mesh for reachability — is conceptually closer to
  a client than to infrastructure.
- **Gateway** (`bins/karstd/src/gateway.rs`, the node-agent capability for subnet/
  exit routing) is, in practice, deliberately provisioned by an admin on a node
  with a public IP in an authorized location — conceptually closer to dedicated
  infrastructure than to an ordinary client capability.

The names read backwards relative to their roles.

## Decision

### AVEN → Resurgence

The path-discovery/NAT-traversal protocol (`spec/aven-v1.md`, `crates/karst-disco`)
is renamed **Resurgence** — where a stream that vanished underground at a *ponor*
re-emerges at the surface. This fits "finds a direct path after starting
relayed," and keeps the existing Ponor metaphor coherent instead of colliding
with it. This also frees the name "Aven" for the Gateway rename below.

This is a genuine wire-protocol version bump, not a cosmetic rename: the AVEN
magic bytes (`crates/karst-disco/src/lib.rs`, `MAGIC: [u8; 4] = *b"KAVN"`) are a
literal discriminator on every UDP probe datagram and are bumped alongside the
name change. Old and new nodes will not discover each other via this protocol
until both are upgraded — this is accepted as part of the clean break below, not
an oversight.

### Relay → Estavelle

The operator-facing transport-infrastructure component is renamed **Estavelle**
— a karst feature that alternates between swallowing and discharging, fitting a
bidirectional node that depends on the mesh for reachability.

### Gateway → Aven

The node-agent capability for subnet/exit routing is renamed **Aven** — a shaft
deliberately used by cavers as a known surface entrance, fitting deliberately
provisioned, publicly reachable infrastructure.

### Clean break, not a staged migration

This rename ships as a single coordinated, versioned, breaking release across
client, server, and console — not an incremental rollout. Explicitly, and in
deliberate departure from ADR-0056's coexistence principle for this rename only:

- DB tables (`karst_relays`, `karst_relay_telemetry`, etc.) are renamed via a
  migration, not aliased or left in place.
- REST routes (`/relays`, `/gateways`, `/karst/v1/relay-services`, etc.) are
  renamed outright, not dual-mounted alongside the old paths.
- TOML config keys (`[gateway]`, `relay_ca_file`, `prefer_quic_relay`) are
  renamed with no legacy-key support and no deprecation window.
- The CLI `gateway` subcommand and IPC/status-JSON string literals (`"relay"`,
  `"gateway"`) are renamed outright, with no alias.
- The console's persisted installation-receipt `kind` string
  (`"karst-relay-installation"`) drops the old value entirely; old receipts will
  no longer parse after upgrade.

ADR-0056's own #404 migration contract (Gateway unification, TURN drop) is
otherwise unaffected by this decision — that contract continues to govern #404's
own additive rollout. This ADR carves out a narrow, explicit exception for the
terminology rename alone.

## Alternatives rejected

- **Staged/aliased rollout** (ADR-0056's default pattern): rejected for this
  rename. The maintainer explicitly chose a clean break over carrying dual
  names, dual routes, and dual config keys indefinitely or through a
  deprecation window, judging the ongoing maintenance cost of coexistence higher
  than the one-time cost of a coordinated breaking release.
- **Freezing the AVEN magic bytes** while renaming everything else: rejected as
  inconsistent with the clean-break posture elsewhere in this decision.

## Consequences

### Positive

- Terminology now matches actual deployment roles: Estavelle for the NAT-bound,
  client-like side; Aven for deliberately provisioned, publicly reachable
  infrastructure.
- No long-lived dual-name code paths, no deprecation-window bookkeeping, no
  stale aliases to remove later.

### Negative

- Every existing `karstd.toml`, operator script matching on CLI/IPC output, and
  saved installation receipt breaks on upgrade.
- Requires a single coordinated client + server + console release; cannot be
  rolled out gradually.

### Reconsider if

If #404's Gateway-unification work lands first and changes the underlying data
model, reconcile this naming change inside that PR instead of layering it on
afterward.
