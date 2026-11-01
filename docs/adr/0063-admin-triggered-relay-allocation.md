<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0063: Admin-triggered relay allocation through infrastructure connections

- **Status:** Accepted
- **Date:** 2026-10-28
- **Deciders:** Project owner (issue #439)
- **Related:** [#439](https://github.com/karst-net/karst/issues/439), ADR-0045, ADR-0058, ADR-0059, ADR-0062

---

## Context

#439 asks for one workflow: name a host, choose its infrastructure connection
and location, enable relay transport, optionally enable internet egress,
choose a permitted group, review the resulting access, and apply — with the
Gateway/relay/group work actually provisioned, not just registered.

Three systems already exist in this area, and none of them is that workflow:

- **Infrastructure connections** (`web/console/src/views/infrastructure-connections.tsx`,
  `server/management/internals/karst/infraconnections/discover.go`) are a
  location picker. `Discover`/`DiscoverLegacy` (`discover.go:121,140`) only
  list regions; the one write path, `EnableLocalZone` (`discover.go:177`), is
  a one-way AWS Local Zone opt-in. There is no `Create`/provision method in
  the package. The console's own tutorial copy says so: connections let
  Authorized Locations "offer real regions... instead of typing coordinates
  by hand," and "nothing else in Karst uses them to create or change
  infrastructure yet."
- **The scaler** (`bins/karst-scaler`, `-aws`, `-k8s`) genuinely provisions
  `karst-relay` compute — `AwsDriver` (`bins/karst-scaler-aws/src/driver.rs:76`)
  boots EC2 instances from an `ami_id` (`driver.rs:64`), mints a
  scaler-scoped relay-enroll token good for nothing else (`driver.rs:71-73`),
  and runs `karst-relay` on them. But it does this inside `drive_loop.rs`'s
  continuous reconciliation of a **pool** against ADR-0045's cost/demand
  solver — sizing a count of fungible instances in a region, not creating one
  specifically named host with its own capabilities and permitted group.
  ADR-0045 §7's Manual/Automated scaling modes distinguish who decides pool
  *size*; neither shape is "allocate this one named thing."
- **Relay service associations** (`server/management/internals/karst/relayservice/access.go:308`)
  already have the right transactional discipline for *access*: `UpdateAccess`
  commits the association/grant/route change in one local database
  transaction, and ADR-0058 is explicit that "no provider is called from this
  transaction" — a provider call can take minutes and must never hold a DB
  transaction open or be retried via rollback.

ADR-0058 named this gap on purpose rather than papering over it: "remote
workload provisioning is not implemented," and lists "provider provisioning
acquires durable orchestration" as a trigger to reconsider. This ADR is that
reconsideration.

## Decision

Add a new **manual relay allocation** record, distinct from both the scaler's
pool state and relay service associations' access state: `name`,
`infra_connection_id`, `location`, requested capabilities (`relay transport`,
`egress_v4`, `egress_v6`), `permitted_group_id`, and a state machine
(`requested` → `provisioning` → `granting` → `ready`, or → `failed` from any
step, each with a human-readable reason).

The console presents one form combining infrastructure-connections' existing
location/discovery data, a capabilities section, and the existing group
picker component from Groups & access — one name, one connection, one
location, one capability set, one group, one review, one apply, matching
#439's own example.

`apply` persists the record as `requested` in one local transaction with no
provider call inside it — the same discipline `relayservice.UpdateAccess`
already follows, for the same reason.

A new reconciliation loop, sibling to `drive_loop.rs` and sharing its
`Driver` trait (`list`/`create`/`drain`/`destroy`) but **not merged into
it**, picks up `requested` records and drives them forward:

1. `provisioning`: call `Driver::create` for one instance (not a pool
   shortfall), mint a relay-enroll token the same way `AwsDriver` already
   does (`driver.rs:71-73`), wait for the relay to register.
2. `granting`: once the relay is registered, call
   `relayservice.UpdateAccess` with the requested capabilities and permitted
   group — reusing that exact transactional path rather than inventing a
   second one.
3. `ready`: both steps above succeeded. `failed`: record which step failed
   and why; never leave a grant referencing compute that failed to come up,
   and never leave compute running with a grant the system believes failed
   to apply.

Deprovisioning reverses the order: withdraw the grant via
`relayservice.UpdateAccess` first, confirm it took effect, then `drain`/
`destroy` the instance. Destroying compute before withdrawing its grant would
leave an access record pointing at nothing; the reverse order means access is
revoked before the thing it protected disappears.

### Alternatives rejected

- **Extend the scaler's pool reconciliation to also track named,
  capability-specific one-off allocations.** A pool member is fungible and
  has no identity or capability selection; forcing one to carry a name, a
  specific group grant, and egress settings would corrupt the cost model's
  assumption that every member in a pool is interchangeable.
- **Call a provider from inside `relayservice.UpdateAccess`'s transaction.**
  ADR-0058 already rejected this shape for access-only changes; it is worse
  here, where the provider call is a multi-minute instance boot, not a
  sub-second local write.
- **Wire the console directly to scaler's existing APIs with no new durable
  record.** Scaler's APIs answer a cost-model recommendation; there is
  nowhere durable to track "this specific admin request is still
  provisioning" across a page reload or control-plane restart without one.

---

## Consequences

### Positive

An administrator can allocate a relay through a real cloud provider using
only the form #439 describes, with the same honest pending/ready/failed
states and default-no-access discipline the rest of #439's work already
established for BYO registration.

### Negative

This is new infrastructure — a new store, a new reconciliation loop, a new
state machine — not a UI-wiring task on top of what exists. Deprovisioning
ordering is a new correctness-critical path that has to be gotten right in
both directions (apply and tear-down). Initial scope should cover the AWS
driver only: `karst-scaler-k8s` provisions cluster workloads rather than a
single named host with its own address/TLS identity the way `AwsDriver`
does, and the LXD connection type PR #430 added has no provisioning driver at
all yet — both are plausible later targets, not v1.

### Reconsider if

A general durable job/workflow system is added elsewhere in this codebase
that this should use instead of a bespoke reconciliation loop, or the
scaler's pool model gains per-member identity/capability tagging that could
absorb one-off allocations instead of a separate entity.
