<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0067: One provisioning workflow, with the cloud mechanism hidden behind a driver

- **Status:** Accepted and implemented — the `infraprovision.Driver` abstraction (AWS, Nomad; #550), the collapsed console "Add relay" workflow (#551), and the Kubernetes driver added in a follow-up are all shipped
- **Date:** 2026-11-07
- **Deciders:** Project owner
- **Related:** ADR-0045, ADR-0058, ADR-0059, ADR-0062, ADR-0063, ADR-0065, ADR-0066

---

## Context

An administrator adding a relay today lands on one console page
(`web/console/src/views/relay-services.tsx`) with three buttons, each a
different workflow with a different shape:

- **Add relay** (`relay-registration.tsx`) — manual BYO registration.
  Address, TLS server name, identity pubkey, region, typed in by hand. No
  infrastructure connection, no provider, no provisioning: the admin already
  stood up `karst-relay` somewhere themselves.
- **Install a local relay** (`relay-installation.tsx`, ADR-0062) — generates
  a Python script for the *existing co-located control host only*. Running
  it produces a receipt the admin then pastes into **Add relay** above to
  finish registering it. Two pages, two steps, for one relay.
- **Allocate a relay** (`relay-allocation.tsx`, ADR-0063) — the only path
  that provisions compute. Name, infrastructure connection, location,
  capabilities, permitted group → `relayalloc.Store.Create`
  (`server/management/internals/karst/relayalloc/store.go:253`) persists a
  `requested` row; an in-process worker
  (`relayalloc/awsdrive_loop.go:118`, `RunAllocateWorker`) drives it through
  `provisioning` → `granting` → `ready`.

Only the third path provisions anything, and it is AWS-only end to end, in a
way the console does not make visible:

- `infraconnections.Account.Type` already generalizes **credential storage**
  across six types — `aws | azure | gcp | kubernetes | nomad | lxd`
  (`infraconnections/aws.go`, `azure.go`, `gcp.go`, `kubernetes.go`,
  `nomad.go`, `lxd.go`) — behind one console picker
  (`infrastructure-connections.tsx:158`). Each type does real,
  type-specific, read-only discovery (regions, namespaces, datacenters,
  cluster members).
- But **actuation** — the part that creates compute — exists for exactly one
  of those six types. `relayalloc/awsdrive.go` and `awsdrive_loop.go` call
  the EC2 SDK (`RunInstances`/`StopInstances`/`TerminateInstances`)
  directly, by name, hand-ported line-for-line from a separate Rust driver
  (`bins/karst-scaler-aws/src/driver.rs`) because this package cannot depend
  on a Rust crate. The one method the loop asks `infraconnections.Store` for
  is literally named `AWSActuationClient`
  (`infraconnections/aws.go:74`), and it hard-gates on
  `record.Type != TypeAWS` (line 89), returning
  `"connection is not a read-write AWS connection"` for anything else.
  Azure, GCP, Kubernetes, and LXD connections have no actuation code
  anywhere in the tree. Nomad has a connection type and discovery
  (`infraconnections/nomad.go`) but likewise no actuation.
- **Nothing stops an admin from picking a non-AWS connection and finding
  this out only after they apply.** `relay-allocation.tsx:75-78`'s
  connection `<select>` lists every connection type unfiltered — it does not
  restrict to AWS, unlike `infrastructure-connections.tsx:149`'s own
  "Launch defaults" button, which *is* correctly gated to
  `connection.type === "aws" && connection.mode === "read_write"`. Pick an
  Azure or Nomad connection in the allocation form today and the request is
  accepted, persisted as `requested`, and only fails — generically, via
  `ErrInvalid` — the first time the worker ticks and calls
  `AWSActuationClient`.
- The one place provider mechanics are already correctly hidden from a
  per-request form is launch *shape*: AMI id, instance type, subnet,
  security groups live only on the connection's own "Launch defaults"
  (`infraconnections.LaunchDefaults`, `infraconnections.go:208`), set once in
  Settings, never collected on the allocation form itself — a deliberate
  security boundary (ADR-0045's 2026-11-04 addendum, "a request can't choose
  the launch shape"). That principle is correct. It is just implemented only
  for AWS, because there is no second implementation to generalize the
  interface from.
- The Rust `karst_scaler_driver::Driver` trait
  (`crates/karst-scaler-driver/src/lib.rs:86`) already generalizes
  "provision against a pool" (`list`/`create(n)`/`drain`/`destroy`) for the
  *continuous pool autoscaler*'s separate use case, with AWS and Kubernetes
  implementations. `relayalloc`'s actuation is Go, in-process
  (ADR-0063's 2026-11-04 addendum), and was explicitly **not** built against
  that trait — it cannot be, across the Rust/Go boundary — so it duplicates
  the trait's shape by hand, for one provider, with no interface at all to
  implement a second one against.
- Both ADR-0063 ("a general durable job/workflow system is added elsewhere
  in this codebase") and ADR-0066 ("there is no generic job/workflow
  framework; billing and relayalloc each hand-rolled the same shape
  independently") already flag this exact duplication as unresolved.

Net effect: adding a relay means knowing which of three pages to use, and
the one page that promises to abstract the cloud away only actually does so
for AWS — every other already-configured connection type is a visible but
silently non-functional choice.

## Decision

### One console workflow, not three

Collapse the three entry points into a single **Add relay** flow on
`relay-services.tsx`:

1. **"Is this relay already running somewhere?"**
   - **Yes** → today's manual registration fields (`relay-registration.tsx`,
     unchanged). This step cannot be abstracted further — it is describing
     infrastructure Karst does not own.
   - **I have a host, but nothing is running on it yet** → today's installer
     script (`relay-installation.tsx`, ADR-0062, unchanged), now a sub-step
     of this same flow rather than a separately branded page. It still ends
     by handing the resulting receipt to the step above.
   - **No, provision one for me** → the form below.
2. **Provisioning form** (today's `relay-allocation.tsx`, same fields: name,
   infrastructure connection, location, permitted group) becomes the only
   "ask Karst to create compute" surface, reached from inside Add relay
   instead of a separate "Allocate a relay" button.

This changes navigation, not capability: every existing field, receipt
format, and registration record stays exactly as it is today.

### A provider-agnostic driver interface, Go-native

Add `infraprovision.Driver` in a new package,
`server/management/internals/karst/infraprovision/`:

```go
type Driver interface {
    // Create provisions exactly one instance for allocationID, or finds
    // one already live under that same correlation tag (crash-safe
    // retry) -- matching what provisionStep already does by hand today.
    Create(ctx context.Context, allocationID string, req CreateRequest) (Instance, error)
    // TLSServerName looks up the correlation tag an already-created
    // instance was given, once it is discoverable -- matching
    // grantStep's describeTLSServerName.
    TLSServerName(ctx context.Context, instanceID string) (string, error)
    Drain(ctx context.Context, instanceID string) error
    Destroy(ctx context.Context, instanceID string) (tlsServerName string, err error)
}
```

This is not the pool-scoped Rust trait reused — it cannot be, across the
Rust/Go boundary — it is a Go-native interface with the same *philosophy*
(a handful of verbs, no cloud specifics leak through), shaped for what
`relayalloc` actually does: one named allocation, not a pool count. The
existing `awsdrive.go` logic becomes the `aws` implementation, unchanged in
behavior. A new `nomaddrive.go` implementation dispatches a pre-registered,
parameterized Nomad job (job ID/template, datacenter, resource class — a
Nomad-shaped `LaunchDefaults` equivalent, set once on the connection in
Settings, exactly as AMI/instance-type/subnet/security-groups are today) and
reads the relay's correlation tag back from the dispatched allocation's own
metadata.

`infraconnections.Store` gains one method replacing `AWSActuationClient`:

```go
func (s *Store) ActuationDriver(ctx context.Context, id string) (infraprovision.Driver, error)
```

It looks up the connection, checks a small registry keyed by
`Account.Type`, and returns a typed `ErrUnsupportedType` for any type with
no registered driver — today that is `azure`, `gcp`, `lxd`.
`relayalloc/awsdrive_loop.go` is generalized to call through this interface
instead of the EC2 SDK by name; its control flow (provision → grant → ready,
revoke → deprovision, crash-safe retry by re-describing before creating)
does not change at all, only what it calls.

### Fail at request time, not at the first tick

`relayalloc.Store.Create` calls `ActuationDriver` as part of its existing
validation (same transaction, no provider call — a registry lookup, not an
API call) and rejects a connection with no driver before persisting
`requested`, with a message naming the connection type. The console's
connection picker in the provisioning form filters to connections whose
type the API reports as actuatable (a `supports_allocation` field on the
infrastructure-connections list response), so an Azure, GCP, or LXD
connection is still visible for registration/discovery purposes everywhere
else, but is
not offered where it cannot actually be used yet. This closes the exact gap
§"Context" describes: today a non-AWS connection is selectable, accepted,
and only fails generically after the fact.

### v1 driver scope: AWS, Nomad, and Kubernetes

Three drivers ship behind `infraprovision.Driver`: **AWS** (the existing
code, re-homed, behavior unchanged), **Nomad** (new), and **Kubernetes**
(new). Azure, GCP, and LXD connections remain
registration-and-discovery-only — present in every picker that lists
connections generally, absent from `supports_allocation` — until a later
driver is written for them. Adding one is, from this point on, "implement
`infraprovision.Driver`, register it against that `Account.Type`, and add
that provider's own small launch-defaults form" (as Nomad's job ID/
datacenter and Kubernetes's image/cpu/memory each needed) — no new
allocation workflow, console entry point, or state machine, because the
one workflow and the one interface already exist; only the provider-
specific launch shape, which was always going to differ per provider, is
new per driver.

Kubernetes was initially scoped out of v1 (see "Alternatives rejected"
below) and shipped in a follow-up once requested, precisely because that
cost held: `infraprovision/kubernetesdriver` is new code, not a port.
`bins/karst-scaler-k8s`'s own `K8sDriver` proves real Kubernetes
actuation for the *pool* autoscaler's separate use case
(`StatefulSet`/ordinal pods, ADR-0045 §7 Phase 2) — the same relationship
the pool `Driver` trait has to this ADR's own interface, and rejected for
the same reason (Rust, a different process, a pool shape `relayalloc`
does not have). `kubernetesdriver` instead creates one bare `Pod` per
allocation directly from the connection's own launch defaults (image,
cpu/memory, optional service account) — the same relationship AWS's
`RunInstances` call has to its own launch defaults, not Nomad's
dispatch-a-pre-registered-job shape. A Kubernetes Pod's name is
caller-chosen, so unlike AWS/Nomad it needs no tag/meta lookup to survive
a crash between create and record: the driver just recomputes the
deterministic name (`karst-relay-<allocation ID>`) and `Get`s it.

### Alternatives rejected

- **Reuse the Rust `Driver` trait from Go directly.** Rejected: no
  cross-language trait boundary exists in this codebase, and `relayalloc`'s
  actuation deliberately moved in-process into Go specifically to avoid
  running a second binary/process (ADR-0063's 2026-11-04 addendum). A
  Go-native interface with the same shape gets the abstraction without
  inventing a new FFI contract for one feature.
- **Keep three separate console pages.** Rejected: that is the convolution
  this ADR exists to remove. Collapsing the *entry points* costs nothing —
  every underlying field, record, and script stays identical — while fixing
  the thing an admin actually experiences as friction (which of three pages,
  for which situation).
- **Shape the new interface like the pool `Driver` trait** (`list` /
  `create(n)` / `drain` / `destroy` against a `pool_id`). Rejected: a named
  allocation has no pool and no count — ADR-0063's own "Alternatives
  rejected" already refused to merge one-off allocations into pool
  semantics for exactly this reason. The new interface should match what
  `relayalloc` actually does (one instance, found-or-created by a
  correlation tag), not force an ill-fitting pool shape onto it a second
  time.
- **Build real actuation for all six connection types in v1.** Rejected:
  Azure/GCP/Kubernetes/LXD actuation each need new provider-SDK integration,
  a new enrollment-bundle shape, and testing infrastructure this repo had
  none of yet for those providers. ADR-0063 already set the precedent of
  narrowing v1 scope explicitly in the ADR rather than guessing at every
  provider a feature request could imply; Nomad was the requested addition
  and already had the most plumbing of the remaining four (a client, a
  discovery call) to build the second driver against. Kubernetes followed
  once requested, specifically *because* `bins/karst-scaler-k8s`'s
  `K8sDriver` gave it a concrete reference to build the third driver's own
  enrollment convention against, the same way AWS's own port had one — see
  "v1 driver scope" above. Azure, GCP, and LXD still have neither a
  requester nor a reference implementation to build from, so they remain
  out of scope.
- **Leave the connection picker unfiltered and rely on the clearer
  request-time error alone.** Rejected: a clear rejection *after* filling
  in a whole form is still worse than not offering the dead end in the
  first place, and the fix (reuse the exact same registry lookup on the
  list endpoint) is nearly free once `ActuationDriver`'s registry exists at
  all.

---

## Consequences

### Positive

- One admin-facing workflow to add a relay, regardless of destination:
  register, install-then-register, or provision — not three differently
  shaped pages the admin has to pick between up front.
- An admin provisioning a relay never names or chooses AWS vs. GCP vs. Azure
  vs. Nomad at request time — only a name, an already-configured
  connection, a location, and a group. The mechanism lives entirely in a
  Settings-time choice (which connection) and that connection's own
  provider-specific "launch defaults," never in the per-allocation request.
- A connection type with no driver is now a visible-but-not-offered state,
  not a silent dead end discovered only after a `requested` allocation never
  moves.
- Adding a new provider's actuation later is "implement one interface,
  register it against one `Account.Type`, add that provider's own small
  launch-defaults form" — no new allocation workflow, console entry point,
  or state machine — directly answering the duplication both ADR-0063 and
  ADR-0066 already flagged. Nomad and Kubernetes both bore this out: each
  needed its own launch-defaults fields (job ID/datacenter; image/cpu/
  memory), nothing else.

### Negative

- This generalizes the **driver/actuation** seam only. It does not build the
  general durable job/workflow framework ADR-0063 and ADR-0066 both gesture
  at for billing, rollout, and allocation to eventually share;
  `relayalloc` keeps its own hand-rolled GORM store and state machine,
  unchanged, same as billing's and rollout's. That remains separate, later
  work.
- Nomad and Kubernetes actuation are both new, unverified-in-production
  code, carrying the same caveat the AWS port's own comments already admit
  ("not independently verified against a real EC2 instance in this
  environment") — each should ship with the same honest
  `requested`/`provisioning`/`failed` states as AWS, not an implied parity
  with AWS's maturity neither has yet earned. Kubernetes additionally
  invents its own enrollment convention (three `KARST_*` environment
  variables on the container, read by that image's own entrypoint) rather
  than reusing AWS's or Nomad's, since there is no existing single-instance
  Kubernetes actuator to stay wire-compatible with — a prebuilt
  `karst-relay` container image implementing that convention does not yet
  exist in this repository.
- Collapsing three console entry points into one multi-step flow is a real
  navigation change for anyone with existing muscle memory, screenshots, or
  doc links pointing at "Allocate a relay" or "Install a local relay" as
  distinct pages — the records and scripts they produce are unchanged, only
  how an admin reaches them moves.
- Azure, GCP, and LXD connections remain registration-and-discovery-only
  after this ADR ships. The "mechanism abstracted from the admin" promise
  is only real for the three provider types this ADR implements;
  connecting an Azure account today still cannot provision a relay through
  this workflow.

### Reconsider if

- A general durable job/workflow system is added elsewhere in this
  codebase (the same trigger ADR-0063 and ADR-0066 already name) —
  `relayalloc`'s store should move onto it, and `infraprovision.Driver`
  should become that system's own provider-extension point rather than
  one feature's private interface.
- Gateway provisioning (ADR-0065's deliberately-manual gap — no safe,
  machine-mintable Gateway-enrollment credential exists yet) gets that
  credential. At that point `infraprovision.Driver` is the natural seam to
  provision Gateway hosts through this same one workflow, rather than a
  fifth bespoke path alongside relay's three-turned-one.
- A third provider actuator is requested and the interface defined here
  turns out not to fit it. Having generalized from only two
  implementations (AWS, Nomad), that would mean the interface was
  underspecified, not that a third provider is unusually strange — expect
  to revisit the interface's shape, not just add a case to it.
