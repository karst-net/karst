<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0064: Destination-scoped Gateway ingress

- **Status:** Accepted
- **Date:** 2026-10-30
- **Deciders:** Project owner direction in #453
- **Related:** #453, ADR-0057, ADR-0058

## Context

ADR-0058's managed internet-egress grant named both destination prefixes and
the Gateway machine. The latter granted all-port machine ingress. Merely adding
prefixes to outbound policy cannot constrain a compromised sender, and merely
excluding the Gateway's overlay addresses leaves its LAN/public addresses and
aliases exposed through the kernel INPUT path.

## Decision

Persist a grant with `gateway`, `networks`, source groups and ports. It cannot
also name target machines/groups or grant SSH. Compile its networks into the
source's existing outbound CIDR rules and a destination-scoped inbound rule on
that Gateway. Do not generate an ordinary machine-ingress rule. Resolve current
active membership using the existing account-scoped registry contract.

Gateway ingress schema 1 adds `dst_cidrs` to `KarstFilterRule`: nonempty means
source **and** destination **and** port must match, and authorizes forwarding
only. Empty retains existing machine ingress semantics. Unlike outbound rules,
these fields are conjunctive. SSH rules cannot carry destination scope.

The authenticated netmap request advertises `gateway_ingress_schema = 1`.
Before responding, including unchanged responses, reject a Gateway lacking that
exact schema if it would receive scoped rules. The response declares schema 1;
the agent rejects unsupported schemas and scoped rules without that declaration
before changing its held map. CIDRs participate in the shared content hash.
An older decoder dropping them cannot reproduce the version. Persisted `gateway`
is an unknown field to older controllers' strict policy parser: downgrades fail
explicitly rather than reinterpret the grant as ordinary ingress. This is a
compatibility declaration, not attestation that a machine runs approved code.

The native filter keeps scoped rules separate from ordinary ingress. Only the
forwarding path evaluates them. Local IP services, SSH admission and inner
control-channel services cannot use them. Existing independent SSH-gate behavior
is unchanged, including its current treatment of forwarded TCP/22.

Linux TUN mode is required. Atomically install a kernel INPUT guard in Karst's
existing nftables table. Overlay-address traffic has already passed native
machine ingress; other local destinations require an ordinary machine grant
matching authenticated source ranges and ports. All other packets arriving from
the TUN on INPUT are dropped. Do not add a generic conntrack reply exception:
an original packet dropped on INPUT can still create kernel conntrack state;
a peer authorized for routed source prefixes must not reverse that state into
local-service permission. Overlay-address replies retain their native stateful
behavior. Host applications using non-overlay source addresses need ordinary
machine permission for replies delivered to those addresses. Kernel FORWARD rules continue requiring authenticated
route offers; local forwarding consent and client exit consent remain separate.

Do not enable scoped transit until kernel reconciliation succeeds. Pause it
before reconciliation; test readiness before flow lookup so cached conversations
cannot bypass a failure or the local forwarding switch. Once INPUT protection
has been used, retain it until shutdown, even when scope is withdrawn. On apply
failure retain the last atomic kernel table, report failed readiness and deny
transit in the native datapath, including established flows. This avoids removing
INPUT protection underneath already queued TUN packets. The next successful
snapshot replaces the kernel table and restores readiness.

### Upgrade and migration

Upgrade every controller replica and the Linux Gateway agent before creating or updating
managed exit access. The console requires the policy schema to advertise the
new Gateway grant field before enabling managed egress on an older controller.
Do not enable scope during a mixed-controller rollout. Saving new access emits the scoped shape; legacy agents
receive an explicit netmap compatibility error. A successful save is not proof
that an offline Gateway has applied it: inspect Gateway readiness after refresh.

Existing persisted broad grants are preserved until an administrator reviews
and reapplies the service's group access. That transaction replaces its generated
grant with the scoped shape. Other explicit or legacy machine grants remain
additive; removing the generated machine grant cannot revoke independent access.
Do not downgrade controllers while scoped grants exist. An offline old agent
may retain its previously applied policy; upgrade/reconnect it before relying on
the new scope. This change does not introduce policy leases or offline revocation.

### Alternatives rejected

- Outbound-only constraints: a compromised sender bypasses them.
- An unversioned field: an old agent can silently drop the constraint.
- CIDR matching as an alternative to source matching: every group could use the
  Gateway regardless of the permitted roster.
- Excluding only overlay addresses: host aliases are still local INPUT targets.
- Dropping all local INPUT from scoped sources: independent machine grants
  must retain their existing behavior.
- Automatically rewriting existing ledger entries: immutable history and
  explicit administration review must survive the migration.

## Consequences

### Positive

Managed egress no longer grants machine access. Default deny, source identity,
SSH gating, and explicit additive grants retain their existing roles. Shared
hash vectors, native flow tests and isolated IPv4/IPv6 kernel tests exercise the
boundaries, including LAN/public aliases.

### Negative

Deployment requires coordinated upgrades. Scope adds a kernel INPUT hook and
requires retaining its protection for the running daemon's lifetime. A failed
kernel update can interrupt forwarding until a later successful reconciliation.
Host applications bound to non-overlay source addresses may need ordinary
machine grants for their replies while INPUT protection is active.
Broader independently configured grants still grant broader access. Existing
broad grants and offline agents require explicit operational migration.

### Reconsider if

Gateway forwarding gains a userspace backend that can classify all local
addresses, or policy leases introduce bounded offline revocation.
