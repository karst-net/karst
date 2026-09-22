<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0034: KarstDNS encrypted upstream transport is DoT-only, fail-closed on failure

- **Status:** Proposed
- **Date:** 2026-09-22
- **Deciders:** TBD
- **Related:** #169 (this decision), #131 (disposition record: pursue),
  ADR-0018 (CNSA 2.0 as the sole PHREATIC suite — explicitly out of scope
  for this decision, see Context), ADR-0031 (fail-closed precedent this
  borrows its reasoning from), ADR-0025 (nearest DNS-adjacent ADR;
  establishes that a DNS-scoped non-goal gets recorded even when the answer
  is "don't build"). Implementation split into #176 (Rust DoT transport),
  #177 (proto/control-plane structured config), #178 (Go server/admin API)

---

## Context

`plans/phase-5/01-karstdns.md` scoped encrypted upstream transport out of
Phase 5 on purpose, stating it as a decision rather than a gap:

> DNSSEC validation (...) and encrypted upstream transport (DoH/DoT). Both
> are defensible later; neither is Phase 5.

`spec/karstdns-v1.md`'s own Non-goals section restates the same thing more
narrowly, and is the precise scope this ADR now resolves:

> Forwarded queries go out in plain DNS over the resolvers `KarstDNSConfig`
> names, whether that is the open internet or, for a split route, a resolver
> reachable only over the mesh.

Issue #131 already recorded the disposition as **pursue**. #169 is the
scoping ticket that asks three concrete questions before any code lands:
which protocol, how the node verifies the resolver's certificate, and what
happens when the encrypted upstream is unreachable. This ADR answers all
three.

### What this protects, precisely

KarstDNS is a policy resolver, not a general recursive resolver
(`spec/karstdns-v1.md`). Mesh-zone answers (`<label>.<zone>.`) are
authoritative and served from data that arrived over the authenticated
Karst control channel — nothing is ever forwarded for a mesh name, encrypted
or not. Split-DNS suffix matches are forwarded only to the resolvers a route
names (`crates/karst-dns/src/split.rs::RoutingTable`), which may themselves
be mesh-reachable-only resolvers. Everything else forwards to the node's
global upstreams (`KarstDNSConfig.nameservers`). In every one of these
forwarding cases, the query currently leaves the node as plain UDP/TCP DNS
(`crates/karst-dns/src/forward.rs::udp`) — visible in the clear to whatever
sits between the node and that resolver. That leg, and only that leg, is
what this ADR encrypts. It has nothing to do with PHREATIC or the mesh
control channel: ADR-0018 mandates CNSA 2.0 (ML-KEM-1024/ML-DSA-87) as the
*sole* suite for Karst-to-Karst traffic, but a DoT upstream is a
Karst-to-third-party connection — a public resolver (Cloudflare, Quad9,
NextDNS) or a self-hosted one an admin names, none of which will ever offer
Karst's PQ/CNSA suite. Treating this as a PHREATIC-adjacent decision would
be a category error; it is decided independently below.

### What the codebase already establishes

- `crates/karst-dns/src/forward.rs` is a small, synchronous, blocking,
  `#![forbid(unsafe_code)]` module with exactly one external dependency
  surface today (`hickory-proto`, no default features). Its shape — take a
  raw DNS wire message, hand it to a transport, get a raw DNS wire message
  back — is transport-agnostic by construction; only `service.rs::forward()`
  needs to change which transport it calls.
- `crates/karst-dns/src/split.rs`'s `RoutingTable` already establishes the
  precedent this ADR's fallback decision extends: "A route failure is
  SERVFAIL; it never falls back to global upstreams." No forwarding path in
  KarstDNS silently degrades to a different resolver set than the one
  policy named.
- `bins/karstd/src/relay_tls.rs` is the one existing TLS client in the
  workspace that talks to something outside the PHREATIC application
  protocol (Karst's own relay, over HTTPS). It hard-requires
  `X25519MLKEM768` (`REQUIRED_GROUP`) and refuses to connect without it.
  That requirement is specific to Karst-to-Karst TLS, where both ends are
  Karst software and PQ hybrid support can be guaranteed. It must not be
  carried into this decision: no public or self-hosted third-party DNS
  resolver will offer that group, so requiring it here would make DoT
  unusable everywhere. `relay_tls.rs` also supports an optional local CA
  bundle override (`bins/karstd/src/config.rs`'s `relay_ca_file`) for
  self-hosted relays behind non-public TLS termination — noted below as the
  precedent to reach for later, not adopted now.
- `server/shared/management/proto/karst_control.proto` carries a
  `reserved 8;` never-reuse discipline and shows no precedent for breaking
  an existing field's meaning; additive fields are how this schema evolves.

## Decision

### 1. DoT (RFC 7858) only — not DoH, not both

KarstDNS's encrypted upstream transport is DNS-over-TLS. DNS-over-HTTPS
(RFC 8484) is not implemented, now or as a parallel option.

DoT is DNS wire messages carried directly over a TLS stream — it composes
onto the existing forwarder's raw-message shape with no reframing. DoH
requires an HTTP/2 (or HTTP/1.1) client, base64url query encoding, and
`Content-Type: application/dns-message` negotiation: a materially larger
implementation and audit surface, pulling in an HTTP stack where none
exists in this crate today, for a protocol capability KarstDNS does not
need. DoH's principal advantage over DoT — HTTPS-shaped traffic is harder
for a network operator to distinguish and block than TLS on port 853 — is a
censorship-circumvention property. It protects a query from being blocked
or observed *by the network the node itself is on*. That is not this
crate's threat model: the resolver a node encrypts to is one the node
operator (or their account admin) explicitly configured and already
trusts; there is no adversarial relationship between the node and its own
chosen upstream to hide from. Where DoT's port is blocked on a given
network, that is a reachability problem for the operator to solve by
choosing a different network or a reachable resolver, not a reason to carry
a second transport and its own cert/config/audit surface for a case this
project has no evidence anyone hits.

DoT's simpler wire shape also matches this crate's existing posture:
synchronous, blocking, `#![forbid(unsafe_code)]`, minimal dependencies. A
DoT client is a blocking `TcpStream` wrapped in a TLS stream that carries
the same length-prefixed DNS messages TCP DNS already uses — a small,
auditable addition next to `forward::udp`, not a new subsystem.

### 2. Config shape: additive structured upstream entries

`KarstDNSConfig.nameservers` and `KarstDNSRoute.resolvers` remain, unchanged
in meaning, as implicit-plaintext address lists — every existing
configuration keeps working exactly as today. A new, additive field on each
message carries structured upstream entries for anything encrypted:

- a connect address (`ip:port`, e.g. `1.1.1.1:853`),
- a TLS server name — the hostname the node verifies the resolver's
  certificate against (SNI and cert-name checking both need a name, not
  just the bare IP most DNS configuration uses; this field is what
  `KarstDNSConfig` is currently missing to express an encrypted upstream at
  all, per #169's own framing),
- a transport tag (plain or DoT — reserved for future values, not
  DoH — rather than a boolean, so a resolver's transport is legible in the
  wire format itself),
- an optional pinned SPKI hash.

This follows the schema's existing `reserved 8` discipline: extend, never
repurpose. The exact field/message names and numbering are implementation
detail for the follow-up proto issue, not fixed by this ADR.

### 3. Trust model: system store by default, opt-in pinning for self-hosted resolvers

The node's default verifier is the system trust store
(`rustls-native-certs`), used against the TLS server name in the config
entry above. This covers the common case — an administrator points a
nameserver group at a public resolver with a publicly-issued certificate —
with no extra configuration.

For a self-hosted or otherwise non-publicly-CA'd DoT resolver, the account
admin may additionally set a pinned SPKI hash in the same config entry. When
present, the node requires the resolver's leaf certificate to match the pin,
in addition to (not instead of) ordinary chain validation. This mirrors how
the control plane already pins other trust material (Bedrock binds a peer's
ML-DSA identity rather than trusting a name alone) rather than introducing a
new pinning mechanism. Pin material travels in the authenticated netmap, the
same channel that already carries every other piece of trust-sensitive DNS
and mesh configuration — not a node-local file.

This is deliberately not `relay_tls.rs`'s model: no `X25519MLKEM768`
requirement (see Context), and no local CA-file override in this decision.
`relay_ca_file` exists because a self-hosted *relay* may sit behind TLS
termination the system store doesn't trust and the control plane can't
always reach ahead of time; a DoT resolver's trust material comes from the
same authenticated netmap that already names the resolver, so there is no
equivalent bootstrapping gap today. If a static-roster or
no-control-server deployment mode ever needs a resolver's trust configured
without a netmap, that is a new local-override mechanism to design then —
see Reconsider if.

### 4. Fallback behavior: fail closed, always

Exhausting the configured DoT upstream(s) for a query returns SERVFAIL. It
never silently retries the same query over plain DNS, to the same resolver
or a different one. This extends `split.rs`'s existing rule — "a route
failure is SERVFAIL; it never falls back to global upstreams" — to the new
transport dimension: a failure changes *how* a query fails, never *what
guarantee it silently gives up*. It also matches ADR-0031's core reasoning
for the managed-device kill switch, restated here for a different
guarantee: a claimed security property does not degrade automatically on
failure, and there is no timeout-based safety valve back to a weaker mode.
Recovery is explicit — the admin reconfigures a reachable encrypted
upstream, or accepts the resulting SERVFAIL — not implicit in the failure
path itself.

An admin who wants redundancy configures more than one DoT upstream in the
same entry; the node retries within that encrypted set exactly as
`forward::udp` already retries within a plain resolver set today. Nothing
in this decision prevents an admin from also configuring plain upstreams
elsewhere (a different nameserver group, a different split route) — that
combination is a config-time policy choice the admin makes explicitly, not
an automatic fallback the node performs on encrypted-upstream failure.

### Alternatives rejected

- **DoH (RFC 8484), alone or alongside DoT.** Rejected per the reasoning in
  Decision §1: DoH's real advantage is irrelevant to this crate's threat
  model, and it costs an HTTP client stack this codebase does not otherwise
  need. Supporting both doubles the cert-handling, config, and audit
  surface for v1 with no identified demand for DoH specifically.
- **Automatic plain-DNS fallback when the encrypted upstream is
  unreachable.** Rejected explicitly — this is the exact failure mode #169
  calls out as defeating the point of the feature. An operator who wants
  that tradeoff can configure a plain nameserver group directly; the node
  does not make that substitution silently.
- **A local CA/pin file override as a v1 requirement**, mirroring
  `relay_ca_file`. Deferred, not rejected outright: today's netmap already
  carries every piece of trust material a DoT entry needs, so there is no
  bootstrapping gap that a local override would close. Revisit if a
  static-roster/no-control-server deployment mode needs one (see
  Reconsider if).
- **Reusing `relay_tls.rs`'s `X25519MLKEM768`-required TLS config
  directly.** Rejected: that requirement is meaningful only when both TLS
  peers are Karst software under ADR-0018's mandate. A public or
  self-hosted third-party DNS resolver will not offer it, so reusing it
  here would make DoT non-functional against every real-world resolver.

## Consequences

### Positive

- Closes both halves of the non-goal `plans/phase-5/01-karstdns.md` named
  for encrypted upstream transport, with a precise, narrow answer instead of
  an open-ended "DoH and/or DoT, somehow."
- The chosen transport composes directly onto the existing forwarder with
  no new async runtime, HTTP stack, or framing layer — a small, reviewable
  addition consistent with the crate's current dependency and safety
  posture.
- The trust model reuses an existing pattern (authenticated-netmap-carried
  pin material, mirroring Bedrock identity pinning) instead of inventing a
  new one, and explicitly avoids importing a PQ/CNSA requirement that would
  make the feature unusable against real-world resolvers.
- The fail-closed rule is a direct, literal extension of a rule the
  codebase already enforces for split-DNS route failures, so it introduces
  no new class of behavior to reason about.
- Unblocks scoped, independently reviewable follow-up issues (Rust
  transport, proto/control-plane, Go server/admin API) rather than one
  large cross-language change.

### Negative

Be honest here, per this project's own template:

- **DoT is less broadly documented/tested across public resolver providers
  than DoH.** Every major public resolver this project would plausibly
  recommend (Cloudflare, Quad9, Google, NextDNS) supports RFC 7858 DoT, but
  some providers' own documentation and default client tooling favor DoH
  more prominently. An admin following a resolver's own quick-start guide
  may need to specifically look for the DoT/port-853 instructions.
- **Opt-in pinning means an unpinned entry gets ordinary CA-trust
  exposure, not a stronger guarantee.** A self-hosted resolver an admin
  configures without setting a pin is only as trustworthy as the public CA
  system generally — this decision does not silently upgrade every
  encrypted entry to pinned trust; the admin must choose to set a pin for
  the stronger property.
- **Fail-closed means a DoT misconfiguration is a visible outage for
  whatever names depend on that upstream, not a silent degrade.** This is
  the intended tradeoff (see Decision §4), but it is a real operational cost
  when it triggers — a mistyped TLS server name or an expired resolver cert
  breaks resolution for those names until corrected, where a fallback-
  permitting design would have kept working (in plaintext).
- **No local trust-anchor override exists yet for a resolver the netmap
  can't authoritatively describe** (e.g., a hypothetical static-roster
  deployment with no control server). This decision does not build one;
  see Reconsider if.

### Reconsider if

- Real operator demand surfaces for DoH specifically — e.g., a deployment
  where port 853 is blocked on networks nodes must operate on but 443 is
  not, and no reachable DoT resolver exists as an alternative.
- A static-roster or no-control-server deployment mode is added that needs
  a DoT resolver's trust material configured without an authenticated
  netmap to carry it — at that point, a `relay_ca_file`-shaped local
  override is the precedent to extend, not reinvent.
