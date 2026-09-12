# ADR-0021: Relay telemetry reporting to the control plane

- **Status:** Accepted
- **Date:** 2026-09-12
- **Deciders:** TBD
- **Supersedes:** —
- **Related:** ADR-0008 (relay infrastructure), ADR-0015/ADR-0018 (ML-DSA-87,
  the identity this reuses), `docs/observability.md` (Phase 6 observability,
  which this extends), GitHub issues #128 (admin console), #147

---

## Context

The admin console's Relays view (issue #128) is correctly wired to real API
types, but every row shows health as `"unknown"`. The Go control server's
`unknownRelayHealth()` (`server/management/internals/karst/api/nodes.go`)
always returns that value, and its own comment says why: "Until a relay
reports per-relay telemetry... unknown is the only truthful value for this
API." Nothing was ever wrong here — a relay genuinely has never had a way to
tell the control plane anything about itself.

This is not a general observability gap. Phase 6 already shipped real
Prometheus metrics and OTel trace spans for `karst-control`, and a metrics
surface for `karstd` (`docs/observability.md`). `karst-relay` already has its
own local, opt-in, unauthenticated Prometheus endpoint
(`bins/karst-relay/src/metrics.rs`) for an operator to scrape directly. The
one missing piece is narrower: nothing connects a relay's own knowledge of
itself to the control plane. From the control server's side, a relay is
purely operator-asserted registry data
(`server/management/internals/karst/relayreg`) — registering one proves
nothing cryptographically about the poster, and there is no live relationship
between a relay process and the control server at all.

## Decision

**A relay periodically pushes a signed, aggregate-only telemetry report to
the control server. No pull, no challenge/response round trip.**

### Push, not pull

Either direction needs new code — there is no existing channel to reuse
either way. Pull (the control server scraping each relay's existing metrics
endpoint) would require the control server to have inbound network
reachability to an admin port on every registered relay, which is a
materially stronger assumption than "a relay can reach the control server
outbound": relays must already be independently reachable by nodes on their
client-facing port, but nothing requires they accept connections from
anywhere else, and a self-hosted relay behind a restrictive firewall is
exactly the deployment ADR-0008 optimizes for. Push also lets the relay reuse
its own existing ML-DSA-87 identity — the same key it already uses for
Ponor's `RelayHello`/`RelayAuth` — rather than exposing its operator-only
metrics endpoint to a second, differently-trusted caller.

### No challenge/response

This is periodic, best-effort, advisory telemetry — the same category the
node control channel already treats its own session observations as (a write
failure there is logged, never blocks the netmap;
`server/management/internals/karst/control/netmap.go`). A timestamp-windowed
signature authenticates the report and bounds replay without needing session
state on either side for what is otherwise a fire-and-forget POST:

- The relay signs a canonical binary message (below) that includes a
  timestamp.
- The server rejects a report whose timestamp is more than
  `relayTelemetryFreshnessWindow` (5 minutes) away from its own clock, in
  either direction.

### Authentication reuses an existing pattern, with a new context string

The server already has exactly the primitive this needs:
`identity.Verify(publicKey, ctx, msg, sig) bool`
(`server/management/internals/karst/identity/identity.go`), used today for
the control channel with `ControlContext = "karst-control-v1"`. This ADR adds
`RelayTelemetryContext = "karst-relay-telemetry-v1"` and nothing else new on
the crypto side. Rust-side, `bins/karst-relay/src/sign.rs`'s `Identity`
already signs/verifies with `verify_with_context` under FIPS 204's context
mechanism for Ponor; this adds one more context constant and a small
signing helper next to it — the same key, a different, disjoint purpose,
exactly the discipline `karst-crypto`'s `ROOT_CONTEXT`/`AUTHORITY_CONTEXT`/
`ANCHOR_CONTEXT` already established.

A relay is not scoped to one account the way a node is — it authenticates by
proving control of the key a `relayreg` entry names, and that entry could in
principle be registered under more than one account (an operator copying the
same key into two accounts). The lookup is therefore **by relay id, not by
account**: the server finds every `StoredRelay` row with a matching id (in
the ordinary case, exactly one) and records the report against each account
whose stored key the signature verifies against.

### Wire format

`POST /karst/v1/relays/{relayId}/telemetry`, registered on the server's outer
router rather than the `/karst/v1` subrouter every other Karst endpoint uses
— that subrouter carries a blanket user/permission `karstAuthorization`
middleware, and a relay has no user session to present. This mirrors how
`RegisterEnrollmentMetadata` already sits outside that subrouter for its own,
different reason.

`{relayId}` and the body's `relay_id` are `base64.RawURLEncoding` of the raw
32-byte relay id — the same encoding `relayreg.StoredRelay.ID` already uses,
so the URL matches the existing `/relays/{relayId}/health` convention
exactly.

JSON body (the transport envelope):

```json
{
  "relay_id": "<base64url, no padding, 32 bytes decoded>",
  "timestamp": 1234567890,
  "local_clients": 12,
  "mesh_peers": 2,
  "remote_clients": 30,
  "bytes_total": 918273645,
  "uptime_secs": 86400,
  "signature": "<base64 standard, ML-DSA-87 signature, 4627 bytes decoded>"
}
```

**The signed message is not the JSON** — JSON has no canonical
serialization, and a Rust encoder and a Go decoder must never be trusted to
agree on field order or whitespace for something a signature covers. The
signed message is a fixed 80-byte concatenation, big-endian throughout,
matching the codebase's existing signing-input convention (Ponor's
`client_auth_signing_input`/`relay_auth_signing_input`):

```
relay_id        32 bytes   (raw, not re-encoded)
timestamp        8 bytes   (i64, seconds since epoch)
local_clients    8 bytes   (u64)
mesh_peers       8 bytes   (u64)
remote_clients   8 bytes   (u64)
bytes_total      8 bytes   (u64)
uptime_secs      8 bytes   (u64)
```

Total 80 bytes, signed under `RelayTelemetryContext`. The relay builds this
buffer once and both signs it and derives the JSON fields from it, so the two
representations cannot drift against each other in the sending code the way
two independent constructions could.

### Scope: aggregate only

The report carries relay-wide totals — client count, mesh-peer count, byte
total, uptime — never per-node data. This matches
`bins/karst-relay/src/metrics.rs`'s own stated posture: "a metrics endpoint
that named every node by id would publish the tailnet's membership to
anything that could reach it." The control plane learns exactly what an
operator already sees on that endpoint, aggregated the same way, and nothing
more.

`AdmissionState` on the health response becomes `"confirmed"` if a report
exists within `relayTelemetryFreshnessWindow`, `"stale"` if one exists but is
older, and `"unknown"` only if none has ever arrived — the three states the
console's `<Status>` mapping already expects (confirmed/stale/unknown →
healthy/warning/unknown, from the #128 audit), so no console change is
needed for this part.

### Explicitly out of scope

- **Per-node/per-path throughput.** A related but separate gap the #128 audit
  found — the API's `PathObservation` type has no bytes/rate field at all.
  That is a node-self-reported concern that would extend the *existing*
  `KarstSessionObservation` flow the control channel already carries, not
  this relay→server channel. Tracked separately.
- **Historical trending.** This reports only the most recent snapshot; there
  is no time series.
- **A relay proving reachability**, as opposed to reporting its own view of
  itself. A relay that is lying about its own client count is already
  indistinguishable from a relay lying in its local Prometheus output, which
  is out of scope for the same reason ADR-0008's threat model already
  excludes it.

## Consequences

### Positive

- The console's Relays view (already correctly wired, per #128) shows real
  health with zero console changes.
- No new cryptographic mechanism — a new context string on an existing key
  and an existing verifier function.
- No new operator-facing configuration surface on the relay beyond one
  opt-in `[telemetry]` section, off by default, matching `[reflect]`/
  `[metrics]`.

### Negative

- A relay now has an outbound HTTPS dependency it did not have before, if an
  operator opts in. It remains fully functional with `[telemetry]` unset —
  this is additive, not load-bearing for Ponor itself.
- The account-agnostic `FindByID` lookup is a new kind of query in
  `relayreg.Store` (every other method is account-scoped); a future
  contributor adding a method there should not assume account scoping is
  universal.

### Reconsider if

A relay ever needs to prove something the control server cannot otherwise
verify (e.g., third-party reachability attestation) — that is a different,
larger trust question than "let me tell you what I already know about
myself," and would need its own decision.
