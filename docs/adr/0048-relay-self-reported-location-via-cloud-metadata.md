<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0048: Relay self-reported location via cloud instance metadata

- **Status:** Proposed
- **Date:** 2026-10-07
- **Deciders:** TBD
- **Related:** ADR-0021 (relay telemetry reporting — this ADR extends its
  signed 80-byte wire format to 104 bytes; ADR-0021 stays Accepted and this
  is recorded as its own ADR rather than an in-place edit, the same
  "reconsider on the record" convention ADR-0024 used for ADR-0023), ADR-0046
  (NOC location and visibility policy — operator-declared relay location,
  which this ADR adds a second source alongside, without reopening its
  client-aggregate-only decision), ADR-0023 (declining device-activity
  visibility — the authority-asymmetry reasoning that rules out GeoIP as the
  mechanism here), ADR-0039 (air-gapped scope — why `detect_location`
  defaults off), ADR-0045 (cost-aware geographic scaling — "one hyperscaler
  (AWS, as the most common)" is the precedent for scoping this to AWS first),
  ADR-0035 (pre-GA breaking-change precedent). Tracking: #241 follow-on.

---

## Context

ADR-0046 gave relays an optional, operator-declared `Location{lat, lon,
label}` for the NOC map — typed by hand into the console or the registry
file. That is manual, and goes stale the moment a relay is actually moved
to a different region or rebuilt in a different cloud account without
anyone remembering to update the console.

The requirement is to get relay location without an operator typing it,
**without** reopening either of two decisions this project has already
made deliberately:

- **Not GeoIP.** Resolving a relay's declared `address` to a location via an
  IP-geolocation database is the inference ADR-0046 §1 already rejected —
  it is involuntary observation of a kind this project has consistently
  avoided (ADR-0023's authority-asymmetry reasoning, restated there for
  client devices, applies identically to inferring anything from network
  behavior rather than being told it directly). GeoIP would also need a
  bundled offline database to satisfy ADR-0039's air-gapped bar, bringing
  its own licensing review (MaxMind GeoLite2 is not freely redistributable;
  DB-IP's CC-BY data would need its own license audit) for a mechanism this
  project doesn't want anyway.
- **Not client location.** Clients stay aggregate-only per ADR-0046 §2.
  Nothing here touches that.

What's left, and what this ADR adopts: **a relay asks its own cloud
platform where it is.** AWS (and other hyperscalers) already expose an
instance-metadata service that answers exactly this, authoritatively, for
any instance running on it. This is still a **declared** fact — the
provider's own record of where it placed the instance, not an inference
from the relay's traffic or address — so it keeps ADR-0046's
declared-not-inferred principle intact while removing the manual step for
the common case of a cloud-hosted relay. A self-hosted, on-prem, or
air-gapped relay has no such service to ask and simply falls back to
whatever is operator-declared, or "unknown" — unchanged from today.

### Checked against the tree before deciding the mechanism

- `bins/karst-relay`'s dependency tree has no HTTP client crate at all.
  `src/metrics.rs`'s own doc comment explains this is deliberate — "avoid a
  registry/macro/dependency tree in a network-facing daemon." `telemetry.rs`
  hand-rolls its HTTPS POST to the control plane over a raw `TcpStream` +
  `tokio-rustls` for the same reason. A cloud-metadata probe follows the
  same discipline: no new crate, a bare `TcpStream` (metadata services are
  plain HTTP, so no TLS layer is even needed here).
- The existing telemetry channel (ADR-0021) is already exactly the right
  transport: a relay periodically pushes a **signed, aggregate-only** report
  about itself, authenticated with its own registered ML-DSA-87 key, no
  session, best-effort. A self-reported location is one more fact about
  itself — this extends that channel by one optional field rather than
  inventing a second reporting path.
- `relayreg.go`'s `compile()` already validates a declared location's range
  (`-90..90` lat, `-180..180` lon) with a named-field error message. A
  self-reported location gets the identical bound, server-side, because the
  server trusts what a relay signs no further than it already does for
  `bytes_total` or any other self-reported field (`RelayTelemetryRecord`'s
  own doc comment: "relay-asserted, signature-authenticated observation,"
  not independently verified truth) — range-checking is a sanity bound, not
  a truthfulness check.
- `relayHealth.Source` (`nodes.go`) already distinguishes `"roster_mtime"`
  from `"relay_telemetry"` on the API response — the exact shape this ADR
  reuses for `location_source` (`"declared"` vs `"detected"`), rather than
  inventing a new provenance convention next to an existing one.

## Decision

**A relay may self-report its location as one more field on ADR-0021's
existing signed telemetry push, detected via AWS's instance-metadata
service (IMDSv2) when the relay chooses to enable it. Detected location
overrides declared location when present; declared remains the fallback
when it isn't.**

### 1. Wire format: 80 bytes → 104 bytes

ADR-0021's signed message gains three more big-endian `uint64` fields,
appended after `uptime_secs`, each kept full-width like every field already
in the layout (nothing packed into fewer bytes, matching the existing
"uniform width, nothing implicit" convention):

```
relay_id        32 bytes   (raw, unchanged)
timestamp        8 bytes   (unchanged)
local_clients     8 bytes   (unchanged)
mesh_peers        8 bytes   (unchanged)
remote_clients    8 bytes   (unchanged)
bytes_total       8 bytes   (unchanged)
uptime_secs       8 bytes   (unchanged)
has_location      8 bytes   (u64, 0 or 1 — new)
lat_e7            8 bytes   (i64 bit pattern, degrees × 10,000,000 — new)
lon_e7            8 bytes   (i64 bit pattern, degrees × 10,000,000 — new)
```

Total 104 bytes. `has_location = 0` means "no detected location"; `lat_e7`/
`lon_e7` are unset/ignored in that case — never a default coordinate.

**Fixed-point scale is ×1e7 ("E7"), not "microdegree."** A microdegree
conventionally means ×1e6; ×1e7 is the scale Google's S2/`LatLng` libraries
call E7, giving roughly 1.1 cm of precision — far more than this needs, but
the point is the name should not mislead a future reader into "fixing" what
looks like an off-by-10. Field names on both sides are `lat_e7`/`lon_e7`.

An explicit presence flag was chosen over a sentinel value (e.g.
`lat_e7 == i64::MIN` meaning "absent") for the same reason the project
already prefers explicit fields over implicit ones elsewhere — a magic
value in a cryptographically signed message is exactly the kind of thing a
future maintainer would have to rediscover by reading both implementations
side by side; a named flag says so directly.

**No label travels over the wire.** A free-text label cannot fit a
fixed-width signed buffer, and the console already falls back to a relay's
`region` string (registry data, a separate and already-authenticated
channel) when `location.label` is empty — a detected location simply has
no label, which is not a regression from today's declared-location display.

### 2. Detection: AWS IMDSv2 only, behind an opt-in flag that defaults off

A new `[telemetry] detect_location` boolean (default **`false`**) gates a
one-time probe, run once at relay startup before the telemetry loop begins
(not re-probed every tick — an instance does not change cloud region
mid-process):

1. `PUT http://169.254.169.254/latest/api/token` with
   `X-aws-ec2-metadata-token-ttl-seconds` — IMDSv2's session-token step.
2. `GET http://169.254.169.254/latest/meta-data/placement/region` with
   `X-aws-ec2-metadata-token: <token>` — the region code (e.g.
   `"us-west-2"`).
3. Look the region code up in a small, explicitly bounded
   `AWS_REGION_CENTROIDS` table (major, well-known AWS regions only — an
   unrecognized code is not guessed at, it falls through to "no location,"
   the same discipline the registry's own validation already applies to a
   malformed declared entry).

A bare `TcpStream`, no TLS (IMDS is plain HTTP by design — this is not the
same code path as `telemetry.rs::post()`, which wraps TLS for the control-
plane POST; the new prober matches only its request-construction and
status-line-parsing *style*). A roughly one-second total budget bounds the
whole probe, so a relay running anywhere other than AWS — self-hosted,
on-prem, or genuinely air-gapped, where `169.254.169.254` is typically
unreachable or refuses the connection immediately — doesn't stall startup
waiting on it. Any failure, timeout, or unrecognized region returns "no
detected location," never a guess.

**`detect_location` defaults to `false`.** Defaulting it on would make
every relay that upgrades begin probing a new network target
(`169.254.169.254`) the moment it restarts, with no operator action and no
notice — exactly the "quietly ignored... rather than told" pattern this
project avoids elsewhere (the explicit presence flag above is the same
instinct applied to the wire format; this is it applied to the config
surface). ADR-0039 frames a deployed relay's reachability as "only the mesh
peers and control plane the operator explicitly configured" — a link-local
metadata probe is a new, if narrowly scoped and bounded, departure from
that, and should be something an AWS-hosted operator turns on, not
something every relay does until told otherwise. One config line is the
entire cost of opting in.

### 3. Precedence: detected overrides declared, never both, never silently dropped

`RelayTelemetryRecord` (`relayreg/store.go`) gains `DetectedLat`,
`DetectedLon *float64`, alongside — not replacing — the registry's existing
`StoredRelay.LocationLat/LocationLon` (declared). `relayResponseFor`
(`api/nodes.go`) prefers the telemetry record's detected coordinates when
present, falling back to the registry's declared ones, falling back to
absent — the same three-tier fallback `healthFor` already uses for health
state, extended to location. The API response carries `location_source:
"declared" | "detected"` so the console can show provenance rather than
implying every pin was hand-entered.

A malformed or out-of-range reported location (`has_location = true` with
`lat_e7`/`lon_e7` outside range once converted) is dropped **on its own** —
the rest of the report (sessions, bytes, uptime) still records normally.
These are unrelated facts riding in one signed payload; a relay with a
corrupted region table has no reason to also go dark on the health view.

### 4. Scope: AWS first, no abstraction built ahead of it

Only AWS IMDSv2 is implemented. `cloud_location::detect()` is a plain
dispatcher function calling into an `aws_imds` submodule — not a trait or
an enum of providers. This codebase has no existing provider-abstraction
pattern to extend, and a trait with exactly one implementor is the kind of
speculative structure this project's own ADRs argue against building ahead
of a second real need (ADR-0045 §5's "no-op/advise driver" is the
deliberately minimal placeholder for exactly this situation). A GCP or
Azure prober, if one is ever written, becomes another `if let Some(loc) =
... { return Some(loc); }` arm in the same dispatcher — a small, concrete
addition, not a migration.

### Alternatives rejected

- **GeoIP on the relay's own `address`.** Rejected per Context above —
  the inference ADR-0046 already ruled out, plus a bundled-database
  licensing question this project doesn't need to take on for a mechanism
  it doesn't want.
- **`detect_location` defaulting to `true`.** Rejected: see §2. The
  asymmetry between "costs one config line to opt in" and "every relay
  silently gains a new network target on upgrade" is not close.
- **A trait-based multi-provider abstraction now**, anticipating GCP/Azure.
  Rejected: no second implementor exists yet to tell us what the right
  shape even is; a plain dispatcher function is the smallest thing that is
  still trivially extensible later.
- **Backward-compatible dual-format verification** (the server accepts
  either the 80-byte or 104-byte signing input, so old relay binaries and
  new server binaries — or vice versa — keep interoperating through an
  upgrade). Rejected: Karst is pre-GA (issue #123 still open) with no
  shipped deployment whose interoperability this decision would break —
  the same floor ADR-0035 already used to decline backfilling pre-migration
  audit rows rather than writing a backfill for a case that does not yet
  exist for any real deployment. A relay and server not upgraded together
  simply fail reports uniformly (the same "telemetry report rejected"
  response a bad signature already produces) until both sides match.
- **A sentinel coordinate for "no location"** instead of an explicit
  `has_location` flag. Rejected per §1 — a magic value inside a signed
  message is the implicit pattern this project avoids, not the convention
  to extend.

---

## Consequences

### Positive

- Relay location on the NOC map no longer requires an operator to type
  coordinates for the common case of a cloud-hosted relay, without
  reopening either the GeoIP or the client-visibility decision.
- No new cryptographic mechanism, no new dependency, no new reporting
  channel — three fields on an existing signed push, detected by a
  dependency-free probe matching this crate's existing style.
- The declared-location path (console form, registry file) is untouched
  and remains the only option for self-hosted/on-prem/air-gapped relays.

### Negative

- **This is a breaking wire-format change.** A relay binary built before
  this ADR and a control-server binary built after it (or vice versa) sign
  and verify different byte layouts; every telemetry report between a
  mismatched pair is rejected, indistinguishable from a bad signature,
  until both sides are upgraded together. Named here rather than solved,
  per the Alternatives-rejected entry above — acceptable pre-GA, not
  acceptable once a real deployment exists, which is a line this project
  will cross and need to revisit (see Reconsider if).
- **A new, if bounded and opt-in, network target.** An AWS-hosted operator
  who enables `detect_location` has a relay that now reaches
  `169.254.169.254` at startup — a narrow, well-understood, non-routable
  address, but a reachability fact that did not exist before and belongs in
  `docs/THREAT-MODEL.md` alongside ADR-0046's own NOC-map entry.
- **The AWS region-centroid table is approximate and will go stale.** New
  AWS regions open after this table is written and will fall through to
  "no detected location" (never a guess) until someone updates it — a real,
  visible gap, not a silent wrong answer, but a maintenance burden
  nonetheless.
- **GCP and Azure relays get nothing from this ADR.** An operator on either
  keeps typing coordinates by hand until a follow-on adds that prober.

### Reconsider if

- Karst ships a real, versioned deployment where a mismatched relay/server
  pair during a rolling upgrade is an actual operational problem rather
  than a pre-GA abstraction — that is when a versioned signing input (a
  leading version byte, or a server that tries both lengths) earns its
  complexity, not before.
- A GCP or Azure operator actually asks for this — at that point `detect()`
  gains a second dispatcher arm, and if a third provider follows after
  that, the trait-abstraction question this ADR declined to answer early
  is worth revisiting with two real implementations to design against
  instead of zero.
- The AWS region table's staleness becomes a recurring real complaint
  rather than a named, visible gap — worth automating against AWS's own
  published region list at that point rather than hand-maintaining it
  forever.
